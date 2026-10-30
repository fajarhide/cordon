//! The backend for code you did not write. `CORDON_CONTAINER_CLI` picks docker or podman.
//! Shells out to the CLI rather than an SDK, keeping a large client out of a security boundary.

pub mod hosts;

use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{read_capped, ExecError, Job, Network, Outcome, Spawned};

const PIDS_LIMIT: &str = "128";

pub async fn run(cli: &str, image: &str, job: Job) -> Result<Outcome, ExecError> {
    let Spawned {
        mut child,
        network,
        env_file: _env_file,
    } = spawn(cli, image, &job).await?;
    let started = Instant::now();

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(job.stdin.as_bytes()).await;
        drop(stdin);
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let cap = job.limits.stdout_kb.saturating_mul(1024).max(1024);

    let collect = async {
        let (o, ot) = match stdout {
            Some(s) => read_capped(s, cap).await,
            None => (String::new(), false),
        };
        let (e, et) = match stderr {
            Some(s) => read_capped(s, cap).await,
            None => (String::new(), false),
        };
        (o, ot, e, et, child.wait().await)
    };

    match tokio::time::timeout(Duration::from_millis(job.limits.wall_ms), collect).await {
        Ok((stdout, ot, stderr, et, status)) => Ok(Outcome {
            exit_code: status.ok().and_then(|s| s.code()).unwrap_or(-1),
            stdout,
            stderr,
            truncated: ot || et,
            duration_ms: started.elapsed().as_millis(),
            network: network.clone(),
        }),
        Err(_) => Ok(Outcome {
            exit_code: 124,
            stdout: String::new(),
            stderr: format!("killed after {}ms", job.limits.wall_ms),
            truncated: true,
            duration_ms: started.elapsed().as_millis(),
            network,
        }),
    }
}

/// The job's container, started, and the network it actually got. `run` waits on it; a stdio job
/// (`/v1/stdio`) relays it for as long as its client stays connected.
pub async fn spawn(cli: &str, image: &str, job: &Job) -> Result<Spawned, ExecError> {
    // Unasked means no network; this backend can provide either.
    let network = job.network.clone().unwrap_or_default();
    // Built before probing the runtime, so a malformed host pin is a request error.
    let env_file = if job.env.is_empty() {
        None
    } else {
        Some(EnvFile::write(&job.env)?)
    };
    let args = container_args(
        cli,
        image,
        job,
        &network,
        current_ids()?,
        env_file.as_ref().map(|f| f.path.as_path()),
    )?;
    cli_reachable(cli).await?;
    image_present(cli, image).await?;
    let child = Command::new(cli)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| ExecError::BackendUnavailable(format!("{cli}: {e}")))?;
    Ok(Spawned {
        child,
        network,
        env_file,
    })
}

/// The job's environment for `--env-file`: owner-only, removed when the job's `Spawned` goes.
/// The CLI reads it at a time cordon cannot see, so it stays for the whole job.
pub struct EnvFile {
    pub path: std::path::PathBuf,
}

impl EnvFile {
    fn write(env: &[(String, String)]) -> Result<Self, ExecError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut body = String::new();
        for (k, v) in env {
            // One line per variable in an env file: a newline would start a second one.
            if v.contains(['\n', '\r', '\0']) {
                return Err(ExecError::Unsupported(format!(
                    "the value of {k} has a newline or a NUL"
                )));
            }
            body.push_str(&format!("{k}={v}\n"));
        }
        let mut rand = [0u8; 12];
        getrandom::fill(&mut rand).map_err(|e| ExecError::Spawn(format!("random: {e}")))?;
        let name: String = rand.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("cordon-env-{name}"));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| ExecError::Spawn(format!("env file: {e}")))?;
        f.write_all(body.as_bytes())
            .map_err(|e| ExecError::Spawn(format!("env file: {e}")))?;
        Ok(EnvFile { path })
    }
}

impl Drop for EnvFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The daemon's own uid:gid, not `nobody`, which cannot write the daemon-owned bind mount.
/// Refused when the daemon is root: that would be uid 0 in a container sharing the host kernel.
fn current_ids() -> Result<String, ExecError> {
    // Reading the process's own ids. No pointers, no allocation, cannot fail.
    #[allow(unsafe_code)]
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    if uid == 0 {
        return Err(ExecError::Unsupported(
            "cordon is running as root, so a container job would run as root inside a container that shares the host kernel; run cordon as an unprivileged user (see packaging/cordond.service)".into(),
        ));
    }
    Ok(format!("{uid}:{gid}"))
}

/// Split from `run` so the isolation flags can be unit tested without a runtime.
pub fn container_args(
    cli: &str,
    image: &str,
    job: &Job,
    network: &Network,
    user: String,
    env_file: Option<&std::path::Path>,
) -> Result<Vec<String>, ExecError> {
    let mut a: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "-i".into(),
        // Without this the runtime's pull progress lands in the job's stderr.
        "--pull".into(),
        "never".into(),
        "--read-only".into(),
        "--user".into(),
        user,
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit".into(),
        PIDS_LIMIT.into(),
        "--memory".into(),
        format!("{}m", job.limits.memory_mb),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,size=64m".into(),
        "-v".into(),
        // Shared SELinux label: unlabelled fails on enforcing hosts, and :Z cuts off a
        // concurrent job for the same owner. Runtimes ignore it without SELinux (#24).
        format!("{}:/workspace:z", job.workspace.display()),
        "-w".into(),
        "/workspace".into(),
    ];
    // Rootless podman maps container uids to host subuids, so without keep-id the job cannot
    // write its bind-mounted workspace. Docker's --user is already a host uid.
    if cli == "podman" {
        a.push("--userns".into());
        a.push("keep-id".into());
    }
    a.extend(network_args(network)?);
    // Values ride in a file, so they are never on this command line or in the CLI's own environment.
    if let Some(f) = env_file {
        a.push("--env-file".into());
        a.push(f.display().to_string());
    }

    // Nothing may be appended past the image: an entrypoint of `--privileged` stays an argument.
    a.push(image.to_string());
    a.push(job.entrypoint.clone());
    a.extend(job.args.iter().cloned());
    Ok(a)
}

fn network_args(network: &Network) -> Result<Vec<String>, ExecError> {
    match network {
        Network::None => Ok(vec!["--network".into(), "none".into()]),
        Network::Open { pins } => {
            let mut a = vec!["--network".into(), "bridge".into()];
            for p in pins {
                // The resolver stays on: disabling it blocks names, not addresses (#11).
                a.push("--add-host".into());
                a.push(format!("{}:{}", p.name, p.addr));
            }
            Ok(a)
        }
    }
}

/// cordon never pulls (`--pull never`), so the operator pulls `CORDON_IMAGE` beforehand.
/// Checked before the job so a missing image is a backend error, not runtime text in its output.
async fn image_present(cli: &str, image: &str) -> Result<(), ExecError> {
    let probe = Command::new(cli)
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match tokio::time::timeout(Duration::from_secs(10), probe).await {
        Ok(Ok(s)) if s.success() => Ok(()),
        Ok(Ok(_)) => Err(ExecError::BackendUnavailable(format!(
            "{image} is not present; cordon does not pull images, run `{cli} pull {image}` first"
        ))),
        Ok(Err(e)) => Err(ExecError::BackendUnavailable(format!(
            "{cli} image inspect: {e}"
        ))),
        Err(_) => Err(ExecError::BackendUnavailable(format!(
            "{cli} image inspect did not answer in 10s"
        ))),
    }
}

async fn cli_reachable(cli: &str) -> Result<(), ExecError> {
    let probe = Command::new(cli)
        .args(["version", "--format", "{{.Server.Version}}"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match tokio::time::timeout(Duration::from_secs(10), probe).await {
        Ok(Ok(s)) if s.success() => Ok(()),
        Ok(Ok(s)) => Err(ExecError::BackendUnavailable(format!(
            "docker is installed but not answering (exit {})",
            s.code().unwrap_or(-1)
        ))),
        Ok(Err(e)) => Err(ExecError::BackendUnavailable(format!(
            "docker not runnable: {e}"
        ))),
        Err(_) => Err(ExecError::BackendUnavailable(
            "docker did not answer in 3s".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{Backend, Limits};
    use std::path::PathBuf;

    /// `CORDON_CONTAINER_CLI=podman cargo test` points the live tests at podman.
    fn cli() -> String {
        std::env::var("CORDON_CONTAINER_CLI").unwrap_or_else(|_| "docker".into())
    }

    fn job(script: &str) -> Job {
        Job {
            workspace: PathBuf::from("/ws"),
            entrypoint: "sh".into(),
            args: vec!["-c".into(), script.into()],
            stdin: String::new(),
            limits: Limits {
                wall_ms: 20_000,
                memory_mb: 128,
                stdout_kb: 64,
            },
            network: None,
            unsafe_process: cfg!(not(target_os = "linux")),
            env: Vec::new(),
        }
    }

    fn args_for(j: &Job, net: &Network) -> Vec<String> {
        container_args(&cli(), "alpine:3.20", j, net, "1000:1000".into(), None).unwrap()
    }

    fn joined(j: &Job) -> String {
        args_for(j, &Network::None).join(" ")
    }

    fn pins(pairs: &[(&str, &str)]) -> Network {
        use std::collections::BTreeMap;
        let m: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Network::Open {
            pins: hosts::parse(m.iter()).unwrap(),
        }
    }

    #[test]
    fn the_isolation_flags_are_all_present() {
        let a = joined(&job("true"));
        for want in [
            "--rm",
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--pids-limit 128",
            "--memory 128m",
            "-v /ws:/workspace:z",
            "-w /workspace",
        ] {
            assert!(a.contains(want), "missing {want} in: {a}");
        }
    }

    /// `:Z` would give each job a private label, so a second job for the same owner would
    /// lock the first out of its own workspace (#24).
    #[test]
    fn the_workspace_label_is_shared_never_private() {
        let a = joined(&job("true"));
        assert!(a.contains("/ws:/workspace:z "), "{a}");
        assert!(
            !a.contains(":Z"),
            "a private label cuts off concurrent jobs: {a}"
        );
    }

    /// Without keep-id a rootless podman job cannot write to its own bind-mounted workspace.
    #[test]
    fn podman_gets_keep_id_and_docker_does_not() {
        let j = job("true");
        let pod = container_args(
            "podman",
            "alpine:3.20",
            &j,
            &Network::None,
            "1000:1000".into(),
            None,
        )
        .unwrap()
        .join(" ");
        let doc = container_args(
            "docker",
            "alpine:3.20",
            &j,
            &Network::None,
            "1000:1000".into(),
            None,
        )
        .unwrap()
        .join(" ");
        assert!(pod.contains("--userns keep-id"), "{pod}");
        assert!(!doc.contains("--userns"), "{doc}");
    }

    #[test]
    fn the_runtime_never_pulls_during_a_job() {
        assert!(joined(&job("true")).contains("--pull never"));
    }

    #[test]
    fn the_job_never_runs_as_root() {
        assert!(
            joined(&job("true")).contains("--user 1000:1000"),
            "no --user pinned"
        );
    }

    #[test]
    fn a_container_job_refuses_to_run_as_root() {
        let msg = match current_ids() {
            Err(ExecError::Unsupported(m)) => m,
            _ => return, // not running as root, nothing to assert here
        };
        assert!(msg.contains("unprivileged"), "unhelpful message: {msg}");
    }

    #[test]
    fn a_writable_tmpfs_exists_but_cannot_execute() {
        assert!(joined(&job("true")).contains("--tmpfs /tmp:rw,noexec,nosuid"));
    }

    #[test]
    fn the_image_and_entrypoint_come_last_so_no_flag_can_follow() {
        let args = args_for(&job("echo hi"), &Network::None);
        let image_at = args.iter().position(|a| a == "alpine:3.20").unwrap();
        assert_eq!(args[image_at + 1], "sh");
        assert!(
            args[image_at..].iter().all(|a| !a.starts_with("--")),
            "a flag appears after the image: {args:?}"
        );
    }

    #[test]
    fn an_argument_that_looks_like_a_flag_is_not_treated_as_one() {
        let mut j = job("true");
        j.entrypoint = "--privileged".into();
        let args = args_for(&j, &Network::None);
        let image_at = args.iter().position(|a| a == "alpine:3.20").unwrap();
        assert_eq!(args[image_at + 1], "--privileged", "{args:?}");
        assert!(image_at > 0 && args[image_at - 1] != "--privileged");
    }

    /// `--dns` must not come back: it blocks names and leaves every address reachable (#11).
    #[test]
    fn open_is_a_bridge_with_no_pretence_of_filtering() {
        let a = args_for(&job("true"), &pins(&[("litellm.internal", "10.0.0.5")])).join(" ");
        assert!(a.contains("--network bridge"), "{a}");
        assert!(!a.contains("--network none"), "{a}");
        assert!(
            !a.contains("--dns"),
            "a --dns flag is back, and it only ever looked like a filter: {a}"
        );
        assert!(a.contains("--add-host litellm.internal:10.0.0.5"), "{a}");
    }

    #[test]
    fn a_pin_carries_an_address_the_caller_gave_not_a_magic_name() {
        let a = args_for(&job("true"), &pins(&[("db.internal", "10.0.0.9")])).join(" ");
        assert!(
            !a.contains("host-gateway"),
            "host-gateway is back; it fails the container outright under rootless podman with netavark: {a}"
        );
    }

    #[test]
    fn no_network_takes_no_pins_and_stays_closed() {
        let a = args_for(&job("true"), &Network::None).join(" ");
        assert!(a.contains("--network none"), "{a}");
        assert!(!a.contains("--add-host"), "{a}");
    }

    /// Never a panic or a silent downgrade to the weaker backend. Names a runtime that cannot
    /// exist rather than emptying PATH, which the parallel live container tests also read.
    #[tokio::test]
    async fn a_missing_runtime_is_reported_not_worked_around() {
        let err = Backend::Container {
            image: "alpine:3.20".into(),
            cli: "cordon-no-such-runtime".into(),
        }
        .run(job("true"))
        .await
        .expect_err("must refuse when the runtime is unreachable");
        assert!(
            matches!(err, ExecError::BackendUnavailable(_)),
            "got {err:?}"
        );
    }

    async fn runtime_or_skip(test: &str) -> bool {
        if cli_reachable(&cli()).await.is_ok() {
            return true;
        }
        assert!(
            std::env::var("CORDON_REQUIRE_DOCKER").is_err(),
            "{test}: CORDON_REQUIRE_DOCKER is set but the {} probe failed",
            cli()
        );
        eprintln!("SKIPPED {test}: no {} here", cli());
        false
    }

    #[tokio::test]
    async fn runs_a_real_container_when_a_runtime_is_present() {
        if !runtime_or_skip("runs_a_real_container_when_a_runtime_is_present").await {
            return;
        }
        let ws = std::env::temp_dir().join(format!("cordon-ctr-{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();
        let mut j = job("printf hi > out.txt; echo done");
        j.workspace = ws.clone();

        let out = Backend::Container {
            image: "alpine:3.20".into(),
            cli: cli(),
        }
        .run(j)
        .await
        .unwrap();
        assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
        assert_eq!(out.stdout.trim(), "done");
        // A shell carries on after a failed redirect, so the empty stderr is what proves it.
        assert_eq!(out.stderr, "", "the job wrote to stderr");
        assert_eq!(
            std::fs::read(ws.join("out.txt"))
                .expect("the job could not write to its own workspace"),
            b"hi"
        );
        assert_eq!(out.network, Network::None);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn a_container_has_no_network_unless_asked() {
        if !runtime_or_skip("a_container_has_no_network_unless_asked").await {
            return;
        }
        let ws = std::env::temp_dir().join(format!("cordon-ctr-net-{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();
        let mut j = job("wget -q -T 3 -O - https://example.com || echo BLOCKED");
        j.workspace = ws.clone();
        let out = Backend::Container {
            image: "alpine:3.20".into(),
            cli: cli(),
        }
        .run(j)
        .await
        .unwrap();
        assert!(
            out.stdout.contains("BLOCKED"),
            "the container reached the network: {}",
            out.stdout
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    /// The path `/v1/stdio` takes: started, fed a line, read back, with no network and nothing past its workspace.
    #[tokio::test]
    async fn a_spawned_container_answers_on_stdout_and_still_has_no_network_or_outside_view() {
        if !runtime_or_skip(
            "a_spawned_container_answers_on_stdout_and_still_has_no_network_or_outside_view",
        )
        .await
        {
            return;
        }
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let parent = std::env::temp_dir().join(format!("cordon-ctr-stdio-{}", std::process::id()));
        let ws = parent.join("owner");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(parent.join("next-to-the-workspace.db"), b"secret").unwrap();
        let j = job("read l; echo got:$l; ls -a / /workspace | tr '\\n' ' '; echo; wget -q -T 3 -O - https://example.com || echo BLOCKED");
        let j = Job {
            workspace: ws.clone(),
            ..j
        };
        let Spawned {
            mut child, network, ..
        } = Backend::Container {
            image: "alpine:3.20".into(),
            cli: cli(),
        }
        .spawn(&j)
        .await
        .unwrap();
        assert_eq!(network, Network::None);
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"hello\n")
            .await
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut seen = String::new();
        while let Ok(Some(l)) = lines.next_line().await {
            seen.push_str(&l);
            seen.push('\n');
        }
        assert!(seen.contains("got:hello"), "no answer on stdout: {seen}");
        assert!(
            seen.contains("BLOCKED"),
            "the container reached the network: {seen}"
        );
        assert!(
            !seen.contains("next-to-the-workspace.db"),
            "a file outside the workspace showed: {seen}"
        );
        let _ = child.wait().await;
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn an_env_file_is_a_flag_before_the_image_and_no_value_reaches_the_command_line() {
        let j = Job {
            env: vec![("GITHUB_TOKEN".into(), "s3cret".into())],
            ..job("true")
        };
        let path = std::path::Path::new("/tmp/cordon-env-x");
        let a = container_args(
            "podman",
            "alpine:3.20",
            &j,
            &Network::None,
            "1000:1000".into(),
            Some(path),
        )
        .unwrap();
        let flag = a
            .iter()
            .position(|x| x == "--env-file")
            .expect("no --env-file");
        assert_eq!(a[flag + 1], "/tmp/cordon-env-x");
        assert!(
            flag < a.iter().position(|x| x == "alpine:3.20").unwrap(),
            "the flag came after the image"
        );
        assert!(
            !a.join(" ").contains("s3cret"),
            "a value reached the command line"
        );
    }

    #[test]
    fn an_env_file_is_owner_only_and_goes_with_the_job() {
        use std::os::unix::fs::PermissionsExt;
        let f =
            EnvFile::write(&[("A".into(), "b c".into()), ("TOKEN".into(), "x=y".into())]).unwrap();
        let path = f.path.clone();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "A=b c\nTOKEN=x=y\n"
        );
        drop(f);
        assert!(!path.exists(), "the env file outlived its job");
        assert!(
            EnvFile::write(&[("A".into(), "one\nB=two".into())]).is_err(),
            "a newline made a second variable"
        );
    }

    #[tokio::test]
    async fn a_spawned_container_sees_its_env_and_the_env_file_goes_with_it() {
        if !runtime_or_skip("a_spawned_container_sees_its_env_and_the_env_file_goes_with_it").await
        {
            return;
        }
        use tokio::io::AsyncReadExt;
        let ws = std::env::temp_dir().join(format!("cordon-ctr-env-{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();
        let j = Job {
            workspace: ws.clone(),
            env: vec![("GREETING".into(), "hello there".into())],
            ..job("echo \"$GREETING\"")
        };
        let spawned = Backend::Container {
            image: "alpine:3.20".into(),
            cli: cli(),
        }
        .spawn(&j)
        .await
        .unwrap();
        let path = spawned.env_file.as_ref().unwrap().path.clone();
        let Spawned {
            mut child,
            env_file,
            ..
        } = spawned;
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .await
            .unwrap();
        let _ = child.wait().await;
        assert_eq!(out.trim(), "hello there");
        drop(env_file);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&ws);
    }
}
