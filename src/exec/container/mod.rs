//! The backend for code you did not write.
//!
//! It shells out to a container CLI rather than taking an SDK dependency. The
//! CLI is the interface every operator already has, and it keeps a large async
//! client library out of a security boundary.
//!
//! `CORDON_CONTAINER_CLI` picks it: `docker` by default, `podman` where that is
//! what the host has. The README used to claim docker worked "unchanged against
//! podman's docker alias", which is only true on a host that installed the
//! shim; plenty have podman and no `docker` binary at all.

pub mod hosts;

use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{read_capped, ExecError, Job, Network, Outcome};

const PIDS_LIMIT: &str = "128";

pub async fn run(cli: &str, image: &str, job: Job) -> Result<Outcome, ExecError> {
    // The network a container can actually have, which is whatever was asked
    // for: this backend can provide both.
    let network = job.network.clone().unwrap_or_default();
    // Arguments are built before the runtime is probed, so a malformed host pin
    // is a request error rather than reported as the runtime being down.
    let args = container_args(image, &job, &network, current_ids()?)?;
    cli_reachable(cli).await?;

    let started = Instant::now();
    let mut child = Command::new(cli)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| ExecError::BackendUnavailable(format!("{cli}: {e}")))?;

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

/// The uid:gid a container job runs as.
///
/// It is the daemon's own, not `nobody`. The workspace is a bind mount owned by
/// the daemon's user, so a job running as 65534 cannot write to its own
/// workspace: the redirect fails, and because a shell keeps going after a
/// failed redirect the job can still exit 0 and look fine. CI caught exactly
/// that.
///
/// Running as the daemon's uid keeps file ownership correct on both sides of
/// the mount and is still unprivileged, as long as the daemon itself is not
/// root. When it is, the container backend refuses rather than handing a job
/// uid 0 inside a container that shares the host kernel.
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

/// Builds the argument list. Split out from `run` so the isolation policy can
/// be asserted in a unit test with no Docker daemon anywhere near it, which is
/// the only way these flags get reviewed on every change.
pub fn container_args(
    image: &str,
    job: &Job,
    network: &Network,
    user: String,
) -> Result<Vec<String>, ExecError> {
    let mut a: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "-i".into(),
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
        format!("{}:/workspace", job.workspace.display()),
        "-w".into(),
        "/workspace".into(),
    ];
    a.extend(network_args(network)?);

    // The image and everything after it belong to the job, never to docker.
    // Nothing may be appended past this point, which is what the ordering test
    // pins: an entrypoint of `--privileged` has to stay an argument.
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
                // A name to address pin, nothing more. The resolver stays on,
                // because turning it off was the thing that made this look
                // like a boundary while leaving every address reachable.
                a.push("--add-host".into());
                a.push(format!("{}:{}", p.name, p.addr));
            }
            Ok(a)
        }
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

    /// Which runtime the live tests use. `CORDON_CONTAINER_CLI=podman cargo
    /// test` points them at podman, which is what plenty of hosts have instead
    /// of docker, and is how the host-gateway failure in #11 was found.
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
        }
    }

    fn args_for(j: &Job, net: &Network) -> Vec<String> {
        container_args("alpine:3.20", j, net, "1000:1000".into()).unwrap()
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
            "-v /ws:/workspace",
            "-w /workspace",
        ] {
            assert!(a.contains(want), "missing {want} in: {a}");
        }
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

    /// An entrypoint or argument that looks like a flag has to stay an argument
    /// to the job, never a flag to the container runtime.
    #[test]
    fn an_argument_that_looks_like_a_flag_is_not_treated_as_one() {
        let mut j = job("true");
        j.entrypoint = "--privileged".into();
        let args = args_for(&j, &Network::None);
        let image_at = args.iter().position(|a| a == "alpine:3.20").unwrap();
        assert_eq!(args[image_at + 1], "--privileged", "{args:?}");
        assert!(image_at > 0 && args[image_at - 1] != "--privileged");
    }

    /// Issue #11. `open` means open, and the flags say so: a bridge and
    /// nothing that pretends to filter. The old version added
    /// `--dns 0.0.0.0`, which blocked name resolution and left every address
    /// reachable, so it read as a boundary it never was.
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

    /// Review Focus 4. A missing runtime must be a clean BackendUnavailable,
    /// never a panic and never a silent downgrade to the weaker backend.
    ///
    /// Names a runtime that cannot exist rather than emptying PATH. The
    /// earlier version did the latter, and since tests run in parallel it
    /// clobbered PATH underneath the two live container tests, which then
    /// reported the runtime as missing. It only looked harmless because this
    /// machine had no docker for the probe to find either way.
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
        // A shell carries on after a failed redirect, so exit 0 alone does not
        // mean the write happened. An empty stderr is what proves it.
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
}
