//! The backend for code you did not write.
//!
//! It shells out to the `docker` CLI rather than taking a Docker SDK
//! dependency. The CLI is the interface every operator already has, it works
//! unchanged against podman's docker alias, and it keeps a large async client
//! library out of a security boundary.

pub mod egress;

use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{read_capped, ExecError, Job, Outcome};

const PIDS_LIMIT: &str = "128";

pub async fn run(image: &str, job: Job) -> Result<Outcome, ExecError> {
    // Arguments are built before the daemon is probed, so a malformed egress
    // entry is a request error rather than reported as docker being down.
    let args = docker_args_as(image, &job, current_ids()?)?;
    docker_reachable().await?;

    let started = Instant::now();
    let mut child = Command::new("docker")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| ExecError::BackendUnavailable(format!("docker: {e}")))?;

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
        }),
        Err(_) => Ok(Outcome {
            exit_code: 124,
            stdout: String::new(),
            stderr: format!("killed after {}ms", job.limits.wall_ms),
            truncated: true,
            duration_ms: started.elapsed().as_millis(),
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
pub fn docker_args_as(image: &str, job: &Job, user: String) -> Result<Vec<String>, ExecError> {
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
    a.extend(network_args(job)?);

    // The image and everything after it belong to the job, never to docker.
    // Nothing may be appended past this point, which is what the ordering test
    // pins: an entrypoint of `--privileged` has to stay an argument.
    a.push(image.to_string());
    a.push(job.entrypoint.clone());
    a.extend(job.args.iter().cloned());
    Ok(a)
}

fn network_args(job: &Job) -> Result<Vec<String>, ExecError> {
    if job.egress.is_empty() {
        return Ok(vec!["--network".into(), "none".into()]);
    }
    egress::args(&job.egress)
}

async fn docker_reachable() -> Result<(), ExecError> {
    let probe = Command::new("docker")
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
            egress: vec![],
        }
    }

    /// A live container test skips on a laptop with no docker and fails where
    /// docker is supposed to be there. Deciding it inside the test means CI
    /// needs no second cargo run and no grep over its output, which is how the
    /// previous version of this check went flaky.
    async fn docker_or_skip(test: &str) -> bool {
        if docker_reachable().await.is_ok() {
            return true;
        }
        assert!(
            std::env::var("CORDON_REQUIRE_DOCKER").is_err(),
            "{test}: CORDON_REQUIRE_DOCKER is set but the docker probe failed"
        );
        eprintln!("SKIPPED {test}: no docker here");
        false
    }

    fn joined(j: &Job) -> String {
        docker_args_as("alpine:3.20", j, "1000:1000".into())
            .unwrap()
            .join(" ")
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
        // The daemon's own uid, which is what makes the bind mount writable.
        // Root is refused outright, which current_ids covers.
        assert!(
            joined(&job("true")).contains("--user 1000:1000"),
            "no --user pinned"
        );
    }

    #[test]
    fn a_container_job_refuses_to_run_as_root() {
        // current_ids is what enforces it; this asserts the message an
        // operator sees, since the condition itself depends on who runs the
        // test suite.
        let msg = match current_ids() {
            Err(ExecError::Unsupported(m)) => m,
            _ => return, // not running as root, nothing to assert here
        };
        assert!(msg.contains("unprivileged"), "unhelpful message: {msg}");
    }

    #[test]
    fn a_writable_tmpfs_exists_but_cannot_execute() {
        let a = joined(&job("true"));
        assert!(a.contains("--tmpfs /tmp:rw,noexec,nosuid"), "{a}");
    }

    #[test]
    fn the_image_and_entrypoint_come_last_so_no_flag_can_follow() {
        let args = docker_args_as("alpine:3.20", &job("echo hi"), "1000:1000".into()).unwrap();
        let image_at = args.iter().position(|a| a == "alpine:3.20").unwrap();
        assert_eq!(args[image_at + 1], "sh");
        assert!(
            args[image_at..].iter().all(|a| !a.starts_with("--")),
            "a flag appears after the image: {args:?}"
        );
    }

    /// An entrypoint or argument that looks like a docker flag has to stay an
    /// argument to the job, never a flag to docker.
    #[test]
    fn an_argument_that_looks_like_a_flag_is_not_treated_as_one() {
        let mut j = job("true");
        j.entrypoint = "--privileged".into();
        let args = docker_args_as("alpine:3.20", &j, "1000:1000".into()).unwrap();
        let image_at = args.iter().position(|a| a == "alpine:3.20").unwrap();
        assert_eq!(args[image_at + 1], "--privileged", "{args:?}");
        assert!(image_at > 0 && args[image_at - 1] != "--privileged");
    }

    #[test]
    fn a_malformed_egress_entry_is_a_request_error_not_a_backend_error() {
        let mut j = job("true");
        j.egress = vec!["--privileged:443".into()];
        let err = docker_args_as("alpine:3.20", &j, "1000:1000".into()).unwrap_err();
        assert!(matches!(err, ExecError::Unsupported(_)), "got {err:?}");
    }

    /// Review Focus 4. Docker missing or stopped must be a clean
    /// BackendUnavailable, never a panic and never a silent downgrade to the
    /// weaker process backend.
    #[tokio::test]
    async fn a_missing_docker_is_reported_not_worked_around() {
        // PATH is emptied rather than DOCKER_HOST set, so the probe fails the
        // same way on a machine that has no docker binary at all.
        let saved = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", "/nonexistent");
        let err = Backend::Container {
            image: "alpine:3.20".into(),
        }
        .run(job("true"))
        .await
        .expect_err("must refuse when docker is unreachable");
        std::env::set_var("PATH", saved);
        assert!(
            matches!(err, ExecError::BackendUnavailable(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn runs_a_real_container_when_docker_is_present() {
        if !docker_or_skip("runs_a_real_container_when_docker_is_present").await {
            return;
        }
        let ws = std::env::temp_dir().join(format!("cordon-ctr-{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();
        let mut j = job("printf hi > out.txt; echo done");
        j.workspace = ws.clone();

        let out = Backend::Container {
            image: "alpine:3.20".into(),
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
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn a_container_has_no_network_unless_asked() {
        if !docker_or_skip("a_container_has_no_network_unless_asked").await {
            return;
        }
        let ws = std::env::temp_dir().join(format!("cordon-ctr-net-{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();
        let mut j = job("wget -q -T 3 -O - https://example.com || echo BLOCKED");
        j.workspace = ws.clone();
        let out = Backend::Container {
            image: "alpine:3.20".into(),
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
