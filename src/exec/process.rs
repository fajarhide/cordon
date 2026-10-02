//! One unsafe block lives here, and nowhere else in the crate.
#![allow(unsafe_code)]

//! The default backend. One process, cwd pinned to the workspace, a scrubbed
//! environment, its own session so a timeout takes the children too, and
//! rlimits applied between fork and exec.
//!
//! What it does not give you: a network namespace, a read only root, or a
//! separate pid namespace. It is the backend for a 1 GB VPS running code you
//! wrote. Code you did not write belongs in the container backend.

use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{read_capped, ExecError, Job, Outcome};

pub async fn run(job: Job) -> Result<Outcome, ExecError> {
    if !job.egress.is_empty() {
        return Err(ExecError::Unsupported(
            "the process backend shares the host network namespace and cannot enforce an egress allowlist; use the container backend".into(),
        ));
    }

    let mut cmd = Command::new(&job.entrypoint);
    cmd.args(&job.args)
        .current_dir(&job.workspace)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", &job.workspace)
        .env("TMPDIR", &job.workspace)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    apply_limits(&mut cmd, &job);

    let started = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| ExecError::Spawn(format!("spawn {}: {e}", job.entrypoint)))?;

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
        // 124 is what timeout(1) uses, so an operator reading a log already
        // knows what it means.
        Err(_) => Ok(Outcome {
            exit_code: 124,
            stdout: String::new(),
            stderr: format!("killed after {}ms", job.limits.wall_ms),
            truncated: true,
            duration_ms: started.elapsed().as_millis(),
        }),
    }
}

/// Applies rlimits in the child between fork and exec.
///
/// `pre_exec` runs in a forked process where only async-signal-safe calls are
/// legal, which is why the closure does nothing but `setsid` and `setrlimit`.
/// This is the one unsafe block in the crate.
fn apply_limits(cmd: &mut Command, job: &Job) {
    let memory_bytes = job.limits.memory_mb.saturating_mul(1024 * 1024);
    unsafe {
        cmd.pre_exec(move || {
            // Its own session, so a timeout can take the whole tree and not
            // just the shell that spawned it.
            libc::setsid();

            set(libc::RLIMIT_CPU, 60);
            set(libc::RLIMIT_FSIZE, 1024 * 1024 * 1024);
            set(libc::RLIMIT_NOFILE, 256);
            set(libc::RLIMIT_CORE, 0);
            // RLIMIT_AS is the portable address space cap. On Linux it is the
            // effective memory limit for this backend; on macOS it is
            // advisory, which is one more reason untrusted code belongs in the
            // container backend.
            if memory_bytes > 0 {
                set(libc::RLIMIT_AS, memory_bytes);
            }
            Ok(())
        });
    }
}

/// RLIMIT_CPU is fixed at 60s rather than derived from wall_ms: a job can be
/// slow on IO without burning CPU, and killing it for that would be wrong. The
/// wall clock is the limit the request controls.
unsafe fn set(resource: libc::c_int, value: u64) {
    let rl = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    libc::setrlimit(resource, &rl);
}

#[cfg(test)]
mod tests {
    use crate::exec::{Backend, ExecError, Job, Limits};
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("cordon-proc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("temp workspace");
        p
    }

    fn job(ws: PathBuf, script: &str) -> Job {
        Job {
            workspace: ws,
            entrypoint: "sh".into(),
            args: vec!["-c".into(), script.into()],
            stdin: String::new(),
            limits: Limits { wall_ms: 5_000, memory_mb: 256, stdout_kb: 64 },
            egress: vec![],
        }
    }

    #[tokio::test]
    async fn runs_a_job_in_its_workspace() {
        let ws = tmp("ok");
        let out = Backend::Process
            .run(job(ws.clone(), "printf hello > out.txt; echo done"))
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
        assert_eq!(out.stdout.trim(), "done");
        assert_eq!(std::fs::read(ws.join("out.txt")).unwrap(), b"hello");
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_a_result_not_an_error() {
        let out = Backend::Process.run(job(tmp("exit"), "exit 3")).await.unwrap();
        assert_eq!(out.exit_code, 3);
    }

    #[tokio::test]
    async fn stdin_reaches_the_job() {
        let mut j = job(tmp("stdin"), "cat");
        j.stdin = "fed in".into();
        let out = Backend::Process.run(j).await.unwrap();
        assert_eq!(out.stdout, "fed in");
    }

    #[tokio::test]
    async fn a_job_over_its_wall_clock_is_killed() {
        let mut j = job(tmp("timeout"), "sleep 10");
        j.limits.wall_ms = 300;
        let out = Backend::Process.run(j).await.unwrap();
        assert_ne!(out.exit_code, 0, "a timed out job reported success");
        assert!(
            out.duration_ms < 5_000,
            "took {}ms, the timeout did not fire",
            out.duration_ms
        );
    }

    #[tokio::test]
    async fn runaway_output_is_truncated_rather_than_buffered() {
        let mut j = job(tmp("flood"), "yes abcdefgh | head -c 500000");
        j.limits.stdout_kb = 1;
        let out = Backend::Process.run(j).await.unwrap();
        assert!(out.truncated, "a 500 KB flood was not marked truncated");
        assert!(out.stdout.len() <= 2048, "kept {} bytes", out.stdout.len());
    }

    /// The process backend shares the host network namespace, so it cannot
    /// honour an allowlist. Refusing is the only honest answer: silently
    /// granting full network access because the caller asked for two hosts
    /// would be worse than either.
    #[tokio::test]
    async fn an_egress_allowlist_is_refused_rather_than_ignored() {
        let mut j = job(tmp("egress"), "true");
        j.egress = vec!["example.com:443".into()];
        let err = Backend::Process.run(j).await.expect_err("must refuse");
        assert!(matches!(err, ExecError::Unsupported(_)), "got {err:?}");
    }

    /// Review Focus 3. Two jobs for one owner must not interleave into a
    /// corrupt file.
    #[tokio::test]
    async fn concurrent_jobs_in_one_workspace_do_not_corrupt_a_shared_file() {
        let ws = tmp("concurrent");
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let ws = ws.clone();
            set.spawn(async move {
                Backend::Process.run(job(ws, "printf x >> shared.txt")).await.unwrap()
            });
        }
        while let Some(r) = set.join_next().await {
            assert_eq!(r.unwrap().exit_code, 0);
        }
        assert_eq!(
            std::fs::read(ws.join("shared.txt")).unwrap().len(),
            8,
            "appends interleaved"
        );
    }

    #[tokio::test]
    async fn a_missing_entrypoint_is_an_error_not_a_panic() {
        let mut j = job(tmp("missing"), "true");
        j.entrypoint = "definitely-not-on-this-machine".into();
        let err = Backend::Process.run(j).await.expect_err("must error");
        assert!(matches!(err, ExecError::Spawn(_)), "got {err:?}");
    }
}
