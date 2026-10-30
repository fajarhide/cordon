#![allow(unsafe_code)]

//! The default backend: one process in its own session, scrubbed environment, rlimits, Landlock.
//! No network or pid namespace and no read only root: untrusted code belongs in the container.

use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{read_capped, ExecError, Job, Network, Outcome};

pub async fn run(job: Job) -> Result<Outcome, ExecError> {
    let (mut child, network) = spawn(&job)?;
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
        // 124 is what timeout(1) uses.
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

/// The job's process, started inside its boundary, and the network it actually got. `run` waits on it;
/// a stdio job (`/v1/stdio`) relays it for as long as its client stays connected.
pub fn spawn(job: &Job) -> Result<(tokio::process::Child, Network), ExecError> {
    // Shares the host network namespace, so it can give open access and never none (#1, #11).
    let network = match &job.network {
        None => Network::Open { pins: Vec::new() },
        Some(Network::Open { pins }) if pins.is_empty() => Network::Open { pins: Vec::new() },
        Some(Network::Open { .. }) => {
            return Err(ExecError::Unsupported(
                "the process backend cannot pin host names for a job; use the container backend"
                    .into(),
            ))
        }
        Some(Network::None) => {
            return Err(ExecError::Unsupported(
                "the process backend shares the host network namespace and cannot give a job no network; use the container backend".into(),
            ))
        }
    };

    // Built in the parent, where allocating is safe; the child applies it with syscalls only (#1).
    let boundary = crate::sandbox::Prepared::build(&job.workspace, &crate::sandbox::system_paths());
    if let Some(why) = boundary.why_unavailable() {
        if !job.unsafe_process {
            return Err(ExecError::Unsupported(format!(
                "refusing to run a job with no filesystem boundary: {why}. Use the container backend, or set CORDON_UNSAFE_PROCESS_BACKEND=1 if this is a development machine"
            )));
        }
        eprintln!("cordon: WARNING no filesystem boundary for this job: {why}");
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

    apply_limits(&mut cmd, job, boundary.raw_fd());

    let child = cmd
        .spawn()
        .map_err(|e| ExecError::Spawn(format!("spawn {}: {e}", job.entrypoint)))?;
    // The child has exec'd by the time spawn returns, so the ruleset descriptor can go.
    drop(boundary);
    Ok((child, network))
}

/// `pre_exec` runs after fork, where only async-signal-safe calls are legal: no allocation.
fn apply_limits(cmd: &mut Command, job: &Job, boundary_fd: Option<i32>) {
    let memory_bytes = job.limits.memory_mb.saturating_mul(1024 * 1024);
    unsafe {
        cmd.pre_exec(move || {
            // Own session, so a timeout kills the whole tree and not just the shell.
            libc::setsid();

            // Syscalls only, on a descriptor the parent already built.
            #[cfg(target_os = "linux")]
            if let Some(fd) = boundary_fd {
                crate::sandbox::linux::apply(fd)?;
            }
            #[cfg(not(target_os = "linux"))]
            let _ = boundary_fd;

            set(libc::RLIMIT_CPU, 60);
            set(libc::RLIMIT_FSIZE, 1024 * 1024 * 1024);
            set(libc::RLIMIT_NOFILE, 256);
            set(libc::RLIMIT_CORE, 0);
            // RLIMIT_AS is the effective memory cap on Linux and only advisory on macOS.
            if memory_bytes > 0 {
                set(libc::RLIMIT_AS, memory_bytes);
            }
            Ok(())
        });
    }
}

/// Rlimit constants are `c_int` on macOS and the BSDs, `__rlimit_resource_t` (u32) on glibc.
#[cfg(target_env = "gnu")]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
type Resource = libc::c_int;

/// RLIMIT_CPU is fixed at 60s, not derived from wall_ms: a job slow on IO burns no CPU.
unsafe fn set(resource: Resource, value: u64) {
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
            limits: Limits {
                wall_ms: 5_000,
                memory_mb: 256,
                stdout_kb: 64,
            },
            network: None,
            // Landlock gives Linux a real boundary; elsewhere the suite runs without one.
            unsafe_process: cfg!(not(target_os = "linux")),
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
        let out = Backend::Process
            .run(job(tmp("exit"), "exit 3"))
            .await
            .unwrap();
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

    /// An explicit request for no network is refused, not quietly given the host network.
    #[tokio::test]
    async fn asking_for_no_network_is_refused_rather_than_ignored() {
        let mut j = job(tmp("nonet"), "true");
        j.network = Some(crate::exec::Network::None);
        let err = Backend::Process.run(j).await.expect_err("must refuse");
        assert!(matches!(err, ExecError::Unsupported(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn the_outcome_reports_the_network_the_job_really_had() {
        let out = Backend::Process
            .run(job(tmp("reportnet"), "true"))
            .await
            .unwrap();
        assert_eq!(out.network.label(), "open");
    }

    #[tokio::test]
    async fn concurrent_jobs_in_one_workspace_do_not_corrupt_a_shared_file() {
        let ws = tmp("concurrent");
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let ws = ws.clone();
            set.spawn(async move {
                Backend::Process
                    .run(job(ws, "printf x >> shared.txt"))
                    .await
                    .unwrap()
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

    /// With no boundary available the backend refuses rather than running the job (#1).
    #[tokio::test]
    async fn no_boundary_and_no_override_means_the_job_does_not_run() {
        let mut j = job(tmp("noboundary"), "echo hello");
        j.unsafe_process = false;

        let result = Backend::Process.run(j).await;

        // A kernel without landlock lands in the refusal arm, which is also correct.
        #[cfg(target_os = "linux")]
        match result {
            Ok(out) => assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr),
            Err(ExecError::Unsupported(m)) => {
                assert!(m.contains("filesystem boundary"), "unhelpful refusal: {m}")
            }
            Err(e) => panic!("wrong error: {e:?}"),
        }

        // No boundary exists here, so running the job at all would be the bug.
        #[cfg(not(target_os = "linux"))]
        match result {
            Err(ExecError::Unsupported(m)) => {
                assert!(m.contains("filesystem boundary"), "unhelpful refusal: {m}")
            }
            Ok(out) => panic!("a job ran with no boundary on a platform that has none: {out:?}"),
            Err(e) => panic!("wrong error: {e:?}"),
        }
    }

    /// Linux only: landlock is the thing under test (#1).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_job_cannot_read_another_owners_file() {
        use crate::owner::Owner;

        let root = tmp("crossowner");
        let budi = Owner::parse(&["acme".into(), "budi".into()]).unwrap();
        let ani = Owner::parse(&["acme".into(), "ani".into()]).unwrap();
        std::fs::create_dir_all(budi.dir(&root)).unwrap();
        std::fs::create_dir_all(ani.dir(&root)).unwrap();
        std::fs::write(ani.dir(&root).join("secret.md"), b"ANI-SECRET").unwrap();

        // Run from inside the job, not through the guard. The find output is fenced by markers
        // because cat's own error text mentions the path it was denied.
        let script = "\
            cat ../../ani/.workspace/secret.md 2>&1;
            cat ../../../owners/acme/ani/.workspace/secret.md 2>&1;
            ls ../.. 2>&1;
            echo FIND-START;
            find / -name secret.md 2>/dev/null | head -5;
            echo FIND-END;
            cat /etc/passwd > /dev/null 2>&1 && echo CAN-READ-ETC;
            echo DONE";

        let mut j = job(budi.dir(&root), script);
        j.unsafe_process = false;
        let out = Backend::Process.run(j).await.expect("the job should run");

        assert!(out.stdout.contains("DONE"), "the job never ran: {out:?}");
        assert!(
            !out.stdout.contains("ANI-SECRET"),
            "a job read another owner's file:\n{}",
            out.stdout
        );

        let found = out
            .stdout
            .split("FIND-START")
            .nth(1)
            .and_then(|s| s.split("FIND-END").next())
            .unwrap_or("")
            .trim()
            .to_string();
        assert!(
            found.is_empty(),
            "a job found another owner's file by walking the filesystem:\n{found}"
        );

        // And it can still work inside its own sandbox.
        let mut j2 = job(budi.dir(&root), "printf mine > own.txt; cat own.txt");
        j2.unsafe_process = false;
        let own = Backend::Process.run(j2).await.unwrap();
        assert_eq!(
            own.stdout, "mine",
            "a job cannot use its own sandbox: {own:?}"
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
