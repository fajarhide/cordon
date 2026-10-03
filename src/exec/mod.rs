//! Execution backends. An enum, not a trait object, so two variants need no `async-trait`.

pub mod container;
pub mod process;

use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, serde::Deserialize)]
pub struct Limits {
    pub wall_ms: u64,
    pub memory_mb: u64,
    pub stdout_kb: usize,
}

/// No packet filter exists, so anything but `None` is the host's full outbound access (#11).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Network {
    #[default]
    None,
    Open {
        /// Name to address pins: a convenience, not a restriction.
        pins: Vec<container::hosts::Pin>,
    },
}

impl Network {
    pub fn label(&self) -> &'static str {
        match self {
            Network::None => "none",
            Network::Open { .. } => "open",
        }
    }
}

#[derive(Debug)]
pub struct Job {
    pub workspace: PathBuf,
    pub entrypoint: String,
    pub args: Vec<String>,
    pub stdin: String,
    pub limits: Limits,
    /// None means the caller did not ask: the backend uses what it can provide and reports it.
    pub network: Option<Network>,
    /// Process backend only: decides whether a missing filesystem boundary is fatal.
    pub unsafe_process: bool,
}

#[derive(Debug)]
pub struct Outcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub duration_ms: u128,
    /// What the job actually got, which is not always what it asked for.
    pub network: Network,
}

#[derive(Debug)]
pub enum ExecError {
    /// The backend cannot honour something the request asked for.
    Unsupported(String),
    /// The backend is missing. Never fall back to a weaker one: the caller must be told.
    BackendUnavailable(String),
    Spawn(String),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::Unsupported(m) | ExecError::BackendUnavailable(m) | ExecError::Spawn(m) => {
                write!(f, "{m}")
            }
        }
    }
}

pub enum Backend {
    Process,
    Container { image: String, cli: String },
}

impl Backend {
    pub async fn run(&self, job: Job) -> Result<Outcome, ExecError> {
        match self {
            Backend::Process => process::run(job).await,
            Backend::Container { image, cli } => container::run(cli, image, job).await,
        }
    }
}

/// Shared by both backends so neither buffers a job's whole output into the daemon's heap.
pub(crate) async fn read_capped<R>(mut r: R, cap: usize) -> (String, bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::with_capacity(cap.min(8192));
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() >= cap {
                    truncated = true;
                    continue;
                }
                let room = cap - buf.len();
                buf.extend_from_slice(&chunk[..n.min(room)]);
                if n > room {
                    truncated = true;
                }
            }
        }
    }
    (String::from_utf8_lossy(&buf).into_owned(), truncated)
}
