//! The backend for code you did not write. Filled in by the next task.

use super::{ExecError, Job, Outcome};

pub async fn run(_image: &str, _job: Job) -> Result<Outcome, ExecError> {
    Err(ExecError::BackendUnavailable(
        "the container backend is not wired up yet".into(),
    ))
}
