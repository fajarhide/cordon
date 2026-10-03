//! POST /v1/run. Runs a job in the owner's workspace and hands back whatever
//! the job was asked to produce, as tokens rather than paths.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::Config;
use crate::exec::{Backend, ExecError, Job, Limits};
use crate::guard::Guard;
use crate::http::ApiError;
use crate::owner::Owner;
use crate::resolve::{guard_error, owner_or_error};

#[derive(Deserialize)]
pub struct RunRequest {
    pub owner: Vec<String>,
    #[serde(default)]
    pub inherit: bool,
    pub entrypoint: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub collect: Vec<String>,
    #[serde(default)]
    pub limits: Option<Limits>,
    #[serde(default)]
    pub egress: Vec<String>,
    #[serde(default)]
    pub backend: Option<String>,
}

pub async fn handler(
    State(cfg): State<Arc<Config>>,
    Json(req): Json<RunRequest>,
) -> Result<Json<Value>, ApiError> {
    let owner = owner_or_error(&req.owner)?;
    let limits = clamp_limits(&cfg, req.limits)?;
    let backend = pick_backend(&cfg, req.backend.as_deref())?;

    // The workspace is created first. The guard resolves a path against the
    // real filesystem, so checking a pattern before the workspace exists
    // refuses every first-time owner: the parent it would canonicalise is not
    // there yet.
    let workspace = owner.dir(&cfg.root);
    std::fs::create_dir_all(&workspace).map_err(|e| workspace_error(e, &owner))?;

    // Collect patterns are checked before the job runs, so a job never does
    // work only to be told afterwards that its output was unreachable.
    let guard = Guard::new(&cfg.root, &owner, req.inherit);
    for pattern in &req.collect {
        check_pattern(&guard, pattern)?;
    }

    let outcome = backend
        .run(Job {
            workspace: workspace.clone(),
            entrypoint: req.entrypoint,
            args: req.args,
            stdin: req.stdin,
            limits,
            egress: req.egress,
            unsafe_process: cfg.unsafe_process_backend,
        })
        .await
        .map_err(exec_error)?;

    let artifacts = collect(&cfg, &owner, &workspace, &req.collect)?;

    Ok(Json(json!({
        "exit_code": outcome.exit_code,
        "stdout": outcome.stdout,
        "stderr": outcome.stderr,
        "truncated": outcome.truncated,
        "duration_ms": outcome.duration_ms,
        "artifacts": artifacts,
    })))
}

/// A pattern is checked through the guard, with the trailing `*` stripped so
/// the directory it lives in is what gets judged.
fn check_pattern(guard: &Guard, pattern: &str) -> Result<(), ApiError> {
    if pattern.is_empty() || pattern.starts_with('/') || pattern.contains("..") {
        return Err(ApiError::forbidden(
            "path_escapes_workspace",
            "a collect pattern must stay inside the owner workspace",
        )
        .with_detail(json!({ "path": pattern })));
    }
    let dir = match pattern.rsplit_once('/') {
        Some((d, _)) => d,
        None => return Ok(()),
    };
    guard
        .resolve(dir)
        .map(|_| ())
        .map_err(|e| guard_error(e, pattern))
}

/// A request may lower a limit and may never raise it past the operator's
/// ceiling. An absent limit takes the ceiling, so a caller cannot get more by
/// saying less.
fn clamp_limits(cfg: &Config, asked: Option<Limits>) -> Result<Limits, ApiError> {
    let l = asked.unwrap_or(Limits {
        wall_ms: cfg.max_wall_ms,
        memory_mb: cfg.max_memory_mb,
        stdout_kb: 256,
    });
    // memory_mb == 0 used to pass: the process backend skipped RLIMIT_AS
    // behind `if memory_bytes > 0` and the container backend emitted
    // `--memory 0m`, which docker reads as unlimited. Lowering a limit to zero
    // is not a lower limit, it is no limit (issue #9).
    if l.wall_ms == 0
        || l.memory_mb == 0
        || l.wall_ms > cfg.max_wall_ms
        || l.memory_mb > cfg.max_memory_mb
    {
        return Err(ApiError::bad_request(
            "limit_exceeded",
            "a requested limit is zero or above the configured ceiling",
        )
        .with_detail(json!({
            "max_wall_ms": cfg.max_wall_ms,
            "max_memory_mb": cfg.max_memory_mb,
        })));
    }
    Ok(Limits {
        stdout_kb: if l.stdout_kb == 0 {
            256
        } else {
            l.stdout_kb.min(4096)
        },
        ..l
    })
}

/// The operator's backend is a floor, not a default.
///
/// Issue #1b: this was `asked.unwrap_or(&cfg.backend)`, so a deployment
/// configured for container isolation handed a caller the process backend for
/// one extra JSON field. Limits already had a ceiling a request could only
/// lower; isolation needs a floor a request can only raise.
fn pick_backend(cfg: &Config, asked: Option<&str>) -> Result<Backend, ApiError> {
    let container = Backend::Container {
        image: cfg.image.clone(),
    };
    match (cfg.backend.as_str(), asked) {
        (_, Some("container")) => Ok(container),
        ("container", Some("process")) => Err(ApiError::bad_request(
            "backend_below_floor",
            "this daemon is configured for the container backend; a request cannot ask for a weaker one",
        )),
        ("container", _) => Ok(container),
        (_, Some("process")) | ("process", None) => Ok(Backend::Process),
        (_, Some(other)) => Err(ApiError::bad_request(
            "invalid_request",
            format!("backend {other:?} is not process or container"),
        )),
        (other, None) => Err(ApiError::bad_request(
            "invalid_request",
            format!("backend {other:?} is not process or container"),
        )),
    }
}

/// An owner the filesystem cannot hold is the caller's fault, not the daemon's.
///
/// Issue #10: both of these came back as 500 `workspace_unavailable`, which put
/// a bad request in someone's error budget. `AlreadyExists` means a path
/// component is a file, usually an owner segment that names one; the name
/// length errors mean the owner is valid to cordon and impossible on disk.
fn workspace_error(e: std::io::Error, owner: &Owner) -> ApiError {
    use std::io::ErrorKind;
    let is_too_long = e.raw_os_error() == Some(libc::ENAMETOOLONG);
    if matches!(
        e.kind(),
        ErrorKind::AlreadyExists | ErrorKind::NotADirectory
    ) || is_too_long
    {
        return ApiError::bad_request(
            "invalid_owner",
            format!("owner {owner} cannot be a directory on this filesystem: {e}"),
        );
    }
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "workspace_unavailable",
        e.to_string(),
    )
}

/// A missing backend is a 503 and never a fallback. The caller asked for
/// container isolation; handing it the process backend instead would be giving
/// it less than it asked for without saying so.
fn exec_error(e: ExecError) -> ApiError {
    match e {
        ExecError::Unsupported(m) => ApiError::bad_request("backend_cannot_honour_request", m),
        ExecError::BackendUnavailable(m) => {
            ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "backend_unavailable", m)
        }
        ExecError::Spawn(m) => ApiError::bad_request("spawn_failed", m),
    }
}

fn collect(
    cfg: &Config,
    owner: &Owner,
    workspace: &Path,
    patterns: &[String],
) -> Result<Vec<Value>, ApiError> {
    let Ok(real_ws) = std::fs::canonicalize(workspace) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for pattern in patterns {
        for path in glob(workspace, pattern) {
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            // The job may have written a symlink pointing out of the
            // workspace. Collecting it would mint a token for someone else's
            // file, so the resolved target is checked, not the name.
            let Ok(real) = std::fs::canonicalize(&path) else {
                continue;
            };
            if !real.starts_with(&real_ws) {
                continue;
            }
            // Issue #6: a hardlink has nothing to resolve, so canonicalize
            // says it is inside the sandbox while the inode is someone
            // else's. A file a job just produced has one link; more than one
            // means it is also reachable under another name, and this is not
            // the place to work out whose.
            if std::os::unix::fs::MetadataExt::nlink(&meta) > 1 {
                continue;
            }
            let rel = path
                .strip_prefix(workspace)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let token = crate::artifact::mint(cfg, owner, &real).map_err(|e| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "artifact_mint_failed",
                    e.to_string(),
                )
            })?;
            out.push(json!({ "token": token, "path": rel, "bytes": meta.len() }));
        }
    }
    Ok(out)
}

/// A deliberately small glob: a literal path, or one trailing `*` in the final
/// segment. Taking a glob crate for this, in the code path that decides what a
/// token gets minted for, is more surface than the feature is worth.
fn glob(workspace: &Path, pattern: &str) -> Vec<PathBuf> {
    let (dir, name) = pattern.rsplit_once('/').unwrap_or(("", pattern));
    let base = if dir.is_empty() {
        workspace.to_path_buf()
    } else {
        workspace.join(dir)
    };
    match name.strip_suffix('*') {
        None => {
            let p = base.join(name);
            if p.is_file() {
                vec![p]
            } else {
                vec![]
            }
        }
        Some(prefix) => {
            let Ok(entries) = std::fs::read_dir(&base) else {
                return vec![];
            };
            let mut v: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().starts_with(prefix))
                        .unwrap_or(false)
                })
                .collect();
            // Stable order, so a caller diffing two runs sees the same list.
            v.sort();
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testsupport::{fixture, get, owner_dir, post};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn runs_a_job_and_hands_back_a_fetchable_artifact() {
        let f = fixture("run-ok");
        let payload = r#"{"owner":["acme","budi"],"entrypoint":"sh",
            "args":["-c","mkdir -p out; printf hi > out/r.txt"],
            "collect":["out/*"],
            "limits":{"wall_ms":5000,"memory_mb":128,"stdout_kb":64}}"#;
        let (status, body) = post(&f, "/v1/run", payload).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["exit_code"], 0, "{body}");

        let arts = body["artifacts"].as_array().expect("artifacts array");
        assert_eq!(arts.len(), 1, "{body}");
        assert_eq!(arts[0]["path"], "out/r.txt");
        assert_eq!(arts[0]["bytes"], 2);

        let token = arts[0]["token"].as_str().unwrap();
        let (st, bytes) = get(&f, &format!("/v1/artifact/{token}?owner=acme/budi")).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(bytes, b"hi");
    }

    #[tokio::test]
    async fn a_job_cannot_collect_outside_its_workspace() {
        let f = fixture("run-collect-escape");
        for pattern in ["../ani/*", "/etc/passwd", "../../../etc/hosts"] {
            let payload = format!(
                r#"{{"owner":["acme","budi"],"entrypoint":"true","collect":["{pattern}"],
                     "limits":{{"wall_ms":5000,"memory_mb":128,"stdout_kb":64}}}}"#
            );
            let (status, body) = post(&f, "/v1/run", &payload).await;
            assert!(
                status.is_client_error(),
                "collecting {pattern} gave {status}: {body}"
            );
        }
    }

    /// A job writing a symlink out of its workspace must not get a token for
    /// what it points at.
    #[tokio::test]
    async fn a_symlink_the_job_wrote_is_not_collected() {
        let f = fixture("run-collect-symlink");
        let payload = r#"{"owner":["acme","budi"],"entrypoint":"sh",
            "args":["-c","mkdir -p out; ln -s ../../ani/secret.md out/stolen.md"],
            "collect":["out/*"],
            "limits":{"wall_ms":5000,"memory_mb":128,"stdout_kb":64}}"#;
        let (status, body) = post(&f, "/v1/run", payload).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["artifacts"].as_array().unwrap().len(),
            0,
            "a symlink out of the workspace was minted a token: {body}"
        );
    }

    /// Issue #6. A hardlink passes the canonicalize check, because there is
    /// nothing to resolve, so the link count is what catches it.
    #[tokio::test]
    async fn a_hardlink_to_another_owners_file_is_not_collected() {
        let f = fixture("run-hardlink");
        let payload = r#"{"owner":["acme","budi"],"entrypoint":"sh",
            "args":["-c","mkdir -p out; ln ../../ani/.workspace/secret.md out/stolen.md 2>/dev/null; printf mine > out/own.txt"],
            "collect":["out/*"],
            "limits":{"wall_ms":5000,"memory_mb":128,"stdout_kb":64}}"#;
        let (status, body) = post(&f, "/v1/run", payload).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let paths: Vec<&str> = body["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["path"].as_str().unwrap())
            .collect();
        assert!(
            !paths.contains(&"out/stolen.md"),
            "a hardlink was minted a token: {body}"
        );
        // The job's own file still comes back, so the check is not just
        // refusing everything.
        assert!(paths.contains(&"out/own.txt"), "{body}");
    }

    /// Issue #9. Lowering the memory limit to zero is not a lower limit, it is
    /// no limit: the process backend skipped RLIMIT_AS and docker read
    /// `--memory 0m` as unlimited.
    #[tokio::test]
    async fn a_zero_memory_limit_is_refused() {
        let f = fixture("run-zeromem");
        let (status, body) = post(
            &f,
            "/v1/run",
            r#"{"owner":["acme","budi"],"entrypoint":"true","limits":{"wall_ms":1000,"memory_mb":0,"stdout_kb":8}}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "limit_exceeded", "{body}");
    }

    /// Issue #10. An owner the filesystem cannot hold is a bad request, not a
    /// broken daemon.
    #[tokio::test]
    async fn an_owner_the_filesystem_cannot_hold_is_a_4xx() {
        let f = fixture("run-badowner-fs");
        // acme/.workspace exists as a directory; name a file inside the tree
        // that an owner segment would have to become a directory over.
        std::fs::create_dir_all(f.cfg.root.join("owners/acme")).unwrap();
        std::fs::write(f.cfg.root.join("owners/acme/blocked"), b"i am a file").unwrap();

        let (status, body) = post(
            &f,
            "/v1/run",
            r#"{"owner":["acme","blocked"],"entrypoint":"true"}"#,
        )
        .await;
        assert!(
            status.is_client_error(),
            "a bad owner gave {status}, which lands in someone's error budget: {body}"
        );
        assert_eq!(body["error"]["code"], "invalid_owner", "{body}");
    }

    #[tokio::test]
    async fn a_limit_above_the_ceiling_is_refused() {
        let f = fixture("run-ceiling");
        for payload in [
            r#"{"owner":["acme","budi"],"entrypoint":"true","limits":{"wall_ms":999999,"memory_mb":128,"stdout_kb":64}}"#,
            r#"{"owner":["acme","budi"],"entrypoint":"true","limits":{"wall_ms":1000,"memory_mb":999999,"stdout_kb":64}}"#,
            r#"{"owner":["acme","budi"],"entrypoint":"true","limits":{"wall_ms":0,"memory_mb":128,"stdout_kb":64}}"#,
        ] {
            let (status, body) = post(&f, "/v1/run", payload).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{payload}: {body}");
            assert_eq!(body["error"]["code"], "limit_exceeded", "{body}");
        }
    }

    #[tokio::test]
    async fn limits_are_optional_and_default_inside_the_ceiling() {
        let f = fixture("run-default-limits");
        let (status, body) = post(
            &f,
            "/v1/run",
            r#"{"owner":["acme","budi"],"entrypoint":"true"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn an_egress_allowlist_on_the_process_backend_is_a_400() {
        let f = fixture("run-egress");
        let payload = r#"{"owner":["acme","budi"],"entrypoint":"true","egress":["example.com:443"],
            "limits":{"wall_ms":1000,"memory_mb":64,"stdout_kb":8}}"#;
        let (status, body) = post(&f, "/v1/run", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body["error"]["code"], "backend_cannot_honour_request",
            "{body}"
        );
    }

    #[tokio::test]
    async fn stdout_and_stderr_come_back_separately() {
        let f = fixture("run-streams");
        let payload = r#"{"owner":["acme","budi"],"entrypoint":"sh",
            "args":["-c","echo out; echo err >&2; exit 2"],
            "limits":{"wall_ms":5000,"memory_mb":64,"stdout_kb":8}}"#;
        let (status, body) = post(&f, "/v1/run", payload).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["exit_code"], 2);
        assert_eq!(body["stdout"].as_str().unwrap().trim(), "out");
        assert_eq!(body["stderr"].as_str().unwrap().trim(), "err");
    }

    #[tokio::test]
    async fn the_workspace_is_created_on_first_use() {
        let f = fixture("run-firstuse");
        let payload = r#"{"owner":["acme","brandnew"],"entrypoint":"sh",
            "args":["-c","pwd > where.txt"],"collect":["where.txt"],
            "limits":{"wall_ms":5000,"memory_mb":64,"stdout_kb":8}}"#;
        let (status, body) = post(&f, "/v1/run", payload).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(owner_dir(&f.cfg.root, &["acme", "brandnew"]).is_dir());
    }

    /// Caught by an end to end run, not by the suite: the collect check used to
    /// run before the workspace existed, so a first-time owner with any
    /// pattern containing a directory was always refused.
    #[tokio::test]
    async fn a_brand_new_owner_can_collect_from_a_directory_the_job_creates() {
        let f = fixture("run-newowner-collect");
        let payload = r#"{"owner":["acme","firstrun"],"entrypoint":"sh",
            "args":["-c","mkdir -p out; printf hi > out/r.txt"],
            "collect":["out/*"],
            "limits":{"wall_ms":5000,"memory_mb":128,"stdout_kb":64}}"#;
        let (status, body) = post(&f, "/v1/run", payload).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["artifacts"].as_array().unwrap().len(),
            1,
            "nothing collected: {body}"
        );
    }

    /// Issue #1b. A deployment configured for the container backend must not
    /// hand out the process backend for one extra JSON field.
    #[tokio::test]
    async fn a_request_cannot_ask_for_a_weaker_backend_than_the_operator_set() {
        let mut f = fixture("run-floor");
        std::sync::Arc::get_mut(&mut f.cfg)
            .expect("sole owner")
            .backend = "container".into();

        let (status, body) = post(
            &f,
            "/v1/run",
            r#"{"owner":["acme","budi"],"entrypoint":"true","backend":"process"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "backend_below_floor", "{body}");
    }

    /// The other direction stays open: a process-configured daemon lets a
    /// request ask for the stronger backend.
    #[tokio::test]
    async fn a_request_can_ask_for_a_stronger_backend_than_the_operator_set() {
        let f = fixture("run-upgrade");
        let (status, body) = post(
            &f,
            "/v1/run",
            r#"{"owner":["acme","budi"],"entrypoint":"true","backend":"container"}"#,
        )
        .await;
        // Either it runs, or docker is absent and it says so. What it must not
        // be is a 400 refusing the upgrade.
        assert!(
            status == StatusCode::OK || status == StatusCode::SERVICE_UNAVAILABLE,
            "{status}: {body}"
        );
    }

    #[tokio::test]
    async fn an_unknown_backend_name_is_refused() {
        let f = fixture("run-badbackend");
        let (status, body) = post(
            &f,
            "/v1/run",
            r#"{"owner":["acme","budi"],"entrypoint":"true","backend":"firecracker"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
}
