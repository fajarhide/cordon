//! POST /v1/run. Runs a job in the owner's workspace and returns its outputs as tokens, not paths.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};

use crate::http::ApiJson;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::Config;
use crate::exec::{Backend, ExecError, Job, Limits, Network};
use crate::guard::Guard;
use crate::http::ApiError;
use crate::owner::Owner;
use crate::resolve::{guard_error, owner_or_error};
use crate::token::Scope;

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
    /// "none" or "open". Absent means the backend's own default, and the response says which.
    #[serde(default)]
    pub network: Option<String>,
    /// Name to address pins, only with "open". A convenience, never a restriction (#11).
    #[serde(default)]
    pub hosts: std::collections::BTreeMap<String, String>,
    /// Refused on sight: it named an allowlist that restricted nothing (#11).
    #[serde(default)]
    pub egress: Option<serde_json::Value>,
    #[serde(default)]
    pub backend: Option<String>,
}

pub async fn handler(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    ApiJson(req): ApiJson<RunRequest>,
) -> Result<Json<Value>, ApiError> {
    let owner = owner_or_error(&scope, &req.owner)?;
    let limits = clamp_limits(&cfg, req.limits)?;
    let backend = pick_backend(&cfg, req.backend.as_deref())?;
    let network = parse_network(&req)?;

    // Created before the collect check: the guard canonicalises against the real filesystem,
    // so a pattern checked first refuses every first-time owner.
    let workspace = owner.dir(&cfg.root);
    std::fs::create_dir_all(&workspace).map_err(|e| workspace_error(e, &owner))?;

    // Checked before the job runs, so a job never works for output it cannot collect.
    let guard = Guard::new(&cfg.root, &owner, req.inherit, &scope);
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
            network,
            unsafe_process: cfg.unsafe_process_backend,
            env: Vec::new(),
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
        "network": outcome.network.label(),
        "artifacts": artifacts,
    })))
}

/// The final segment is stripped, so the directory it lives in is what the guard judges.
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

/// A request may lower a limit, never raise it. An absent limit takes the operator's ceiling.
fn clamp_limits(cfg: &Config, asked: Option<Limits>) -> Result<Limits, ApiError> {
    let l = asked.unwrap_or(Limits {
        wall_ms: cfg.max_wall_ms,
        memory_mb: cfg.max_memory_mb,
        stdout_kb: 256,
    });
    // Zero is no limit, not a lower one: docker reads `--memory 0m` as unlimited (#9).
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

/// `egress` is refused, not translated: it never limited which addresses were reachable (#11).
fn parse_network(req: &RunRequest) -> Result<Option<Network>, ApiError> {
    if req.egress.is_some() {
        return Err(ApiError::bad_request(
            "egress_removed",
            "egress was never a boundary: it blocked name resolution and left every address reachable. Use network none or open, with hosts for name pins",
        ));
    }
    network_from(req.network.as_deref(), &req.hosts)
}

/// Shared with `/v1/stdio`, so a stdio job asks for a network the same way a run does.
pub(crate) fn network_from(
    network: Option<&str>,
    hosts: &std::collections::BTreeMap<String, String>,
) -> Result<Option<Network>, ApiError> {
    let pins = crate::exec::container::hosts::parse(hosts.iter())
        .map_err(|e| ApiError::bad_request("invalid_request", e))?;

    match network {
        None if pins.is_empty() => Ok(None),
        None => Err(ApiError::bad_request(
            "invalid_request",
            "hosts needs network open; pins mean nothing without a network",
        )),
        Some("none") if !pins.is_empty() => Err(ApiError::bad_request(
            "invalid_request",
            "hosts cannot be used with network none",
        )),
        Some("none") => Ok(Some(Network::None)),
        Some("open") => Ok(Some(Network::Open { pins })),
        Some(other) => Err(ApiError::bad_request(
            "invalid_request",
            format!("network {other:?} is not none or open"),
        )),
    }
}

/// The operator's backend is a floor, not a default: a request can only raise isolation (#1).
pub(crate) fn pick_backend(cfg: &Config, asked: Option<&str>) -> Result<Backend, ApiError> {
    let container = Backend::Container {
        image: cfg.image.clone(),
        cli: cfg.container_cli.clone(),
        env_dir: cfg.root.join("env"),
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

/// An owner the filesystem cannot hold is the caller's fault: a 400, not a 500 (#10).
/// That covers a path component that is a file, and a name too long for the disk.
pub fn workspace_error(e: std::io::Error, owner: &Owner) -> ApiError {
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

/// A missing backend is a 503, never a silent fallback to weaker isolation.
pub(crate) fn exec_error(e: ExecError) -> ApiError {
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
            // The job may have written a symlink out of the workspace, so judge the target.
            let Ok(real) = std::fs::canonicalize(&path) else {
                continue;
            };
            if !real.starts_with(&real_ws) {
                continue;
            }
            // canonicalize cannot see a hardlink to another owner's inode (#6).
            // A file the job just produced has one link, so anything with more is skipped.
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

/// A literal path, or one trailing `*` in the final segment.
/// Deliberately not a glob crate: this path decides what a token gets minted for.
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

    /// A hardlink passes the canonicalize check, so the link count is what catches it (#6).
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
        // The job's own file still comes back, so the check is not refusing everything.
        assert!(paths.contains(&"out/own.txt"), "{body}");
    }

    /// Zero is no limit, not a lower one (#9).
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

    /// A bad request, not a broken daemon (#10).
    #[tokio::test]
    async fn an_owner_the_filesystem_cannot_hold_is_a_4xx() {
        let f = fixture("run-badowner-fs");
        // A file where an owner segment would have to become a directory.
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

    /// Refused, not translated, so a caller still sending it learns the promise changed (#11).
    #[tokio::test]
    async fn the_old_egress_field_is_refused_on_sight() {
        let f = fixture("run-egress-gone");
        for payload in [
            r#"{"owner":["acme","budi"],"entrypoint":"true","egress":["example.com:443"]}"#,
            r#"{"owner":["acme","budi"],"entrypoint":"true","egress":[]}"#,
        ] {
            let (status, body) = post(&f, "/v1/run", payload).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{payload}: {body}");
            assert_eq!(body["error"]["code"], "egress_removed", "{body}");
        }
    }

    #[tokio::test]
    async fn the_network_field_takes_only_none_or_open() {
        let f = fixture("run-network-values");
        for bad in ["bridge", "host", "allowlist", ""] {
            let payload =
                format!(r#"{{"owner":["acme","budi"],"entrypoint":"true","network":"{bad}"}}"#);
            let (status, body) = post(&f, "/v1/run", &payload).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}: {body}");
        }
    }

    /// Pins with no network field, or with network none, are refused rather than silently dropped.
    #[tokio::test]
    async fn host_pins_need_an_open_network() {
        let f = fixture("run-pins");
        for payload in [
            r#"{"owner":["acme","budi"],"entrypoint":"true","hosts":{"db.internal":"10.0.0.5"}}"#,
            r#"{"owner":["acme","budi"],"entrypoint":"true","network":"none","hosts":{"db.internal":"10.0.0.5"}}"#,
        ] {
            let (status, body) = post(&f, "/v1/run", payload).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{payload}: {body}");
        }
    }

    #[tokio::test]
    async fn a_host_pin_needs_an_address_not_a_magic_name() {
        let f = fixture("run-pin-addr");
        let payload = r#"{"owner":["acme","budi"],"entrypoint":"true","network":"open",
            "hosts":{"db.internal":"host-gateway"}}"#;
        let (status, body) = post(&f, "/v1/run", payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "invalid_request", "{body}");
    }

    #[tokio::test]
    async fn the_response_reports_the_network_the_job_had() {
        let f = fixture("run-network-report");
        let (status, body) = post(
            &f,
            "/v1/run",
            r#"{"owner":["acme","budi"],"entrypoint":"true"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // The process backend shares the host network, and reports that.
        assert_eq!(body["network"], "open", "{body}");
    }

    /// It cannot isolate the network, so it refuses rather than quietly grant the host's.
    #[tokio::test]
    async fn the_process_backend_refuses_to_promise_no_network() {
        let f = fixture("run-nonet");
        let (status, body) = post(
            &f,
            "/v1/run",
            r#"{"owner":["acme","budi"],"entrypoint":"true","network":"none"}"#,
        )
        .await;
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

    /// The collect check must run after the workspace exists, or a first-time owner is refused.
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

    /// The operator's backend is a floor (#1).
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

    #[tokio::test]
    async fn a_request_can_ask_for_a_stronger_backend_than_the_operator_set() {
        let f = fixture("run-upgrade");
        let (status, body) = post(
            &f,
            "/v1/run",
            r#"{"owner":["acme","budi"],"entrypoint":"true","backend":"container"}"#,
        )
        .await;
        // Either it runs or docker is absent. It must not be a 400 refusing the upgrade.
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
