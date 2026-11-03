//! /v1/files and /v1/file: an owner's workspace read and written without starting a job (#33).
//! Scoped by owner and token like /v1/run. Nothing here executes; every open goes through `beneath`.

use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::beneath;
use crate::config::Config;
use crate::guard::components;
use crate::http::ApiError;
use crate::http::ApiJson;
use crate::owner::Owner;
use crate::resolve::{guard_error, owner_or_error};
use crate::token::Scope;

/// Enough for a large project; a caller that needs more lists a folder at a time.
const LIST_CAP: usize = 20_000;
const MB: u64 = 1024 * 1024;

#[derive(Deserialize)]
pub struct FileQuery {
    /// Slash separated, as `/v1/artifact` takes it. Required.
    pub owner: Option<String>,
    pub path: Option<String>,
    #[serde(default)]
    pub hash: bool,
}

fn owner(scope: &Scope, q: &FileQuery) -> Result<Owner, ApiError> {
    let raw = q.owner.as_deref().unwrap_or("");
    let segments: Vec<String> = raw.split('/').map(str::to_string).collect();
    owner_or_error(scope, &segments)
}

/// Splits a file path into its folders and its name, or refuses it.
fn file_path(q: &FileQuery) -> Result<(Vec<String>, String, String), ApiError> {
    let rel = q.path.as_deref().unwrap_or("");
    let mut parts: Vec<String> = components(rel)
        .map_err(|e| guard_error(e, rel))?
        .into_iter()
        .map(str::to_string)
        .collect();
    let name = parts.pop().unwrap_or_default();
    if name.starts_with(beneath::TMP_PREFIX) {
        return Err(not_found(rel));
    }
    Ok((parts, name, rel.to_string()))
}

fn not_found(path: &str) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "file_not_found", "no such file")
        .with_detail(json!({ "path": path }))
}

/// One mapping from what the kernel said to what the caller gets.
fn io_error(e: io::Error, path: &str) -> ApiError {
    let detail = json!({ "path": path });
    match e.raw_os_error() {
        Some(libc::ELOOP) => ApiError::forbidden(
            "path_escapes_workspace",
            "the path resolves outside the owner workspace",
        )
        .with_detail(detail),
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => not_found(path),
        Some(libc::EISDIR) | Some(libc::ENOTEMPTY) | Some(libc::EEXIST) => ApiError::new(
            StatusCode::CONFLICT,
            "not_a_file",
            "that path is not a regular file",
        )
        .with_detail(detail),
        _ => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "io_error", e.to_string())
            .with_detail(detail),
    }
}

fn too_large(code: &'static str, message: String, path: &str) -> ApiError {
    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, code, message).with_detail(json!({ "path": path }))
}

/// `If-Match: "<sha256>"`, quotes optional. Anything unparseable is a hash that never matches.
fn if_match(headers: &HeaderMap) -> Option<String> {
    headers.get(header::IF_MATCH).map(|v| {
        v.to_str()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_ascii_lowercase()
    })
}

fn stale(path: &str) -> ApiError {
    ApiError::new(
        StatusCode::PRECONDITION_FAILED,
        "file_changed",
        "the file changed since that hash was read",
    )
    .with_detail(json!({ "path": path }))
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "io_error", e.to_string()))?
}

pub async fn list(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    Query(q): Query<FileQuery>,
) -> Result<Json<Value>, ApiError> {
    let owner = owner(&scope, &q)?;
    let rel = q.path.clone().unwrap_or_default();
    let parts: Vec<String> = if rel.is_empty() {
        Vec::new()
    } else {
        components(&rel)
            .map_err(|e| guard_error(e, &rel))?
            .into_iter()
            .map(str::to_string)
            .collect()
    };
    let hash = q.hash;
    blocking(move || {
        let ws = owner.dir(&cfg.root);
        let root = match beneath::root(&ws) {
            Ok(fd) => fd,
            // An owner that never wrote anything has an empty workspace, not a missing one.
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) && parts.is_empty() => {
                return Ok(Json(json!({ "entries": [], "truncated": false })));
            }
            Err(e) => return Err(io_error(e, &rel)),
        };
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let dir = match beneath::dir(root, &refs, false) {
            Ok(d) => d,
            // The path names a file: that one entry, so a caller can hash one file without hashing the owner.
            Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
                let (name, parent) = refs.split_last().ok_or_else(|| not_found(&rel))?;
                let dir = open_dir(&ws, parent, false).map_err(|e| io_error(e, &rel))?;
                let size = beneath::existing_size(&dir, name)
                    .map_err(|e| io_error(e, &rel))?
                    .ok_or_else(|| not_found(&rel))?;
                let mut v = json!({ "path": rel, "size": size });
                if hash {
                    let h = beneath::current_hash(&dir, name).map_err(|e| io_error(e, &rel))?;
                    v["sha256"] = json!(h.ok_or_else(|| not_found(&rel))?);
                }
                return Ok(Json(json!({ "entries": [v], "truncated": false })));
            }
            Err(e) => return Err(io_error(e, &rel)),
        };
        let (entries, truncated) =
            beneath::list(&dir, hash, LIST_CAP).map_err(|e| io_error(e, &rel))?;
        let prefix = if rel.is_empty() {
            String::new()
        } else {
            format!("{rel}/")
        };
        let entries: Vec<Value> = entries
            .into_iter()
            .map(|e| {
                let mut v = json!({ "path": format!("{prefix}{}", e.path), "size": e.size });
                if let Some(h) = e.sha256 {
                    v["sha256"] = json!(h);
                }
                v
            })
            .collect();
        Ok(Json(json!({ "entries": entries, "truncated": truncated })))
    })
    .await
}

pub async fn read(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    Query(q): Query<FileQuery>,
) -> Result<Response, ApiError> {
    let owner = owner(&scope, &q)?;
    let (parts, name, rel) = file_path(&q)?;
    blocking(move || {
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let dir = beneath::root(&owner.dir(&cfg.root))
            .and_then(|r| beneath::dir(r, &refs, false))
            .map_err(|e| io_error(e, &rel))?;
        let mut file = beneath::open_file(&dir, &name).map_err(|e| io_error(e, &rel))?;
        let cap = cfg.max_file_mb * MB;
        let mut bytes = Vec::new();
        // One byte past the cap tells a file that fits from one that does not, without reading it all.
        (&mut file)
            .take(cap + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| io_error(e, &rel))?;
        if bytes.len() as u64 > cap {
            return Err(too_large(
                "file_too_large",
                format!("files over {} MB are not served here", cfg.max_file_mb),
                &rel,
            ));
        }
        let mut sha = crate::sha256::Sha256::new();
        sha.update(&bytes);
        Ok((
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (header::ETAG, format!("\"{}\"", sha.hex())),
            ],
            bytes,
        )
            .into_response())
    })
    .await
}

pub async fn write(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    Query(q): Query<FileQuery>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, ApiError> {
    let owner = owner(&scope, &q)?;
    let (parts, name, rel) = file_path(&q)?;
    let cap = cfg.max_file_mb * MB;
    let too_big = || {
        too_large(
            "file_too_large",
            format!("files over {} MB are refused", cfg.max_file_mb),
            &rel,
        )
    };
    let body = body.map_err(|_| too_big())?;
    if body.len() as u64 > cap {
        return Err(too_big());
    }
    let expect = if_match(&headers);
    blocking(move || {
        let ws = owner.dir(&cfg.root);
        std::fs::create_dir_all(&ws).map_err(|e| io_error(e, &rel))?;
        let root = beneath::root(&ws).map_err(|e| io_error(e, &rel))?;
        let quota = cfg.owner_quota_mb * MB;
        let used = beneath::usage(&root).map_err(|e| io_error(e, &rel))?;
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let dir = beneath::dir(root, &refs, true).map_err(|e| io_error(e, &rel))?;
        let old = beneath::existing_size(&dir, &name).map_err(|e| io_error(e, &rel))?;
        if used - old.unwrap_or(0).min(used) + body.len() as u64 > quota {
            return Err(too_large(
                "quota_exceeded",
                format!(
                    "this owner may hold {} MB through the file endpoints",
                    cfg.owner_quota_mb
                ),
                &rel,
            ));
        }
        if let Some(want) = expect {
            let now = beneath::current_hash(&dir, &name).map_err(|e| io_error(e, &rel))?;
            if now.as_deref() != Some(want.as_str()) {
                return Err(stale(&rel));
            }
        }
        beneath::write(&dir, &name, &body).map_err(|e| io_error(e, &rel))?;
        let mut sha = crate::sha256::Sha256::new();
        sha.update(&body);
        Ok(Json(
            json!({ "path": rel, "size": body.len(), "sha256": sha.hex() }),
        ))
    })
    .await
}

pub async fn remove(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    Query(q): Query<FileQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let owner = owner(&scope, &q)?;
    let (parts, name, rel) = file_path(&q)?;
    let expect = if_match(&headers);
    blocking(move || {
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let dir = beneath::root(&owner.dir(&cfg.root))
            .and_then(|r| beneath::dir(r, &refs, false))
            .map_err(|e| io_error(e, &rel))?;
        if beneath::existing_size(&dir, &name)
            .map_err(|e| io_error(e, &rel))?
            .is_none()
        {
            return Err(not_found(&rel));
        }
        if let Some(want) = expect {
            let now = beneath::current_hash(&dir, &name).map_err(|e| io_error(e, &rel))?;
            if now.as_deref() != Some(want.as_str()) {
                return Err(stale(&rel));
            }
        }
        beneath::unlink(&dir, &name).map_err(|e| io_error(e, &rel))?;
        Ok(Json(json!({ "deleted": rel })))
    })
    .await
}

fn refs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

fn open_dir(ws: &std::path::Path, parts: &[&str], create: bool) -> io::Result<OwnedFd> {
    beneath::root(ws).and_then(|r| beneath::dir(r, parts, create))
}

/// Enough for one job's inputs or outputs; a caller with more makes more calls.
const COPY_CAP: usize = 200;

#[derive(Deserialize)]
pub struct CopyRequest {
    pub from_owner: Vec<String>,
    pub to_owner: Vec<String>,
    pub files: Vec<CopyPair>,
}

#[derive(Deserialize)]
pub struct CopyPair {
    pub from: String,
    pub to: String,
}

/// POST /v1/copy: files from one owner to another without the bytes leaving the daemon (#36).
/// Everything is checked before the first byte is written, so a refusal copies nothing.
pub async fn copy(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    ApiJson(req): ApiJson<CopyRequest>,
) -> Result<Json<Value>, ApiError> {
    let from = owner_or_error(&scope, &req.from_owner)?;
    let to = owner_or_error(&scope, &req.to_owner)?;
    if req.files.is_empty() || req.files.len() > COPY_CAP {
        return Err(ApiError::bad_request(
            "invalid_request",
            format!("copy between 1 and {COPY_CAP} files a call"),
        ));
    }
    let split = |rel: &str| -> Result<(Vec<String>, String), ApiError> {
        let mut parts: Vec<String> = components(rel)
            .map_err(|e| guard_error(e, rel))?
            .into_iter()
            .map(str::to_string)
            .collect();
        let name = parts.pop().unwrap_or_default();
        Ok((parts, name))
    };
    let mut pairs = Vec::new();
    for f in &req.files {
        pairs.push((f.from.clone(), split(&f.from)?, f.to.clone(), split(&f.to)?));
    }
    blocking(move || {
        let (src_ws, dst_ws) = (from.dir(&cfg.root), to.dir(&cfg.root));
        let cap = cfg.max_file_mb * MB;
        let mut total = 0u64;
        for (rel, (parts, name), _, _) in &pairs {
            let dir = open_dir(&src_ws, &refs(parts), false).map_err(|e| io_error(e, rel))?;
            let size = beneath::open_file(&dir, name)
                .and_then(|f| f.metadata())
                .map_err(|e| io_error(e, rel))?
                .len();
            if size > cap {
                return Err(too_large(
                    "file_too_large",
                    format!("files over {} MB are not copied", cfg.max_file_mb),
                    rel,
                ));
            }
            total += size;
        }
        std::fs::create_dir_all(&dst_ws).map_err(|e| io_error(e, "."))?;
        let root = beneath::root(&dst_ws).map_err(|e| io_error(e, "."))?;
        let mut used = beneath::usage(&root).map_err(|e| io_error(e, "."))?;
        for (_, _, rel, (parts, name)) in &pairs {
            // A destination that would be replaced gives its bytes back to the quota.
            if let Ok(dir) = open_dir(&dst_ws, &refs(parts), false) {
                used -= beneath::existing_size(&dir, name)
                    .map_err(|e| io_error(e, rel))?
                    .unwrap_or(0)
                    .min(used);
            }
        }
        if used + total > cfg.owner_quota_mb * MB {
            return Err(too_large(
                "quota_exceeded",
                format!("the destination may hold {} MB", cfg.owner_quota_mb),
                ".",
            ));
        }
        let mut copied = Vec::new();
        for (from_rel, (fparts, fname), rel, (parts, name)) in &pairs {
            let src = open_dir(&src_ws, &refs(fparts), false).map_err(|e| io_error(e, from_rel))?;
            let mut bytes = Vec::new();
            beneath::open_file(&src, fname)
                .and_then(|f| f.take(cap + 1).read_to_end(&mut bytes))
                .map_err(|e| io_error(e, from_rel))?;
            let dir = open_dir(&dst_ws, &refs(parts), true).map_err(|e| io_error(e, rel))?;
            beneath::write(&dir, name, &bytes).map_err(|e| io_error(e, rel))?;
            let mut sha = crate::sha256::Sha256::new();
            sha.update(&bytes);
            copied.push(json!({ "to": rel, "size": bytes.len(), "sha256": sha.hex() }));
        }
        Ok(Json(json!({ "copied": copied })))
    })
    .await
}

#[cfg(test)]
mod tests {
    use crate::testsupport::{fixture, fixture_with_token, owner_dir, post_auth, request, Fixture};
    use axum::http::StatusCode;
    use serde_json::Value;

    const BUDI: &str = "owner=acme/budi";

    async fn put(
        f: &Fixture,
        path: &str,
        body: &[u8],
        extra: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let (s, b, _) = request(
            f,
            "PUT",
            &format!("/v1/file?{BUDI}&path={path}"),
            body.to_vec(),
            extra,
        )
        .await;
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    async fn read(f: &Fixture, path: &str) -> (StatusCode, Vec<u8>, Option<String>) {
        let (s, b, h) = request(
            f,
            "GET",
            &format!("/v1/file?{BUDI}&path={path}"),
            vec![],
            &[],
        )
        .await;
        (s, b, h.get("etag").map(|v| v.to_str().unwrap().to_string()))
    }

    async fn listing(f: &Fixture, query: &str) -> Value {
        let (s, b, _) = request(f, "GET", &format!("/v1/files?{BUDI}{query}"), vec![], &[]).await;
        assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        serde_json::from_slice(&b).unwrap()
    }

    fn code(v: &Value) -> &str {
        v["error"]["code"].as_str().unwrap_or("")
    }

    #[tokio::test]
    async fn bytes_written_come_back_whole_with_their_hash() {
        let f = fixture("files-roundtrip");
        let data = b"PNG\x00\x01\xff and text".to_vec();
        let (s, out) = put(&f, "art/frames/f1.png", &data, &[]).await;
        assert_eq!(s, StatusCode::OK, "{out}");
        let (s, got, etag) = read(&f, "art/frames/f1.png").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(got, data);
        assert_eq!(
            etag.unwrap(),
            format!("\"{}\"", out["sha256"].as_str().unwrap())
        );

        let all = listing(&f, "&hash=true").await;
        let paths: Vec<&str> = all["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap())
            .collect();
        assert_eq!(paths, ["art/frames/f1.png", "notes.md"]);
        assert_eq!(all["entries"][0]["sha256"], out["sha256"]);
        assert_eq!(all["entries"][0]["size"], data.len());
        assert!(
            listing(&f, "").await["entries"][0].get("sha256").is_none(),
            "hashes only when asked"
        );
        assert_eq!(
            listing(&f, "&path=art").await["entries"][0]["path"],
            "art/frames/f1.png"
        );
    }

    #[tokio::test]
    async fn a_symlink_a_job_planted_is_never_followed() {
        let f = fixture("files-symlink");
        let mine = owner_dir(&f.cfg.root, &["acme", "budi"]);
        let hers = owner_dir(&f.cfg.root, &["acme", "ani"]);
        std::os::unix::fs::symlink(&hers, mine.join("link")).unwrap();
        std::os::unix::fs::symlink(hers.join("secret.md"), mine.join("leak.md")).unwrap();

        for path in ["link/secret.md", "leak.md"] {
            let (s, body, _) = read(&f, path).await;
            assert_eq!(
                s,
                StatusCode::FORBIDDEN,
                "{path}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        let (s, out) = put(&f, "link/planted.md", b"x", &[]).await;
        assert_eq!(
            (s, code(&out)),
            (StatusCode::FORBIDDEN, "path_escapes_workspace")
        );
        assert!(
            !hers.join("planted.md").exists(),
            "nothing landed in another owner's workspace"
        );
        let (s, _, _) = request(
            &f,
            "DELETE",
            &format!("/v1/file?{BUDI}&path=link/secret.md"),
            vec![],
            &[],
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(hers.join("secret.md").exists());

        let paths: Vec<Value> = listing(&f, "&hash=true").await["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].clone())
            .collect();
        assert_eq!(paths, ["notes.md"], "symlinks are not listed or followed");

        // A symlinked name is refused for writing too, and its target keeps its bytes.
        let (s, out) = put(&f, "leak.md", b"mine now", &[]).await;
        assert_eq!(
            (s, code(&out)),
            (StatusCode::FORBIDDEN, "path_escapes_workspace")
        );
        assert_eq!(std::fs::read(hers.join("secret.md")).unwrap(), b"hers");
    }

    #[tokio::test]
    async fn paths_that_climb_or_are_absolute_are_refused() {
        let f = fixture("files-paths");
        for path in [
            "../ani/secret.md",
            "a/../notes.md",
            "./notes.md",
            "a//b",
            "",
        ] {
            let (s, out) = put(&f, path, b"x", &[]).await;
            assert_eq!(
                (s, code(&out)),
                (StatusCode::FORBIDDEN, "path_escapes_workspace"),
                "{path}"
            );
        }
        let (s, out) = put(&f, "/etc/passwd", b"x", &[]).await;
        assert_eq!(
            (s, code(&out)),
            (StatusCode::BAD_REQUEST, "absolute_path_rejected")
        );
    }

    #[tokio::test]
    async fn a_token_for_another_prefix_reaches_nothing() {
        let f = fixture_with_token("files-scope", "s3cret");
        let (s, out) = post_auth(
            &f,
            "/v1/token",
            r#"{"prefix":["acme","budi"]}"#,
            Some("Bearer s3cret"),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{out}");
        let auth = format!("Bearer {}", out["token"].as_str().unwrap());
        let a = [("authorization", auth.as_str())];
        let (s, b, _) = request(
            &f,
            "GET",
            "/v1/file?owner=acme/ani&path=secret.md",
            vec![],
            &a,
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{}", String::from_utf8_lossy(&b));
        let (s, _, _) = request(
            &f,
            "PUT",
            "/v1/file?owner=acme/ani&path=x.md",
            b"x".to_vec(),
            &a,
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, _) = request(&f, "GET", "/v1/files?owner=acme/ani", vec![], &a).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, got, _) = request(
            &f,
            "GET",
            "/v1/file?owner=acme/budi&path=notes.md",
            vec![],
            &a,
        )
        .await;
        assert_eq!((s, got.as_slice()), (StatusCode::OK, &b"mine"[..]));
        let (s, _, _) = request(
            &f,
            "GET",
            "/v1/file?owner=acme/budi&path=notes.md",
            vec![],
            &[],
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_stale_hash_changes_nothing() {
        let f = fixture("files-ifmatch");
        let (_, _, etag) = read(&f, "notes.md").await;
        let etag = etag.unwrap();
        let (s, out) = put(&f, "notes.md", b"edited", &[("if-match", "\"0000\"")]).await;
        assert_eq!(
            (s, code(&out)),
            (StatusCode::PRECONDITION_FAILED, "file_changed")
        );
        let (s, _, _) = request(
            &f,
            "DELETE",
            &format!("/v1/file?{BUDI}&path=notes.md"),
            vec![],
            &[("if-match", "\"0000\"")],
        )
        .await;
        assert_eq!(s, StatusCode::PRECONDITION_FAILED);
        assert_eq!(read(&f, "notes.md").await.1, b"mine");
        let (s, _) = put(&f, "notes.md", b"edited", &[("if-match", &etag)]).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(read(&f, "notes.md").await.1, b"edited");
    }

    #[tokio::test]
    async fn file_size_and_quota_are_held_and_leave_old_bytes() {
        let f = fixture("files-quota");
        let big = vec![7u8; 1024 * 1024 + 1];
        let (s, out) = put(&f, "big.bin", &big, &[]).await;
        assert_eq!(
            (s, code(&out)),
            (StatusCode::PAYLOAD_TOO_LARGE, "file_too_large")
        );
        let part = vec![1u8; 900 * 1024];
        assert_eq!(put(&f, "a.bin", &part, &[]).await.0, StatusCode::OK);
        assert_eq!(put(&f, "b.bin", &part, &[]).await.0, StatusCode::OK);
        let (s, out) = put(&f, "c.bin", &part, &[]).await;
        assert_eq!(
            (s, code(&out)),
            (StatusCode::PAYLOAD_TOO_LARGE, "quota_exceeded")
        );
        assert_eq!(read(&f, "c.bin").await.0, StatusCode::NOT_FOUND);
        // Replacing a file counts its new size, not both.
        assert_eq!(put(&f, "a.bin", &part, &[]).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_takes_files_only() {
        let f = fixture("files-delete");
        assert_eq!(put(&f, "dir/x.md", b"x", &[]).await.0, StatusCode::OK);
        let del = |p: &str| format!("/v1/file?{BUDI}&path={p}");
        let (s, _, _) = request(&f, "DELETE", &del("dir"), vec![], &[]).await;
        assert_eq!(s, StatusCode::CONFLICT);
        let (s, _, _) = request(&f, "DELETE", &del("dir/x.md"), vec![], &[]).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = request(&f, "DELETE", &del("dir/x.md"), vec![], &[]).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[allow(unsafe_code)]
    async fn a_fifo_answers_instead_of_hanging() {
        let f = fixture("files-fifo");
        let p = owner_dir(&f.cfg.root, &["acme", "budi"]).join("pipe");
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c is a NUL terminated path alive for the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), read(&f, "pipe")).await;
        assert_eq!(got.expect("answered in time").0, StatusCode::CONFLICT);
    }

    async fn copy(f: &Fixture, body: &str, auth: Option<&str>) -> (StatusCode, Value) {
        crate::testsupport::post_auth(f, "/v1/copy", body, auth).await
    }

    #[tokio::test]
    async fn copy_moves_bytes_between_owners_and_says_what_it_wrote() {
        let f = fixture("copy-ok");
        let (s, out) = copy(&f, r#"{"from_owner":["acme","budi"],"to_owner":["acme","ani"],"files":[{"from":"notes.md","to":"in/notes.md"}]}"#, None).await;
        assert_eq!(s, StatusCode::OK, "{out}");
        assert_eq!(out["copied"][0]["size"], 4);
        let hers = owner_dir(&f.cfg.root, &["acme", "ani"]);
        assert_eq!(std::fs::read(hers.join("in/notes.md")).unwrap(), b"mine");
        // the one-file listing gives the same hash the copy reported
        let (s, b, _) = request(
            &f,
            "GET",
            "/v1/files?owner=acme/ani&path=in/notes.md&hash=true",
            vec![],
            &[],
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["entries"][0]["sha256"], out["copied"][0]["sha256"]);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn copy_refuses_symlinks_on_either_side_and_writes_nothing() {
        let f = fixture("copy-symlink");
        let mine = owner_dir(&f.cfg.root, &["acme", "budi"]);
        let hers = owner_dir(&f.cfg.root, &["acme", "ani"]);
        std::os::unix::fs::symlink(hers.join("secret.md"), mine.join("leak.md")).unwrap();
        let (s, out) = copy(&f, r#"{"from_owner":["acme","budi"],"to_owner":["acme","budi"],"files":[{"from":"leak.md","to":"got.md"}]}"#, None).await;
        assert_eq!(
            (s, code(&out)),
            (StatusCode::FORBIDDEN, "path_escapes_workspace")
        );
        assert!(!mine.join("got.md").exists());
        std::os::unix::fs::symlink(&hers, mine.join("out")).unwrap();
        let (s, _) = copy(&f, r#"{"from_owner":["acme","budi"],"to_owner":["acme","budi"],"files":[{"from":"notes.md","to":"out/planted.md"}]}"#, None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(!hers.join("planted.md").exists());
    }

    #[tokio::test]
    async fn copy_stays_inside_the_tokens_scope() {
        let f = fixture_with_token("copy-scope", "s3cret");
        let (_, out) = post_auth(
            &f,
            "/v1/token",
            r#"{"prefix":["acme","budi"]}"#,
            Some("Bearer s3cret"),
        )
        .await;
        let auth = format!("Bearer {}", out["token"].as_str().unwrap());
        for body in [
            r#"{"from_owner":["acme","ani"],"to_owner":["acme","budi"],"files":[{"from":"secret.md","to":"x.md"}]}"#,
            r#"{"from_owner":["acme","budi"],"to_owner":["acme","ani"],"files":[{"from":"notes.md","to":"x.md"}]}"#,
        ] {
            let (s, out) = copy(&f, body, Some(&auth)).await;
            assert_eq!(
                (s, code(&out)),
                (StatusCode::FORBIDDEN, "owner_outside_token_scope")
            );
        }
        assert!(!owner_dir(&f.cfg.root, &["acme", "budi"])
            .join("x.md")
            .exists());
        assert!(!owner_dir(&f.cfg.root, &["acme", "ani"])
            .join("x.md")
            .exists());
    }

    #[tokio::test]
    async fn a_copy_over_the_quota_or_the_count_copies_nothing() {
        let f = fixture("copy-quota");
        let part = vec![1u8; 900 * 1024];
        assert_eq!(put(&f, "a.bin", &part, &[]).await.0, StatusCode::OK);
        assert_eq!(put(&f, "b.bin", &part, &[]).await.0, StatusCode::OK);
        let (s, out) = copy(&f, r#"{"from_owner":["acme","budi"],"to_owner":["acme","budi"],"files":[{"from":"a.bin","to":"c.bin"},{"from":"b.bin","to":"d.bin"}]}"#, None).await;
        assert_eq!(
            (s, code(&out)),
            (StatusCode::PAYLOAD_TOO_LARGE, "quota_exceeded")
        );
        let mine = owner_dir(&f.cfg.root, &["acme", "budi"]);
        assert!(!mine.join("c.bin").exists() && !mine.join("d.bin").exists());
        // replacing a file in place counts its new size, not both
        let (s, out) = copy(&f, r#"{"from_owner":["acme","budi"],"to_owner":["acme","budi"],"files":[{"from":"a.bin","to":"b.bin"}]}"#, None).await;
        assert_eq!(s, StatusCode::OK, "{out}");
        let (s, _) = copy(
            &f,
            r#"{"from_owner":["acme","budi"],"to_owner":["acme","budi"],"files":[]}"#,
            None,
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, out) = copy(&f, r#"{"from_owner":["acme","budi"],"to_owner":["acme","budi"],"files":[{"from":"missing.md","to":"x.md"}]}"#, None).await;
        assert_eq!((s, code(&out)), (StatusCode::NOT_FOUND, "file_not_found"));
    }

    #[tokio::test]
    async fn an_owner_with_no_files_lists_empty() {
        let f = fixture("files-empty");
        let (s, b, _) = request(&f, "GET", "/v1/files?owner=acme/new", vec![], &[]).await;
        assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["entries"].as_array().unwrap().len(), 0);
    }
}
