//! Test only helpers: one fixture shared by the endpoint suites, compiled out of release.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use crate::config::Config;
use crate::owner::Owner;

pub struct Fixture {
    pub cfg: Arc<Config>,
    tmp: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

/// Two owners under one root: acme/budi holding notes.md, acme/ani holding secret.md.
pub fn fixture(tag: &str) -> Fixture {
    build(tag, None)
}

pub fn fixture_with_token(tag: &str, token: &str) -> Fixture {
    build(tag, Some(token.to_string()))
}

fn build(tag: &str, token: Option<String>) -> Fixture {
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("cordon-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);

    // Built through Owner::dir, so a change to the on-disk layout cannot leave the fixture stale.
    std::fs::create_dir_all(owner_dir(&tmp, &["acme", "budi"])).expect("fixture dirs");
    std::fs::create_dir_all(owner_dir(&tmp, &["acme", "ani"])).expect("fixture dirs");
    std::fs::write(owner_dir(&tmp, &["acme", "budi"]).join("notes.md"), b"mine")
        .expect("fixture file");
    std::fs::write(owner_dir(&tmp, &["acme", "ani"]).join("secret.md"), b"hers")
        .expect("fixture file");

    let cfg = Arc::new(Config {
        root: tmp.clone(),
        listen: "unix:/tmp/unused.sock".into(),
        token,
        backend: "process".into(),
        image: "alpine:3.20".into(),
        container_cli: "docker".into(),
        artifact_ttl: std::time::Duration::from_secs(3600),
        max_wall_ms: 10_000,
        max_memory_mb: 256,
        // The boundary exists on Linux only, so the suite runs without it elsewhere.
        unsafe_process_backend: cfg!(not(target_os = "linux")),
    });
    Fixture { cfg, tmp }
}

/// Where an owner's own files live, for a test that needs to look at disk.
pub fn owner_dir(root: &std::path::Path, segments: &[&str]) -> PathBuf {
    Owner::parse(&segments.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .expect("valid owner in a test")
        .dir(root)
}

/// Posts through the real router, so routing, extraction and the error shape are exercised.
pub async fn post(f: &Fixture, uri: &str, payload: &str) -> (StatusCode, Value) {
    post_auth(f, uri, payload, None).await
}

pub async fn post_auth(
    f: &Fixture,
    uri: &str,
    payload: &str,
    auth: Option<&str>,
) -> (StatusCode, Value) {
    post_typed(f, uri, payload, auth, Some("application/json")).await
}

pub async fn post_typed(
    f: &Fixture,
    uri: &str,
    payload: &str,
    auth: Option<&str>,
    content_type: Option<&str>,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method("POST").uri(uri);
    if let Some(ct) = content_type {
        b = b.header("content-type", ct);
    }
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    let res = crate::http::router(Arc::clone(&f.cfg))
        .oneshot(
            b.body(Body::from(payload.to_string()))
                .expect("build request"),
        )
        .await
        .expect("router answered");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read body");
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
    (status, body)
}

pub async fn get(f: &Fixture, uri: &str) -> (StatusCode, Vec<u8>) {
    get_auth(f, uri, None).await
}

pub async fn get_auth(f: &Fixture, uri: &str, auth: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut b = Request::builder().uri(uri);
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    let res = crate::http::router(Arc::clone(&f.cfg))
        .oneshot(b.body(Body::empty()).expect("build request"))
        .await
        .expect("router answered");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read body");
    (status, bytes.to_vec())
}
