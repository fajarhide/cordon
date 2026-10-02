//! Test only helpers, compiled out of the release binary entirely.
//!
//! Four endpoint suites ask the same question of the same shape, so the
//! fixture is built once here rather than copied into each of them.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use crate::config::Config;

pub struct Fixture {
    pub cfg: Arc<Config>,
    tmp: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

/// Two owners under one root: acme/budi holding notes.md, acme/ani holding
/// secret.md. Every endpoint test starts from this and tries to cross it.
pub fn fixture(tag: &str) -> Fixture {
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("cordon-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("owners/acme/budi")).expect("fixture dirs");
    std::fs::create_dir_all(tmp.join("owners/acme/ani")).expect("fixture dirs");
    std::fs::write(tmp.join("owners/acme/budi/notes.md"), b"mine").expect("fixture file");
    std::fs::write(tmp.join("owners/acme/ani/secret.md"), b"hers").expect("fixture file");

    let cfg = Arc::new(Config {
        root: tmp.clone(),
        listen: "unix:/tmp/unused.sock".into(),
        token: None,
        backend: "process".into(),
        image: "alpine:3.20".into(),
        artifact_ttl: std::time::Duration::from_secs(3600),
        max_wall_ms: 10_000,
        max_memory_mb: 256,
    });
    Fixture { cfg, tmp }
}

/// Posts through the real router, so a test exercises routing, extraction and
/// the error shape rather than calling a handler function directly.
pub async fn post(f: &Fixture, uri: &str, payload: &str) -> (StatusCode, Value) {
    let res = crate::http::router(Arc::clone(&f.cfg))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
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
    let res = crate::http::router(Arc::clone(&f.cfg))
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router answered");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read body");
    (status, bytes.to_vec())
}
