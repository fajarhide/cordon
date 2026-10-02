//! The HTTP surface. Routes only: every rule lives in `owner` and `guard`, so a
//! second client in another language cannot implement a rule differently.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::config::Config;

/// One shape for every refusal, so a caller can branch on `code` instead of
/// matching on prose. A refusal is 4xx, never 5xx: it is the daemon working.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub detail: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut error = json!({ "code": self.code, "message": self.message });
        if let Some(detail) = self.detail {
            error["detail"] = detail;
        }
        (self.status, Json(json!({ "error": error }))).into_response()
    }
}

pub fn router(cfg: Arc<Config>) -> Router {
    Router::new()
        .route(
            "/v1/health",
            get(|| async { Json(json!({ "status": "ok" })) }),
        )
        .route("/v1/resolve", post(crate::resolve::handler))
        .route("/v1/run", post(crate::run::handler))
        .route("/v1/fork", post(crate::fork::handler))
        .route("/v1/artifact/{token}", get(crate::artifact::handler))
        .with_state(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            root: std::env::temp_dir().join("cordon-http-test"),
            listen: "unix:/tmp/x.sock".into(),
            token: None,
            backend: "process".into(),
            image: "alpine:3.20".into(),
            artifact_ttl: std::time::Duration::from_secs(60),
            max_wall_ms: 5_000,
            max_memory_mb: 128,
        })
    }

    #[tokio::test]
    async fn health_answers_ok() {
        let res = router(test_config())
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], br#"{"status":"ok"}"#);
    }

    #[tokio::test]
    async fn an_unknown_route_is_404_not_a_panic() {
        let res = router(test_config())
            .oneshot(
                Request::builder()
                    .uri("/v1/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
