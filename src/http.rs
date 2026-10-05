//! The HTTP surface. Routes only: every rule lives in `owner` and `guard`, so a
//! second client in another language cannot implement a rule differently.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::config::Config;
use crate::token::Scope;

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

/// Refuses in cordon's shape: axum's `Json` rejects with plain text and no stable `code`.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(v)) => Ok(ApiJson(v)),
            // One code for every shape problem: to a caller they are all a wrong body.
            Err(e) => Err(ApiError::bad_request(
                "invalid_request",
                rejection_message(&e),
            )),
        }
    }
}

fn rejection_message(e: &JsonRejection) -> String {
    match e {
        JsonRejection::MissingJsonContentType(_) => {
            "the body must be sent with Content-Type: application/json".into()
        }
        other => other.body_text(),
    }
}

pub fn router(cfg: Arc<Config>) -> Router {
    // Health is outside the token check: a probe should not need the secret.
    let open = Router::new().route(
        "/v1/health",
        get(|| async { Json(json!({ "status": "ok" })) }),
    );

    let guarded = Router::new()
        .route("/v1/resolve", post(crate::resolve::handler))
        .route("/v1/run", post(crate::run::handler))
        .route("/v1/fork", post(crate::fork::handler))
        .route("/v1/artifact/{token}", get(crate::artifact::handler))
        .route("/v1/token", post(crate::token::handler))
        .route("/v1/token/{token}", delete(crate::token::revoke))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&cfg),
            require_token,
        ))
        .with_state(cfg);

    open.merge(guarded)
}

/// With no token every request is allowed; `Config::from_env` refuses a public listener then (#3).
/// Attaches the `Scope` every handler extracts, so a route added outside this layer fails.
async fn require_token(
    State(cfg): State<Arc<Config>>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let scope = match cfg.token.as_deref() {
        None => Some(Scope::Operator),
        Some(expected) => req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(bearer_value)
            .and_then(|got| {
                if constant_time_eq(got.as_bytes(), expected.as_bytes()) {
                    Some(Scope::Operator)
                } else {
                    crate::token::lookup(&cfg.root, got)
                }
            }),
    };
    let Some(scope) = scope else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a bearer token is required",
        ));
    };
    req.extensions_mut().insert(scope);
    Ok(next.run(req).await)
}

/// The scheme is case insensitive per RFC 7235, so `bearer` has to work too.
fn bearer_value(value: &str) -> Option<&str> {
    let (scheme, rest) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(rest.trim())
}

/// No early exit on the first differing byte. The length is observable, fine for a shared secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
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
            container_cli: "docker".into(),
            artifact_ttl: std::time::Duration::from_secs(60),
            max_wall_ms: 5_000,
            max_memory_mb: 128,
            // The boundary exists on Linux only, so the suite runs without it elsewhere.
            unsafe_process_backend: cfg!(not(target_os = "linux")),
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

    /// A configured token is checked on every endpoint that can name an owner (#3).
    #[tokio::test]
    async fn a_configured_token_is_required() {
        let f = crate::testsupport::fixture_with_token("auth", "s3cret");
        let body = r#"{"owner":["acme","budi"],"path":"notes.md"}"#;

        for (name, auth) in [
            ("no header", None),
            ("wrong token", Some("Bearer WRONG")),
            ("right token, wrong scheme", Some("Basic s3cret")),
            ("bare value", Some("s3cret")),
            ("empty bearer", Some("Bearer ")),
            ("prefix of the token", Some("Bearer s3cre")),
            ("token plus a byte", Some("Bearer s3cret1")),
        ] {
            let (status, out) = crate::testsupport::post_auth(&f, "/v1/resolve", body, auth).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}: {out}");
            assert_eq!(out["error"]["code"], "unauthorized", "{name}: {out}");
        }

        // The right token, and the scheme is case insensitive per RFC 7235.
        for auth in ["Bearer s3cret", "bearer s3cret", "BEARER s3cret"] {
            let (status, out) =
                crate::testsupport::post_auth(&f, "/v1/resolve", body, Some(auth)).await;
            assert_eq!(status, StatusCode::OK, "{auth}: {out}");
        }
    }

    #[tokio::test]
    async fn every_owner_naming_endpoint_is_behind_the_token() {
        let f = crate::testsupport::fixture_with_token("auth-all", "s3cret");
        let cases = [
            (
                "/v1/resolve",
                r#"{"owner":["acme","budi"],"path":"notes.md"}"#,
            ),
            (
                "/v1/run",
                r#"{"owner":["acme","budi"],"entrypoint":"true"}"#,
            ),
            (
                "/v1/fork",
                r#"{"from":["acme","budi"],"to":["acme","copy"]}"#,
            ),
        ];
        for (uri, body) in cases {
            let (status, out) = crate::testsupport::post_auth(&f, uri, body, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri} was open: {out}");
        }
        let (status, _) = crate::testsupport::get_auth(
            &f,
            "/v1/artifact/art_00000000000000000000000000000000",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "/v1/artifact was open");
    }

    /// Covers the cases axum would otherwise answer with plain text and its own statuses.
    #[tokio::test]
    async fn a_malformed_body_refuses_in_cordons_shape() {
        use crate::testsupport::{fixture, post_typed};
        let f = fixture("json-shape");

        let cases: [(&str, &str, Option<&str>); 4] = [
            (
                "no content type",
                r#"{"owner":["acme","budi"],"path":"a.md"}"#,
                None,
            ),
            (
                "wrong content type",
                r#"{"owner":["acme","budi"],"path":"a.md"}"#,
                Some("text/plain"),
            ),
            ("not json at all", "bukan json", Some("application/json")),
            (
                "a missing field",
                r#"{"owner":["acme","budi"]}"#,
                Some("application/json"),
            ),
        ];

        for (name, body, ct) in cases {
            let (status, out) = post_typed(&f, "/v1/resolve", body, None, ct).await;
            assert!(status.is_client_error(), "{name}: status {status}");
            assert_eq!(
                out["error"]["code"], "invalid_request",
                "{name}: the body was not cordon's error shape: {out}"
            );
            assert!(
                out["error"]["message"].is_string(),
                "{name}: no message to act on: {out}"
            );
        }
    }

    #[tokio::test]
    async fn health_does_not_need_the_token() {
        let f = crate::testsupport::fixture_with_token("auth-health", "s3cret");
        let (status, _) = crate::testsupport::get_auth(&f, "/v1/health", None).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn with_no_token_configured_nothing_is_required() {
        let f = crate::testsupport::fixture("auth-none");
        let (status, out) = crate::testsupport::post_auth(
            &f,
            "/v1/resolve",
            r#"{"owner":["acme","budi"],"path":"notes.md"}"#,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
    }

    #[test]
    fn the_comparison_does_not_exit_early() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
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
