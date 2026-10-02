//! POST /v1/resolve. The endpoint an agent runtime calls before it touches a
//! file, and the cheapest way to adopt cordon: no job execution, no container,
//! just an answer.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::Config;
use crate::guard::{Guard, GuardError};
use crate::http::ApiError;
use crate::owner::Owner;

#[derive(Deserialize)]
pub struct ResolveRequest {
    pub owner: Vec<String>,
    #[serde(default)]
    pub inherit: bool,
    pub path: String,
}

pub async fn handler(
    State(cfg): State<Arc<Config>>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<Value>, ApiError> {
    let owner = owner_or_error(&req.owner)?;
    let resolved = Guard::new(&cfg.root, &owner, req.inherit)
        .resolve(&req.path)
        .map_err(|e| guard_error(e, &req.path))?;

    Ok(Json(json!({
        "resolved": resolved.to_string_lossy(),
        "exists": resolved.exists(),
    })))
}

pub fn owner_or_error(segments: &[String]) -> Result<Owner, ApiError> {
    Owner::parse(segments).map_err(|e| ApiError::bad_request("invalid_owner", e))
}

/// One place turns a guard refusal into an HTTP answer, so every endpoint
/// returns the same code for the same refusal.
pub fn guard_error(e: GuardError, path: &str) -> ApiError {
    let detail = json!({ "path": path });
    match e {
        GuardError::Absolute(_) => ApiError::new(
            StatusCode::BAD_REQUEST,
            "absolute_path_rejected",
            "paths are relative to the owner workspace",
        ),
        GuardError::Escapes(_) => ApiError::forbidden(
            "path_escapes_workspace",
            "the path resolves outside the owner workspace",
        ),
    }
    .with_detail(detail)
}

#[cfg(test)]
mod tests {
    use crate::testsupport::{fixture, post};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn resolves_a_file_the_owner_owns() {
        let f = fixture("resolve-ok");
        let (status, body) =
            post(&f, "/v1/resolve", r#"{"owner":["acme","budi"],"path":"notes.md"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["exists"], true);
        assert!(
            body["resolved"].as_str().unwrap().ends_with("/acme/budi/notes.md"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn reports_a_path_that_does_not_exist_yet_without_refusing_it() {
        let f = fixture("resolve-new");
        let (status, body) =
            post(&f, "/v1/resolve", r#"{"owner":["acme","budi"],"path":"new.txt"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["exists"], false);
    }

    #[tokio::test]
    async fn refuses_an_escape_with_a_stable_code() {
        let cases: &[(&str, &str, StatusCode)] = &[
            (
                r#"{"owner":["acme","budi"],"path":"../ani/secret.md"}"#,
                "path_escapes_workspace",
                StatusCode::FORBIDDEN,
            ),
            (
                r#"{"owner":["acme","budi"],"path":"/etc/passwd"}"#,
                "absolute_path_rejected",
                StatusCode::BAD_REQUEST,
            ),
            (
                r#"{"owner":["acme",".."],"path":"notes.md"}"#,
                "invalid_owner",
                StatusCode::BAD_REQUEST,
            ),
            (
                r#"{"owner":[],"path":"notes.md"}"#,
                "invalid_owner",
                StatusCode::BAD_REQUEST,
            ),
        ];
        let f = fixture("resolve-refuse");
        for (payload, want_code, want_status) in cases {
            let (status, body) = post(&f, "/v1/resolve", payload).await;
            assert_eq!(status, *want_status, "{payload}: {body}");
            assert_eq!(body["error"]["code"], *want_code, "{payload}: {body}");
        }
    }

    #[tokio::test]
    async fn a_malformed_body_is_a_client_error_not_a_crash() {
        let f = fixture("resolve-junk");
        for payload in ["not json", "{}", r#"{"owner":"acme"}"#, "[]", ""] {
            let (status, body) = post(&f, "/v1/resolve", payload).await;
            assert!(status.is_client_error(), "{payload:?} gave {status}: {body}");
        }
    }

    #[tokio::test]
    async fn inherit_is_off_unless_asked_for() {
        let f = fixture("resolve-inherit");
        std::fs::write(f.cfg.root.join("owners/acme/team.md"), b"ours").unwrap();
        let (off, _) = post(
            &f,
            "/v1/resolve",
            r#"{"owner":["acme","budi"],"path":"../team.md"}"#,
        )
        .await;
        assert_eq!(off, StatusCode::FORBIDDEN, "inherit defaulted to on");

        let (on, body) = post(
            &f,
            "/v1/resolve",
            r#"{"owner":["acme","budi"],"path":"../team.md","inherit":true}"#,
        )
        .await;
        assert_eq!(on, StatusCode::OK, "{body}");
    }
}
