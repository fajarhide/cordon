//! Tokens scoped to an owner prefix, so two applications can share one daemon
//! without trusting each other (issue #17).
//!
//! `CORDON_TOKEN` stays what it was: the operator's, and unscoped. It is the
//! only thing that can issue a scoped token, and a scoped token can name an
//! owner at or under its prefix and nothing else.
//!
//! A scoped token is a record on disk, like an artifact: the token is the file
//! name and the prefix is the content. Deleting the file revokes it.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::artifact::{is_opaque, opaque};
use crate::config::Config;
use crate::http::{ApiError, ApiJson};
use crate::owner::Owner;

const SHAPE: &str = "tok_";

/// What the presented credential may name. The auth layer puts one on every
/// request, and nothing downstream can build an `Owner` from a request or a
/// `Guard` without handing it over.
#[derive(Debug, Clone, PartialEq)]
pub enum Scope {
    Operator,
    Prefix(Owner),
}

impl Scope {
    pub fn allows(&self, owner: &Owner) -> bool {
        match self {
            Scope::Operator => true,
            Scope::Prefix(p) => owner.within(p),
        }
    }
}

/// The scope a presented token carries, if it is one this daemon issued.
pub fn lookup(root: &Path, presented: &str) -> Option<Scope> {
    // The shape is checked before the filesystem is, for the same reason an
    // artifact token's is: the value becomes a file name.
    if !is_opaque(presented, SHAPE) {
        return None;
    }
    let record =
        std::fs::read_to_string(root.join("tokens").join(format!("{presented}.rec"))).ok()?;
    let segments: Vec<String> = record.trim_end().split('/').map(str::to_string).collect();
    Owner::parse(&segments).ok().map(Scope::Prefix)
}

#[derive(Deserialize)]
pub struct IssueRequest {
    pub prefix: Vec<String>,
}

pub async fn handler(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    ApiJson(req): ApiJson<IssueRequest>,
) -> Result<Json<Value>, ApiError> {
    // With no operator token every caller is already unscoped, so a scoped
    // token would be a promise the daemon does not keep.
    if cfg.token.is_none() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "this daemon has no CORDON_TOKEN, so there is nothing for a scoped token to narrow",
        ));
    }
    if scope != Scope::Operator {
        return Err(ApiError::forbidden(
            "operator_token_required",
            "only the operator token can issue a scoped token",
        ));
    }
    let prefix =
        Owner::parse(&req.prefix).map_err(|e| ApiError::bad_request("invalid_owner", e))?;

    let failed = |e: std::io::Error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "token_issue_failed",
            e.to_string(),
        )
    };
    let token = opaque(SHAPE).map_err(failed)?;
    let dir = cfg.root.join("tokens");
    std::fs::create_dir_all(&dir).map_err(failed)?;
    // Owner only: unlike an artifact record, this file's name is a credential.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join(format!("{token}.rec")))
        .and_then(|mut f| writeln!(f, "{prefix}"))
        .map_err(failed)?;

    Ok(Json(
        json!({ "token": token, "prefix": prefix.to_string() }),
    ))
}

#[cfg(test)]
mod tests {
    use crate::testsupport::{fixture, fixture_with_token, get_auth, owner_dir, post_auth};
    use axum::http::StatusCode;
    use serde_json::Value;

    const OP: Option<&str> = Some("Bearer s3cret");

    /// Issues a token for `prefix` and returns it as a ready Authorization
    /// header value.
    async fn issue(f: &crate::testsupport::Fixture, prefix: &str) -> String {
        let (status, out) =
            post_auth(f, "/v1/token", &format!(r#"{{"prefix":{prefix}}}"#), OP).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(out["token"].as_str().unwrap().len(), 36, "{out}");
        format!("Bearer {}", out["token"].as_str().unwrap())
    }

    fn refused(what: &str, got: (StatusCode, Value)) {
        assert_eq!(got.0, StatusCode::FORBIDDEN, "{what}: {}", got.1);
        assert_eq!(
            got.1["error"]["code"], "owner_outside_token_scope",
            "{what}: {}",
            got.1
        );
    }

    #[tokio::test]
    async fn a_scoped_token_works_inside_its_prefix_and_nowhere_else() {
        let f = fixture_with_token("tok-scope", "s3cret");
        let budi = issue(&f, r#"["acme","budi"]"#).await;
        let budi = Some(budi.as_str());

        let (status, out) = post_auth(
            &f,
            "/v1/resolve",
            r#"{"owner":["acme","budi"],"path":"notes.md"}"#,
            budi,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        // A child of the prefix is inside it.
        let (status, out) = post_auth(
            &f,
            "/v1/run",
            r#"{"owner":["acme","budi","agent-1"],"entrypoint":"true"}"#,
            budi,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");

        for (what, uri, body) in [
            (
                "resolve as a sibling",
                "/v1/resolve",
                r#"{"owner":["acme","ani"],"path":"secret.md"}"#,
            ),
            (
                "run as a sibling",
                "/v1/run",
                r#"{"owner":["acme","ani"],"entrypoint":"cat","args":["secret.md"]}"#,
            ),
            (
                "resolve as the parent",
                "/v1/resolve",
                r#"{"owner":["acme"],"path":"x"}"#,
            ),
            // A string prefix of the token's own prefix, and one it is a
            // string prefix of. Neither is inside it.
            (
                "a shorter lookalike",
                "/v1/resolve",
                r#"{"owner":["acme","bud"],"path":"x"}"#,
            ),
            (
                "a longer lookalike",
                "/v1/resolve",
                r#"{"owner":["acme","budi2"],"path":"x"}"#,
            ),
            (
                "fork a sibling in",
                "/v1/fork",
                r#"{"from":["acme","ani"],"to":["acme","budi","stolen"]}"#,
            ),
            (
                "fork itself out",
                "/v1/fork",
                r#"{"from":["acme","budi"],"to":["acme","elsewhere"]}"#,
            ),
        ] {
            refused(what, post_auth(&f, uri, body, budi).await);
        }
        assert!(
            !owner_dir(&f.cfg.root, &["acme", "budi", "stolen"]).exists(),
            "a refused fork still copied the sibling"
        );
    }

    /// The same shape the guard tests use for a sibling, one level up: with
    /// inherit a job reads its ancestors' files, and an ancestor above the
    /// token's prefix belongs to somebody else.
    #[tokio::test]
    async fn inherit_stops_at_the_prefix() {
        let f = fixture_with_token("tok-inherit", "s3cret");
        let acme = owner_dir(&f.cfg.root, &["acme"]);
        std::fs::create_dir_all(&acme).unwrap();
        std::fs::write(acme.join("team.md"), b"ours").unwrap();
        let body = r#"{"owner":["acme","budi"],"path":"../team.md","inherit":true}"#;

        let (status, out) = post_auth(&f, "/v1/resolve", body, OP).await;
        assert_eq!(status, StatusCode::OK, "the operator lost inherit: {out}");

        let budi = issue(&f, r#"["acme","budi"]"#).await;
        let (status, out) = post_auth(&f, "/v1/resolve", body, Some(&budi)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{out}");
        assert_eq!(out["error"]["code"], "path_escapes_workspace", "{out}");

        // A prefix that contains the ancestor keeps it.
        let acme = issue(&f, r#"["acme"]"#).await;
        let (status, out) = post_auth(&f, "/v1/resolve", body, Some(&acme)).await;
        assert_eq!(status, StatusCode::OK, "{out}");
    }

    #[tokio::test]
    async fn another_prefixes_artifact_looks_like_no_artifact() {
        let f = fixture_with_token("tok-artifact", "s3cret");
        let (_, out) = post_auth(
            &f,
            "/v1/run",
            r#"{"owner":["acme","ani"],"entrypoint":"true","collect":["secret.md"]}"#,
            OP,
        )
        .await;
        let token = out["artifacts"][0]["token"].as_str().expect("an artifact");
        let budi = issue(&f, r#"["acme","budi"]"#).await;

        let real = get_auth(
            &f,
            &format!("/v1/artifact/{token}?owner=acme/ani"),
            Some(&budi),
        )
        .await;
        let fake = get_auth(
            &f,
            "/v1/artifact/art_ffffffffffffffffffffffffffffffff?owner=acme/ani",
            Some(&budi),
        )
        .await;
        assert_eq!(real.0, StatusCode::NOT_FOUND, "a scoped token fetched it");
        assert_eq!(real, fake, "the refusal confirms the artifact exists");

        let (status, body) =
            get_auth(&f, &format!("/v1/artifact/{token}?owner=acme/ani"), OP).await;
        assert_eq!((status, body.as_slice()), (StatusCode::OK, &b"hers"[..]));
    }

    #[tokio::test]
    async fn only_the_operator_issues_and_only_when_there_is_one() {
        let f = fixture_with_token("tok-issue", "s3cret");
        let budi = issue(&f, r#"["acme","budi"]"#).await;

        // Not even for its own prefix: a token that can mint tokens cannot be
        // revoked by deleting one file.
        for prefix in [r#"["acme"]"#, r#"["acme","budi"]"#] {
            let (status, out) = post_auth(
                &f,
                "/v1/token",
                &format!(r#"{{"prefix":{prefix}}}"#),
                Some(&budi),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{out}");
            assert_eq!(out["error"]["code"], "operator_token_required", "{out}");
            assert!(out["token"].is_null(), "a token came back anyway: {out}");
        }

        let (status, out) = post_auth(&f, "/v1/token", r#"{"prefix":["acme",".."]}"#, OP).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
        assert_eq!(out["error"]["code"], "invalid_owner", "{out}");

        let open = fixture("tok-open");
        let (status, out) = post_auth(&open, "/v1/token", r#"{"prefix":["acme"]}"#, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    }

    #[tokio::test]
    async fn an_unknown_or_revoked_token_is_unauthorized() {
        let f = fixture_with_token("tok-revoke", "s3cret");
        let body = r#"{"owner":["acme","budi"],"path":"notes.md"}"#;
        let budi = issue(&f, r#"["acme","budi"]"#).await;

        for auth in [
            "Bearer tok_00000000000000000000000000000000",
            "Bearer tok_../../artifacts/x",
            "Bearer tok_",
        ] {
            let (status, out) = post_auth(&f, "/v1/resolve", body, Some(auth)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{auth}: {out}");
        }

        let (status, _) = post_auth(&f, "/v1/resolve", body, Some(&budi)).await;
        assert_eq!(status, StatusCode::OK);
        let rec = f
            .cfg
            .root
            .join("tokens")
            .join(format!("{}.rec", budi.trim_start_matches("Bearer ")));
        let mode = std::os::unix::fs::PermissionsExt::mode(&rec.metadata().unwrap().permissions());
        assert_eq!(mode & 0o777, 0o600, "the record is readable by others");
        std::fs::remove_file(rec).unwrap();
        let (status, _) = post_auth(&f, "/v1/resolve", body, Some(&budi)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a deleted token still works"
        );
    }
}
