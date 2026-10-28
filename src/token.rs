//! Tokens scoped to an owner prefix, so two applications can share one daemon (#17).
//! A scoped token is a file named for the token, holding its prefix and an optional expiry (#23).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::artifact::{is_opaque, now_secs, opaque};
use crate::config::Config;
use crate::http::{ApiError, ApiJson};
use crate::owner::Owner;

const SHAPE: &str = "tok_";

/// What the presented credential may name. No request `Owner` or `Guard` is built without it.
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
    // Shape before filesystem: the value becomes a file name.
    if !is_opaque(presented, SHAPE) {
        return None;
    }
    let record =
        std::fs::read_to_string(root.join("tokens").join(format!("{presented}.rec"))).ok()?;
    let (prefix, expires) = parse_record(&record)?;
    if expires.is_some_and(|at| now_secs() >= at) {
        return None;
    }
    Some(Scope::Prefix(prefix))
}

/// The prefix on the first line, and an expiry in unix seconds on the second if there is one.
/// A second line that is not a number refuses the token, so a damaged expiry never means forever.
fn parse_record(record: &str) -> Option<(Owner, Option<u64>)> {
    let mut lines = record.lines();
    let segments: Vec<String> = lines.next()?.split('/').map(str::to_string).collect();
    let expires = match lines.next() {
        None => None,
        Some(at) => Some(at.parse().ok()?),
    };
    Some((Owner::parse(&segments).ok()?, expires))
}

/// Deletes the records of expired tokens and returns how many went (#23).
pub fn reap(root: &Path) -> usize {
    let now = now_secs();
    // MAX means the clock is unreadable, which must not delete every token.
    if now == u64::MAX {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(root.join("tokens")) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            std::fs::read_to_string(p)
                .ok()
                .and_then(|s| parse_record(&s))
                .is_some_and(|(_, expires)| expires.is_some_and(|at| now >= at))
        })
        .filter(|p| std::fs::remove_file(p).is_ok())
        .count()
}

#[derive(Deserialize)]
pub struct IssueRequest {
    pub prefix: Vec<String>,
    /// Absent means the token lasts until it is revoked.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

fn operator_only(cfg: &Config, scope: &Scope) -> Result<(), ApiError> {
    // With no operator token every caller is unscoped, so a scoped token would narrow nothing.
    if cfg.token.is_none() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "this daemon has no CORDON_TOKEN, so there is nothing for a scoped token to narrow",
        ));
    }
    if *scope != Scope::Operator {
        return Err(ApiError::forbidden(
            "operator_token_required",
            "only the operator token can issue or revoke a scoped token",
        ));
    }
    Ok(())
}

pub async fn handler(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    ApiJson(req): ApiJson<IssueRequest>,
) -> Result<Json<Value>, ApiError> {
    operator_only(&cfg, &scope)?;
    let prefix =
        Owner::parse(&req.prefix).map_err(|e| ApiError::bad_request("invalid_owner", e))?;
    // Zero is refused, not read as "no expiry": the same trap as a zero memory limit (#9).
    if req.ttl_seconds == Some(0) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "ttl_seconds must be at least 1; leave it out for a token that does not expire",
        ));
    }
    let expires = req.ttl_seconds.map(|ttl| now_secs().saturating_add(ttl));

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
        .and_then(|mut f| match expires {
            Some(at) => writeln!(f, "{prefix}\n{at}"),
            None => writeln!(f, "{prefix}"),
        })
        .map_err(failed)?;

    Ok(Json(
        json!({ "token": token, "prefix": prefix.to_string(), "expires": expires }),
    ))
}

/// DELETE /v1/token/{token}. Operator only, so one tenant cannot revoke another's token.
pub async fn revoke(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    UrlPath(token): UrlPath<String>,
) -> Result<Json<Value>, ApiError> {
    operator_only(&cfg, &scope)?;
    let gone = || ApiError::new(StatusCode::NOT_FOUND, "token_not_found", "no such token");
    // Shape before filesystem: the value becomes a file name.
    if !is_opaque(&token, SHAPE) {
        return Err(gone());
    }
    std::fs::remove_file(cfg.root.join("tokens").join(format!("{token}.rec")))
        .map_err(|_| gone())?;
    Ok(Json(json!({ "revoked": true })))
}

#[cfg(test)]
mod tests {
    use crate::testsupport::{
        fixture, fixture_with_token, get_auth, owner_dir, post_auth, send_auth,
    };
    use axum::http::StatusCode;
    use serde_json::Value;

    const OP: Option<&str> = Some("Bearer s3cret");

    /// Issues a token for `prefix`, as a ready Authorization header value.
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
            // A string prefix in either direction is not inside the owner prefix.
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
        // The scope is checked before resolve creates a workspace, so a refusal leaves nothing.
        assert!(
            !owner_dir(&f.cfg.root, &["acme", "bud"]).exists(),
            "a refused owner got a workspace"
        );
    }

    /// An ancestor above the token's prefix belongs to somebody else, even with inherit.
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

        // Not even for its own prefix: a token that mints tokens cannot be revoked by one delete.
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

    #[tokio::test]
    async fn a_token_past_its_ttl_is_refused_and_then_swept() {
        let f = fixture_with_token("tok-ttl", "s3cret");
        let body = r#"{"owner":["acme","budi"],"path":"notes.md"}"#;
        let dir = f.cfg.root.join("tokens");

        let (status, out) = post_auth(
            &f,
            "/v1/token",
            r#"{"prefix":["acme","budi"],"ttl_seconds":3600}"#,
            OP,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        let now = crate::artifact::now_secs();
        let expires = out["expires"].as_u64().expect("an expiry");
        assert!((now + 3590..=now + 3610).contains(&expires), "{out}");
        let live = format!("Bearer {}", out["token"].as_str().unwrap());
        let (status, _) = post_auth(&f, "/v1/resolve", body, Some(&live)).await;
        assert_eq!(status, StatusCode::OK);

        // The same shape of record, already past its expiry, and one whose expiry is damaged.
        let past = "tok_00000000000000000000000000000001";
        let damaged = "tok_00000000000000000000000000000002";
        std::fs::write(dir.join(format!("{past}.rec")), "acme/budi\n1\n").unwrap();
        std::fs::write(dir.join(format!("{damaged}.rec")), "acme/budi\nnever\n").unwrap();
        for token in [past, damaged] {
            let auth = format!("Bearer {token}");
            let (status, out) = post_auth(&f, "/v1/resolve", body, Some(&auth)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{token}: {out}");
        }

        let forever = issue(&f, r#"["acme","budi"]"#).await;
        assert_eq!(super::reap(&f.cfg.root), 1, "only the expired record goes");
        assert!(!dir.join(format!("{past}.rec")).exists());
        assert!(dir.join(format!("{damaged}.rec")).exists());
        for auth in [&live, &forever] {
            let (status, _) = post_auth(&f, "/v1/resolve", body, Some(auth)).await;
            assert_eq!(status, StatusCode::OK, "a live token was swept");
        }

        let (status, out) = post_auth(
            &f,
            "/v1/token",
            r#"{"prefix":["acme"],"ttl_seconds":0}"#,
            OP,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "zero was accepted: {out}");
    }

    #[tokio::test]
    async fn the_operator_revokes_a_token_and_nobody_else_can() {
        let f = fixture_with_token("tok-del", "s3cret");
        let body = r#"{"owner":["acme","budi"],"path":"notes.md"}"#;
        let budi = issue(&f, r#"["acme","budi"]"#).await;
        let ani = issue(&f, r#"["acme","ani"]"#).await;
        let uri = |auth: &str| format!("/v1/token/{}", auth.trim_start_matches("Bearer "));

        let (status, out) = send_auth(&f, "DELETE", &uri(&ani), Some(&budi)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{out}");
        assert_eq!(out["error"]["code"], "operator_token_required", "{out}");
        let (status, _) = send_auth(&f, "DELETE", &uri(&budi), Some(&budi)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a token revoked itself");

        let (status, out) = send_auth(&f, "DELETE", &uri(&budi), OP).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        let (status, _) = post_auth(&f, "/v1/resolve", body, Some(&budi)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a revoked token still works"
        );
        let ani_body = r#"{"owner":["acme","ani"],"path":"secret.md"}"#;
        let (status, _) = post_auth(&f, "/v1/resolve", ani_body, Some(&ani)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "revoking one token took another with it"
        );

        for missing in [
            uri(&budi),
            "/v1/token/tok_ffffffffffffffffffffffffffffffff".to_string(),
            "/v1/token/..%2f..%2fartifacts".to_string(),
        ] {
            let (status, out) = send_auth(&f, "DELETE", &missing, OP).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{missing}: {out}");
        }
    }
}
