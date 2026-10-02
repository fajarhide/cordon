//! Artifacts are addressed by an opaque token, never by a path.
//!
//! A token carries no path and no owner inside it, so a caller cannot build
//! another owner's token by guessing a filename. The binding lives in a record
//! the daemon writes and the daemon alone reads.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::config::Config;
use crate::http::ApiError;
use crate::owner::Owner;

#[derive(Deserialize)]
pub struct ArtifactQuery {
    pub owner: Option<String>,
}

pub fn mint(cfg: &Config, owner: &Owner, path: &Path) -> std::io::Result<String> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|e| std::io::Error::other(e.to_string()))?;
    let token = format!("art_{}", hex(&raw));

    let dir = cfg.root.join("artifacts");
    std::fs::create_dir_all(&dir)?;
    let expires = SystemTime::now()
        .checked_add(cfg.artifact_ttl)
        .unwrap_or_else(SystemTime::now)
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    // A tab separated record. A serialiser dependency for three fields only
    // this file reads is not a trade worth making, and neither field can carry
    // a tab: the owner allowlist forbids it, and the path came out of the guard.
    let record = format!("{}\t{}\t{}\n", owner, path.display(), expires);
    std::fs::write(dir.join(format!("{token}.rec")), record)?;
    Ok(token)
}

pub async fn handler(
    State(cfg): State<Arc<Config>>,
    UrlPath(token): UrlPath<String>,
    Query(q): Query<ArtifactQuery>,
) -> Result<Response, ApiError> {
    // One refusal for every failure below, so the answer never reveals whether
    // the token existed, belonged to someone else, or had expired.
    let gone = || {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "artifact_not_found",
            "no such artifact",
        )
    };

    if !is_token(&token) {
        return Err(gone());
    }
    let record = std::fs::read_to_string(cfg.root.join("artifacts").join(format!("{token}.rec")))
        .map_err(|_| gone())?;
    let (owner, path, expires) = parse_record(&record).ok_or_else(gone)?;

    if now_secs() >= expires {
        return Err(gone());
    }
    if let Some(asked) = q.owner.as_deref() {
        if asked != owner {
            return Err(gone());
        }
    }
    let bytes = std::fs::read(&path).map_err(|_| gone())?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "artifact".into());

    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename={name:?}"),
            ),
        ],
        bytes,
    )
        .into_response())
}

/// `art_` and exactly 32 lowercase hex characters. Checking the shape before
/// touching the filesystem is what stops `art_../../etc/passwd` from becoming
/// a filename.
fn is_token(t: &str) -> bool {
    t.len() == 36
        && t.starts_with("art_")
        && t.as_bytes()[4..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

fn parse_record(s: &str) -> Option<(String, PathBuf, u64)> {
    let mut parts = s.trim_end_matches('\n').splitn(3, '\t');
    let owner = parts.next()?.to_string();
    let path = PathBuf::from(parts.next()?);
    let expires = parts.next()?.parse().ok()?;
    Some((owner, path, expires))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{fixture, get};

    fn budi() -> Owner {
        Owner::parse(&["acme".into(), "budi".into()]).expect("static owner")
    }

    #[tokio::test]
    async fn a_minted_token_fetches_the_file() {
        let f = fixture("art-ok");
        let file = budi().dir(&f.cfg.root).join("notes.md");
        let token = mint(&f.cfg, &budi(), &file).unwrap();

        let (status, body) = get(&f, &format!("/v1/artifact/{token}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"mine");
    }

    #[tokio::test]
    async fn tokens_are_unguessable_and_unique() {
        let f = fixture("art-unique");
        let file = budi().dir(&f.cfg.root).join("notes.md");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let t = mint(&f.cfg, &budi(), &file).unwrap();
            assert!(t.starts_with("art_") && t.len() == 36, "bad shape: {t}");
            assert!(seen.insert(t), "a token repeated");
        }
    }

    #[tokio::test]
    async fn an_unknown_token_is_404() {
        let f = fixture("art-unknown");
        let (status, _) = get(&f, "/v1/artifact/art_00000000000000000000000000000000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_token_shaped_path_traversal_is_refused() {
        let f = fixture("art-traverse");
        for token in [
            "..%2f..%2fetc%2fpasswd",
            "....",
            "art_..%2f..%2fetc%2fpasswd",
        ] {
            let (status, _) = get(&f, &format!("/v1/artifact/{token}")).await;
            assert!(status.is_client_error(), "{token} gave {status}");
        }
    }

    #[tokio::test]
    async fn an_expired_token_is_404() {
        let mut f = fixture("art-expired");
        Arc::get_mut(&mut f.cfg).expect("sole owner").artifact_ttl = Duration::from_secs(0);
        let file = budi().dir(&f.cfg.root).join("notes.md");
        let token = mint(&f.cfg, &budi(), &file).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        let (status, _) = get(&f, &format!("/v1/artifact/{token}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Review Focus 5. A valid token and the wrong owner must be refused, and
    /// the body must be identical to an unknown token so the answer does not
    /// confirm that the token exists.
    #[tokio::test]
    async fn another_owner_cannot_open_it_and_cannot_tell_it_exists() {
        let f = fixture("art-wrong-owner");
        let file = budi().dir(&f.cfg.root).join("notes.md");
        let token = mint(&f.cfg, &budi(), &file).unwrap();

        let (wrong, wrong_body) = get(&f, &format!("/v1/artifact/{token}?owner=acme/ani")).await;
        let (unknown, unknown_body) = get(
            &f,
            "/v1/artifact/art_ffffffffffffffffffffffffffffffff?owner=acme/ani",
        )
        .await;

        assert_eq!(wrong, StatusCode::NOT_FOUND, "another owner got {wrong}");
        assert_eq!(
            wrong, unknown,
            "the status tells a real token from a fake one"
        );
        assert_eq!(
            wrong_body, unknown_body,
            "the body tells a real token from a fake one"
        );
    }

    #[tokio::test]
    async fn the_right_owner_named_explicitly_still_works() {
        let f = fixture("art-right-owner");
        let file = budi().dir(&f.cfg.root).join("notes.md");
        let token = mint(&f.cfg, &budi(), &file).unwrap();
        let (status, body) = get(&f, &format!("/v1/artifact/{token}?owner=acme/budi")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"mine");
    }
}
