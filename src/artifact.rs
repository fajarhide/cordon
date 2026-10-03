//! Artifacts are addressed by an opaque token that carries no path and no owner.
//! The binding lives in a record only the daemon reads, so a filename gives a caller nothing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use serde::Deserialize;

use crate::config::Config;
use crate::http::ApiError;
use crate::owner::Owner;
use crate::token::Scope;

#[derive(Deserialize)]
pub struct ArtifactQuery {
    /// Required: an absent owner must be refused, not treated as a skipped check (#8).
    pub owner: Option<String>,
}

pub fn mint(cfg: &Config, owner: &Owner, path: &Path) -> std::io::Result<String> {
    let token = opaque("art_")?;

    let dir = cfg.root.join("artifacts");
    std::fs::create_dir_all(&dir)?;
    let expires = SystemTime::now()
        .checked_add(cfg.artifact_ttl)
        .unwrap_or_else(SystemTime::now)
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    // Tab separated, to avoid a serialiser dependency for three fields.
    // Neither can carry a tab: the owner allowlist forbids it, the path came out of the guard.
    let record = format!("{}\t{}\t{}\n", owner, path.display(), expires);
    std::fs::write(dir.join(format!("{token}.rec")), record)?;
    Ok(token)
}

pub async fn handler(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    UrlPath(token): UrlPath<String>,
    Query(q): Query<ArtifactQuery>,
) -> Result<Response, ApiError> {
    // One refusal for every failure, so the answer never reveals whether the token exists.
    let gone = || {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "artifact_not_found",
            "no such artifact",
        )
    };

    if !is_opaque(&token, "art_") {
        return Err(gone());
    }
    let record = std::fs::read_to_string(cfg.root.join("artifacts").join(format!("{token}.rec")))
        .map_err(|_| gone())?;
    let (owner, path, expires) = parse_record(&record).ok_or_else(gone)?;

    if now_secs() >= expires {
        return Err(gone());
    }
    // Absent is a refusal, not a skip (#8).
    match q.owner.as_deref() {
        Some(asked) if asked == owner => {}
        _ => return Err(gone()),
    }
    // The owner must also be inside this credential's scope.
    let segments: Vec<String> = owner.split('/').map(str::to_string).collect();
    if !Owner::parse(&segments).is_ok_and(|o| scope.allows(&o)) {
        return Err(gone());
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

/// Deletes expired records and returns how many went. Housekeeping, not a check (#18).
/// An unparseable record is left alone: `mint` creates the file before filling it.
pub fn reap(root: &Path) -> usize {
    let now = now_secs();
    // MAX means the clock is unreadable: right for refusing a fetch, wrong for deleting records.
    if now == u64::MAX {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(root.join("artifacts")) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rec"))
        .filter(|p| {
            std::fs::read_to_string(p)
                .ok()
                .and_then(|s| parse_record(&s))
                .is_some_and(|(_, _, expires)| now >= expires)
        })
        .filter(|p| std::fs::remove_file(p).is_ok())
        .count()
}

/// `prefix` and 128 bits from the kernel's generator, as hex.
pub fn opaque(prefix: &str) -> std::io::Result<String> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(format!("{prefix}{}", hex(&raw)))
}

/// `prefix` and exactly 32 lowercase hex characters.
/// Checked before the filesystem, so `art_../../etc/passwd` never becomes a filename.
pub fn is_opaque(t: &str, prefix: &str) -> bool {
    t.strip_prefix(prefix).is_some_and(|rest| {
        rest.len() == 32
            && rest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
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

        let (status, body) = get(&f, &format!("/v1/artifact/{token}?owner=acme/budi")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"mine");
    }

    /// Omitting the owner cannot be the way past the check (#8).
    #[tokio::test]
    async fn a_fetch_without_an_owner_is_refused() {
        let f = fixture("art-noowner");
        let file = budi().dir(&f.cfg.root).join("notes.md");
        let token = mint(&f.cfg, &budi(), &file).unwrap();

        let (bare, bare_body) = get(&f, &format!("/v1/artifact/{token}")).await;
        let (wrong, wrong_body) = get(&f, &format!("/v1/artifact/{token}?owner=acme/ani")).await;

        assert_eq!(bare, StatusCode::NOT_FOUND, "a bare fetch succeeded");
        // Same answer as the wrong owner, so the laxer call is not the more informative one.
        assert_eq!(bare, wrong);
        assert_eq!(bare_body, wrong_body);
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
        // With the right owner, or the missing owner refuses it before expiry is ever checked.
        let (status, _) = get(&f, &format!("/v1/artifact/{token}?owner=acme/budi")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Refusing an expired token does not delete its record; reap does (#18).
    #[tokio::test]
    async fn reap_deletes_expired_records_and_nothing_else() {
        let mut f = fixture("art-reap");
        let file = budi().dir(&f.cfg.root).join("notes.md");
        let dir = f.cfg.root.join("artifacts");
        let rec = |t: &str| dir.join(format!("{t}.rec"));

        let live = mint(&f.cfg, &budi(), &file).unwrap();
        Arc::get_mut(&mut f.cfg).expect("sole owner").artifact_ttl = Duration::from_secs(0);
        let dead = mint(&f.cfg, &budi(), &file).unwrap();
        // A record caught between create and write, and a file that is not ours.
        std::fs::write(rec("art_half"), b"").unwrap();
        std::fs::write(dir.join("README"), b"not a record").unwrap();

        assert_eq!(reap(&f.cfg.root), 1);
        assert!(!rec(&dead).exists(), "the expired record is still on disk");
        assert!(rec(&live).exists(), "a live record was deleted");
        assert!(
            rec("art_half").exists(),
            "an unparseable record was deleted"
        );
        assert!(dir.join("README").exists(), "a stranger's file was deleted");

        let (status, _) = get(&f, &format!("/v1/artifact/{live}?owner=acme/budi")).await;
        assert_eq!(status, StatusCode::OK, "the live token stopped working");
        assert_eq!(reap(&f.cfg.root), 0, "a second sweep found something");
    }

    /// The refusal must match an unknown token's, so it does not confirm the token exists.
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
