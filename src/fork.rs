//! POST /v1/fork. Gives a new owner a copy of an existing workspace, which is
//! how a team template becomes a member's starting point and how a reproducible
//! run gets its inputs.
//!
//! It copies bytes. A reflink or a filesystem snapshot would be cheaper and is
//! the obvious v2 item; v1 does the boring thing that works everywhere.

use std::path::Path;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::Config;
use crate::http::ApiError;
use crate::resolve::owner_or_error;

#[derive(Deserialize)]
pub struct ForkRequest {
    pub from: Vec<String>,
    pub to: Vec<String>,
}

pub async fn handler(
    State(cfg): State<Arc<Config>>,
    Json(req): Json<ForkRequest>,
) -> Result<Json<Value>, ApiError> {
    let from = owner_or_error(&req.from)?;
    let to = owner_or_error(&req.to)?;

    let src = from.dir(&cfg.root);
    let dst = to.dir(&cfg.root);

    if !src.is_dir() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "source_not_found",
            format!("owner {from} has no workspace"),
        ));
    }
    // Overwriting someone's workspace silently is worse than refusing, and this
    // also catches a fork onto itself.
    if dst.exists() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "destination_exists",
            format!("owner {to} already has a workspace"),
        ));
    }

    let skipped = copy_tree(&src, &dst).map_err(|e| {
        // A half copied destination is worse than none: it looks like a
        // finished fork to the next caller.
        let _ = std::fs::remove_dir_all(&dst);
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "fork_failed", e.to_string())
    })?;

    Ok(Json(json!({ "forked": to.to_string(), "skipped_links": skipped })))
}

/// Copies a directory tree, returning how many symlinks were left behind.
///
/// A symlink is never followed and never recreated. Following it copies someone
/// else's bytes into the new workspace; recreating it carries a path that means
/// something different, or nothing, once it sits under a different owner.
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<u64> {
    let mut skipped = 0u64;
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if kind.is_symlink() {
            skipped += 1;
        } else if kind.is_dir() {
            skipped += copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target)?;
        }
        // Anything else (a socket, a fifo, a device) is not something a
        // workspace should carry across an owner boundary.
    }
    Ok(skipped)
}

#[cfg(test)]
mod tests {
    use crate::testsupport::{fixture, post};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn copies_a_workspace_to_a_new_owner() {
        let f = fixture("fork-ok");
        let (status, body) =
            post(&f, "/v1/fork", r#"{"from":["acme","budi"],"to":["acme","copy"]}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            std::fs::read(f.cfg.root.join("owners/acme/copy/notes.md")).unwrap(),
            b"mine"
        );
        assert!(f.cfg.root.join("owners/acme/budi/notes.md").exists(), "source changed");
    }

    #[tokio::test]
    async fn copies_nested_directories() {
        let f = fixture("fork-nested");
        std::fs::create_dir_all(f.cfg.root.join("owners/acme/budi/a/b")).unwrap();
        std::fs::write(f.cfg.root.join("owners/acme/budi/a/b/deep.txt"), b"deep").unwrap();
        let (status, body) =
            post(&f, "/v1/fork", r#"{"from":["acme","budi"],"to":["acme","copy2"]}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            std::fs::read(f.cfg.root.join("owners/acme/copy2/a/b/deep.txt")).unwrap(),
            b"deep"
        );
    }

    #[tokio::test]
    async fn never_overwrites_an_existing_workspace() {
        let f = fixture("fork-exists");
        let (status, body) =
            post(&f, "/v1/fork", r#"{"from":["acme","budi"],"to":["acme","ani"]}"#).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "destination_exists", "{body}");
        assert_eq!(
            std::fs::read(f.cfg.root.join("owners/acme/ani/secret.md")).unwrap(),
            b"hers",
            "the destination's own file was overwritten"
        );
    }

    #[tokio::test]
    async fn a_symlink_is_dropped_rather_than_copied() {
        let f = fixture("fork-symlink");
        std::os::unix::fs::symlink(
            f.cfg.root.join("owners/acme/ani/secret.md"),
            f.cfg.root.join("owners/acme/budi/peek"),
        )
        .unwrap();
        let (status, body) =
            post(&f, "/v1/fork", r#"{"from":["acme","budi"],"to":["acme","copy3"]}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !f.cfg.root.join("owners/acme/copy3/peek").exists(),
            "a symlink to a sibling's file was carried into the fork"
        );
        assert_eq!(body["skipped_links"], 1, "{body}");
    }

    #[tokio::test]
    async fn a_missing_source_is_404() {
        let f = fixture("fork-nosource");
        let (status, body) =
            post(&f, "/v1/fork", r#"{"from":["acme","ghost"],"to":["acme","copy4"]}"#).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }

    #[tokio::test]
    async fn an_invalid_owner_on_either_side_is_refused() {
        let f = fixture("fork-badowner");
        for payload in [
            r#"{"from":["acme",".."],"to":["acme","x"]}"#,
            r#"{"from":["acme","budi"],"to":["acme","../escape"]}"#,
            r#"{"from":[],"to":["acme","x"]}"#,
        ] {
            let (status, body) = post(&f, "/v1/fork", payload).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{payload}: {body}");
        }
    }

    #[tokio::test]
    async fn forking_onto_itself_is_a_conflict_not_a_loop() {
        let f = fixture("fork-self");
        let (status, _) =
            post(&f, "/v1/fork", r#"{"from":["acme","budi"],"to":["acme","budi"]}"#).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
}
