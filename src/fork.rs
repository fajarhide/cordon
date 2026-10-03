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
use axum::{Extension, Json};

use crate::http::ApiJson;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::Config;
use crate::http::ApiError;
use crate::resolve::owner_or_error;
use crate::token::Scope;

#[derive(Deserialize)]
pub struct ForkRequest {
    pub from: Vec<String>,
    pub to: Vec<String>,
}

pub async fn handler(
    State(cfg): State<Arc<Config>>,
    Extension(scope): Extension<Scope>,
    ApiJson(req): ApiJson<ForkRequest>,
) -> Result<Json<Value>, ApiError> {
    // Both ends. A fork across two prefixes is a copy between tenants.
    let from = owner_or_error(&scope, &req.from)?;
    let to = owner_or_error(&scope, &req.to)?;

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
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "fork_failed",
            e.to_string(),
        )
    })?;

    Ok(Json(
        json!({ "forked": to.to_string(), "skipped_links": skipped }),
    ))
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
    use crate::testsupport::{fixture, owner_dir, post};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn copies_a_workspace_to_a_new_owner() {
        let f = fixture("fork-ok");
        let (status, body) = post(
            &f,
            "/v1/fork",
            r#"{"from":["acme","budi"],"to":["acme","copy"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            std::fs::read(owner_dir(&f.cfg.root, &["acme", "copy"]).join("notes.md")).unwrap(),
            b"mine"
        );
        assert!(
            owner_dir(&f.cfg.root, &["acme", "budi"])
                .join("notes.md")
                .exists(),
            "source changed"
        );
    }

    #[tokio::test]
    async fn copies_nested_directories() {
        let f = fixture("fork-nested");
        std::fs::create_dir_all(owner_dir(&f.cfg.root, &["acme", "budi"]).join("a/b")).unwrap();
        std::fs::write(
            owner_dir(&f.cfg.root, &["acme", "budi"]).join("a/b/deep.txt"),
            b"deep",
        )
        .unwrap();
        let (status, body) = post(
            &f,
            "/v1/fork",
            r#"{"from":["acme","budi"],"to":["acme","copy2"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            std::fs::read(owner_dir(&f.cfg.root, &["acme", "copy2"]).join("a/b/deep.txt")).unwrap(),
            b"deep"
        );
    }

    #[tokio::test]
    async fn never_overwrites_an_existing_workspace() {
        let f = fixture("fork-exists");
        let (status, body) = post(
            &f,
            "/v1/fork",
            r#"{"from":["acme","budi"],"to":["acme","ani"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "destination_exists", "{body}");
        assert_eq!(
            std::fs::read(owner_dir(&f.cfg.root, &["acme", "ani"]).join("secret.md")).unwrap(),
            b"hers",
            "the destination's own file was overwritten"
        );
    }

    #[tokio::test]
    async fn a_symlink_is_dropped_rather_than_copied() {
        let f = fixture("fork-symlink");
        std::os::unix::fs::symlink(
            owner_dir(&f.cfg.root, &["acme", "ani"]).join("secret.md"),
            owner_dir(&f.cfg.root, &["acme", "budi"]).join("peek"),
        )
        .unwrap();
        let (status, body) = post(
            &f,
            "/v1/fork",
            r#"{"from":["acme","budi"],"to":["acme","copy3"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !owner_dir(&f.cfg.root, &["acme", "copy3"])
                .join("peek")
                .exists(),
            "a symlink to a sibling's file was carried into the fork"
        );
        assert_eq!(body["skipped_links"], 1, "{body}");
    }

    /// Issue #7, the part of it that was a real amplification. Forking a
    /// parent owner used to carry every descendant owner with it, because
    /// copy_tree recursed over a directory that contained them. The workspace
    /// leaf from #2 means a parent's source is now its own files only.
    #[tokio::test]
    async fn forking_a_parent_does_not_carry_its_descendants() {
        let f = fixture("fork-parent");
        let acme = owner_dir(&f.cfg.root, &["acme"]);
        std::fs::create_dir_all(&acme).unwrap();
        std::fs::write(acme.join("top.md"), b"ACME-TOP").unwrap();

        let (status, body) = post(&f, "/v1/fork", r#"{"from":["acme"],"to":["taker"]}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let taker = owner_dir(&f.cfg.root, &["taker"]);
        assert_eq!(std::fs::read(taker.join("top.md")).unwrap(), b"ACME-TOP");

        // Nothing belonging to budi or ani came along.
        let mut carried = Vec::new();
        for e in walkdir(&taker) {
            let name = e.file_name().unwrap().to_string_lossy().to_string();
            if name == "notes.md" || name == "secret.md" {
                carried.push(e.display().to_string());
            }
        }
        assert!(
            carried.is_empty(),
            "a fork of the parent carried descendant owners' files: {carried:?}"
        );
    }

    fn walkdir(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out
    }

    #[tokio::test]
    async fn a_missing_source_is_404() {
        let f = fixture("fork-nosource");
        let (status, body) = post(
            &f,
            "/v1/fork",
            r#"{"from":["acme","ghost"],"to":["acme","copy4"]}"#,
        )
        .await;
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
        let (status, _) = post(
            &f,
            "/v1/fork",
            r#"{"from":["acme","budi"],"to":["acme","budi"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
}
