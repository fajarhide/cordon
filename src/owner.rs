//! Turns a caller supplied identifier into a workspace location.
//! Segments are validated, never cleaned: rewriting one lets two owners share a directory.

use std::fmt;
use std::path::{Path, PathBuf};

const MAX_SEGMENTS: usize = 8;
/// Fits a UUID (36). At 128, eight segments overran PATH_MAX on a deep root (#10).
const MAX_SEGMENT_LEN: usize = 64;

/// An owner's files live in this leaf, so its directory never contains a child owner's files.
/// `validate` refuses a leading dot, so the leaf cannot collide with a child owner's name.
pub const WORKSPACE_LEAF: &str = ".workspace";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    segments: Vec<String>,
}

impl Owner {
    pub fn parse(segments: &[String]) -> Result<Self, String> {
        if segments.is_empty() {
            return Err("owner must have at least one segment".into());
        }
        if segments.len() > MAX_SEGMENTS {
            return Err(format!(
                "owner has {} segments, the limit is {MAX_SEGMENTS}",
                segments.len()
            ));
        }
        for s in segments {
            validate(s)?;
        }
        Ok(Owner {
            segments: segments.to_vec(),
        })
    }

    /// Where this owner's own files live.
    pub fn dir(&self, root: &Path) -> PathBuf {
        self.node(root).join(WORKSPACE_LEAF)
    }

    /// Holds the workspace leaf and the child nodes. Nothing may be resolved against it.
    fn node(&self, root: &Path) -> PathBuf {
        let mut p = root.join("owners");
        for s in &self.segments {
            p.push(s);
        }
        p
    }

    /// Compared by segment: `acme2` is not inside `acme`, which a string prefix would claim.
    pub fn within(&self, prefix: &Owner) -> bool {
        self.segments.starts_with(&prefix.segments)
    }

    /// Nearest ancestor first, so a caller can take the most specific match without sorting.
    pub fn ancestors(&self) -> Vec<Owner> {
        (1..self.segments.len())
            .rev()
            .map(|i| Owner {
                segments: self.segments[..i].to_vec(),
            })
            .collect()
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.segments.join("/"))
    }
}

/// An allowlist: a blocklist of dangerous characters is a list someone finds a gap in.
/// Lowercase ASCII only: APFS, SMB and NFS fold case and Unicode forms that ext4 keeps apart.
fn validate(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("owner segment is empty".into());
    }
    if s.len() > MAX_SEGMENT_LEN {
        return Err(format!(
            "owner segment is longer than {MAX_SEGMENT_LEN} bytes"
        ));
    }
    if s.starts_with('.') {
        return Err(format!("owner segment {s:?} starts with a dot"));
    }
    if let Some(bad) = s.chars().find(|c| !is_allowed(*c)) {
        return Err(format!(
            "owner segment {s:?} contains {bad:?}; allowed: a-z 0-9 - _ ."
        ));
    }
    Ok(())
}

fn is_allowed(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(parts: &[&str]) -> Result<Owner, String> {
        Owner::parse(&parts.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn maps_segments_to_a_directory_under_owners() {
        let o = owner(&["acme", "legal", "budi"]).expect("valid owner");
        assert_eq!(
            o.dir(Path::new("/var/lib/cordon")),
            PathBuf::from("/var/lib/cordon/owners/acme/legal/budi/.workspace")
        );
        assert_eq!(o.to_string(), "acme/legal/budi");
    }

    #[test]
    fn accepts_the_characters_identifiers_actually_use() {
        for s in [
            "acme",
            "acme-corp",
            "acme_corp",
            "team.legal",
            "u123",
            "550e8400-e29b-41d4-a716-446655440000",
        ] {
            owner(&[s]).unwrap_or_else(|e| panic!("{s:?} should be valid: {e}"));
        }
    }

    #[test]
    fn refuses_everything_that_could_move_a_workspace() {
        let cases: &[(&str, &[&str])] = &[
            ("empty list", &[]),
            ("empty segment", &["acme", ""]),
            ("dot", &["acme", "."]),
            ("dotdot", &["acme", ".."]),
            ("forward slash", &["acme", "legal/budi"]),
            ("backslash", &["acme", "legal\\budi"]),
            ("nul", &["acme", "bu\0di"]),
            ("leading dot", &["acme", ".hidden"]),
            ("space", &["acme", "budi santoso"]),
            ("colon", &["acme", "budi:1"]),
            ("newline", &["acme", "budi\nani"]),
            ("tilde", &["acme", "~root"]),
            ("percent", &["acme", "budi%2e%2e"]),
        ];
        for (name, parts) in cases {
            assert!(owner(parts).is_err(), "{name}: {parts:?} was accepted");
        }
    }

    #[test]
    fn refuses_a_segment_over_the_length_cap() {
        assert!(owner(&["acme", &"a".repeat(65)]).is_err());
        owner(&["acme", &"a".repeat(64)]).expect("64 is the cap, not over it");
    }

    /// A case insensitive filesystem would give `BUDI` and `budi` one directory (#4).
    #[test]
    fn refuses_uppercase_so_two_spellings_cannot_share_a_directory() {
        for s in ["ACME", "Budi", "budI", "acme-Corp"] {
            assert!(owner(&["acme", s]).is_err(), "{s:?} was accepted");
        }
        owner(&["acme", "budi"]).expect("the lowercase spelling stays valid");
    }

    /// An owner's leaf cannot contain a child owner's leaf (#2).
    #[test]
    fn an_owners_files_never_contain_a_child_owners_files() {
        let parent = owner(&["acme"]).unwrap();
        let child = owner(&["acme", "legal", "budi"]).unwrap();
        let r = Path::new("/r");
        assert!(
            !child.dir(r).starts_with(parent.dir(r)),
            "{} contains {}",
            parent.dir(r).display(),
            child.dir(r).display()
        );
        // And the leaf cannot be spelled as a segment, so nothing can collide.
        assert!(owner(&["acme", WORKSPACE_LEAF]).is_err());
    }

    #[test]
    fn refuses_more_segments_than_the_cap() {
        owner(&["a"; 8]).expect("8 is the cap");
        assert!(owner(&["a"; 9]).is_err(), "9 segments was accepted");
    }

    /// Refusing all non-ASCII removes normalisation and homoglyph collisions outright.
    #[test]
    fn refuses_every_non_ascii_spelling() {
        let cases: &[(&str, &str)] = &[
            ("NFD cafe", "cafe\u{0301}"),
            ("NFC cafe", "caf\u{00e9}"),
            ("CJK", "\u{65e5}\u{672c}"),
            ("Cyrillic a that reads as Latin a", "\u{0430}cme"),
            ("zero width space", "ac\u{200b}me"),
        ];
        for (name, s) in cases {
            assert!(owner(&["acme", s]).is_err(), "{name}: {s:?} was accepted");
        }
    }

    #[test]
    fn ancestors_run_from_nearest_to_root() {
        let o = owner(&["acme", "legal", "budi"]).unwrap();
        let got: Vec<String> = o.ancestors().iter().map(ToString::to_string).collect();
        assert_eq!(got, vec!["acme/legal", "acme"]);
        let r = Path::new("/r");
        assert_eq!(
            o.ancestors()[0].dir(r),
            PathBuf::from("/r/owners/acme/legal/.workspace")
        );
    }

    #[test]
    fn within_compares_segments_not_strings() {
        let acme = owner(&["acme"]).unwrap();
        let legal = owner(&["acme", "legal"]).unwrap();
        assert!(legal.within(&acme));
        assert!(acme.within(&acme), "an owner is inside its own prefix");
        assert!(!acme.within(&legal), "a parent is not inside its child");
        assert!(!owner(&["acme2"]).unwrap().within(&acme));
        assert!(!owner(&["acme", "legal2"]).unwrap().within(&legal));
        assert!(!owner(&["acme", "lega"]).unwrap().within(&legal));
    }

    #[test]
    fn a_root_owner_has_no_ancestors() {
        assert!(owner(&["acme"]).unwrap().ancestors().is_empty());
    }
}
