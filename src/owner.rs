//! Turns a caller supplied identifier into a workspace location.
//!
//! A segment is validated, never cleaned. Silently rewriting an identifier is
//! how two different owners end up sharing one directory, which is the exact
//! failure this whole program exists to prevent.

use std::fmt;
use std::path::{Path, PathBuf};

const MAX_SEGMENTS: usize = 8;
const MAX_SEGMENT_LEN: usize = 128;

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
        Ok(Owner { segments: segments.to_vec() })
    }

    pub fn dir(&self, root: &Path) -> PathBuf {
        let mut p = root.join("owners");
        for s in &self.segments {
            p.push(s);
        }
        p
    }

    /// Nearest ancestor first, so a caller can take the most specific match
    /// without sorting.
    pub fn ancestors(&self) -> Vec<Owner> {
        (1..self.segments.len())
            .rev()
            .map(|i| Owner { segments: self.segments[..i].to_vec() })
            .collect()
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.segments.join("/"))
    }
}

/// An allowlist, not a blocklist. A blocklist of dangerous characters is a list
/// someone eventually finds a gap in; an allowlist of the characters real
/// identifiers use has no gap to find.
///
/// ASCII only, on purpose. A tenant id, a user id or a team slug is machine
/// generated and ASCII in every system this integrates with. Allowing Unicode
/// means deciding what `cafe\u{0301}` and `caf\u{00e9}` mean, and on a
/// normalising case-insensitive filesystem that decision is not ours to make:
/// one spelling would become two workspaces on Linux and one on macOS. A
/// caller holding a Unicode display name hashes or slugifies it first.
fn validate(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("owner segment is empty".into());
    }
    if s.len() > MAX_SEGMENT_LEN {
        return Err(format!("owner segment is longer than {MAX_SEGMENT_LEN} bytes"));
    }
    if s.starts_with('.') {
        return Err(format!("owner segment {s:?} starts with a dot"));
    }
    if let Some(bad) = s.chars().find(|c| !is_allowed(*c)) {
        return Err(format!(
            "owner segment {s:?} contains {bad:?}; allowed: a-z A-Z 0-9 - _ ."
        ));
    }
    Ok(())
}

fn is_allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
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
            PathBuf::from("/var/lib/cordon/owners/acme/legal/budi")
        );
        assert_eq!(o.to_string(), "acme/legal/budi");
    }

    #[test]
    fn accepts_the_characters_identifiers_actually_use() {
        for s in [
            "acme",
            "ACME",
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
        assert!(owner(&["acme", &"a".repeat(129)]).is_err());
        owner(&["acme", &"a".repeat(128)]).expect("128 is the cap, not over it");
    }

    #[test]
    fn refuses_more_segments_than_the_cap() {
        owner(&vec!["a"; 8]).expect("8 is the cap");
        assert!(owner(&vec!["a"; 9]).is_err(), "9 segments was accepted");
    }

    /// Review Focus 1. Two spellings of one word must never become two
    /// workspaces, and must never collapse into one on a filesystem that
    /// normalises for us. Refusing every non-ASCII byte removes the
    /// equivalence class rather than picking a winner inside it, and takes
    /// homoglyph confusion with it.
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
    }

    #[test]
    fn a_root_owner_has_no_ancestors() {
        assert!(owner(&["acme"]).unwrap().ancestors().is_empty());
    }
}
