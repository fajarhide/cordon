//! Answers one question: may this owner touch this path.
//!
//! Every answer resolves the path on the filesystem first and checks the
//! resolved result. Checking the string instead is defeated by a symlink, so
//! the string is never the subject of the decision.
//!
//! Nothing here is cached. A job can plant a symlink between two calls, so a
//! verdict is only true for the instant it was computed.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use crate::owner::Owner;

#[derive(Debug)]
pub enum GuardError {
    Absolute(String),
    Escapes(String),
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardError::Absolute(p) => write!(f, "absolute path rejected: {p}"),
            GuardError::Escapes(p) => write!(f, "path escapes workspace: {p}"),
        }
    }
}

pub struct Guard {
    root: PathBuf,
    owner: Owner,
    inherit: bool,
}

impl Guard {
    pub fn new(root: &Path, owner: &Owner, inherit: bool) -> Self {
        Guard {
            root: root.to_path_buf(),
            owner: owner.clone(),
            inherit,
        }
    }

    /// Returns the real, canonicalised location of `rel`, or refuses.
    ///
    /// The returned path is the one that was checked, not the one that was
    /// asked for. Handing back the requested spelling lets a caller open a
    /// name whose meaning changed after the answer (issue #5). It is still not
    /// a capability: a component created between this answer and the open is
    /// outside what any path string can promise.
    pub fn resolve(&self, rel: &str) -> Result<PathBuf, GuardError> {
        if rel.is_empty() {
            return Err(GuardError::Escapes("<empty>".into()));
        }
        if rel.starts_with('/') || Path::new(rel).is_absolute() {
            return Err(GuardError::Absolute(rel.into()));
        }
        // None of these are path syntax here. A caller sending one is either
        // confused about the interface or probing it, and both earn a refusal
        // rather than a best effort interpretation.
        if rel.contains('\0') || rel.contains('%') || rel.contains('\\') {
            return Err(GuardError::Escapes(rel.into()));
        }

        let (hops, tail) = split_hops(rel).ok_or_else(|| GuardError::Escapes(rel.into()))?;

        let (base, ancestor) = if hops == 0 {
            (self.owner.dir(&self.root), false)
        } else {
            if !self.inherit {
                return Err(GuardError::Escapes(rel.into()));
            }
            let ancestors = self.owner.ancestors();
            let Some(a) = ancestors.get(hops - 1) else {
                return Err(GuardError::Escapes(rel.into()));
            };
            // An ancestor lends its own files, never a directory under them.
            // One component only, so there is no subtree to walk.
            if tail.len() != 1 {
                return Err(GuardError::Escapes(rel.into()));
            }
            (a.dir(&self.root), true)
        };

        let joined = tail.iter().fold(base.clone(), |p, c| p.join(c));
        let real = resolve_existing(&joined).ok_or_else(|| GuardError::Escapes(rel.into()))?;

        let allowed = if ancestor {
            // Directly inside the ancestor's own workspace, and a file. A
            // directory there could be anything, including a future owner.
            real.parent() == Some(canonical_or_literal(&base).as_path()) && !real.is_dir()
        } else {
            let own = canonical_or_literal(&base);
            real == own || real.starts_with(&own)
        };
        if !allowed {
            return Err(GuardError::Escapes(rel.into()));
        }
        Ok(real)
    }
}

/// Splits a request path into ancestor hops and the remaining components.
///
/// `..` is a step up the ownership tree, not a filesystem traversal, so it is
/// only meaningful as a prefix. A `..` after any other component, a `.`
/// anywhere, and an empty component are all refused rather than normalised,
/// which removes the entire class of hidden-parent tricks instead of trying to
/// out-guess them.
fn split_hops(rel: &str) -> Option<(usize, Vec<&str>)> {
    let mut hops = 0usize;
    let mut tail: Vec<&str> = Vec::new();
    for c in rel.split('/') {
        match c {
            ".." if tail.is_empty() => hops += 1,
            ".." | "." | "" => return None,
            other => tail.push(other),
        }
    }
    if tail.is_empty() {
        return None;
    }
    Some((hops, tail))
}

/// Canonicalises if the directory is there, falls back to the literal path if
/// it is not. A workspace that does not exist yet has no symlinks to resolve,
/// and the containment check still holds against the literal form.
fn canonical_or_literal(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Resolves as far as the filesystem allows. A path that does not exist yet
/// still has to have a real, canonicalised parent inside the workspace, which
/// is what lets a job create a file without opening a hole.
fn resolve_existing(p: &Path) -> Option<PathBuf> {
    if let Ok(real) = std::fs::canonicalize(p) {
        return Some(real);
    }
    let parent = p.parent()?;
    let name = p.file_name()?;
    // A trailing `..` or `.` has no usable file name, and a parent that is
    // itself missing is refused rather than walked further up, so a job cannot
    // reach an ancestor by naming enough nonexistent directories.
    if matches!(
        Path::new(name).components().next(),
        Some(Component::ParentDir) | Some(Component::CurDir)
    ) {
        return None;
    }
    let real_parent = std::fs::canonicalize(parent).ok()?;
    Some(real_parent.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A temp directory that cleans itself up, so the suite does not take a
    /// dependency on tempfile for four lines of work.
    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!("cordon-guard-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).expect("temp root");
            TempRoot(p)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        _tmp: TempRoot,
        root: PathBuf,
        budi: Owner,
        ani: Owner,
    }

    fn fixture(tag: &str) -> Fixture {
        let tmp = TempRoot::new(tag);
        let root = tmp.0.clone();
        let budi = Owner::parse(&["acme".into(), "legal".into(), "budi".into()]).unwrap();
        let ani = Owner::parse(&["acme".into(), "legal".into(), "ani".into()]).unwrap();
        for o in [&budi, &ani] {
            fs::create_dir_all(o.dir(&root)).unwrap();
        }
        fs::write(ani.dir(&root).join("secret.md"), b"hers").unwrap();
        fs::write(budi.dir(&root).join("notes.md"), b"mine").unwrap();
        Fixture {
            _tmp: tmp,
            root,
            budi,
            ani,
        }
    }

    #[test]
    fn refuses_every_way_out_of_the_workspace() {
        let f = fixture("escape");
        // A symlink inside Budi's workspace pointing at Ani's file.
        std::os::unix::fs::symlink(
            f.ani.dir(&f.root).join("secret.md"),
            f.budi.dir(&f.root).join("peek"),
        )
        .unwrap();
        // A symlink pointing clean out of the root.
        std::os::unix::fs::symlink("/etc/passwd", f.budi.dir(&f.root).join("passwd")).unwrap();
        // A symlinked directory, so the escape is in a path segment not the leaf.
        std::os::unix::fs::symlink(f.ani.dir(&f.root), f.budi.dir(&f.root).join("hers")).unwrap();

        let g = Guard::new(&f.root, &f.budi, false);
        let attacks: &[(&str, &str)] = &[
            ("parent then sibling", "../ani/secret.md"),
            ("many parents", "../../../../../../etc/passwd"),
            ("absolute", "/etc/passwd"),
            ("symlink to a sibling file", "peek"),
            ("symlink out of the root", "passwd"),
            ("symlinked directory segment", "hers/secret.md"),
            ("percent encoded separator", "..%2fani%2fsecret.md"),
            ("dot segment then parent", "./../ani/secret.md"),
            ("parent hidden mid path", "sub/../../ani/secret.md"),
            ("empty", ""),
            ("just a parent", ".."),
            ("nul byte", "notes.md\0/../../ani/secret.md"),
            ("backslash as a separator", "..\\ani\\secret.md"),
        ];
        for (name, rel) in attacks {
            assert!(
                g.resolve(rel).is_err(),
                "{name}: resolve({rel:?}) was allowed"
            );
        }
    }

    #[test]
    fn allows_the_owners_own_files() {
        let f = fixture("own");
        let g = Guard::new(&f.root, &f.budi, false);
        // Issue #5: the answer is the canonicalised path that was checked, not
        // the spelling that was asked for.
        let want = fs::canonicalize(f.budi.dir(&f.root))
            .unwrap()
            .join("notes.md");
        assert_eq!(g.resolve("notes.md").unwrap(), want);
        // A file that does not exist yet still resolves, so a job can create it.
        assert!(g.resolve("out.txt").is_ok());
        // A nested path under a real directory resolves.
        fs::create_dir(f.budi.dir(&f.root).join("sub")).unwrap();
        assert!(g.resolve("sub/deep.txt").is_ok());
    }

    #[test]
    fn inherit_reaches_an_ancestor_and_still_refuses_a_sibling() {
        let f = fixture("inherit");
        for a in f.budi.ancestors() {
            let d = a.dir(&f.root);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("team.md"), b"ours").unwrap();
        }

        let g = Guard::new(&f.root, &f.budi, true);
        // `..` is one step up the ownership tree, not a directory traversal.
        assert!(
            g.resolve("../team.md").is_ok(),
            "inherit must reach the parent"
        );
        assert!(
            g.resolve("../../team.md").is_ok(),
            "inherit must reach the grandparent"
        );
        assert!(
            g.resolve("../../../team.md").is_err(),
            "there is no third ancestor to reach"
        );
        assert!(
            g.resolve("../ani/secret.md").is_err(),
            "inherit must never reach a sibling"
        );
    }

    /// An ancestor grant stops at the ancestor's own files. Every directory
    /// under an ancestor is, or could become, another owner, so the subtree is
    /// closed rather than filtered.
    #[test]
    fn inherit_does_not_open_an_ancestors_subtree() {
        let f = fixture("inherit-subtree");
        let legal = f.budi.dir(&f.root).parent().unwrap().to_path_buf();
        fs::create_dir(legal.join("shared")).unwrap();
        fs::write(legal.join("shared/template.md"), b"tmpl").unwrap();

        let g = Guard::new(&f.root, &f.budi, true);
        // A plain subdirectory of the ancestor is closed, the same as a
        // sibling workspace, because the guard cannot tell them apart.
        assert!(
            g.resolve("../shared/template.md").is_err(),
            "an ancestor subtree was reachable, so a sibling workspace is too"
        );
        // The sibling directory itself is not resolvable either.
        assert!(g.resolve("../ani").is_err(), "a sibling directory resolved");
    }

    #[test]
    fn without_inherit_the_parent_is_closed() {
        let f = fixture("noinherit");
        let legal = f.budi.dir(&f.root).parent().unwrap().to_path_buf();
        fs::write(legal.join("team.md"), b"ours").unwrap();
        assert!(Guard::new(&f.root, &f.budi, false)
            .resolve("../team.md")
            .is_err());
    }

    #[test]
    fn an_absolute_path_is_its_own_error_code() {
        let f = fixture("abs");
        let err = Guard::new(&f.root, &f.budi, false)
            .resolve("/etc/passwd")
            .unwrap_err();
        assert!(matches!(err, GuardError::Absolute(_)), "got {err:?}");
    }

    /// Review Focus 2. The guard answers at call time. A job can write a
    /// symlink and read through it on a later call, so a verdict must never be
    /// cached and the resolution must happen again every time.
    #[test]
    fn a_symlink_planted_after_the_guard_was_built_is_still_refused() {
        let f = fixture("planted");
        let g = Guard::new(&f.root, &f.budi, false);

        // First call: the path does not exist, but its parent does, so it
        // resolves. This is what lets a job create a new file.
        assert!(g.resolve("later").is_ok());

        // The job now plants a symlink at exactly that name.
        std::os::unix::fs::symlink(f.ani.dir(&f.root), f.budi.dir(&f.root).join("later")).unwrap();

        assert!(
            g.resolve("later/secret.md").is_err(),
            "the guard followed a symlink planted after it was built"
        );
        assert!(
            g.resolve("later").is_err(),
            "the planted symlink itself is still reachable"
        );
    }

    /// Issue #2. An owner must not read its descendant owners' bytes.
    ///
    /// Asserted on content, not on an error. A parent asking for `legal` gets a
    /// creatable path inside its own workspace, which is legitimate; what must
    /// never happen is that path handing back the child's file.
    #[test]
    fn a_parent_owner_cannot_read_its_childrens_bytes() {
        let f = fixture("parent-child");
        let acme = Owner::parse(&["acme".into()]).unwrap();
        let legal = Owner::parse(&["acme".into(), "legal".into()]).unwrap();
        for o in [&acme, &legal] {
            fs::create_dir_all(o.dir(&f.root)).unwrap();
        }
        fs::write(legal.dir(&f.root).join("team.md"), b"LEGAL-SECRET").unwrap();
        fs::write(f.budi.dir(&f.root).join("notes.md"), b"BUDI-SECRET").unwrap();

        // inherit on, which is the most permissive setting there is.
        let cases: [(&Owner, &[&str]); 2] = [
            (
                &acme,
                &[
                    "legal/budi/notes.md",
                    "legal/team.md",
                    "legal/.workspace/team.md",
                    "legal/budi/.workspace/notes.md",
                    "budi/notes.md",
                ],
            ),
            (
                &legal,
                &["budi/notes.md", "budi/.workspace/notes.md", "ani/secret.md"],
            ),
        ];
        for (who, attempts) in cases {
            let g = Guard::new(&f.root, who, true);
            for rel in attempts {
                match g.resolve(rel) {
                    Err(_) => {}
                    Ok(p) => {
                        let body = fs::read(&p).unwrap_or_default();
                        assert!(
                            body.is_empty(),
                            "owner {who} read {rel:?} and got {:?}",
                            String::from_utf8_lossy(&body)
                        );
                    }
                }
            }
        }
    }

    /// `..` is an ownership step, so it only means anything as a prefix.
    /// Everything else is refused rather than normalised, which removes the
    /// hidden-parent class instead of trying to out-guess it.
    #[test]
    fn a_parent_step_is_refused_anywhere_but_the_front() {
        let f = fixture("hops");
        let g = Guard::new(&f.root, &f.budi, true);
        for rel in [
            "sub/../notes.md",
            "notes.md/..",
            "./notes.md",
            "sub/./notes.md",
            "a//b",
            "..",
            "../..",
        ] {
            assert!(g.resolve(rel).is_err(), "resolve({rel:?}) was allowed");
        }
    }

    #[test]
    fn a_missing_parent_is_refused_rather_than_guessed() {
        let f = fixture("missing");
        let g = Guard::new(&f.root, &f.budi, false);
        assert!(g.resolve("no/such/dir/file.txt").is_err());
    }
}
