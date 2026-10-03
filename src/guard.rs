//! May this owner touch this path. Resolved on disk first: a symlink defeats a string check.
//! Nothing is cached: a job can plant a symlink between two calls.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use crate::owner::Owner;
use crate::token::Scope;

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
    scope: Scope,
}

impl Guard {
    /// Scope is required: without it `inherit` reaches above a scoped token's prefix (#17).
    pub fn new(root: &Path, owner: &Owner, inherit: bool, scope: &Scope) -> Self {
        Guard {
            root: root.to_path_buf(),
            owner: owner.clone(),
            inherit,
            scope: scope.clone(),
        }
    }

    /// Returns the canonical path that was checked, not the requested spelling (#5).
    /// Not a capability: a component created between this answer and the open is not covered.
    pub fn resolve(&self, rel: &str) -> Result<PathBuf, GuardError> {
        if rel.is_empty() {
            return Err(GuardError::Escapes("<empty>".into()));
        }
        if rel.starts_with('/') || Path::new(rel).is_absolute() {
            return Err(GuardError::Absolute(rel.into()));
        }
        // None of these are path syntax here, so refuse instead of interpreting them.
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
            if !self.scope.allows(a) {
                return Err(GuardError::Escapes(rel.into()));
            }
            // An ancestor lends its own files only, never a directory under them.
            if tail.len() != 1 {
                return Err(GuardError::Escapes(rel.into()));
            }
            (a.dir(&self.root), true)
        };

        let joined = tail.iter().fold(base.clone(), |p, c| p.join(c));
        let real = resolve_existing(&joined).ok_or_else(|| GuardError::Escapes(rel.into()))?;

        let allowed = if ancestor {
            // A file directly in the ancestor's workspace: a directory could be a future owner.
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

/// `..` is a step up the ownership tree, not a traversal, so it is only valid as a prefix.
/// A later `..`, any `.` and an empty component are refused, never normalised.
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

/// A workspace that does not exist yet has no symlinks, so its literal path is safe to check.
fn canonical_or_literal(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// A path that does not exist yet resolves through its real parent, so a job can create a file.
fn resolve_existing(p: &Path) -> Option<PathBuf> {
    if let Ok(real) = std::fs::canonicalize(p) {
        return Some(real);
    }
    let parent = p.parent()?;
    let name = p.file_name()?;
    // A missing parent is refused, not walked up, or made-up directories would reach an ancestor.
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

    /// Self-cleaning temp directory, to avoid a tempfile dependency.
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
        std::os::unix::fs::symlink(
            f.ani.dir(&f.root).join("secret.md"),
            f.budi.dir(&f.root).join("peek"),
        )
        .unwrap();
        std::os::unix::fs::symlink("/etc/passwd", f.budi.dir(&f.root).join("passwd")).unwrap();
        // A symlinked directory, so the escape is in a path segment not the leaf.
        std::os::unix::fs::symlink(f.ani.dir(&f.root), f.budi.dir(&f.root).join("hers")).unwrap();

        let g = Guard::new(&f.root, &f.budi, false, &Scope::Operator);
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
        let g = Guard::new(&f.root, &f.budi, false, &Scope::Operator);
        // The answer is the canonical path that was checked, not the requested spelling (#5).
        let want = fs::canonicalize(f.budi.dir(&f.root))
            .unwrap()
            .join("notes.md");
        assert_eq!(g.resolve("notes.md").unwrap(), want);
        // A file that does not exist yet still resolves, so a job can create it.
        assert!(g.resolve("out.txt").is_ok());
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

        let g = Guard::new(&f.root, &f.budi, true, &Scope::Operator);
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

    /// A scoped token lends the ancestors inside its prefix and none above it (#17).
    #[test]
    fn inherit_stops_at_the_scope() {
        let f = fixture("inherit-scope");
        for a in f.budi.ancestors() {
            let d = a.dir(&f.root);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("team.md"), b"ours").unwrap();
        }
        let legal = Scope::Prefix(f.budi.ancestors()[0].clone());
        let g = Guard::new(&f.root, &f.budi, true, &legal);
        assert!(g.resolve("notes.md").is_ok());
        assert!(
            g.resolve("../team.md").is_ok(),
            "acme/legal is inside the scope"
        );
        assert!(
            g.resolve("../../team.md").is_err(),
            "acme is above the scope"
        );

        let own = Guard::new(&f.root, &f.budi, true, &Scope::Prefix(f.budi.clone()));
        assert!(own.resolve("notes.md").is_ok());
        assert!(
            own.resolve("../team.md").is_err(),
            "the parent is above the scope"
        );
    }

    /// Any directory under an ancestor could become another owner, so the subtree is closed.
    #[test]
    fn inherit_does_not_open_an_ancestors_subtree() {
        let f = fixture("inherit-subtree");
        let legal = f.budi.dir(&f.root).parent().unwrap().to_path_buf();
        fs::create_dir(legal.join("shared")).unwrap();
        fs::write(legal.join("shared/template.md"), b"tmpl").unwrap();

        let g = Guard::new(&f.root, &f.budi, true, &Scope::Operator);
        // The guard cannot tell a plain subdirectory from a sibling workspace, so both are closed.
        assert!(
            g.resolve("../shared/template.md").is_err(),
            "an ancestor subtree was reachable, so a sibling workspace is too"
        );
        assert!(g.resolve("../ani").is_err(), "a sibling directory resolved");
    }

    #[test]
    fn without_inherit_the_parent_is_closed() {
        let f = fixture("noinherit");
        let legal = f.budi.dir(&f.root).parent().unwrap().to_path_buf();
        fs::write(legal.join("team.md"), b"ours").unwrap();
        assert!(Guard::new(&f.root, &f.budi, false, &Scope::Operator)
            .resolve("../team.md")
            .is_err());
    }

    #[test]
    fn an_absolute_path_is_its_own_error_code() {
        let f = fixture("abs");
        let err = Guard::new(&f.root, &f.budi, false, &Scope::Operator)
            .resolve("/etc/passwd")
            .unwrap_err();
        assert!(matches!(err, GuardError::Absolute(_)), "got {err:?}");
    }

    /// A job can plant a symlink between calls, so every call must resolve again.
    #[test]
    fn a_symlink_planted_after_the_guard_was_built_is_still_refused() {
        let f = fixture("planted");
        let g = Guard::new(&f.root, &f.budi, false, &Scope::Operator);

        // A missing path with a real parent resolves, which lets a job create a file.
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

    /// An owner must not read its descendant owners' bytes (#2).
    /// Asserted on content: a parent may create its own `legal`, but never read the child's file.
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
            let g = Guard::new(&f.root, who, true, &Scope::Operator);
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

    /// `..` is only valid as a prefix. Anywhere else it is refused, never normalised.
    #[test]
    fn a_parent_step_is_refused_anywhere_but_the_front() {
        let f = fixture("hops");
        let g = Guard::new(&f.root, &f.budi, true, &Scope::Operator);
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
        let g = Guard::new(&f.root, &f.budi, false, &Scope::Operator);
        assert!(g.resolve("no/such/dir/file.txt").is_err());
    }
}
