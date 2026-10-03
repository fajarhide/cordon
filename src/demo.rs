//! `cordon demo` builds two owners in a temp directory, plants the traps a real
//! job would plant, and runs every escape attempt through the guard directly.
//!
//! It needs no daemon, no Docker and no configuration, so it is the first thing
//! a reader runs and the thing the README quotes. Keeping the claim and the
//! command that prints it in one place is the point: a quoted block cannot
//! drift from the code when the code is what printed it.

use std::io::Write;
use std::path::Path;

use crate::guard::{Guard, GuardError};
use crate::owner::Owner;
use crate::style::Style;

pub fn run(root: &Path, out: &mut impl Write, s: Style) -> std::io::Result<bool> {
    let a = Owner::parse(&["demo".into(), "owner-a".into()]).map_err(std::io::Error::other)?;
    let b = Owner::parse(&["demo".into(), "owner-b".into()]).map_err(std::io::Error::other)?;

    std::fs::create_dir_all(a.dir(root))?;
    std::fs::create_dir_all(b.dir(root))?;
    std::fs::write(b.dir(root).join("secret.md"), b"owner b's private notes")?;
    std::fs::write(a.dir(root).join("notes.md"), b"owner a's own notes")?;
    // The traps: a symlink to the sibling's file, and one to the sibling's
    // directory so the escape hides in a path segment rather than the leaf.
    std::os::unix::fs::symlink(b.dir(root).join("secret.md"), a.dir(root).join("peek"))?;
    std::os::unix::fs::symlink(b.dir(root), a.dir(root).join("theirs"))?;

    writeln!(out, "{}", s.bold("cordon demo"))?;
    writeln!(out, "  root      {}", s.dim(&root.display().to_string()))?;
    writeln!(out, "  owner a   {a}")?;
    writeln!(out, "  owner b   {b}   {}", s.dim("holds secret.md"))?;
    writeln!(
        out,
        "  planted   {}\n",
        s.dim("a/peek and a/theirs, both symlinks into b")
    )?;

    let guard = Guard::new(root, &a, false);

    writeln!(out, "{}", s.bold("owner a reads its own file"))?;
    match guard.resolve("notes.md") {
        Ok(p) => writeln!(
            out,
            "  {}        notes.md -> {}\n",
            s.green("ok"),
            s.dim(&p.display().to_string())
        )?,
        Err(e) => writeln!(
            out,
            "  {}    owner a cannot read its own file: {e}\n",
            s.red("BROKEN")
        )?,
    }

    writeln!(out, "{}", s.bold("owner a cannot read owner b, nine ways"))?;
    let attempts: &[(&str, &str)] = &[
        ("parent then sibling", "../owner-b/secret.md"),
        ("many parents", "../../../../../../etc/passwd"),
        ("absolute path", "/etc/passwd"),
        ("symlink to their file", "peek"),
        ("symlink to their directory", "theirs/secret.md"),
        ("percent encoded", "..%2fowner-b%2fsecret.md"),
        ("backslash separator", "..\\owner-b\\secret.md"),
        ("parent hidden mid path", "sub/../../owner-b/secret.md"),
        ("nul byte smuggled in", "notes.md\0/../../owner-b/secret.md"),
    ];

    let mut refused = 0usize;
    for (name, rel) in attempts {
        match guard.resolve(rel) {
            Err(e) => {
                refused += 1;
                writeln!(
                    out,
                    "  {}   {name:<28} {}",
                    s.green("refused"),
                    s.dim(code_of(&e))
                )?;
            }
            Ok(p) => writeln!(
                out,
                "  {}   {name:<28} {}   {}",
                s.red("ALLOWED"),
                p.display(),
                s.red("<- this is a bug")
            )?,
        }
    }

    let all = refused == attempts.len();
    let tally = format!("{refused} of {} attempts refused", attempts.len());
    writeln!(
        out,
        "\n{}",
        if all { s.green(&tally) } else { s.red(&tally) }
    )?;
    if all {
        writeln!(
            out,
            "\nRun `cordon verify <addr>` to prove the same thing against your own daemon."
        )?;
    } else {
        writeln!(out, "\nSomething is wrong: not every attempt was refused.")?;
    }

    let _ = std::fs::remove_dir_all(root);
    Ok(all)
}

/// The same code strings the HTTP surface returns, so the demo and the API
/// tell one story.
fn code_of(e: &GuardError) -> &'static str {
    match e {
        GuardError::Absolute(_) => "absolute_path_rejected",
        GuardError::Escapes(_) => "path_escapes_workspace",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("cordon-demo-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn the_demo_refuses_every_attempt_and_says_so() {
        let root = tmp("refuse");
        let mut out = Vec::new();
        let all_refused = run(&root, &mut out, Style::plain()).expect("demo must not fail");
        let text = String::from_utf8(out).expect("utf8 output");

        assert!(
            all_refused,
            "the demo reported an attempt that was not refused:\n{text}"
        );
        for want in [
            "owner a cannot read owner b",
            "path_escapes_workspace",
            "absolute_path_rejected",
        ] {
            assert!(
                text.contains(want),
                "demo output is missing {want:?}:\n{text}"
            );
        }
        let refused = text.matches("refused   ").count();
        assert_eq!(refused, 9, "only {refused} refusals in:\n{text}");
        assert!(!text.contains("ALLOWED"), "an attempt was allowed:\n{text}");
    }

    #[test]
    fn the_demo_cleans_up_after_itself() {
        let root = tmp("clean");
        let mut out = Vec::new();
        run(&root, &mut out, Style::plain()).unwrap();
        assert!(!root.exists(), "the demo left {} behind", root.display());
    }
}
