//! Colour for the two commands a human reads: `demo` and `verify`.
//!
//! Bare ANSI codes rather than a crate. Four colours and a reset is not a
//! dependency, and this is the only place in the project that writes any.
//!
//! Colour is decided by the caller and passed in, never sniffed at the point of
//! writing. A test asserting on output must be able to get the plain text, and
//! a tool whose output changes depending on where it is piped is a tool whose
//! output cannot be tested.

#[derive(Clone, Copy)]
pub struct Style {
    on: bool,
}

impl Style {
    /// On when stdout is a terminal and `NO_COLOR` is unset.
    ///
    /// `NO_COLOR` is honoured at any value including empty, per no-color.org,
    /// which is the convention users expect rather than the one that is
    /// convenient to implement.
    pub fn for_stdout() -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        Style {
            on: !no_color && is_tty(),
        }
    }

    /// Test only. A caller that is not a terminal already gets this from
    /// `for_stdout`, so there is no reason to reach for it in the binary.
    #[cfg(test)]
    pub fn plain() -> Self {
        Style { on: false }
    }

    pub fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }

    fn wrap(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

#[allow(unsafe_code)]
fn is_tty() -> bool {
    // SAFETY: isatty takes a file descriptor and reads no memory.
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_adds_nothing_at_all() {
        let s = Style::plain();
        assert_eq!(s.green("ok"), "ok");
        assert_eq!(s.red("FAIL"), "FAIL");
        assert_eq!(s.bold("x"), "x");
        // Which is what lets every output test assert on exact strings.
        assert!(!s.green("ok").contains('\x1b'));
    }

    #[test]
    fn colour_wraps_and_always_resets() {
        let s = Style { on: true };
        assert_eq!(s.green("ok"), "\x1b[32mok\x1b[0m");
        // An unterminated sequence bleeds into whatever the terminal prints
        // next, including the user's prompt.
        for painted in [s.red("a"), s.yellow("b"), s.dim("c"), s.bold("d")] {
            assert!(painted.ends_with("\x1b[0m"), "{painted:?} does not reset");
        }
    }

    #[test]
    fn no_color_wins_even_when_empty() {
        // no-color.org says any value, including empty, disables colour.
        let saved = std::env::var_os("NO_COLOR");
        std::env::set_var("NO_COLOR", "");
        let off = Style::for_stdout();
        match saved {
            Some(v) => std::env::set_var("NO_COLOR", v),
            None => std::env::remove_var("NO_COLOR"),
        }
        assert_eq!(off.green("ok"), "ok");
    }
}
