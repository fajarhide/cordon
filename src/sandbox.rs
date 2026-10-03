//! The filesystem boundary for the process backend.
//!
//! Issue #1: there was none. `/v1/run` resolved its `collect` patterns through
//! the guard and then handed the job a process whose only restriction was its
//! working directory, so `cat ../other-owner/secret.md` worked and the whole
//! guarantee was prose.
//!
//! The boundary is Landlock, a Linux LSM an unprivileged process uses to
//! restrict its own filesystem access, inherited across `exec`. No root, no
//! namespaces, no container, which is what lets the process backend keep
//! running on a 1 GB VPS and still mean something.
//!
//! The split matters. A ruleset is built in the parent, where allocating is
//! safe, and becomes a file descriptor. The child then needs one syscall on
//! that descriptor, which is all `pre_exec` is allowed to do: allocating after
//! `fork` in a process that has threads can deadlock on the allocator's lock,
//! and a tokio daemon always has threads.
//!
//! Three raw syscalls rather than a crate, because the crate's API wants to
//! build and apply in one place and that is exactly the thing that cannot
//! happen here.

use std::path::{Path, PathBuf};

/// Read and execute are granted on these so the job can start at all: without
/// them `exec` of `/bin/sh` is denied and every job dies before it runs.
///
/// Notably absent: `/tmp` and `/var`. `CORDON_ROOT` usually lives under one of
/// them, and granting either would hand the job every other owner's sandbox
/// through the same hole this module exists to close. The job's `TMPDIR` points
/// at its own workspace instead.
const DEFAULT_SYSTEM_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/dev/null",
    "/dev/urandom",
    "/dev/zero",
];

pub fn system_paths() -> Vec<PathBuf> {
    match std::env::var("CORDON_SYSTEM_PATHS") {
        Ok(v) if !v.is_empty() => v.split(':').map(PathBuf::from).collect(),
        _ => DEFAULT_SYSTEM_PATHS.iter().map(PathBuf::from).collect(),
    }
}

/// A boundary built and ready to apply in a child, or the reason there is none.
pub enum Prepared {
    #[cfg(target_os = "linux")]
    Landlock(linux::Ruleset),
    Unavailable(String),
}

impl Prepared {
    /// Builds the boundary for one workspace. Called in the parent.
    pub fn build(workspace: &Path, system: &[PathBuf]) -> Self {
        #[cfg(target_os = "linux")]
        {
            match linux::Ruleset::build(workspace, system) {
                Ok(r) => Prepared::Landlock(r),
                Err(e) => Prepared::Unavailable(e),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (workspace, system);
            Prepared::Unavailable(
                "landlock is Linux only, so the process backend has no filesystem boundary on this platform"
                    .into(),
            )
        }
    }

    pub fn why_unavailable(&self) -> Option<&str> {
        match self {
            Prepared::Unavailable(e) => Some(e),
            #[cfg(target_os = "linux")]
            Prepared::Landlock(_) => None,
        }
    }

    /// The raw descriptor to apply in the child, if there is one.
    pub fn raw_fd(&self) -> Option<i32> {
        match self {
            #[cfg(target_os = "linux")]
            Prepared::Landlock(r) => Some(r.fd),
            Prepared::Unavailable(_) => None,
        }
    }
}

/// Three raw syscalls and two file descriptors. The crate root denies unsafe,
/// and this module plus the one `pre_exec` block in `exec/process.rs` are the
/// only places it is allowed.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub mod linux {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    // Added together in 5.13, and the same numbers on every architecture.
    const SYS_CREATE_RULESET: libc::c_long = 444;
    const SYS_ADD_RULE: libc::c_long = 445;
    const SYS_RESTRICT_SELF: libc::c_long = 446;

    const CREATE_RULESET_VERSION: u32 = 1;
    const RULE_PATH_BENEATH: libc::c_int = 1;

    /// ABI v1 is bits 0 through 12: execute, write, read, readdir, the remove
    /// pair and the seven make operations. Later ABIs add refer and truncate;
    /// nothing here needs them, and asking for them on an older kernel would
    /// make the ruleset only partially enforceable, which this code treats as
    /// a failure.
    const ACCESS_FS_ALL_V1: u64 = 0x1fff;
    /// Execute, read a file, read a directory.
    const ACCESS_FS_READ: u64 = 0b1101;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    // Packed, as the kernel defines it. A padded version silently misreads the
    // fd and the rule lands on the wrong directory or fails.
    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    /// An owned ruleset descriptor. Closed on drop, so a failed spawn does not
    /// leak one per job.
    pub struct Ruleset {
        pub fd: i32,
    }

    impl Drop for Ruleset {
        fn drop(&mut self) {
            // SAFETY: fd came from a successful landlock_create_ruleset and is
            // closed exactly once.
            unsafe { libc::close(self.fd) };
        }
    }

    impl Ruleset {
        pub fn build(workspace: &Path, system: &[PathBuf]) -> Result<Self, String> {
            let abi = abi_version()?;
            if abi < 1 {
                return Err(format!("landlock reported ABI {abi}, which is unusable"));
            }

            let attr = RulesetAttr {
                handled_access_fs: ACCESS_FS_ALL_V1,
            };
            // SAFETY: attr is a valid initialised struct of the size given.
            let fd = unsafe {
                libc::syscall(
                    SYS_CREATE_RULESET,
                    &attr as *const RulesetAttr,
                    std::mem::size_of::<RulesetAttr>(),
                    0u32,
                )
            };
            if fd < 0 {
                return Err(format!(
                    "landlock_create_ruleset: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let set = Ruleset { fd: fd as i32 };

            set.allow(workspace, ACCESS_FS_ALL_V1)
                .map_err(|e| format!("the workspace rule failed: {e}"))?;
            for p in system {
                // A path that is not on this machine is skipped rather than
                // fatal: /lib64 is absent on plenty of distributions.
                let _ = set.allow(p, ACCESS_FS_READ);
            }
            Ok(set)
        }

        fn allow(&self, path: &Path, access: u64) -> Result<(), String> {
            let c = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| format!("{} contains a NUL", path.display()))?;
            // O_PATH is enough to name a directory for a rule and opens nothing.
            // SAFETY: c is a valid NUL terminated string for the call's lifetime.
            let dir = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if dir < 0 {
                return Err(format!(
                    "open {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            let attr = PathBeneathAttr {
                allowed_access: access,
                parent_fd: dir,
            };
            // SAFETY: attr is initialised and dir is open for the duration.
            let rc = unsafe {
                libc::syscall(
                    SYS_ADD_RULE,
                    self.fd,
                    RULE_PATH_BENEATH,
                    &attr as *const PathBeneathAttr,
                    0u32,
                )
            };
            // SAFETY: dir is open and closed exactly once.
            unsafe { libc::close(dir) };
            if rc != 0 {
                return Err(format!(
                    "landlock_add_rule for {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        }
    }

    fn abi_version() -> Result<i64, String> {
        // SAFETY: the version query takes a null attr and a zero size by
        // contract.
        let v = unsafe {
            libc::syscall(
                SYS_CREATE_RULESET,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        };
        if v < 0 {
            let e = std::io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::ENOSYS) => {
                    "this kernel has no landlock; it needs Linux 5.13 or later".into()
                }
                Some(libc::EOPNOTSUPP) => {
                    "landlock is compiled in but disabled; add lsm=landlock to the kernel command line".into()
                }
                _ => format!("landlock version query: {e}"),
            });
        }
        Ok(v)
    }

    /// Applies a prepared ruleset to the calling process.
    ///
    /// Called from `pre_exec`, so it does nothing but two syscalls: no
    /// allocation, no locks, nothing that can deadlock after a fork.
    ///
    /// # Safety
    /// `fd` must be a live landlock ruleset descriptor.
    pub unsafe fn apply(fd: i32) -> Result<(), std::io::Error> {
        // Landlock requires either this or CAP_SYS_ADMIN.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::syscall(SYS_RESTRICT_SELF, fd, 0u32) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_system_paths_never_include_a_root_a_sandbox_could_live_under() {
        // Under the same lock as the override test below. Without it this read
        // the environment while that test had CORDON_SYSTEM_PATHS set, and
        // failed about one run in six.
        temp_env(&[], || {
            let paths = system_paths();
            for bad in ["/tmp", "/var", "/home", "/", "/root"] {
                assert!(
                    !paths.iter().any(|p| p == Path::new(bad)),
                    "{bad} is in the default allowlist, which would expose CORDON_ROOT"
                );
            }
            for needed in ["/usr", "/bin"] {
                assert!(
                    paths.iter().any(|p| p == Path::new(needed)),
                    "{needed} is missing, so no job could exec anything"
                );
            }
        });
    }

    #[test]
    fn the_allowlist_is_overridable_and_colon_separated() {
        temp_env(&[("CORDON_SYSTEM_PATHS", "/opt:/nix/store")], || {
            assert_eq!(
                system_paths(),
                vec![PathBuf::from("/opt"), PathBuf::from("/nix/store")]
            );
        });
    }

    /// On Linux a boundary must be buildable; anywhere else the absence has to
    /// be reported rather than silently treated as success.
    #[test]
    fn build_either_succeeds_or_explains_itself() {
        let tmp = std::env::temp_dir().join(format!("cordon-sb-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let p = Prepared::build(&tmp, &system_paths());
        if cfg!(target_os = "linux") {
            // A kernel without landlock is a legitimate answer, but it has to
            // come with a reason a human can act on.
            if let Some(why) = p.why_unavailable() {
                assert!(why.contains("landlock"), "unhelpful reason: {why}");
            } else {
                assert!(p.raw_fd().is_some(), "enforced but no descriptor");
            }
        } else {
            assert!(
                p.why_unavailable().is_some(),
                "a boundary appeared on a platform with none"
            );
            assert!(p.raw_fd().is_none());
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn temp_env(pairs: &[(&str, &str)], f: impl FnOnce()) {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _g = LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for (k, v) in pairs {
            std::env::set_var(k, v);
        }
        f();
        for (k, _) in pairs {
            std::env::remove_var(k);
        }
    }
}
