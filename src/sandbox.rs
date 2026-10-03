//! The process backend's filesystem boundary: Landlock, which needs no root or namespaces (#1).
//! The ruleset is built in the parent: allocating after fork in a threaded process can deadlock.

use std::path::{Path, PathBuf};

/// Read and execute only, without which no job could exec `/bin/sh`.
/// No `/tmp` or `/var`: `CORDON_ROOT` usually lives there, so either would expose every sandbox.
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
    /// Called in the parent, where allocating is safe.
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

    pub fn raw_fd(&self) -> Option<i32> {
        match self {
            #[cfg(target_os = "linux")]
            Prepared::Landlock(r) => Some(r.fd),
            Prepared::Unavailable(_) => None,
        }
    }
}

/// Raw syscalls, not the landlock crate: its API builds and applies in one place, and the
/// child side here must be a bare syscall on a descriptor the parent built.
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

    /// ABI v1 only, bits 0 through 12. Later bits (refer, truncate) are not needed, and an
    /// older kernel could only partially enforce them.
    const ACCESS_FS_ALL_V1: u64 = 0x1fff;
    /// Execute, read a file, read a directory.
    const ACCESS_FS_READ: u64 = 0b1101;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    // Packed, as the kernel defines it. A padded layout silently misreads the fd.
    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    /// Closed on drop, so a failed spawn does not leak a descriptor per job.
    pub struct Ruleset {
        pub fd: i32,
    }

    impl Drop for Ruleset {
        fn drop(&mut self) {
            // SAFETY: fd came from landlock_create_ruleset and is closed exactly once.
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
                // A missing path is skipped, not fatal: /lib64 is absent on many distributions.
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
        // SAFETY: the version query takes a null attr and a zero size by contract.
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

    /// Called from `pre_exec`, so two syscalls only: no allocation or locks after fork.
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
        // Shares the lock with the override test, which sets CORDON_SYSTEM_PATHS.
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

    /// Off Linux the absence must be reported, not silently treated as success.
    #[test]
    fn build_either_succeeds_or_explains_itself() {
        let tmp = std::env::temp_dir().join(format!("cordon-sb-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let p = Prepared::build(&tmp, &system_paths());
        if cfg!(target_os = "linux") {
            // A kernel without landlock is a legitimate answer, but it needs an actionable reason.
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
