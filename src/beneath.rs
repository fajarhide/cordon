//! File access beneath a workspace by descriptor, never by path string. Every component is opened
//! with O_NOFOLLOW from the one before, so a symlink a job plants before or during a call is refused
//! by the kernel. `Guard` checks a path and then opens it, which leaves a gap a write must not have.

// The whole module is the *at() family through libc; std has no openat or O_NOFOLLOW walk.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::sha256::Sha256;

/// Temporary files a write leaves while it runs; a listing never shows them.
pub const TMP_PREFIX: &str = ".cordon-put-";
/// Deeper than any real project, shallow enough that a planted tree cannot exhaust the stack.
const MAX_DEPTH: usize = 64;

fn cstr(s: &[u8]) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

fn openat(
    dir: &OwnedFd,
    name: &str,
    flags: libc::c_int,
    mode: libc::c_uint,
) -> io::Result<OwnedFd> {
    let c = cstr(name.as_bytes())?;
    let flags = flags | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: dir is an open descriptor and c a NUL terminated string, both alive for the call.
    let fd = check(unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, mode) })?;
    // SAFETY: fd was just returned open by openat and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stat_at(dir: &OwnedFd, name: &str) -> io::Result<libc::stat> {
    let c = cstr(name.as_bytes())?;
    // SAFETY: stat is plain old data, so all zero bytes are a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: dir is open, c is NUL terminated and st is a valid place to write.
    check(unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    Ok(st)
}

fn is(st: &libc::stat, kind: libc::mode_t) -> bool {
    st.st_mode & libc::S_IFMT == kind
}

/// The workspace itself. cordon made this path, but the leaf is still opened without following.
pub fn root(dir: &Path) -> io::Result<OwnedFd> {
    let c = cstr(dir.as_os_str().as_bytes())?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: c is a NUL terminated string alive for the call.
    let fd = check(unsafe { libc::open(c.as_ptr(), flags) })?;
    // SAFETY: fd was just returned open by open and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Walks `parts` as directories. A symlink anywhere answers ELOOP; `create` makes missing ones.
pub fn dir(root: OwnedFd, parts: &[&str], create: bool) -> io::Result<OwnedFd> {
    let mut at = root;
    for p in parts {
        let flags = libc::O_RDONLY | libc::O_DIRECTORY;
        at = match openat(&at, p, flags, 0) {
            Err(e) if create && e.raw_os_error() == Some(libc::ENOENT) => {
                let c = cstr(p.as_bytes())?;
                // EEXIST means another call made it first; the open below still refuses a symlink.
                // SAFETY: at is open and c is NUL terminated for the call.
                if unsafe { libc::mkdirat(at.as_raw_fd(), c.as_ptr(), 0o755) } < 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() != Some(libc::EEXIST) {
                        return Err(e);
                    }
                }
                openat(&at, p, flags, 0)?
            }
            // Linux answers ENOTDIR for a symlink opened with O_DIRECTORY|O_NOFOLLOW. The kernel already
            // refused it; this only names the refusal, so a caller sees an escape and not a missing file.
            Err(e)
                if e.raw_os_error() == Some(libc::ENOTDIR)
                    && stat_at(&at, p).is_ok_and(|st| is(&st, libc::S_IFLNK)) =>
            {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            other => other?,
        };
    }
    Ok(at)
}

/// A regular file for reading. O_NONBLOCK so a FIFO answers instead of hanging the call.
pub fn open_file(dir: &OwnedFd, name: &str) -> io::Result<File> {
    let fd = openat(dir, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EISDIR));
    }
    Ok(file)
}

pub fn hash_reader(mut r: impl Read) -> io::Result<String> {
    let mut s = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(s.hex());
        }
        s.update(&buf[..n]);
    }
}

/// The current hash of `name`, or None when it does not exist.
pub fn current_hash(dir: &OwnedFd, name: &str) -> io::Result<Option<String>> {
    match open_file(dir, name) {
        Ok(f) => Ok(Some(hash_reader(f)?)),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Size of a regular file, None when absent. Anything else is refused, never replaced.
pub fn existing_size(dir: &OwnedFd, name: &str) -> io::Result<Option<u64>> {
    match stat_at(dir, name) {
        Ok(st) if is(&st, libc::S_IFREG) => Ok(Some(st.st_size as u64)),
        Ok(st) if is(&st, libc::S_IFLNK) => Err(io::Error::from_raw_os_error(libc::ELOOP)),
        Ok(_) => Err(io::Error::from_raw_os_error(libc::EISDIR)),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Written to a temporary file in the same directory and renamed over the target, so a reader
/// sees the old bytes or the new ones. rename replaces a symlink itself and never follows it.
pub fn write(dir: &OwnedFd, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = format!("{TMP_PREFIX}{}", crate::artifact::opaque("")?);
    let fd = openat(
        dir,
        &tmp,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o644,
    )?;
    let mut f = File::from(fd);
    let done = f.write_all(bytes).and_then(|_| f.sync_all()).and_then(|_| {
        let (from, to) = (cstr(tmp.as_bytes())?, cstr(name.as_bytes())?);
        let d = dir.as_raw_fd();
        // SAFETY: d is open and both names are NUL terminated for the call.
        check(unsafe { libc::renameat(d, from.as_ptr(), d, to.as_ptr()) }).map(|_| ())
    });
    if done.is_err() {
        let _ = unlink(dir, &tmp);
    }
    done
}

pub fn unlink(dir: &OwnedFd, name: &str) -> io::Result<()> {
    let c = cstr(name.as_bytes())?;
    // SAFETY: dir is open and c is NUL terminated for the call.
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) }).map(|_| ())
}

pub struct Entry {
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
}

/// Regular files under `dir`, recursively, sorted by path. Symlinks, devices and FIFOs are skipped
/// and never followed. Stops at `cap` entries and says so.
pub fn list(dir: &OwnedFd, hash: bool, cap: usize) -> io::Result<(Vec<Entry>, bool)> {
    let mut out = Vec::new();
    let truncated = walk(dir, "", hash, cap, 0, &mut out)?;
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((out, truncated))
}

fn walk(
    dir: &OwnedFd,
    prefix: &str,
    hash: bool,
    cap: usize,
    depth: usize,
    out: &mut Vec<Entry>,
) -> io::Result<bool> {
    if depth > MAX_DEPTH {
        return Ok(true);
    }
    for name in names(dir)? {
        if out.len() >= cap {
            return Ok(true);
        }
        if name.starts_with(TMP_PREFIX) {
            continue;
        }
        let Ok(st) = stat_at(dir, &name) else {
            continue;
        };
        let path = format!("{prefix}{name}");
        if is(&st, libc::S_IFDIR) {
            // Swapped for a symlink since the stat: the open refuses it and the entry is skipped.
            let Ok(sub) = openat(dir, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) else {
                continue;
            };
            if walk(&sub, &format!("{path}/"), hash, cap, depth + 1, out)? {
                return Ok(true);
            }
        } else if is(&st, libc::S_IFREG) {
            let sha256 = if hash {
                match open_file(dir, &name) {
                    Ok(f) => Some(hash_reader(f)?),
                    Err(_) => continue,
                }
            } else {
                None
            };
            out.push(Entry {
                path,
                size: st.st_size as u64,
                sha256,
            });
        }
    }
    Ok(false)
}

/// Names in a directory, read through a duplicate descriptor that closedir then owns.
/// A name that is not UTF-8 is skipped: the API speaks JSON strings.
fn names(dir: &OwnedFd) -> io::Result<Vec<String>> {
    // SAFETY: dir is an open descriptor.
    let dup = check(unsafe { libc::dup(dir.as_raw_fd()) })?;
    // SAFETY: dup is a fresh descriptor of a directory; on success closedir below owns it.
    let dirp = unsafe { libc::fdopendir(dup) };
    if dirp.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so dup is still ours to close, once.
        unsafe { libc::close(dup) };
        return Err(e);
    }
    // A duplicate shares its offset with the original, so a second listing must start over.
    // SAFETY: dirp is a live DIR from fdopendir.
    unsafe { libc::rewinddir(dirp) };
    let mut out = Vec::new();
    loop {
        // SAFETY: dirp is a live DIR; the entry is read before the next readdir call.
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        // SAFETY: ent is non null and d_name is NUL terminated by the kernel.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        match name.to_str() {
            Ok(".") | Ok("..") | Err(_) => {}
            Ok(n) => out.push(n.to_string()),
        }
    }
    // SAFETY: dirp is live and closed exactly once, which also closes dup.
    unsafe { libc::closedir(dirp) };
    Ok(out)
}

/// Bytes held by every regular file in the workspace, for the quota.
pub fn usage(dir: &OwnedFd) -> io::Result<u64> {
    let (entries, _) = list(dir, false, usize::MAX)?;
    Ok(entries.iter().map(|e| e.size).sum())
}
