//! Force-delete core: permanent, recursive, attribute-clearing, link-safe.

use std::fmt;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FindClose, FindFirstFileW, SetFileAttributesW, WIN32_FIND_DATAW,
};
use windows::core::PCWSTR;

const ATTR_READONLY: u32 = 0x1;
const ATTR_HIDDEN: u32 = 0x2;
const ATTR_SYSTEM: u32 = 0x4;
const ATTR_DIRECTORY: u32 = 0x10;
const ATTR_REPARSE_POINT: u32 = 0x400;

const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_LOCK_VIOLATION: i32 = 33;
const ERROR_DIR_NOT_EMPTY: i32 = 145;

/// A single item that could not be deleted.
#[derive(Debug)]
pub struct Failure {
    pub path: PathBuf,
    pub error: io::Error,
}

impl Failure {
    /// True when another process holds the item open (sharing/lock violation).
    pub fn is_locked(&self) -> bool {
        matches!(
            self.error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
        )
    }

    /// True when the OS refused access (OS error 5).
    pub fn is_access_denied(&self) -> bool {
        self.error.raw_os_error() == Some(ERROR_ACCESS_DENIED)
    }
}

#[derive(Debug)]
pub enum DeleteError {
    /// The target does not exist.
    NotFound(PathBuf),
    /// Some items could not be deleted; everything else was.
    Partial(Vec<Failure>),
}

impl fmt::Display for DeleteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeleteError::NotFound(p) => write!(f, "Not found: {}", p.display()),
            DeleteError::Partial(failures) => {
                write!(f, "Could not delete {} item(s):", failures.len())?;
                for fail in failures {
                    write!(f, "\n{} ({})", fail.path.display(), fail.error)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for DeleteError {}

/// Absolute `\\?\` form of `path`. The final component is deliberately not
/// resolved, so a link given as the target is deleted itself, never its target.
fn resolve_target(path: &Path) -> io::Result<PathBuf> {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            Ok(fs::canonicalize(parent)?.join(name))
        }
        _ => fs::canonicalize(path),
    }
}

/// Permanently deletes `path` (file or folder) recursively. Does not check
/// protection; the caller decides whether that is allowed.
pub fn force_delete(path: &Path) -> Result<(), DeleteError> {
    let target = match resolve_target(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(DeleteError::NotFound(path.to_path_buf()));
        }
        Err(error) => {
            return Err(DeleteError::Partial(vec![Failure {
                path: path.to_path_buf(),
                error,
            }]));
        }
    };
    if let Err(e) = fs::symlink_metadata(&target)
        && e.kind() == io::ErrorKind::NotFound
    {
        return Err(DeleteError::NotFound(path.to_path_buf()));
    }

    let mut failures = Vec::new();
    delete_entry(&target, &mut failures);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(DeleteError::Partial(failures))
    }
}

fn delete_entry(path: &Path, failures: &mut Vec<Failure>) {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            failures.push(Failure {
                path: path.to_path_buf(),
                error,
            });
            return;
        }
    };
    let attrs = meta.file_attributes();
    clear_attributes(path, attrs);

    let is_dir = attrs & ATTR_DIRECTORY != 0;
    let failures_before = failures.len();
    // Only name-surrogate reparse points (junctions, symlinks) are links.
    // Other reparse points (cloud placeholders, dedup, ...) are real
    // files/directories and are handled normally. If the tag cannot be read,
    // assume a link: never descending is the safe direction.
    let is_link = attrs & ATTR_REPARSE_POINT != 0 && reparse_tag(path).is_none_or(is_link_tag);
    let result = if is_link {
        // Link: remove the link itself, never descend into its target.
        if is_dir {
            fs::remove_dir(path)
        } else {
            fs::remove_file(path)
        }
    } else if is_dir {
        delete_dir_contents(path, failures);
        fs::remove_dir(path)
    } else {
        fs::remove_file(path)
    };

    if let Err(error) = result
        && error.kind() != io::ErrorKind::NotFound
    {
        // A directory kept alive by undeletable children is already
        // represented by those child failures; don't report it twice.
        let covered =
            failures.len() > failures_before && error.raw_os_error() == Some(ERROR_DIR_NOT_EMPTY);
        if !covered {
            failures.push(Failure {
                path: path.to_path_buf(),
                error,
            });
        }
    }
}

fn delete_dir_contents(path: &Path, failures: &mut Vec<Failure>) {
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(error) => {
            failures.push(Failure {
                path: path.to_path_buf(),
                error,
            });
            return;
        }
    };
    for entry in entries {
        match entry {
            Ok(entry) => delete_entry(&entry.path(), failures),
            Err(error) => failures.push(Failure {
                path: path.to_path_buf(),
                error,
            }),
        }
    }
}

/// `IO_REPARSE_TAG_MOUNT_POINT` (junction).
pub const REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
/// `IO_REPARSE_TAG_SYMLINK`.
pub const REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
/// Bit 29 marks a "name surrogate" tag: the entry stands in for another
/// file system object (`IsReparseTagNameSurrogate`).
const REPARSE_TAG_NAME_SURROGATE_BIT: u32 = 0x2000_0000;

/// True when a reparse tag denotes a link to another object (junction,
/// symlink) rather than a real file/directory with special storage.
pub fn is_link_tag(tag: u32) -> bool {
    tag & REPARSE_TAG_NAME_SURROGATE_BIT != 0
}

/// Reparse tag of `path` itself (not its target), or `None` if unreadable.
fn reparse_tag(path: &Path) -> Option<u32> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut data = WIN32_FIND_DATAW::default();
    // SAFETY: `wide` is NUL-terminated and `data` is a valid out buffer.
    let handle = unsafe { FindFirstFileW(PCWSTR(wide.as_ptr()), &mut data) }.ok()?;
    // SAFETY: `handle` was returned by FindFirstFileW above.
    let _ = unsafe { FindClose(handle) };
    // dwReserved0 holds the reparse tag when the reparse attribute is set.
    (data.dwFileAttributes & ATTR_REPARSE_POINT != 0).then_some(data.dwReserved0)
}

/// Best effort: a failure here surfaces as the delete error that follows.
fn clear_attributes(path: &Path, attrs: u32) {
    if attrs & (ATTR_READONLY | ATTR_HIDDEN | ATTR_SYSTEM) == 0 {
        return;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call.
    let _ = unsafe { SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_ATTRIBUTE_NORMAL) };
}

/// Lowercased path segments; the first is the drive (`c:`) or UNC host.
/// Resolves through `resolve_target` when the path exists, otherwise
/// normalizes lexically (strips `\\?\`, resolves `.`/`..`, ignores a
/// trailing separator).
fn normalize(path: &Path) -> Vec<String> {
    let resolved = if fs::symlink_metadata(path).is_ok() {
        resolve_target(path).ok()
    } else {
        None
    };
    lexical(&resolved.unwrap_or_else(|| path.to_path_buf()))
}

/// Purely lexical segments of `path` (made absolute against the current
/// directory if needed).
fn lexical(path: &Path) -> Vec<String> {
    let base = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |d| d.join(path))
    };

    let text = base.to_string_lossy().replace('/', "\\");
    let (unc, rest) = if let Some(r) = text.strip_prefix(r"\\?\UNC\") {
        (true, r.to_string())
    } else if let Some(r) = text.strip_prefix(r"\\?\") {
        (false, r.to_string())
    } else if let Some(r) = text.strip_prefix(r"\\") {
        (true, r.to_string())
    } else {
        (false, text.clone())
    };

    let mut segments: Vec<String> = Vec::new();
    for part in rest.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                // Never pop the drive / UNC host segment.
                if segments.len() > 1 {
                    segments.pop();
                }
            }
            p => segments.push(p.to_lowercase()),
        }
    }
    if unc && let Some(first) = segments.first_mut() {
        first.insert_str(0, r"\\");
    }
    segments
}

fn is_drive_root(segments: &[String]) -> bool {
    matches!(segments, [d] if d.len() == 2 && d.ends_with(':'))
}

/// True when `path` is a protected system location (see the spec's groups):
/// (a) a drive root, the user profile or `<SystemDrive>\Users`, or an ancestor
/// of one; (b) the Windows, Program Files or ProgramData folders, an ancestor
/// of one, or anything inside one.
pub fn is_protected(path: &Path) -> bool {
    let target = normalize(path);
    if target.is_empty() {
        return false;
    }
    // Also check the lexical form: a mapped drive (`Z:\`) resolves to a UNC
    // share path, which would otherwise hide that it is a drive root.
    if is_drive_root(&target) || is_drive_root(&lexical(path)) {
        return true;
    }

    let env_path = |name: &str| std::env::var_os(name).map(|v| normalize(Path::new(&v)));

    let mut group_a: Vec<Vec<String>> = Vec::new();
    group_a.extend(env_path("USERPROFILE"));
    if let Some(drive) = std::env::var_os("SystemDrive") {
        // "C:" alone means "current directory on C:", so spell out the root.
        let mut users = drive;
        users.push(r"\Users");
        group_a.push(normalize(Path::new(&users)));
    }
    // The path itself or an ancestor of it.
    if group_a
        .iter()
        .any(|p| !p.is_empty() && p.starts_with(&target))
    {
        return true;
    }

    [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
    ]
    .iter()
    .filter_map(|name| env_path(name))
    .filter(|p| !p.is_empty())
    .any(|p| p.starts_with(&target) || target.starts_with(&p))
}
