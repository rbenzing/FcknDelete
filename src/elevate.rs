//! UAC elevation and taking ownership of items the current user cannot touch.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, HANDLE, HLOCAL, LUID, LocalFree, WAIT_FAILED, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
    TRUSTEE_W,
};
use windows::Win32::Security::{
    ACL, AdjustTokenPrivileges, CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetTokenInformation,
    InitializeSecurityDescriptor, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SECURITY_DESCRIPTOR,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, SetKernelObjectSecurity, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation, WinBuiltinAdministratorsSid,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileAttributeTagInfo, GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, w};

use crate::delete::is_link_tag;

const ATTR_DIRECTORY: u32 = 0x10;
const ATTR_REPARSE_POINT: u32 = 0x400;
/// `WRITE_DAC` / `WRITE_OWNER` standard access rights.
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
/// `SECURITY_MAX_SID_SIZE`.
const MAX_SID_SIZE: usize = 68;

/// True when the current process runs with an elevated (admin) token.
/// Any error is treated as "not elevated".
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out pointer; the handle is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: the buffer pointer and length describe `elevation`; `token` is valid.
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: `token` was opened above and is not used afterwards.
    let _ = unsafe { CloseHandle(token) };
    queried.is_ok() && elevation.TokenIsElevated != 0
}

/// Quotes `args` into one command line that `CommandLineToArgvW` splits back
/// into exactly `args`.
pub fn quote_args(args: &[OsString]) -> OsString {
    let mut line: Vec<u16> = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            line.push(u16::from(b' '));
        }
        quote_one(arg, &mut line);
    }
    OsString::from_wide(&line)
}

fn quote_one(arg: &OsStr, out: &mut Vec<u16>) {
    const SPACE: u16 = b' ' as u16;
    const TAB: u16 = b'\t' as u16;
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;

    let wide: Vec<u16> = arg.encode_wide().collect();
    let needs_quotes = wide.is_empty() || wide.iter().any(|&c| matches!(c, SPACE | TAB | QUOTE));
    if !needs_quotes {
        out.extend_from_slice(&wide);
        return;
    }
    out.push(QUOTE);
    let mut backslashes = 0usize;
    for &c in &wide {
        match c {
            BACKSLASH => backslashes += 1,
            QUOTE => {
                // Backslashes before a quote are doubled, then the quote is escaped.
                out.extend(std::iter::repeat_n(BACKSLASH, backslashes * 2 + 1));
                out.push(QUOTE);
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n(BACKSLASH, backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    // Backslashes before the closing quote are doubled too.
    out.extend(std::iter::repeat_n(BACKSLASH, backslashes * 2));
    out.push(QUOTE);
}

fn wide_z(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// Converts a `windows` error into an `io::Error` carrying the plain Win32
/// code (`raw_os_error() == Some(5)` for access denied). The crate's own
/// `From` impl would keep the `0x8007xxxx` HRESULT form.
pub(crate) fn win_err(e: windows::core::Error) -> io::Error {
    let code = e.code().0 as u32;
    if code & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((code & 0xFFFF) as i32)
    } else {
        io::Error::other(e)
    }
}

/// Relaunches this exe with `args` through UAC (`runas`), waits for it and
/// returns its exit code. A declined UAC prompt is an `Err` whose
/// `raw_os_error()` is `Some(1223)` (`ERROR_CANCELLED`).
pub fn relaunch_elevated(args: &[OsString]) -> io::Result<i32> {
    let exe = wide_z(std::env::current_exe()?.as_os_str());
    let params = wide_z(&quote_args(args));

    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(exe.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: `info` is fully initialised and the strings it points to outlive the call.
    if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
        return Err(win_err(e));
    }
    let process = info.hProcess;
    if process.is_invalid() {
        return Err(io::Error::other(
            "ShellExecuteExW returned no process handle",
        ));
    }

    // SAFETY: `process` is a valid process handle owned by us until closed below.
    let result = unsafe {
        if WaitForSingleObject(process, INFINITE) == WAIT_FAILED {
            Err(io::Error::last_os_error())
        } else {
            let mut code = 0u32;
            GetExitCodeProcess(process, &mut code)
                .map(|()| code as i32)
                .map_err(win_err)
        }
    };
    // SAFETY: `process` is not used after this.
    let _ = unsafe { CloseHandle(process) };
    result
}

/// Absolute `\\?\` form of `path`, built on UTF-16 so unpaired surrogates
/// survive. The final component is not resolved, so a link is addressed
/// itself, never its target. A trailing separator is dropped (except on a
/// drive root); paths that already start with `\\?\` or `\\.\` are untouched.
fn long_path(path: &Path) -> io::Result<PathBuf> {
    const BACKSLASH: u16 = b'\\' as u16;
    let abs = std::path::absolute(path)?;
    let mut wide: Vec<u16> = abs.as_os_str().encode_wide().collect();
    let starts_with = |prefix: &[u8]| {
        wide.len() >= prefix.len() && wide.iter().zip(prefix).all(|(&a, &b)| a == u16::from(b))
    };
    if starts_with(br"\\?\") || starts_with(br"\\.\") {
        return Ok(abs);
    }
    while wide.len() > 3 && wide.last() == Some(&BACKSLASH) {
        wide.pop();
    }
    let mut out: Vec<u16> = Vec::with_capacity(wide.len() + 8);
    if wide.starts_with(&[BACKSLASH, BACKSLASH]) {
        out.extend(r"\\?\UNC\".encode_utf16());
        out.extend_from_slice(&wide[2..]);
    } else {
        out.extend(r"\\?\".encode_utf16());
        out.extend_from_slice(&wide);
    }
    Ok(PathBuf::from(OsString::from_wide(&out)))
}

/// Enables `name` on the process token. Best effort: without the privilege
/// (not elevated) the per-item calls fail and are reported.
fn enable_privilege(name: PCWSTR) {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out pointer; the handle is closed below.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    };
    if opened.is_err() {
        return;
    }
    let mut luid = LUID::default();
    // SAFETY: `name` is NUL-terminated and `luid` is a valid out pointer.
    if unsafe { LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid) }.is_ok() {
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: `token` is valid and `privileges` is a fully initialised structure.
        let _ = unsafe { AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None) };
    }
    // SAFETY: `token` is not used after this.
    let _ = unsafe { CloseHandle(token) };
}

fn win32_result(status: WIN32_ERROR) -> io::Result<()> {
    if status.0 == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status.0 as i32))
    }
}

/// A file handle closed on drop.
struct FileHandle(HANDLE);

impl Drop for FileHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by CreateFileW and is closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Share mode for every handle here: others may read and write, but nobody
/// can rename or delete the object while we hold a handle with data access.
const SHARE: FILE_SHARE_MODE = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0);

/// Opens the object at `wide` itself. `FILE_FLAG_OPEN_REPARSE_POINT` means a
/// junction or symlink is opened as the link, never followed to its target;
/// the backup flag allows directories and lets the take-ownership and
/// restore privileges apply.
fn open_no_follow(wide: &[u16], access: u32) -> io::Result<FileHandle> {
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            SHARE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map(FileHandle)
    .map_err(win_err)
}

/// Sets owner and/or DACL on the open object. `SetKernelObjectSecurity`
/// writes exactly this object; unlike `SetNamedSecurityInfo`/`SetSecurityInfo`
/// it does not propagate inheritable ACEs over the existing subtree (the walk
/// fixes every item explicitly, so propagation would only cost O(n*depth)
/// and could abort on unreadable children).
fn set_security(
    handle: &FileHandle,
    info: OBJECT_SECURITY_INFORMATION,
    owner: Option<PSID>,
    dacl: Option<*const ACL>,
) -> io::Result<()> {
    let mut sd = SECURITY_DESCRIPTOR::default();
    let psd = PSECURITY_DESCRIPTOR((&raw mut sd).cast());
    // SAFETY: `psd` points at `sd`, a live SECURITY_DESCRIPTOR; the owner SID
    // and ACL are kept alive by the caller for the duration of the calls.
    unsafe {
        InitializeSecurityDescriptor(psd, 1).map_err(win_err)?;
        if owner.is_some() {
            SetSecurityDescriptorOwner(psd, owner, false).map_err(win_err)?;
        }
        if dacl.is_some() {
            SetSecurityDescriptorDacl(psd, true, dacl, false).map_err(win_err)?;
            SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
                .map_err(win_err)?;
        }
        SetKernelObjectSecurity(handle.0, info, psd).map_err(win_err)
    }
}

/// Frees a `LocalAlloc`ed pointer when dropped.
struct LocalGuard(*mut core::ffi::c_void);

impl Drop for LocalGuard {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a Win32 call that allocates with LocalAlloc.
        unsafe {
            LocalFree(Some(HLOCAL(self.0)));
        }
    }
}

struct Admins {
    /// Backing storage of the SID that `sid()` points into.
    sid_buf: Vec<u8>,
    acl: *mut ACL,
    _acl_guard: LocalGuard,
}

impl Admins {
    fn new() -> io::Result<Self> {
        let mut sid_buf = vec![0u8; MAX_SID_SIZE];
        let mut size = sid_buf.len() as u32;
        let sid = PSID(sid_buf.as_mut_ptr().cast());
        // SAFETY: `sid_buf` holds SECURITY_MAX_SID_SIZE bytes and `size` says so.
        unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(sid), &mut size) }
            .map_err(win_err)?;

        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: windows::core::PWSTR(sid.0.cast()),
                ..Default::default()
            },
        };
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `entry` points at `sid_buf`, which is alive; `acl` is a valid out pointer.
        let status = unsafe { SetEntriesInAclW(Some(&[entry]), None, &mut acl) };
        win32_result(status)?;
        Ok(Self {
            sid_buf,
            acl,
            _acl_guard: LocalGuard(acl.cast()),
        })
    }

    fn sid(&self) -> PSID {
        PSID(self.sid_buf.as_ptr().cast_mut().cast())
    }
}

/// Takes ownership of `path` and everything below it: owner becomes
/// BUILTIN\Administrators and the DACL is replaced by one ACE granting
/// Administrators full control (inherited by future children). Works
/// top-down, so a directory is fixed before it is listed. Junctions and
/// symlinks are fixed themselves but never descended. Failures are collected
/// and the walk continues.
pub fn take_ownership_tree(path: &Path) -> Vec<(PathBuf, io::Error)> {
    let mut failures = Vec::new();
    enable_privilege(w!("SeTakeOwnershipPrivilege"));
    enable_privilege(w!("SeRestorePrivilege"));
    let admins = match Admins::new() {
        Ok(a) => a,
        Err(e) => return vec![(path.to_path_buf(), e)],
    };
    match long_path(path) {
        Ok(p) => take_ownership_entry(&p, &admins, &mut failures),
        Err(e) => failures.push((path.to_path_buf(), e)),
    }
    failures
}

/// Owner first (the take-ownership privilege grants `WRITE_OWNER` even when
/// the DACL denies everything), then the DACL through a second handle: as
/// the new owner we hold `WRITE_DAC` and `READ_CONTROL` implicitly.
fn fix_security(wide: &[u16], admins: &Admins) -> io::Result<()> {
    let handle = open_no_follow(wide, WRITE_OWNER)?;
    set_security(
        &handle,
        OWNER_SECURITY_INFORMATION,
        Some(admins.sid()),
        None,
    )?;
    drop(handle);

    let handle = open_no_follow(wide, WRITE_DAC | READ_CONTROL.0)?;
    set_security(
        &handle,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        Some(admins.acl.cast_const()),
    )
}

/// Attributes and reparse tag of the object behind `handle`.
fn attribute_tag(handle: &FileHandle) -> io::Result<(u32, u32)> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: the buffer pointer and size describe `info`; `handle` is open.
    unsafe {
        GetFileInformationByHandleEx(
            handle.0,
            FileAttributeTagInfo,
            (&raw mut info).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    }
    .map_err(win_err)?;
    Ok((info.FileAttributes, info.ReparseTag))
}

/// A real directory: not a file, and not a junction/symlink (other reparse
/// points such as cloud placeholders are ordinary directories).
fn is_real_dir((attrs, tag): (u32, u32)) -> bool {
    attrs & ATTR_DIRECTORY != 0 && !(attrs & ATTR_REPARSE_POINT != 0 && is_link_tag(tag))
}

/// After the security was fixed: returns a handle to the object when it is a
/// real directory to descend into, `None` for files and links. The tag is
/// read from the very handle that is returned. That handle has list access
/// and does not share `DELETE`, so while it is held the directory cannot be
/// renamed away or replaced by a junction before it is enumerated.
fn open_dir_to_descend(wide: &[u16]) -> io::Result<Option<FileHandle>> {
    let list = FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0;
    match open_no_follow(wide, list) {
        Ok(handle) => Ok(is_real_dir(attribute_tag(&handle)?).then_some(handle)),
        Err(e) => {
            // Files may refuse data access (locked, exclusive share); classify
            // with an attributes-only handle and only report real directories.
            let probe = open_no_follow(wide, FILE_READ_ATTRIBUTES.0)?;
            if is_real_dir(attribute_tag(&probe)?) {
                Err(e)
            } else {
                Ok(None)
            }
        }
    }
}

fn take_ownership_entry(path: &Path, admins: &Admins, failures: &mut Vec<(PathBuf, io::Error)>) {
    let wide = wide_z(path.as_os_str());
    if let Err(e) = fix_security(&wide, admins) {
        failures.push((path.to_path_buf(), e));
        return;
    }
    let dir = match open_dir_to_descend(&wide) {
        Ok(Some(dir)) => dir,
        Ok(None) => return,
        Err(e) => {
            failures.push((path.to_path_buf(), e));
            return;
        }
    };
    match std::fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => take_ownership_entry(&entry.path(), admins, failures),
                    Err(e) => failures.push((path.to_path_buf(), e)),
                }
            }
        }
        Err(e) => failures.push((path.to_path_buf(), e)),
    }
    drop(dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long(s: &str) -> PathBuf {
        long_path(Path::new(s)).unwrap()
    }

    #[test]
    fn long_path_prefixes_and_trims() {
        assert_eq!(long(r"C:\a\b"), PathBuf::from(r"\\?\C:\a\b"));
        assert_eq!(long(r"C:\a\b\"), PathBuf::from(r"\\?\C:\a\b"));
        assert_eq!(long(r"C:\"), PathBuf::from(r"\\?\C:\"));
        assert_eq!(
            long(r"\\srv\share\d\"),
            PathBuf::from(r"\\?\UNC\srv\share\d")
        );
    }

    #[test]
    fn long_path_leaves_verbatim_and_device_paths() {
        assert_eq!(long(r"\\?\C:\a\"), PathBuf::from(r"\\?\C:\a\"));
        assert_eq!(long(r"\\.\pipe\x"), PathBuf::from(r"\\.\pipe\x"));
    }

    #[test]
    fn long_path_keeps_unpaired_surrogates() {
        let mut wide: Vec<u16> = r"C:\a\".encode_utf16().collect();
        wide.push(0xD800);
        let p = PathBuf::from(OsString::from_wide(&wide));
        let out: Vec<u16> = long_path(&p).unwrap().as_os_str().encode_wide().collect();
        assert_eq!(out.last(), Some(&0xD800));
    }
}
