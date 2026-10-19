//! UAC elevation and taking ownership of items the current user cannot touch.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LUID, LocalFree, WAIT_FAILED,
    WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows::Win32::Security::{
    ACL, AdjustTokenPrivileges, CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetTokenInformation,
    LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, OBJECT_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SE_PRIVILEGE_ENABLED,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES,
    TOKEN_QUERY, TokenElevation, WinBuiltinAdministratorsSid,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FindClose, FindFirstFileW, OPEN_EXISTING, WIN32_FIND_DATAW,
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
        // A Win32 error comes back as HRESULT_FROM_WIN32 (0x8007xxxx).
        let code = e.code().0 as u32;
        return Err(if code & 0xFFFF_0000 == 0x8007_0000 {
            io::Error::from_raw_os_error((code & 0xFFFF) as i32)
        } else {
            io::Error::other(e)
        });
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
                .map_err(io::Error::from)
        }
    };
    // SAFETY: `process` is not used after this.
    let _ = unsafe { CloseHandle(process) };
    result
}

/// Absolute `\\?\` form of `path`. The final component is not resolved, so a
/// link is addressed itself, never its target.
fn long_path(path: &Path) -> io::Result<PathBuf> {
    let abs = std::path::absolute(path)?;
    let s = abs.as_os_str().to_string_lossy();
    if s.starts_with(r"\\?\") {
        return Ok(abs);
    }
    Ok(match s.strip_prefix(r"\\") {
        Some(unc) => PathBuf::from(format!(r"\\?\UNC\{unc}")),
        None => PathBuf::from(format!(r"\\?\{s}")),
    })
}

/// Attributes and reparse tag of the entry itself, read from its directory
/// entry so a locked-down item still answers.
fn entry_info(path: &Path) -> io::Result<(u32, u32)> {
    let wide = wide_z(path.as_os_str());
    let mut data = WIN32_FIND_DATAW::default();
    // SAFETY: `wide` is NUL-terminated and `data` is a valid out buffer.
    let handle = unsafe { FindFirstFileW(PCWSTR(wide.as_ptr()), &mut data) }
        .map_err(|_| io::Error::last_os_error())?;
    // SAFETY: `handle` was returned by FindFirstFileW above.
    let _ = unsafe { FindClose(handle) };
    Ok((data.dwFileAttributes, data.dwReserved0))
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

/// Applies `info` (owner or DACL) to the object at `path`. A link is opened
/// with `FILE_FLAG_OPEN_REPARSE_POINT` so its own security is changed, not
/// its target's.
fn set_security(
    path: &Path,
    is_link: bool,
    info: OBJECT_SECURITY_INFORMATION,
    owner: Option<PSID>,
    dacl: Option<*const ACL>,
) -> io::Result<()> {
    let wide = wide_z(path.as_os_str());
    if !is_link {
        // SAFETY: `wide` is NUL-terminated; owner/dacl point to live buffers owned by the caller.
        let status = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                info,
                owner,
                None,
                dacl,
                None,
            )
        };
        return win32_result(status);
    }

    let access = if info == OWNER_SECURITY_INFORMATION {
        WRITE_OWNER
    } else {
        WRITE_DAC
    };
    // SAFETY: `wide` is NUL-terminated; the handle is closed below.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| io::Error::last_os_error())?;
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` is a valid open handle; owner/dacl point to live buffers.
    let status = unsafe { SetSecurityInfo(handle, SE_FILE_OBJECT, info, owner, None, dacl, None) };
    // SAFETY: `handle` is not used after this.
    let _ = unsafe { CloseHandle(handle) };
    win32_result(status)
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
    /// Backing storage of the SID that `sid` points into.
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
            .map_err(|_| io::Error::last_os_error())?;

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
/// Administrators full control (inherited by children). Works top-down, so a
/// directory is fixed before it is listed. Junctions and symlinks are fixed
/// themselves but never descended. Failures are collected and the walk
/// continues.
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

fn take_ownership_entry(path: &Path, admins: &Admins, failures: &mut Vec<(PathBuf, io::Error)>) {
    let (attrs, tag) = match entry_info(path) {
        Ok(info) => info,
        Err(e) => {
            failures.push((path.to_path_buf(), e));
            return;
        }
    };
    let is_dir = attrs & ATTR_DIRECTORY != 0;
    // Only name-surrogate reparse points (junctions, symlinks) are links.
    let is_link = attrs & ATTR_REPARSE_POINT != 0 && is_link_tag(tag);

    let owned = set_security(
        path,
        is_link,
        OWNER_SECURITY_INFORMATION,
        Some(admins.sid()),
        None,
    );
    let granted = owned.and_then(|()| {
        set_security(
            path,
            is_link,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            Some(admins.acl.cast_const()),
        )
    });
    if let Err(e) = granted {
        // Without access this directory cannot be listed either; report once.
        failures.push((path.to_path_buf(), e));
        return;
    }

    if is_dir && !is_link {
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
    }
}
