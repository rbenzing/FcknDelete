//! Find (via the Restart Manager) and terminate processes that lock files.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE, WIN32_ERROR,
};
use windows::Win32::System::RestartManager::{
    CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmCritical, RmEndSession, RmGetList, RmRegisterResources,
    RmStartSession,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
use windows::core::{PCWSTR, PWSTR};

/// A process that currently holds one of the queried files open.
#[derive(Debug, Clone, PartialEq)]
pub struct LockingProcess {
    pub pid: u32,
    pub name: String,
}

/// How many times `RmGetList` is retried when the process list keeps growing.
const MAX_GET_LIST_ATTEMPTS: usize = 8;

fn win32_error(code: WIN32_ERROR) -> io::Error {
    io::Error::from_raw_os_error(code.0 as i32)
}

fn check(code: WIN32_ERROR) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(win32_error(code))
    }
}

/// Ends the Restart Manager session on drop, so every exit path cleans up.
struct Session(u32);

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a session handle returned by `RmStartSession`.
        unsafe {
            let _ = RmEndSession(self.0);
        }
    }
}

/// Returns the processes (deduplicated by pid, critical system processes
/// excluded) that hold any of `paths` open.
///
/// The Restart Manager never reports the calling process itself.
pub fn find_lockers(paths: &[PathBuf]) -> io::Result<Vec<LockingProcess>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    let mut session_handle = 0u32;
    // Session key buffer must be CCH_RM_SESSION_KEY + 1 wide chars.
    let mut session_key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
    // SAFETY: both pointers refer to live, correctly sized locals.
    check(unsafe { RmStartSession(&mut session_handle, None, PWSTR(session_key.as_mut_ptr())) })?;
    let session = Session(session_handle);

    // The wide buffers must outlive the `RmRegisterResources` call.
    let wide: Vec<Vec<u16>> = paths
        .iter()
        .map(|p| p.as_os_str().encode_wide().chain(Some(0)).collect())
        .collect();
    let pcwstrs: Vec<PCWSTR> = wide.iter().map(|w| PCWSTR(w.as_ptr())).collect();
    // SAFETY: each PCWSTR points into a nul-terminated buffer held by `wide`.
    check(unsafe { RmRegisterResources(session.0, Some(&pcwstrs), None, None) })?;
    drop(pcwstrs);
    drop(wide);

    let mut infos: Vec<RM_PROCESS_INFO> = Vec::new();
    for _ in 0..MAX_GET_LIST_ATTEMPTS {
        let mut needed = 0u32;
        let mut count = infos.len() as u32;
        let mut reboot_reasons = 0u32;
        // SAFETY: `infos` has `count` initialised elements; the other
        // out-pointers refer to live locals.
        let code = unsafe {
            RmGetList(
                session.0,
                &mut needed,
                &mut count,
                Some(infos.as_mut_ptr()),
                &mut reboot_reasons,
            )
        };
        if code == ERROR_SUCCESS {
            infos.truncate(count as usize);
            return Ok(collect_lockers(&infos));
        }
        if code != ERROR_MORE_DATA {
            return Err(win32_error(code));
        }
        // Grow (with slack, since the list may change between calls) and retry.
        infos.resize(needed as usize + 4, RM_PROCESS_INFO::default());
    }
    Err(io::Error::other(
        "the list of locking processes kept changing; gave up",
    ))
}

fn collect_lockers(infos: &[RM_PROCESS_INFO]) -> Vec<LockingProcess> {
    let mut lockers: Vec<LockingProcess> = Vec::new();
    for info in infos {
        if info.ApplicationType == RmCritical {
            continue;
        }
        let pid = info.Process.dwProcessId;
        if lockers.iter().any(|l| l.pid == pid) {
            continue;
        }
        let len = info
            .strAppName
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(info.strAppName.len());
        lockers.push(LockingProcess {
            pid,
            name: String::from_utf16_lossy(&info.strAppName[..len]),
        });
    }
    lockers
}

/// Closes a process handle on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by `OpenProcess` and is closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Terminates process `pid`. Refuses to terminate the current process.
pub fn kill(pid: u32) -> io::Result<()> {
    if pid == std::process::id() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to terminate the current process",
        ));
    }
    // SAFETY: plain Win32 calls; the handle is owned and closed by the guard.
    unsafe {
        let handle = OwnedHandle(
            OpenProcess(PROCESS_TERMINATE, false, pid)
                .map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xFFFF))?,
        );
        TerminateProcess(handle.0, 1).map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xFFFF))
    }
}
