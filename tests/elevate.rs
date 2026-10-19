use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use fckn_delete::elevate::{is_elevated, quote_args, take_ownership_tree};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LUID, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, AdjustTokenPrivileges, CreateWellKnownSid, DACL_SECURITY_INFORMATION, InitializeAcl,
    LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, WinLocalSystemSid,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::CommandLineToArgvW;
use windows::core::{PCWSTR, PWSTR, w};

/// Runs the real `CommandLineToArgvW` over `x.exe <quote_args(args)>` and
/// returns argv without argv[0].
fn parse_command_line(args: &[OsString]) -> Vec<OsString> {
    let mut line: Vec<u16> = OsString::from("x.exe ").encode_wide().collect();
    line.extend(quote_args(args).encode_wide());
    line.push(0);

    let mut argc = 0i32;
    // SAFETY: `line` is NUL-terminated and `argc` is a valid out pointer.
    let argv = unsafe { CommandLineToArgvW(PCWSTR(line.as_ptr()), &mut argc) };
    assert!(!argv.is_null(), "CommandLineToArgvW failed");
    let mut out = Vec::new();
    for i in 1..argc as usize {
        // SAFETY: argv points to `argc` valid NUL-terminated PWSTRs.
        let s: PWSTR = unsafe { *argv.add(i) };
        out.push(OsString::from_wide(unsafe { s.as_wide() }));
    }
    // SAFETY: the array returned by CommandLineToArgvW must be freed with LocalFree.
    unsafe {
        LocalFree(Some(windows::Win32::Foundation::HLOCAL(argv.cast())));
    }
    out
}

fn sample_args() -> Vec<OsString> {
    [
        r"C:\plain",
        r"C:\a b\",
        "",
        r#"C:\q"uote"#,
        r"C:\日本 x\\",
        "--elevated",
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

#[test]
fn quote_args_roundtrip() {
    let all = sample_args();
    for arg in &all {
        let one = vec![arg.clone()];
        assert_eq!(parse_command_line(&one), one, "arg {arg:?}");
    }
    assert_eq!(parse_command_line(&all), all);
}

#[test]
fn quote_args_plain_unquoted() {
    assert_eq!(
        quote_args(&["--elevated".into(), r"C:\a".into()]),
        OsString::from(r"--elevated C:\a")
    );
}

#[test]
fn is_elevated_does_not_panic() {
    let _ = is_elevated();
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Test-only: owner SYSTEM + empty DACL, so even the owning admin is locked out.
fn lock_down(path: &Path) {
    let mut sid = vec![0u8; 68];
    let mut size = sid.len() as u32;
    let psid = PSID(sid.as_mut_ptr().cast());
    // SAFETY: `sid` is SECURITY_MAX_SID_SIZE bytes and `size` reflects that.
    unsafe { CreateWellKnownSid(WinLocalSystemSid, None, Some(psid), &mut size) }.unwrap();

    // An empty (non-NULL) ACL grants nobody anything; a NULL DACL would grant everyone.
    let mut acl = vec![0u8; 8];
    let pacl = acl.as_mut_ptr().cast::<ACL>();
    // SAFETY: `acl` is 8 bytes, the size of an empty ACL header; revision 2.
    unsafe {
        InitializeAcl(
            pacl,
            acl.len() as u32,
            windows::Win32::Security::ACE_REVISION(2),
        )
    }
    .unwrap();

    let wpath = wide(path);
    // SAFETY: all pointers refer to live, valid buffers for the duration of the calls.
    unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wpath.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(psid),
            None,
            None,
            None,
        )
        .ok()
        .unwrap();
        SetNamedSecurityInfoW(
            PCWSTR(wpath.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(pacl),
            None,
        )
        .ok()
        .unwrap();
    }
}

fn enable(name: PCWSTR) {
    let mut token = HANDLE::default();
    // SAFETY: valid out pointer; the handle is closed below.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .unwrap();
    let mut luid = LUID::default();
    // SAFETY: `name` is a static NUL-terminated string, `luid` a valid out pointer.
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid) }.unwrap();
    let privs = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: `token` is a valid token handle and `privs` a valid structure.
    unsafe {
        AdjustTokenPrivileges(token, false, Some(&privs), 0, None, None).unwrap();
        let _ = CloseHandle(token);
    }
}

/// Owner + DACL of `path` as an SDDL string.
fn sddl(path: &Path) -> String {
    let wpath = wide(path);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wpath` is NUL-terminated and `psd` a valid out pointer.
    unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wpath.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut psd,
        )
        .ok()
        .unwrap();
    }
    let mut out = PWSTR::null();
    // SAFETY: `psd` was returned by GetNamedSecurityInfoW; `out` is a valid out pointer.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut out,
            None,
        )
        .unwrap();
    }
    // SAFETY: `out` is a NUL-terminated string allocated with LocalAlloc, as is `psd`.
    let text = unsafe { out.to_string() }.unwrap();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(out.0.cast())));
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    text
}

/// Restores access to the tree on drop so the tempdir can always be removed.
struct Restore<'a>(&'a Path);

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _ = take_ownership_tree(self.0);
    }
}

#[test]
#[ignore = "needs an elevated shell: cargo test -- --ignored"]
fn take_ownership_then_delete_locked_down_tree() {
    assert!(is_elevated(), "run this test from an elevated terminal");
    // Assigning SYSTEM as owner needs SeRestorePrivilege.
    enable(w!("SeRestorePrivilege"));

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let sub = root.join("sub");
    let file = sub.join("f.txt");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(&file, b"x").unwrap();

    // A junction inside the tree pointing outside it: the walk must treat the
    // link itself and leave the target's security and contents alone.
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("keep.txt"), b"keep").unwrap();
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(root.join("link"))
        .arg(&outside)
        .output()
        .unwrap()
        .status;
    assert!(status.success(), "mklink /J failed");
    let outside_before = sddl(&outside);
    let keep_before = sddl(&outside.join("keep.txt"));

    let _restore = Restore(&root);
    // Bottom-up, so each parent is still accessible while its child is locked.
    for p in [&file, &sub, &root] {
        lock_down(p);
    }
    assert!(
        std::fs::remove_dir_all(&root).is_err(),
        "tree should be locked"
    );

    let failures = take_ownership_tree(&root);
    assert!(failures.is_empty(), "failures: {failures:?}");
    std::fs::remove_dir_all(&root).unwrap();

    assert_eq!(
        sddl(&outside),
        outside_before,
        "junction target was changed"
    );
    assert_eq!(sddl(&outside.join("keep.txt")), keep_before);
    assert_eq!(std::fs::read(outside.join("keep.txt")).unwrap(), b"keep");
}
