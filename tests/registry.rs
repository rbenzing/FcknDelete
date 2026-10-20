use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use fckn_delete::registry::{command_line, install_at, install_exe, is_installed_at, uninstall_at};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A unique scratch "classes" key under HKCU, removed on drop even if a test panics.
struct TestClasses {
    root: RegKey,
    path: String,
}

impl TestClasses {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = format!(r"Software\FcknDeleteTest-{}-{}", std::process::id(), n);
        Self {
            root: RegKey::predef(HKEY_CURRENT_USER),
            path,
        }
    }
}

impl Drop for TestClasses {
    fn drop(&mut self) {
        let _ = self.root.delete_subkey_all(&self.path);
    }
}

#[test]
fn command_line_quotes_exe_and_arg() {
    assert_eq!(
        command_line(Path::new(r"C:\Prog Files\FcknDelete.exe")),
        r#""C:\Prog Files\FcknDelete.exe" "%1""#
    );
    assert_eq!(
        command_line(Path::new(r"\\?\C:\x\FcknDelete.exe")),
        r#""C:\x\FcknDelete.exe" "%1""#
    );
    assert_eq!(
        command_line(Path::new(r"\\?\UNC\srv\share\FcknDelete.exe")),
        r#""\\srv\share\FcknDelete.exe" "%1""#
    );
}

#[test]
fn install_writes_file_and_directory_verbs() {
    let t = TestClasses::new();
    let exe = Path::new(r"C:\Prog Files\FcknDelete.exe");
    assert!(!is_installed_at(&t.root, &t.path));
    install_at(&t.root, &t.path, exe).unwrap();
    assert!(is_installed_at(&t.root, &t.path));
    for kind in ["*", "Directory"] {
        let verb = t
            .root
            .open_subkey(format!(r"{}\{}\shell\FcknDelete", t.path, kind))
            .unwrap();
        let label: String = verb.get_value("").unwrap();
        assert_eq!(label, "Fckn Delete");
        let cmd = verb.open_subkey("command").unwrap();
        let value: String = cmd.get_value("").unwrap();
        assert_eq!(value, command_line(exe));
    }
}

#[test]
fn uninstall_removes_keys_and_is_idempotent() {
    let t = TestClasses::new();
    // Uninstalling when nothing was ever installed is fine.
    uninstall_at(&t.root, &t.path).unwrap();
    install_at(&t.root, &t.path, Path::new(r"C:\x\FcknDelete.exe")).unwrap();
    assert!(is_installed_at(&t.root, &t.path));
    uninstall_at(&t.root, &t.path).unwrap();
    uninstall_at(&t.root, &t.path).unwrap();
    assert!(!is_installed_at(&t.root, &t.path));
}

#[test]
fn install_exe_copies_to_dest() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("x.exe");
    fs::write(&src, b"hello exe bytes").unwrap();
    let dest_dir = tmp.path().join("nested").join("FcknDelete");

    let dest = install_exe(&src, &dest_dir).unwrap();
    assert_eq!(dest, dest_dir.join("FcknDelete.exe"));
    assert_eq!(fs::read(&dest).unwrap(), b"hello exe bytes");

    // Source is already the installed file: no copy onto itself, content unchanged.
    let again = install_exe(&dest, &dest_dir).unwrap();
    assert_eq!(again, dest);
    assert_eq!(fs::read(&dest).unwrap(), b"hello exe bytes");

    // Same file spelled with different case (Windows paths are case-insensitive).
    let upper = dest_dir.join("FCKNDELETE.EXE");
    let again = install_exe(&upper, &dest_dir).unwrap();
    assert_eq!(again, dest);
    assert_eq!(fs::read(&dest).unwrap(), b"hello exe bytes");
}
