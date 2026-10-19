use fckn_delete::delete::{
    DeleteError, REPARSE_TAG_MOUNT_POINT, REPARSE_TAG_SYMLINK, force_delete, is_link_tag,
    is_protected,
};
use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const HIDDEN: u32 = 0x2;
const SYSTEM: u32 = 0x4;
const READONLY: u32 = 0x1;

/// Creates a file carrying the given Win32 attributes.
fn mk(path: &Path, attrs: u32) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .attributes(attrs)
        .open(path)
        .unwrap();
}

/// Sets a directory's attributes via `attrib`, which works on directories.
fn set_dir_readonly(path: &Path) {
    let status = Command::new("attrib").arg("+R").arg(path).status().unwrap();
    assert!(status.success());
}

#[test]
fn deletes_hidden_system_readonly_nested_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("dir");
    let deep = root.join("a").join("b").join("c");
    fs::create_dir_all(&deep).unwrap();
    let all = HIDDEN | SYSTEM | READONLY;
    mk(&root.join("top.txt"), all);
    mk(&root.join("a").join("a.txt"), all);
    mk(&root.join("a").join("b").join("b.txt"), all);
    mk(&deep.join("c.txt"), all);
    let ro_dir = root.join("a").join("rodir");
    fs::create_dir_all(&ro_dir).unwrap();
    mk(&ro_dir.join("x.txt"), READONLY);
    set_dir_readonly(&ro_dir);

    force_delete(&root).unwrap();
    assert!(!root.exists());
}

#[test]
fn deletes_single_readonly_hidden_file() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("f.txt");
    mk(&file, READONLY | HIDDEN);
    force_delete(&file).unwrap();
    assert!(!file.exists());
}

#[test]
fn deletes_long_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("long");
    let mut cur = PathBuf::from(format!(r"\\?\{}", root.display()));
    fs::create_dir(&cur).unwrap();
    while cur.as_os_str().len() <= 320 {
        cur.push("0123456789_0123456789");
        fs::create_dir(&cur).unwrap();
    }
    mk(&cur.join("leaf.txt"), READONLY);
    assert!(cur.as_os_str().len() > 300);

    force_delete(&root).unwrap();
    assert!(!root.exists());
}

#[test]
fn junction_target_survives() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep.txt"), "keep").unwrap();
    let root = tmp.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("gone.txt"), "x").unwrap();
    let link = root.join("link");
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .output()
        .unwrap()
        .status;
    assert!(status.success());

    force_delete(&root).unwrap();
    assert!(!root.exists());
    assert!(outside.join("keep.txt").exists());
}

#[test]
fn only_name_surrogate_tags_are_links() {
    assert!(is_link_tag(REPARSE_TAG_MOUNT_POINT));
    assert!(is_link_tag(REPARSE_TAG_SYMLINK));
    assert!(!is_link_tag(0x9000_001A)); // IO_REPARSE_TAG_CLOUD (OneDrive placeholders)
    assert!(!is_link_tag(0x8000_0013)); // IO_REPARSE_TAG_DEDUP
}

#[test]
fn symlink_dir_target_survives_when_creatable() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep.txt"), "keep").unwrap();
    let root = tmp.path().join("root");
    fs::create_dir(&root).unwrap();
    if std::os::windows::fs::symlink_dir(&outside, root.join("link")).is_err() {
        return; // symlink creation needs privilege / developer mode
    }
    force_delete(&root).unwrap();
    assert!(!root.exists());
    assert!(outside.join("keep.txt").exists());
}

#[test]
fn missing_path_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let r = force_delete(&tmp.path().join("nope"));
    assert!(matches!(r, Err(DeleteError::NotFound(_))));
}

#[test]
fn protected_paths_detected() {
    let env = |k| PathBuf::from(std::env::var(k).unwrap());
    assert!(is_protected(Path::new(r"C:\")));
    assert!(is_protected(&env("SystemRoot")));
    assert!(is_protected(
        &env("SystemRoot").join(r"System32\notepad.exe")
    )); // inside group (b)
    assert!(is_protected(&env("SYSTEMROOT").join(".."))); // ancestor, case-insensitive
    assert!(is_protected(&env("USERPROFILE")));
    assert!(is_protected(&env("ProgramFiles").join("Anything")));
    assert!(!is_protected(&env("USERPROFILE").join("Desktop"))); // group (a) descendants are fine
    assert!(!is_protected(tempfile::tempdir().unwrap().path()));
}

#[test]
fn protected_works_for_nonexistent_paths() {
    assert!(is_protected(Path::new(r"\\?\C:\")));
    assert!(is_protected(Path::new(r"c:\USERS\")));
    assert!(is_protected(Path::new(r"Q:\"))); // drive root, even if absent or mapped
    assert!(is_protected(Path::new(r"C:\Windows\DoesNotExist\..\")));
    assert!(is_protected(Path::new(r"c:\windows\no\such\thing")));
    assert!(!is_protected(Path::new(r"C:\definitely\not\a\real\folder")));
}

#[test]
fn locked_file_reports_partial_and_keeps_going() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    fs::create_dir(&root).unwrap();
    let locked = root.join("locked.txt");
    let held = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&locked)
        .unwrap();
    fs::write(root.join("free.txt"), "x").unwrap();

    let r = force_delete(&root);
    match r {
        Err(DeleteError::Partial(f)) => {
            assert_eq!(f.len(), 1, "{f:?}");
            assert!(f[0].is_locked());
            assert!(!f[0].is_access_denied());
        }
        other => panic!("expected Partial, got {other:?}"),
    }
    assert!(!root.join("free.txt").exists());
    drop(held);
}
