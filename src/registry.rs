//! Explorer context-menu registration (HKCU, no admin) and the install-copy of the exe.

use std::env;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

/// Where the per-user shell verbs live, relative to `HKCU`.
pub const CLASSES: &str = r"Software\Classes";

const VERB_NAME: &str = "FcknDelete";
const VERB_LABEL: &str = "Fckn Delete";
const INSTALLED_EXE_NAME: &str = "FcknDelete.exe";
/// Class keys the verb is attached to: every file, and every folder.
const TARGETS: [&str; 2] = ["*", "Directory"];

/// The shell command for the verb: `"<exe>" "%1"`. A `\?\` prefix on `exe` is stripped.
pub fn command_line(exe: &Path) -> String {
    let exe = exe.to_string_lossy();
    let exe = exe.strip_prefix(r"\?\").unwrap_or(&exe);
    format!("\"{exe}\" \"%1\"")
}

fn verb_path(classes: &str, target: &str) -> String {
    format!(r"{classes}\{target}\shell\{VERB_NAME}")
}

/// Registers the verb for files and directories under `root\classes`.
pub fn install_at(root: &RegKey, classes: &str, exe: &Path) -> io::Result<()> {
    let command = command_line(exe);
    for target in TARGETS {
        let (verb, _) = root.create_subkey(verb_path(classes, target))?;
        verb.set_value("", &VERB_LABEL)?;
        let (cmd, _) = verb.create_subkey("command")?;
        cmd.set_value("", &command)?;
    }
    Ok(())
}

/// Removes both verb trees under `root\classes`. Keys that are already gone are fine.
pub fn uninstall_at(root: &RegKey, classes: &str) -> io::Result<()> {
    for target in TARGETS {
        match root.delete_subkey_all(verb_path(classes, target)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// True when both verbs have their `command` key.
pub fn is_installed_at(root: &RegKey, classes: &str) -> bool {
    TARGETS.iter().all(|target| {
        root.open_subkey(format!(r"{}\command", verb_path(classes, target)))
            .is_ok()
    })
}

/// Registers the verb under the real `HKCU\Software\Classes`.
pub fn install(exe: &Path) -> io::Result<()> {
    install_at(&RegKey::predef(HKEY_CURRENT_USER), CLASSES, exe)
}

/// Removes the verb from the real `HKCU\Software\Classes`.
pub fn uninstall() -> io::Result<()> {
    uninstall_at(&RegKey::predef(HKEY_CURRENT_USER), CLASSES)
}

/// Whether the verb is registered in the real `HKCU\Software\Classes`.
pub fn is_installed() -> bool {
    is_installed_at(&RegKey::predef(HKEY_CURRENT_USER), CLASSES)
}

/// Copies `src` to `dest_dir\FcknDelete.exe` (creating the directory) and returns that path.
/// Nothing is copied when `src` already is that file, e.g. when the installed copy is running.
pub fn install_exe(src: &Path, dest_dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dest_dir)?;
    let dest = dest_dir.join(INSTALLED_EXE_NAME);
    if !is_same_file(src, &dest) {
        fs::copy(src, &dest)?;
    }
    Ok(dest)
}

/// Compares canonicalized paths, ignoring case (Windows paths are case-insensitive).
fn is_same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase(),
        _ => false,
    }
}

/// `%LOCALAPPDATA%\Programs\FcknDelete`.
pub fn default_install_dir() -> PathBuf {
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    base.join("Programs").join("FcknDelete")
}
