use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as Process;

use fckn_delete::app::{MenuChoice, System, Ui, run};
use fckn_delete::cli::Command;
use fckn_delete::locks::LockingProcess;

struct FakeUi {
    menu: MenuChoice,
    file: Option<PathBuf>,
    folder: Option<PathBuf>,
    confirm_delete: bool,
    confirm_protected: bool,
    confirm_kill: bool,
    confirm_elevate: bool,

    menu_calls: Vec<bool>,
    delete_calls: Vec<Vec<PathBuf>>,
    protected_calls: Vec<Vec<PathBuf>>,
    kill_calls: Vec<Vec<LockingProcess>>,
    elevate_calls: Vec<Vec<PathBuf>>,
    infos: Vec<String>,
    errors: Vec<String>,
}

impl FakeUi {
    fn new() -> Self {
        FakeUi {
            menu: MenuChoice::Cancel,
            file: None,
            folder: None,
            confirm_delete: true,
            confirm_protected: false,
            confirm_kill: false,
            confirm_elevate: false,
            menu_calls: Vec::new(),
            delete_calls: Vec::new(),
            protected_calls: Vec::new(),
            kill_calls: Vec::new(),
            elevate_calls: Vec::new(),
            infos: Vec::new(),
            errors: Vec::new(),
        }
    }

    fn no_confirmations_asked(&self) -> bool {
        self.delete_calls.is_empty()
            && self.protected_calls.is_empty()
            && self.kill_calls.is_empty()
            && self.elevate_calls.is_empty()
    }
}

impl Ui for FakeUi {
    fn main_menu(&mut self, installed: bool) -> MenuChoice {
        self.menu_calls.push(installed);
        self.menu
    }
    fn pick_file(&mut self) -> Option<PathBuf> {
        self.file.take()
    }
    fn pick_folder(&mut self) -> Option<PathBuf> {
        self.folder.take()
    }
    fn confirm_delete(&mut self, paths: &[PathBuf]) -> bool {
        self.delete_calls.push(paths.to_vec());
        self.confirm_delete
    }
    fn confirm_protected(&mut self, paths: &[PathBuf]) -> bool {
        self.protected_calls.push(paths.to_vec());
        self.confirm_protected
    }
    fn confirm_kill(&mut self, procs: &[LockingProcess]) -> bool {
        self.kill_calls.push(procs.to_vec());
        self.confirm_kill
    }
    fn confirm_elevate(&mut self, paths: &[PathBuf]) -> bool {
        self.elevate_calls.push(paths.to_vec());
        self.confirm_elevate
    }
    fn info(&mut self, msg: &str) {
        self.infos.push(msg.to_string());
    }
    fn error(&mut self, msg: &str) {
        self.errors.push(msg.to_string());
    }
}

struct FakeSystem {
    installed: bool,
    elevated: bool,
    lockers: Vec<LockingProcess>,
    held: Option<File>,
    /// Raw OS error to fail `relaunch_elevated` with, else exit code 0.
    relaunch_error: Option<i32>,

    installs: u32,
    uninstalls: u32,
    killed: Vec<u32>,
    relaunches: Vec<Vec<PathBuf>>,
    ownership: Vec<PathBuf>,
}

impl FakeSystem {
    fn new() -> Self {
        FakeSystem {
            installed: false,
            elevated: false,
            lockers: Vec::new(),
            held: None,
            relaunch_error: None,
            installs: 0,
            uninstalls: 0,
            killed: Vec::new(),
            relaunches: Vec::new(),
            ownership: Vec::new(),
        }
    }
}

impl System for FakeSystem {
    fn is_installed(&self) -> bool {
        self.installed
    }
    fn install(&mut self) -> io::Result<()> {
        self.installs += 1;
        Ok(())
    }
    fn uninstall(&mut self) -> io::Result<()> {
        self.uninstalls += 1;
        Ok(())
    }
    fn find_lockers(&mut self, _paths: &[PathBuf]) -> Vec<LockingProcess> {
        self.lockers.clone()
    }
    fn kill(&mut self, pid: u32) -> io::Result<()> {
        self.killed.push(pid);
        self.held = None;
        Ok(())
    }
    fn is_elevated(&self) -> bool {
        self.elevated
    }
    fn relaunch_elevated(&mut self, paths: &[PathBuf]) -> io::Result<i32> {
        self.relaunches.push(paths.to_vec());
        match self.relaunch_error {
            Some(code) => Err(io::Error::from_raw_os_error(code)),
            None => Ok(0),
        }
    }
    fn take_ownership(&mut self, path: &Path) -> Vec<(PathBuf, io::Error)> {
        self.ownership.push(path.to_path_buf());
        let plain = PathBuf::from(path.to_string_lossy().trim_start_matches(r"\\?\"));
        icacls_reset(&plain);
        if let Some(parent) = plain.parent() {
            icacls_reset(parent);
        }
        Vec::new()
    }
}

fn icacls_reset(path: &Path) -> bool {
    Process::new("icacls")
        .arg(path)
        .arg("/reset")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn icacls_deny(path: &Path, rights: &str) {
    let out = Process::new("icacls")
        .arg(path)
        .arg("/deny")
        .arg(format!("*S-1-1-0:({rights})"))
        .output()
        .expect("icacls should launch");
    assert!(
        out.status.success(),
        "icacls /deny failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Resets the ACLs set up by `denied_file` even when the test panics.
struct AclGuard {
    root: PathBuf,
    file: PathBuf,
}

impl Drop for AclGuard {
    fn drop(&mut self) {
        icacls_reset(&self.file);
        icacls_reset(&self.root);
    }
}

/// Creates `root/f.txt` so that deleting f.txt fails with access denied.
fn denied_file(base: &Path) -> (PathBuf, PathBuf, AclGuard) {
    let root = base.join("root");
    fs::create_dir(&root).unwrap();
    let file = root.join("f.txt");
    fs::write(&file, "x").unwrap();
    let guard = AclGuard {
        root: root.clone(),
        file: file.clone(),
    };
    icacls_deny(&root, "DC");
    icacls_deny(&file, "DE");
    // Make sure the setup really blocks deletion, so tests can't pass vacuously.
    let err = fs::remove_file(&file).expect_err("setup should block deletion");
    assert_eq!(
        err.raw_os_error(),
        Some(5),
        "setup should give access denied"
    );
    (root, file, guard)
}

fn temp_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("f.txt");
    fs::write(&f, "x").unwrap();
    (dir, f)
}

#[test]
fn menu_cancel_exits_zero_and_touches_nothing() {
    let mut ui = FakeUi::new();
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::Menu, &mut ui, &mut sys), 0);
    assert_eq!(ui.menu_calls, vec![false]);
    assert!(ui.no_confirmations_asked());
    assert!(ui.infos.is_empty() && ui.errors.is_empty());
    assert_eq!((sys.installs, sys.uninstalls), (0, 0));
}

#[test]
fn menu_receives_install_state() {
    let mut ui = FakeUi::new();
    let mut sys = FakeSystem::new();
    sys.installed = true;
    assert_eq!(run(Command::Menu, &mut ui, &mut sys), 0);
    assert_eq!(ui.menu_calls, vec![true]);
}

#[test]
fn decline_confirm_keeps_file() {
    let (_dir, f) = temp_file();
    let mut ui = FakeUi::new();
    ui.confirm_delete = false;
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::Delete(vec![f.clone()]), &mut ui, &mut sys), 0);
    assert!(f.exists());
    assert_eq!(ui.delete_calls, vec![vec![f]]);
}

#[test]
fn confirm_deletes_silently() {
    let (_dir, f) = temp_file();
    let mut ui = FakeUi::new();
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::Delete(vec![f.clone()]), &mut ui, &mut sys), 0);
    assert!(!f.exists());
    assert!(ui.infos.is_empty());
    assert!(ui.errors.is_empty());
    assert!(ui.protected_calls.is_empty());
}

#[test]
fn menu_pick_file_deletes_and_reports() {
    let (_dir, f) = temp_file();
    let mut ui = FakeUi::new();
    ui.menu = MenuChoice::PickFile;
    ui.file = Some(f.clone());
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::Menu, &mut ui, &mut sys), 0);
    assert!(!f.exists());
    assert_eq!(ui.infos.len(), 1);
    assert_eq!(ui.infos[0], format!("Fckn deleted:\n{}", f.display()));
    assert!(ui.errors.is_empty());
}

#[test]
fn menu_pick_folder_deletes_folder() {
    let (dir, f) = temp_file();
    let folder = dir.path().join("sub");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("a.txt"), "x").unwrap();
    let mut ui = FakeUi::new();
    ui.menu = MenuChoice::PickFolder;
    ui.folder = Some(folder.clone());
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::Menu, &mut ui, &mut sys), 0);
    assert!(!folder.exists());
    assert!(f.exists());
    assert!(ui.infos[0].starts_with("Fckn deleted:"));
}

#[test]
fn menu_decline_confirm_shows_no_info() {
    let (_dir, f) = temp_file();
    let mut ui = FakeUi::new();
    ui.menu = MenuChoice::PickFile;
    ui.file = Some(f.clone());
    ui.confirm_delete = false;
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::Menu, &mut ui, &mut sys), 0);
    assert!(f.exists());
    assert!(ui.infos.is_empty());
}

#[test]
fn picker_cancel_exits_zero() {
    let mut ui = FakeUi::new();
    ui.menu = MenuChoice::PickFolder;
    ui.folder = None;
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::Menu, &mut ui, &mut sys), 0);
    assert!(ui.no_confirmations_asked());
    assert!(ui.infos.is_empty() && ui.errors.is_empty());
}

#[test]
fn locked_file_kill_then_delete() {
    let (_dir, f) = temp_file();
    let mut ui = FakeUi::new();
    ui.confirm_kill = true;
    let mut sys = FakeSystem::new();
    sys.held = Some(
        OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&f)
            .unwrap(),
    );
    let locker = LockingProcess {
        pid: 42,
        name: "x".to_string(),
    };
    sys.lockers = vec![locker.clone()];
    assert_eq!(run(Command::Delete(vec![f.clone()]), &mut ui, &mut sys), 0);
    assert_eq!(sys.killed, vec![42]);
    assert!(sys.held.is_none());
    assert!(!f.exists());
    assert_eq!(ui.kill_calls, vec![vec![locker]]);
    assert!(ui.errors.is_empty());
}

#[test]
fn locked_file_decline_kill_errors() {
    let (_dir, f) = temp_file();
    let mut ui = FakeUi::new();
    ui.confirm_kill = false;
    let mut sys = FakeSystem::new();
    sys.held = Some(
        OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&f)
            .unwrap(),
    );
    sys.lockers = vec![LockingProcess {
        pid: 42,
        name: "x".to_string(),
    }];
    assert_eq!(run(Command::Delete(vec![f.clone()]), &mut ui, &mut sys), 1);
    assert!(sys.killed.is_empty());
    assert!(f.exists());
    assert_eq!(ui.errors.len(), 1);
    assert!(ui.errors[0].starts_with("Couldn't delete:"));
}

#[test]
fn locked_file_without_lockers_errors_without_kill_prompt() {
    let (_dir, f) = temp_file();
    let mut ui = FakeUi::new();
    ui.confirm_kill = true;
    let mut sys = FakeSystem::new();
    sys.held = Some(
        OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&f)
            .unwrap(),
    );
    assert_eq!(run(Command::Delete(vec![f.clone()]), &mut ui, &mut sys), 1);
    assert!(ui.kill_calls.is_empty());
    assert_eq!(ui.errors.len(), 1);
}

#[test]
fn missing_path_shows_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.txt");
    let mut ui = FakeUi::new();
    let mut sys = FakeSystem::new();
    assert_eq!(
        run(Command::Delete(vec![missing.clone()]), &mut ui, &mut sys),
        1
    );
    assert_eq!(ui.errors.len(), 1);
    assert!(ui.errors[0].contains("doesn't exist"));
    assert!(ui.errors[0].contains(&missing.display().to_string()));
    assert!(ui.errors[0].starts_with("Couldn't delete:"));
}

#[test]
fn multiple_paths_continue_past_failure() {
    let (dir, f) = temp_file();
    let missing = dir.path().join("nope.txt");
    let mut ui = FakeUi::new();
    let mut sys = FakeSystem::new();
    let code = run(Command::Delete(vec![missing, f.clone()]), &mut ui, &mut sys);
    assert_eq!(code, 1);
    assert!(!f.exists());
    assert_eq!(ui.errors.len(), 1);
}

#[test]
fn protected_path_needs_proceed() {
    let mut ui = FakeUi::new();
    ui.confirm_protected = false;
    let mut sys = FakeSystem::new();
    let root = PathBuf::from(r"C:\");
    assert_eq!(
        run(Command::Delete(vec![root.clone()]), &mut ui, &mut sys),
        0
    );
    assert_eq!(ui.protected_calls, vec![vec![root]]);
    assert!(ui.delete_calls.is_empty());
    assert!(ui.errors.is_empty());
}

#[test]
fn protected_path_cancel_keeps() {
    let pd = std::env::var_os("ProgramData").expect("ProgramData is set");
    let dir = PathBuf::from(pd).join(format!("FcknDeleteTest-{}", std::process::id()));
    let f = dir.join("f.txt");
    if fs::create_dir_all(&dir)
        .and_then(|()| fs::write(&f, "x"))
        .is_err()
    {
        eprintln!("skipping: cannot create files in ProgramData");
        let _ = fs::remove_dir_all(&dir);
        return;
    }

    let mut ui = FakeUi::new();
    ui.confirm_protected = false;
    let mut sys = FakeSystem::new();
    let code = run(Command::Delete(vec![f.clone()]), &mut ui, &mut sys);
    let kept = f.exists();

    let mut ui2 = FakeUi::new();
    ui2.confirm_protected = true;
    let code2 = run(Command::Delete(vec![f.clone()]), &mut ui2, &mut sys);
    let gone = !f.exists();
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(code, 0);
    assert!(kept);
    assert_eq!(ui.protected_calls.len(), 1);
    assert!(ui.delete_calls.is_empty());
    assert_eq!(code2, 0);
    assert!(gone);
    assert_eq!(ui2.protected_calls.len(), 1);
    assert!(ui2.delete_calls.is_empty());
    assert!(ui2.errors.is_empty());
}

#[test]
fn access_denied_not_elevated_relaunches() {
    let dir = tempfile::tempdir().unwrap();
    let (root, file, _guard) = denied_file(dir.path());
    let mut ui = FakeUi::new();
    ui.confirm_elevate = true;
    let mut sys = FakeSystem::new();
    assert_eq!(
        run(Command::Delete(vec![root.clone()]), &mut ui, &mut sys),
        0
    );
    assert_eq!(ui.elevate_calls, vec![vec![root.clone()]]);
    assert_eq!(sys.relaunches, vec![vec![root]]);
    assert!(sys.ownership.is_empty());
    assert!(ui.errors.is_empty());
    assert!(ui.infos.is_empty());
    assert!(file.exists());
}

#[test]
fn access_denied_relaunch_exit_code_is_returned_as_is() {
    struct CodeSystem(FakeSystem);
    // A relaunch that reports a failing exit code from the elevated child.
    impl System for CodeSystem {
        fn is_installed(&self) -> bool {
            self.0.is_installed()
        }
        fn install(&mut self) -> io::Result<()> {
            self.0.install()
        }
        fn uninstall(&mut self) -> io::Result<()> {
            self.0.uninstall()
        }
        fn find_lockers(&mut self, p: &[PathBuf]) -> Vec<LockingProcess> {
            self.0.find_lockers(p)
        }
        fn kill(&mut self, pid: u32) -> io::Result<()> {
            self.0.kill(pid)
        }
        fn is_elevated(&self) -> bool {
            self.0.is_elevated()
        }
        fn relaunch_elevated(&mut self, _paths: &[PathBuf]) -> io::Result<i32> {
            Ok(7)
        }
        fn take_ownership(&mut self, p: &Path) -> Vec<(PathBuf, io::Error)> {
            self.0.take_ownership(p)
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let (root, _file, _guard) = denied_file(dir.path());
    let mut ui = FakeUi::new();
    ui.confirm_elevate = true;
    let mut sys = CodeSystem(FakeSystem::new());
    assert_eq!(run(Command::Delete(vec![root]), &mut ui, &mut sys), 7);
    assert!(ui.errors.is_empty());
}

#[test]
fn access_denied_uac_declined() {
    let dir = tempfile::tempdir().unwrap();
    let (root, _file, _guard) = denied_file(dir.path());
    let mut ui = FakeUi::new();
    ui.confirm_elevate = true;
    let mut sys = FakeSystem::new();
    sys.relaunch_error = Some(1223);
    assert_eq!(run(Command::Delete(vec![root]), &mut ui, &mut sys), 1);
    assert_eq!(
        ui.errors,
        vec!["Admin permission was declined.".to_string()]
    );
}

#[test]
fn access_denied_decline_elevate_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (root, file, _guard) = denied_file(dir.path());
    let mut ui = FakeUi::new();
    ui.confirm_elevate = false;
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::Delete(vec![root]), &mut ui, &mut sys), 1);
    assert!(sys.relaunches.is_empty());
    assert_eq!(ui.errors.len(), 1);
    assert!(ui.errors[0].starts_with("Couldn't delete:"));
    assert!(file.exists());
}

#[test]
fn access_denied_elevated_takes_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let (root, file, _guard) = denied_file(dir.path());
    let mut ui = FakeUi::new();
    let mut sys = FakeSystem::new();
    sys.elevated = true;
    assert_eq!(
        run(Command::Delete(vec![root.clone()]), &mut ui, &mut sys),
        0
    );
    assert_eq!(sys.ownership.len(), 1);
    assert!(sys.ownership[0].ends_with("f.txt"));
    assert!(ui.elevate_calls.is_empty());
    assert!(sys.relaunches.is_empty());
    assert!(ui.errors.is_empty());
    assert!(!file.exists());
    assert!(!root.exists());
}

#[test]
fn elevated_delete_skips_confirm() {
    let (_dir, f) = temp_file();
    let mut ui = FakeUi::new();
    ui.confirm_delete = false;
    ui.confirm_protected = false;
    let mut sys = FakeSystem::new();
    assert_eq!(
        run(Command::ElevatedDelete(vec![f.clone()]), &mut ui, &mut sys),
        0
    );
    assert!(!f.exists());
    assert!(ui.no_confirmations_asked());
    assert!(ui.infos.is_empty());
    assert!(ui.errors.is_empty());
}

#[test]
fn elevated_delete_reports_errors() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.txt");
    let mut ui = FakeUi::new();
    let mut sys = FakeSystem::new();
    assert_eq!(
        run(Command::ElevatedDelete(vec![missing]), &mut ui, &mut sys),
        1
    );
    assert_eq!(ui.errors.len(), 1);
}

#[test]
fn error_dialog_lists_at_most_ten_paths() {
    let dir = tempfile::tempdir().unwrap();
    let paths: Vec<PathBuf> = (0..12)
        .map(|i| dir.path().join(format!("missing{i}.txt")))
        .collect();
    let mut ui = FakeUi::new();
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::ElevatedDelete(paths), &mut ui, &mut sys), 1);
    assert_eq!(ui.errors.len(), 1);
    assert_eq!(ui.errors[0].matches("doesn't exist").count(), 10);
}

#[test]
fn install_and_uninstall_from_menu() {
    let mut ui = FakeUi::new();
    ui.menu = MenuChoice::Install;
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::Menu, &mut ui, &mut sys), 0);
    assert_eq!(sys.installs, 1);
    assert_eq!(ui.infos, vec!["Added to the right-click menu.".to_string()]);

    let mut ui = FakeUi::new();
    ui.menu = MenuChoice::Uninstall;
    assert_eq!(run(Command::Menu, &mut ui, &mut sys), 0);
    assert_eq!(sys.uninstalls, 1);
    assert_eq!(
        ui.infos,
        vec!["Removed from the right-click menu.".to_string()]
    );
}

#[test]
fn install_and_uninstall_commands() {
    let mut ui = FakeUi::new();
    let mut sys = FakeSystem::new();
    assert_eq!(run(Command::Install, &mut ui, &mut sys), 0);
    assert_eq!(run(Command::Uninstall, &mut ui, &mut sys), 0);
    assert_eq!((sys.installs, sys.uninstalls), (1, 1));
    assert_eq!(ui.infos.len(), 2);
    assert!(ui.menu_calls.is_empty());
}

#[test]
fn install_failure_shows_error() {
    struct FailInstall;
    impl System for FailInstall {
        fn is_installed(&self) -> bool {
            false
        }
        fn install(&mut self) -> io::Result<()> {
            Err(io::Error::other("boom"))
        }
        fn uninstall(&mut self) -> io::Result<()> {
            Err(io::Error::other("bang"))
        }
        fn find_lockers(&mut self, _: &[PathBuf]) -> Vec<LockingProcess> {
            Vec::new()
        }
        fn kill(&mut self, _: u32) -> io::Result<()> {
            Ok(())
        }
        fn is_elevated(&self) -> bool {
            false
        }
        fn relaunch_elevated(&mut self, _: &[PathBuf]) -> io::Result<i32> {
            Ok(0)
        }
        fn take_ownership(&mut self, _: &Path) -> Vec<(PathBuf, io::Error)> {
            Vec::new()
        }
    }

    let mut ui = FakeUi::new();
    assert_eq!(run(Command::Install, &mut ui, &mut FailInstall), 1);
    assert_eq!(run(Command::Uninstall, &mut ui, &mut FailInstall), 1);
    assert_eq!(ui.errors.len(), 2);
    assert!(ui.errors[0].contains("boom"));
    assert!(ui.errors[1].contains("bang"));
    assert!(ui.infos.is_empty());
}
