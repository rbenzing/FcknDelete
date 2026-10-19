//! Application flow: menu, confirmations, delete with lock/admin escalation.
//!
//! All user interaction and OS side effects go through the [`Ui`] and
//! [`System`] traits so the flow can be tested with fakes.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::cli::Command;
use crate::delete::{DeleteError, Failure, force_delete, is_protected};
use crate::locks::LockingProcess;

/// `ERROR_CANCELLED`: the user declined the UAC prompt.
const ERROR_CANCELLED: i32 = 1223;
/// Most paths listed in one dialog.
const MAX_LISTED: usize = 10;

/// What the user picked in the main menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuChoice {
    PickFile,
    PickFolder,
    Install,
    Uninstall,
    Cancel,
}

/// All user interaction. Confirmations return `true` to proceed.
pub trait Ui {
    fn main_menu(&mut self, installed: bool) -> MenuChoice;
    fn pick_file(&mut self) -> Option<PathBuf>;
    fn pick_folder(&mut self) -> Option<PathBuf>;
    fn confirm_delete(&mut self, paths: &[PathBuf]) -> bool;
    fn confirm_protected(&mut self, paths: &[PathBuf]) -> bool;
    fn confirm_kill(&mut self, procs: &[LockingProcess]) -> bool;
    fn confirm_elevate(&mut self, paths: &[PathBuf]) -> bool;
    fn info(&mut self, msg: &str);
    fn error(&mut self, msg: &str);
}

/// OS side effects other than the delete itself.
pub trait System {
    fn is_installed(&self) -> bool;
    fn install(&mut self) -> io::Result<()>;
    fn uninstall(&mut self) -> io::Result<()>;
    fn find_lockers(&mut self, paths: &[PathBuf]) -> Vec<LockingProcess>;
    fn kill(&mut self, pid: u32) -> io::Result<()>;
    fn is_elevated(&self) -> bool;
    /// Runs the elevated copy on `paths` and returns its exit code.
    fn relaunch_elevated(&mut self, paths: &[PathBuf]) -> io::Result<i32>;
    /// Takes ownership of `path`, returning the items that could not be fixed.
    fn take_ownership(&mut self, path: &Path) -> Vec<(PathBuf, io::Error)>;
}

/// Runs `cmd` and returns the process exit code: 0 on success or cancel,
/// 1 on failure (or the elevated child's code after a relaunch).
pub fn run(cmd: Command, ui: &mut dyn Ui, sys: &mut dyn System) -> i32 {
    match cmd {
        Command::Menu => run_menu(ui, sys),
        Command::Delete(paths) => exit_code(delete_flow(&paths, true, ui, sys)),
        Command::ElevatedDelete(paths) => exit_code(delete_flow(&paths, false, ui, sys)),
        Command::Install => install(ui, sys),
        Command::Uninstall => uninstall(ui, sys),
    }
}

fn run_menu(ui: &mut dyn Ui, sys: &mut dyn System) -> i32 {
    let installed = sys.is_installed();
    let picked = match ui.main_menu(installed) {
        MenuChoice::Cancel => return 0,
        MenuChoice::Install => return install(ui, sys),
        MenuChoice::Uninstall => return uninstall(ui, sys),
        MenuChoice::PickFile => ui.pick_file(),
        MenuChoice::PickFolder => ui.pick_folder(),
    };
    let Some(path) = picked else {
        return 0;
    };
    let paths = [path];
    match delete_flow(&paths, true, ui, sys) {
        Flow::Deleted | Flow::Elevated(0) => {
            ui.info(&format!("Fckn deleted:\n{}", paths[0].display()));
            0
        }
        other => exit_code(other),
    }
}

fn install(ui: &mut dyn Ui, sys: &mut dyn System) -> i32 {
    match sys.install() {
        Ok(()) => {
            ui.info("Added to the right-click menu.");
            0
        }
        Err(e) => {
            ui.error(&format!("Couldn't add to the right-click menu:\n{e}"));
            1
        }
    }
}

fn uninstall(ui: &mut dyn Ui, sys: &mut dyn System) -> i32 {
    match sys.uninstall() {
        Ok(()) => {
            ui.info("Removed from the right-click menu.");
            0
        }
        Err(e) => {
            ui.error(&format!("Couldn't remove from the right-click menu:\n{e}"));
            1
        }
    }
}

/// How a delete attempt ended.
enum Flow {
    /// The user declined a confirmation; nothing was deleted.
    Cancelled,
    /// Everything was deleted.
    Deleted,
    /// The run is over with this exit code (errors already shown).
    Exit(i32),
    /// The elevated copy did the work and reported this exit code.
    Elevated(i32),
}

fn exit_code(flow: Flow) -> i32 {
    match flow {
        Flow::Cancelled | Flow::Deleted => 0,
        Flow::Exit(code) | Flow::Elevated(code) => code,
    }
}

/// One user-supplied root and the outcome of the latest attempt at it.
struct Target {
    root: PathBuf,
    result: Result<(), DeleteError>,
}

impl Target {
    fn attempt(root: &Path) -> Target {
        Target {
            root: root.to_path_buf(),
            result: force_delete(root),
        }
    }

    /// Deletes what is left of the root. A root that has vanished meanwhile
    /// counts as deleted.
    fn retry(&mut self) {
        self.result = match force_delete(&self.root) {
            Err(DeleteError::NotFound(_)) => Ok(()),
            other => other,
        };
    }

    fn failures(&self) -> &[Failure] {
        match &self.result {
            Err(DeleteError::Partial(failures)) => failures,
            _ => &[],
        }
    }

    fn has_failure(&self, pred: fn(&Failure) -> bool) -> bool {
        self.failures().iter().any(pred)
    }
}

fn delete_flow(paths: &[PathBuf], confirm: bool, ui: &mut dyn Ui, sys: &mut dyn System) -> Flow {
    if paths.is_empty() {
        return Flow::Cancelled;
    }
    if confirm {
        let proceed = if paths.iter().any(|p| is_protected(p)) {
            ui.confirm_protected(paths)
        } else {
            ui.confirm_delete(paths)
        };
        if !proceed {
            return Flow::Cancelled;
        }
    }

    let mut targets: Vec<Target> = paths.iter().map(|p| Target::attempt(p)).collect();
    close_lockers(&mut targets, ui, sys);
    if let Some(flow) = resolve_access_denied(&mut targets, paths, ui, sys) {
        return flow;
    }
    report(&targets, ui)
}

/// Offers to terminate the processes holding failed items open, then retries
/// the affected roots once.
fn close_lockers(targets: &mut [Target], ui: &mut dyn Ui, sys: &mut dyn System) {
    let locked: Vec<PathBuf> = targets
        .iter()
        .flat_map(Target::failures)
        .filter(|f| f.is_locked())
        // Restart Manager may not match `\\?\` verbatim paths.
        .map(|f| PathBuf::from(display_path(&f.path)))
        .collect();
    if locked.is_empty() {
        return;
    }
    let lockers = sys.find_lockers(&locked);
    if lockers.is_empty() || !ui.confirm_kill(&lockers) {
        return;
    }
    for locker in &lockers {
        // A process that survives shows up as a failure on the retry below.
        let _ = sys.kill(locker.pid);
    }
    for target in targets
        .iter_mut()
        .filter(|t| t.has_failure(Failure::is_locked))
    {
        target.retry();
    }
}

/// Handles items that still fail with "access denied": takes ownership
/// in-process when already elevated, otherwise offers a UAC relaunch.
/// Returns the outcome when the run is finished by a relaunch attempt.
fn resolve_access_denied(
    targets: &mut [Target],
    roots: &[PathBuf],
    ui: &mut dyn Ui,
    sys: &mut dyn System,
) -> Option<Flow> {
    if !targets
        .iter()
        .any(|t| t.has_failure(Failure::is_access_denied))
    {
        return None;
    }

    if sys.is_elevated() {
        for target in targets
            .iter_mut()
            .filter(|t| t.has_failure(Failure::is_access_denied))
        {
            let denied: Vec<PathBuf> = target
                .failures()
                .iter()
                .filter(|f| f.is_access_denied())
                .map(|f| f.path.clone())
                .collect();
            for path in denied {
                // Anything still undeletable shows up as a failure on the retry.
                let _ = sys.take_ownership(&path);
            }
            target.retry();
        }
        return None;
    }

    let existing: Vec<PathBuf> = roots
        .iter()
        .filter(|p| fs::symlink_metadata(p).is_ok())
        .cloned()
        .collect();
    if !ui.confirm_elevate(&existing) {
        return None;
    }
    match sys.relaunch_elevated(&existing) {
        // The elevated child reports its own errors.
        Ok(code) => Some(Flow::Elevated(code)),
        Err(e) if e.raw_os_error() == Some(ERROR_CANCELLED) => {
            ui.error("Admin permission was declined.");
            Some(Flow::Exit(1))
        }
        Err(e) => {
            ui.error(&format!("Couldn't restart with admin rights:\n{e}"));
            Some(Flow::Exit(1))
        }
    }
}

/// Shows one error dialog for everything that is left, if anything is.
fn report(targets: &[Target], ui: &mut dyn Ui) -> Flow {
    let mut lines: Vec<String> = Vec::new();
    for target in targets {
        match &target.result {
            Ok(()) => {}
            Err(DeleteError::NotFound(path)) => {
                lines.push(format!("{} — doesn't exist", path.display()));
            }
            Err(DeleteError::Partial(failures)) => {
                for failure in failures {
                    lines.push(format!(
                        "{} — {}",
                        display_path(&failure.path),
                        reason(&failure.error)
                    ));
                }
            }
        }
    }
    if lines.is_empty() {
        return Flow::Deleted;
    }

    let hidden = lines.len().saturating_sub(MAX_LISTED);
    lines.truncate(MAX_LISTED);
    let mut msg = format!("Couldn't delete:\n{}", lines.join("\n"));
    if hidden > 0 {
        msg.push_str(&format!("\n…and {hidden} more"));
    }
    ui.error(&msg);
    Flow::Exit(1)
}

/// `path` without the `\\?\` verbatim prefix `force_delete` adds.
fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_string()
    }
}

/// The OS message without Rust's trailing ` (os error N)`.
fn reason(error: &io::Error) -> String {
    let text = error.to_string();
    match text.rfind(" (os error ") {
        Some(i) => text[..i].to_string(),
        None => text,
    }
}
