//! Real Windows dialogs behind the [`Ui`] trait: TaskDialogs plus `rfd` pickers.

use std::path::PathBuf;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOG_COMMON_BUTTON_FLAGS, TASKDIALOG_NOTIFICATIONS, TASKDIALOGCONFIG,
    TASKDIALOGCONFIG_0, TD_ERROR_ICON, TD_INFORMATION_ICON, TD_SHIELD_ICON, TD_WARNING_ICON,
    TDCBF_OK_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION, TDF_USE_COMMAND_LINKS,
    TDM_SET_BUTTON_ELEVATION_REQUIRED_STATE, TDN_CREATED, TaskDialogIndirect,
};
use windows::Win32::UI::WindowsAndMessaging::{IDCANCEL, SendMessageW};
use windows::core::{HRESULT, PCWSTR};

use crate::app::{MenuChoice, Ui, display_path};
use crate::delete::is_protected;
use crate::locks::LockingProcess;

const TITLE: &str = "Fckn Delete";
/// Most paths listed in one dialog.
const MAX_LISTED: usize = 10;

const ID_PICK_FILE: i32 = 1001;
const ID_PICK_FOLDER: i32 = 1002;
const ID_TOGGLE_INSTALL: i32 = 1003;
/// The affirmative button of a two-button confirmation.
const ID_ACCEPT: i32 = 1101;
const ID_CANCEL: i32 = 1102;

/// [`Ui`] backed by real Windows dialogs.
pub struct WinUi;

/// A TaskDialog to show. Texts are borrowed; `show` keeps their UTF-16 copies
/// alive for the whole `TaskDialogIndirect` call.
struct Dialog<'a> {
    icon: PCWSTR,
    instruction: Option<&'a str>,
    content: &'a str,
    /// Custom buttons as `(id, text)`; empty means a plain OK button.
    buttons: &'a [(i32, &'a str)],
    /// Button preselected when the dialog opens (0 = the system default).
    default_button: i32,
    command_links: bool,
    /// Button that gets the UAC shield.
    shield_button: Option<i32>,
}

impl Dialog<'_> {
    /// Shows the dialog and returns the pressed button id; closing the
    /// dialog (or a failure to show it) is `IDCANCEL`.
    fn show(&self) -> i32 {
        let title = wide(TITLE);
        let instruction = self.instruction.map(wide);
        let content = wide(&wrap_long_lines(self.content));
        let button_texts: Vec<Vec<u16>> = self
            .buttons
            .iter()
            // `&` marks a mnemonic in button text; `&&` shows a literal one.
            .map(|(_, t)| wide(&t.replace('&', "&&")))
            .collect();
        let buttons: Vec<TASKDIALOG_BUTTON> = self
            .buttons
            .iter()
            .zip(&button_texts)
            .map(|((id, _), text)| TASKDIALOG_BUTTON {
                nButtonID: *id,
                pszButtonText: PCWSTR(text.as_ptr()),
            })
            .collect();

        let mut flags = TDF_ALLOW_DIALOG_CANCELLATION;
        if self.command_links {
            flags |= TDF_USE_COMMAND_LINKS;
        }
        let common_buttons = if buttons.is_empty() {
            TDCBF_OK_BUTTON
        } else {
            TASKDIALOG_COMMON_BUTTON_FLAGS(0)
        };

        let config = TASKDIALOGCONFIG {
            cbSize: size_of::<TASKDIALOGCONFIG>() as u32,
            dwFlags: flags,
            dwCommonButtons: common_buttons,
            pszWindowTitle: PCWSTR(title.as_ptr()),
            Anonymous1: TASKDIALOGCONFIG_0 {
                pszMainIcon: self.icon,
            },
            pszMainInstruction: instruction
                .as_ref()
                .map_or(PCWSTR::null(), |i| PCWSTR(i.as_ptr())),
            pszContent: PCWSTR(content.as_ptr()),
            cButtons: buttons.len() as u32,
            pButtons: buttons.as_ptr(),
            nDefaultButton: self.default_button,
            pfCallback: Some(on_notification),
            lpCallbackData: self.shield_button.unwrap_or(0) as isize,
            ..Default::default()
        };

        let mut pressed = IDCANCEL.0;
        // SAFETY: `config` points at buffers (`title`, `instruction`,
        // `content`, `button_texts`, `buttons`) that all outlive this call,
        // and `pressed` is a valid out pointer.
        let shown = unsafe { TaskDialogIndirect(&config, Some(&mut pressed), None, None) };
        if shown.is_err() {
            return IDCANCEL.0;
        }
        pressed
    }
}

/// Dialog callback: puts the UAC shield on the button named by the callback
/// data once the dialog exists.
unsafe extern "system" fn on_notification(
    hwnd: HWND,
    notification: TASKDIALOG_NOTIFICATIONS,
    _wparam: WPARAM,
    _lparam: LPARAM,
    shield_button: isize,
) -> HRESULT {
    if notification == TDN_CREATED && shield_button != 0 {
        // SAFETY: `hwnd` is the live task dialog this callback was invoked for.
        unsafe {
            SendMessageW(
                hwnd,
                TDM_SET_BUTTON_ELEVATION_REQUIRED_STATE.0 as u32,
                Some(WPARAM(shield_button as usize)),
                Some(LPARAM(1)),
            );
        }
    }
    HRESULT(0)
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// Longest line TaskDialog content may have before it is hard-wrapped.
/// TaskDialog ellipsizes (rather than wraps) a single line wider than the
/// content area, which would hide part of a path in a destructive prompt.
const WRAP_WIDTH: usize = 48;

/// Hard-wraps every line longer than [`WRAP_WIDTH`] characters by inserting
/// `\n` right after the last `\` within the first [`WRAP_WIDTH`] characters,
/// or at [`WRAP_WIDTH`] when there is none. Existing newlines are kept.
pub(crate) fn wrap_long_lines(text: &str) -> String {
    let mut out = Vec::new();
    for line in text.split('\n') {
        let mut rest: Vec<char> = line.chars().collect();
        while rest.len() > WRAP_WIDTH {
            let cut = rest[..WRAP_WIDTH]
                .iter()
                .rposition(|&c| c == '\\')
                .map_or(WRAP_WIDTH, |i| i + 1);
            out.push(rest[..cut].iter().collect::<String>());
            rest.drain(..cut);
        }
        out.push(rest.into_iter().collect());
    }
    out.join("\n")
}

/// Up to [`MAX_LISTED`] paths, one per line, plus a count of the rest.
fn path_list(paths: &[PathBuf]) -> String {
    let mut lines: Vec<String> = paths
        .iter()
        .take(MAX_LISTED)
        .map(|p| display_path(p))
        .collect();
    if paths.len() > MAX_LISTED {
        lines.push(format!("…and {} more", paths.len() - MAX_LISTED));
    }
    lines.join("\n")
}

/// Two-button confirmation whose default button is Cancel.
fn confirm(
    icon: PCWSTR,
    instruction: &str,
    content: &str,
    accept_text: &str,
    shield_accept: bool,
) -> bool {
    Dialog {
        icon,
        instruction: Some(instruction),
        content,
        buttons: &[(ID_ACCEPT, accept_text), (ID_CANCEL, "Cancel")],
        default_button: ID_CANCEL,
        command_links: false,
        shield_button: shield_accept.then_some(ID_ACCEPT),
    }
    .show()
        == ID_ACCEPT
}

impl Ui for WinUi {
    fn main_menu(&mut self, installed: bool) -> MenuChoice {
        let toggle = if installed {
            "Remove \"Fckn Delete\" from the right-click menu"
        } else {
            "Add \"Fckn Delete\" to the right-click menu"
        };
        let pressed = Dialog {
            icon: PCWSTR::null(),
            instruction: Some("What do you want to Fckn Delete?"),
            content: "",
            buttons: &[
                (ID_PICK_FILE, "Pick a file"),
                (ID_PICK_FOLDER, "Pick a folder"),
                (ID_TOGGLE_INSTALL, toggle),
            ],
            default_button: ID_PICK_FILE,
            command_links: true,
            shield_button: None,
        }
        .show();
        match pressed {
            ID_PICK_FILE => MenuChoice::PickFile,
            ID_PICK_FOLDER => MenuChoice::PickFolder,
            ID_TOGGLE_INSTALL if installed => MenuChoice::Uninstall,
            ID_TOGGLE_INSTALL => MenuChoice::Install,
            _ => MenuChoice::Cancel,
        }
    }

    fn pick_file(&mut self) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .set_title("Pick a file to Fckn Delete")
            .pick_file()
    }

    fn pick_folder(&mut self) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .set_title("Pick a folder to Fckn Delete")
            .pick_folder()
    }

    fn confirm_delete(&mut self, paths: &[PathBuf]) -> bool {
        let content = format!(
            "{}\n\nIt skips the Recycle Bin and can't be undone.",
            path_list(paths)
        );
        confirm(
            TD_WARNING_ICON,
            "Permanently delete this?",
            &content,
            "Fckn Delete",
            false,
        )
    }

    fn confirm_protected(&mut self, paths: &[PathBuf]) -> bool {
        // Protected paths first, so the list's cut-off never hides them.
        let mut ordered = paths.to_vec();
        ordered.sort_by_key(|p| !is_protected(p));
        let content = format!(
            "{}\n\nDeleting this can break Windows or your apps, and it can't be undone. \
             Only continue if you're absolutely sure.",
            path_list(&ordered)
        );
        confirm(
            TD_ERROR_ICON,
            "WARNING: This is a protected system location",
            &content,
            "Proceed",
            false,
        )
    }

    fn confirm_kill(&mut self, procs: &[LockingProcess]) -> bool {
        let content = procs
            .iter()
            .map(|p| format!("{} (PID {})", p.name, p.pid))
            .collect::<Vec<_>>()
            .join("\n");
        confirm(
            TD_WARNING_ICON,
            "These programs are using it:",
            &content,
            "Close them & delete",
            false,
        )
    }

    fn confirm_elevate(&mut self, paths: &[PathBuf]) -> bool {
        let content = format!(
            "{}\n\nFckn Delete can take ownership of them as an administrator and then delete them.",
            path_list(paths)
        );
        confirm(
            TD_SHIELD_ICON,
            "Some items need admin rights",
            &content,
            "Take ownership & delete",
            true,
        )
    }

    fn info(&mut self, msg: &str) {
        Dialog {
            icon: TD_INFORMATION_ICON,
            instruction: None,
            content: msg,
            buttons: &[],
            default_button: 0,
            command_links: false,
            shield_button: None,
        }
        .show();
    }

    fn error(&mut self, msg: &str) {
        Dialog {
            icon: TD_ERROR_ICON,
            instruction: None,
            content: msg,
            buttons: &[],
            default_button: 0,
            command_links: false,
            shield_button: None,
        }
        .show();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_path() -> String {
        let dir = "abcdefghij";
        let path = format!(r"C:\{}", [dir; 10].join(r"\"));
        assert!(path.len() >= 100);
        path
    }

    #[test]
    fn long_path_wraps_after_backslashes_within_width() {
        let path = long_path();
        let wrapped = wrap_long_lines(&path);
        let lines: Vec<&str> = wrapped.split('\n').collect();
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.chars().count() <= WRAP_WIDTH, "too long: {line}");
        }
        for line in &lines[..lines.len() - 1] {
            assert!(line.ends_with('\\'), "break not after a backslash: {line}");
        }
        assert_eq!(wrapped.replace('\n', ""), path);
    }

    #[test]
    fn long_run_without_backslash_breaks_at_width() {
        let text = "x".repeat(WRAP_WIDTH * 2 + 5);
        let wrapped = wrap_long_lines(&text);
        let lens: Vec<usize> = wrapped.split('\n').map(|l| l.chars().count()).collect();
        assert_eq!(lens, vec![WRAP_WIDTH, WRAP_WIDTH, 5]);
        assert_eq!(wrapped.replace('\n', ""), text);
    }

    #[test]
    fn short_lines_and_existing_newlines_are_preserved() {
        let text = "C:\\short\n\nIt skips the Recycle Bin.";
        assert_eq!(wrap_long_lines(text), text);
        let mixed = format!("first\n{}\nlast", long_path());
        let wrapped = wrap_long_lines(&mixed);
        assert!(wrapped.starts_with("first\n") && wrapped.ends_with("\nlast"));
        assert_eq!(wrapped.replace('\n', ""), mixed.replace('\n', ""));
    }
}
