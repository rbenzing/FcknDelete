use fckn_delete::cli::{Command, parse};
use std::{ffi::OsString, path::PathBuf};

fn p(a: &[&str]) -> Command {
    parse(a.iter().map(OsString::from))
}

#[test]
fn no_args_is_menu() {
    assert_eq!(p(&[]), Command::Menu);
}

#[test]
fn install_flag() {
    assert_eq!(p(&["--install"]), Command::Install);
}

#[test]
fn uninstall_flag() {
    assert_eq!(p(&["--uninstall"]), Command::Uninstall);
}

#[test]
fn paths_are_delete() {
    assert_eq!(
        p(&[r"C:\a", r"D:\b c"]),
        Command::Delete(vec![PathBuf::from(r"C:\a"), PathBuf::from(r"D:\b c")])
    );
}

#[test]
fn parses_path_with_spaces_and_unicode() {
    assert_eq!(
        p(&[r"C:\My Files\naïve 日本.txt"]),
        Command::Delete(vec![PathBuf::from(r"C:\My Files\naïve 日本.txt")])
    );
}

#[test]
fn unknown_flag_is_menu() {
    assert_eq!(p(&["--bogus"]), Command::Menu);
}

#[test]
fn elevated_flag_with_paths() {
    assert_eq!(
        p(&["--elevated", r"C:\a b\"]),
        Command::ElevatedDelete(vec![PathBuf::from(r"C:\a b\")])
    );
}

#[test]
fn elevated_without_paths_is_menu() {
    assert_eq!(p(&["--elevated"]), Command::Menu);
}
