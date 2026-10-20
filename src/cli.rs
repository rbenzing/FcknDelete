//! Command-line parsing.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// What the process was asked to do.
#[derive(Debug, PartialEq)]
pub enum Command {
    Menu,
    Delete(Vec<PathBuf>),
    ElevatedDelete(Vec<PathBuf>),
    Install,
    Uninstall,
}

fn is_flag(arg: &OsStr) -> bool {
    arg.to_string_lossy().starts_with("--")
}

/// Parses the process arguments (excluding argv[0]).
///
/// The first argument may be `--install`, `--uninstall` or `--elevated`
/// (the latter needs at least one path). Any other `--` argument yields
/// [`Command::Menu`]; otherwise every argument is a path to delete.
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Command {
    let mut args = args.into_iter().peekable();
    let Some(first) = args.peek() else {
        return Command::Menu;
    };
    if first == "--install" {
        return Command::Install;
    }
    if first == "--uninstall" {
        return Command::Uninstall;
    }
    let elevated = first == "--elevated";
    if elevated {
        args.next();
    }
    let args: Vec<OsString> = args.collect();
    if args.is_empty() || args.iter().any(|a| is_flag(a)) {
        return Command::Menu;
    }
    let paths = args.into_iter().map(PathBuf::from).collect();
    if elevated {
        Command::ElevatedDelete(paths)
    } else {
        Command::Delete(paths)
    }
}
