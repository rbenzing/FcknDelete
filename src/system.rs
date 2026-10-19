//! Real OS side effects behind the [`System`] trait.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use crate::app::System;
use crate::locks::{self, LockingProcess};
use crate::{elevate, registry};

/// [`System`] backed by the registry, Restart Manager and UAC.
pub struct WinSystem;

impl System for WinSystem {
    fn is_installed(&self) -> bool {
        registry::is_installed()
    }

    fn install(&mut self) -> io::Result<()> {
        let dest =
            registry::install_exe(&std::env::current_exe()?, &registry::default_install_dir())?;
        registry::install(&dest)
    }

    fn uninstall(&mut self) -> io::Result<()> {
        registry::uninstall()
    }

    fn find_lockers(&mut self, paths: &[PathBuf]) -> Vec<LockingProcess> {
        locks::find_lockers(paths).unwrap_or_default()
    }

    fn kill(&mut self, pid: u32) -> io::Result<()> {
        locks::kill(pid)
    }

    fn is_elevated(&self) -> bool {
        elevate::is_elevated()
    }

    fn relaunch_elevated(&mut self, paths: &[PathBuf]) -> io::Result<i32> {
        let mut args: Vec<OsString> = vec![OsString::from("--elevated")];
        args.extend(paths.iter().map(|p| p.as_os_str().to_owned()));
        elevate::relaunch_elevated(&args)
    }

    fn take_ownership(&mut self, path: &Path) -> Vec<(PathBuf, io::Error)> {
        elevate::take_ownership_tree(path)
    }
}
