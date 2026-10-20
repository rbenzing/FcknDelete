#![windows_subsystem = "windows"]

use fckn_delete::system::WinSystem;
use fckn_delete::ui::WinUi;
use fckn_delete::{app, cli};

fn main() {
    let command = cli::parse(std::env::args_os().skip(1));
    std::process::exit(app::run(command, &mut WinUi, &mut WinSystem));
}
