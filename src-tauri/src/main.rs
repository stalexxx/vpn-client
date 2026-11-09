// The Windows build is a GUI-subsystem executable (no console window).
#![cfg_attr(windows, windows_subsystem = "windows")]

mod probes;
#[cfg(target_os = "macos")]
mod awg;
#[cfg(not(windows))] mod tray;
#[cfg(not(windows))] mod install;
#[cfg(not(windows))] mod helper;
#[cfg(not(windows))] mod xray;
#[cfg(not(windows))] mod control;
#[cfg(not(windows))] mod mac;
#[cfg(windows)] mod win;

#[cfg(not(windows))]
pub(crate) use mac::open_admin_window;

fn main() {
    #[cfg(not(windows))] mac::main();
    #[cfg(windows)] win::main();
}
