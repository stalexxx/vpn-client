//! Small portability layer: file-permission helpers that are no-ops where there are no Unix modes.
#[cfg(unix)]
pub use std::os::unix::fs::OpenOptionsExt;

#[cfg(not(unix))]
pub trait OpenOptionsExt { fn mode(&mut self, mode: u32) -> &mut Self; }
#[cfg(not(unix))]
impl OpenOptionsExt for std::fs::OpenOptions { fn mode(&mut self, _mode: u32) -> &mut Self { self } }

/// Make an open file readable/writable by its owner only (`0600`). Per-user profile directories already provide this on Windows.
pub fn restrict_file(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; file.set_permissions(std::fs::Permissions::from_mode(0o600)) }
    #[cfg(not(unix))] { let _ = file; Ok(()) }
}
pub fn restrict_path(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) }
    #[cfg(not(unix))] { let _ = path; Ok(()) }
}

/// Per-user application data directory (`~/Library/Application Support/VpnClient`, `%APPDATA%\VpnClient`).
pub fn data_dir() -> Result<std::path::PathBuf, String> {
    #[cfg(windows)]
    { std::env::var_os("APPDATA").map(|d| std::path::PathBuf::from(d).join("VpnClient")).ok_or_else(|| "APPDATA is unavailable".to_owned()) }
    #[cfg(not(windows))]
    { std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join("Library/Application Support/VpnClient")).ok_or_else(|| "HOME is unavailable".to_owned()) }
}

/// Cryptographically secure random bytes from the OS (`getrandom`: /dev/urandom on Unix, BCryptGenRandom on Windows).
pub fn random_bytes(buf: &mut [u8]) -> Result<(), String> { getrandom::fill(buf).map_err(|e| format!("Не удалось получить случайные байты: {e}")) }
