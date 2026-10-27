//! Parsing and restoration decisions for macOS networksetup SOCKS settings.
//! These functions do not modify system configuration.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocksSettings {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
    pub authenticated: bool,
}

pub fn parse_socks_settings(output: &str) -> Result<SocksSettings, String> {
    let field = |name: &str| -> Result<&str, String> {
        let mut found = output
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| key.trim() == name)
            .map(|(_, value)| value.trim());
        let result = found
            .next()
            .ok_or_else(|| format!("Missing networksetup field: {name}"))?;
        if found.next().is_some() {
            return Err(format!("Duplicate networksetup field: {name}"));
        }
        Ok(result)
    };
    let enabled = match field("Enabled")? {
        "Yes" => true,
        "No" => false,
        _ => return Err("Invalid proxy state".into()),
    };
    let authenticated = match field("Authenticated Proxy Enabled")? {
        "1" => true,
        "0" => false,
        _ => return Err("Invalid authentication state".into()),
    };
    let server = field("Server")?.to_owned();
    let port = field("Port")?
        .parse::<u16>()
        .map_err(|_| "Invalid proxy port")?;
    if enabled && (server.is_empty() || port == 0) {
        return Err("Enabled proxy has no address".into());
    }
    Ok(SocksSettings {
        enabled,
        server,
        port,
        authenticated,
    })
}

/// Restore only while the system still contains exactly the values we set.
pub fn can_restore(current: &SocksSettings, applied_port: u16) -> bool {
    current.enabled
        && !current.authenticated
        && current.server == "127.0.0.1"
        && current.port == applied_port
        && applied_port != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_realistic_disabled_and_enabled_values() {
        let s = parse_socks_settings(
            "Enabled: No\nServer: 127.0.0.1\nPort: 10808\nAuthenticated Proxy Enabled: 0\n",
        )
        .unwrap();
        assert!(!s.enabled);
        assert_eq!(s.port, 10808);
        let s = parse_socks_settings(
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 12345\nAuthenticated Proxy Enabled: 0\n",
        )
        .unwrap();
        assert!(can_restore(&s, 12345));
        assert!(!can_restore(&s, 12346));
    }
    #[test]
    fn refuses_ambiguous_or_incomplete_output() {
        assert!(parse_socks_settings("Enabled: Yes\nEnabled: No\nServer: localhost\nPort: 80\nAuthenticated Proxy Enabled: 0\n").is_err());
        assert!(parse_socks_settings(
            "Enabled: Yes\nServer: localhost\nPort: bad\nAuthenticated Proxy Enabled: 0\n"
        )
        .is_err());
        assert!(parse_socks_settings(
            "Enabled: Yes\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n"
        )
        .is_err());
    }
}

/// A pending transaction is retained on disk until restoration succeeds.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyJournal {
    pub service: String,
    pub original: SocksSettings,
    pub applied_port: u16,
}

pub trait NetworkSetup {
    fn read(&self, service: &str) -> Result<SocksSettings, String>;
    fn set_address(&self, service: &str, server: &str, port: u16) -> Result<(), String>;
    fn set_enabled(&self, service: &str, enabled: bool) -> Result<(), String>;
}

pub struct MacNetworkSetup;
impl MacNetworkSetup {
    fn run(args: &[&str]) -> Result<String, String> {
        let output = std::process::Command::new("/usr/sbin/networksetup")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "networksetup failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        String::from_utf8(output.stdout).map_err(|_| "networksetup returned invalid UTF-8".into())
    }
}
impl NetworkSetup for MacNetworkSetup {
    fn read(&self, service: &str) -> Result<SocksSettings, String> {
        parse_socks_settings(&Self::run(&["-getsocksfirewallproxy", service])?)
    }
    fn set_address(&self, service: &str, server: &str, port: u16) -> Result<(), String> {
        Self::run(&["-setsocksfirewallproxy", service, server, &port.to_string()]).map(|_| ())
    }
    fn set_enabled(&self, service: &str, enabled: bool) -> Result<(), String> {
        Self::run(&[
            "-setsocksfirewallproxystate",
            service,
            if enabled { "on" } else { "off" },
        ])
        .map(|_| ())
    }
}

pub fn apply_proxy(
    ops: &impl NetworkSetup,
    journal_path: &std::path::Path,
    service: &str,
    port: u16,
) -> Result<(), String> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    if service.trim().is_empty() || port == 0 {
        return Err("Missing network service or port".into());
    }
    let original = ops.read(service)?;
    if original.authenticated {
        return Err("Authenticated proxy restoration is not supported".into());
    }
    if original.server.is_empty() || original.port == 0 {
        return Err("Cannot preserve the existing proxy address; no changes made".into());
    }
    let journal = ProxyJournal {
        service: service.into(),
        original,
        applied_port: port,
    };
    let parent = journal_path.parent().ok_or("Invalid journal path")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(journal_path)
        .map_err(|e| format!("Cannot create proxy recovery journal: {e}"))?;
    let data = serde_json::to_vec(&journal).map_err(|e| e.to_string())?;
    file.write_all(&data)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("Cannot persist proxy recovery journal: {e}"))?;
    drop(file);
    ops.set_address(service, "127.0.0.1", port)?;
    let current = ops.read(service)?;
    if !can_restore(&current, port) {
        return Err(
            "Proxy configuration did not match expected values; recovery journal retained".into(),
        );
    }
    Ok(())
}

pub fn proxy_is_active(journal_path: &std::path::Path) -> Result<bool, String> {
    let data = std::fs::read(journal_path).map_err(|e| e.to_string())?;
    let journal: ProxyJournal = serde_json::from_slice(&data).map_err(|_| "Invalid proxy recovery journal")?;
    let current = MacNetworkSetup.read(&journal.service)?;
    if !can_restore(&current, journal.applied_port) { return Ok(false); }
    Ok(std::net::TcpStream::connect(("127.0.0.1", journal.applied_port)).is_ok())
}

pub fn restore_proxy(
    ops: &impl NetworkSetup,
    journal_path: &std::path::Path,
) -> Result<(), String> {
    let data = std::fs::read(journal_path)
        .map_err(|e| format!("Cannot read proxy recovery journal: {e}"))?;
    let journal: ProxyJournal =
        serde_json::from_slice(&data).map_err(|_| "Invalid proxy recovery journal")?;
    let current = ops.read(&journal.service)?;
    if current == journal.original {
        std::fs::remove_file(journal_path).map_err(|e| e.to_string())?;
        return Ok(());
    }
    let intermediate = !journal.original.enabled
        && current.enabled
        && !current.authenticated
        && current.server == journal.original.server
        && current.port == journal.original.port;
    if !can_restore(&current, journal.applied_port) && !intermediate {
        return Err("Proxy was changed by another process; recovery journal retained".into());
    }
    ops.set_address(
        &journal.service,
        &journal.original.server,
        journal.original.port,
    )?;
    ops.set_enabled(&journal.service, journal.original.enabled)?;
    if ops.read(&journal.service)? != journal.original {
        return Err("Proxy restore verification failed; recovery journal retained".into());
    }
    std::fs::remove_file(journal_path).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod transaction_tests {
    use super::*;
    use std::sync::Mutex;
    struct Mock(Mutex<SocksSettings>);
    impl NetworkSetup for Mock {
        fn read(&self, _: &str) -> Result<SocksSettings, String> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn set_address(&self, _: &str, server: &str, port: u16) -> Result<(), String> {
            let mut s = self.0.lock().unwrap();
            s.server = server.into();
            s.port = port;
            s.enabled = true;
            Ok(())
        }
        fn set_enabled(&self, _: &str, enabled: bool) -> Result<(), String> {
            self.0.lock().unwrap().enabled = enabled;
            Ok(())
        }
    }
    fn original() -> SocksSettings {
        SocksSettings {
            enabled: false,
            server: "old.example".into(),
            port: 1234,
            authenticated: false,
        }
    }
    #[test]
    fn applies_and_restores_exact_original_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let ops = Mock(Mutex::new(original()));
        apply_proxy(&ops, &path, "Wi-Fi", 4321).unwrap();
        assert!(path.exists());
        assert!(can_restore(&ops.read("Wi-Fi").unwrap(), 4321));
        restore_proxy(&ops, &path).unwrap();
        assert_eq!(ops.read("Wi-Fi").unwrap(), original());
        assert!(!path.exists());
    }
    #[test]
    fn does_not_overwrite_external_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let ops = Mock(Mutex::new(original()));
        apply_proxy(&ops, &path, "Wi-Fi", 4321).unwrap();
        ops.set_address("Wi-Fi", "elsewhere", 3333).unwrap();
        assert!(restore_proxy(&ops, &path).is_err());
        assert!(path.exists());
        assert_eq!(ops.read("Wi-Fi").unwrap().server, "elsewhere");
    }
    #[test]
    fn resumes_interrupted_restore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let ops = Mock(Mutex::new(original()));
        apply_proxy(&ops, &path, "Wi-Fi", 4321).unwrap();
        ops.set_address("Wi-Fi", "old.example", 1234).unwrap();
        restore_proxy(&ops, &path).unwrap();
        assert_eq!(ops.read("Wi-Fi").unwrap(), original());
    }
}
