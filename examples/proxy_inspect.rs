fn main() -> Result<(), String> {
    let service = std::env::args().nth(1).ok_or("missing service")?;
    let result = std::process::Command::new("/usr/sbin/networksetup")
        .args(["-getsocksfirewallproxy", &service])
        .output()
        .map_err(|e| e.to_string())?;
    if !result.status.success() {
        return Err("networksetup failed".into());
    }
    let settings = vpn_core::proxy::parse_socks_settings(
        std::str::from_utf8(&result.stdout).map_err(|e| e.to_string())?,
    )?;
    println!(
        "service={service}, enabled={}, authenticated={}",
        settings.enabled, settings.authenticated
    );
    Ok(())
}
