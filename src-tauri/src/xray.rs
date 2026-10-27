pub use vpn_core::xray::XrayState;

pub fn connect_profile_inner(
    state: &XrayState,
    tray: &tauri::State<'_, crate::tray::TrayStatus>,
    inbound_id: u64,
    email: &str,
) -> Result<String, String> {
    if crate::helper::status().unwrap_or(false) {
        crate::tray::update(tray, true)?;
        return Ok("VPN уже подключён через TUN.".into());
    }
    // Stop a legacy unprivileged Xray process before handing TUN ownership to the helper.
    if vpn_core::xray::has_running_process() && !vpn_core::xray::is_tun_process() {
        vpn_core::xray::stop(state)?;
    }
    let proxy_journal = journal_path()?;
    if proxy_journal.exists() {
        vpn_core::proxy::restore_proxy(&vpn_core::proxy::MacNetworkSetup, &proxy_journal)?;
    }
    let link = vpn_core::cached_client_share_link(inbound_id, email)?;
    let result = crate::helper::start(&link)?;
    crate::tray::update(tray, true)?;
    Ok(result)
}

pub fn stop_vpn_inner(
    state: &XrayState,
    tray: &tauri::State<'_, crate::tray::TrayStatus>,
) -> Result<(), String> {
    if crate::helper::status().is_ok() {
        crate::helper::stop()?;
    }
    let path = journal_path()?;
    if path.exists() {
        vpn_core::proxy::restore_proxy(&vpn_core::proxy::MacNetworkSetup, &path)?;
    }
    if vpn_core::xray::has_running_process() {
        vpn_core::xray::stop(state)?;
    }
    crate::tray::update(tray, false)
}

#[tauri::command]
pub fn xray_start(
    state: tauri::State<'_, XrayState>,
    executable: String,
    link: String,
    tray: tauri::State<'_, crate::tray::TrayStatus>,
) -> Result<String, String> {
    let result = vpn_core::xray::start(&state, executable, link)?;
    crate::tray::update(&tray, true)?;
    Ok(result)
}

#[tauri::command]
pub fn xray_stop(
    state: tauri::State<'_, XrayState>,
    tray: tauri::State<'_, crate::tray::TrayStatus>,
) -> Result<(), String> {
    stop_vpn_inner(&state, &tray)
}

pub fn journal_path() -> Result<std::path::PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    Ok(std::path::PathBuf::from(home)
        .join("Library/Application Support/VpnClient/proxy-journal.json"))
}

#[tauri::command]
pub fn proxy_enable(
    state: tauri::State<'_, XrayState>,
    tray: tauri::State<'_, crate::tray::TrayStatus>,
    service: String,
) -> Result<(), String> {
    let path = journal_path()?;
    if path.exists() {
        if vpn_core::proxy::proxy_is_active(&path)? {
            return crate::tray::update(&tray, true);
        }
        return Err("Сначала восстановите предыдущие настройки прокси".into());
    }
    let port = vpn_core::xray::active_port(&state)?;
    vpn_core::proxy::apply_proxy(&vpn_core::proxy::MacNetworkSetup, &path, &service, port)?;
    crate::tray::update(&tray, true)
}

#[tauri::command]
pub fn proxy_recover() -> Result<(), String> {
    let path = journal_path()?;
    if !path.exists() {
        return Ok(());
    }
    vpn_core::proxy::restore_proxy(&vpn_core::proxy::MacNetworkSetup, &path)
}

#[tauri::command]
pub fn proxy_recovery_needed() -> Result<bool, String> {
    Ok(journal_path()?.exists())
}
