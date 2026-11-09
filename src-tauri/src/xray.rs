pub use vpn_core::xray::XrayState;

pub fn connect_imported_inner(
    state: &XrayState,
    tray: &tauri::State<'_, crate::tray::TrayStatus>,
    id: &str,
) -> Result<String, String> {
    prepare_tun(state, tray)?.map_or_else(|| {
        let link = vpn_core::imported_share_link(id)?;
        let relay = if link.starts_with("hysteria2://") {
            Some(vpn_core::imported_relay_link(id)?.ok_or("Для Hysteria 2 в этой сети нужен доступный VLESS/XHTTP relay: добавьте клиента VLESS/XHTTP на сервере или импортируйте vless-ссылку")?)
        } else if vpn_core::profile::vless_config(&link, 10808)?["outbounds"][0]["streamSettings"]["security"] == "reality" {
            vpn_core::reality_relay_link()?
        } else { None };
        let result = crate::helper::start(&link, relay.as_deref())?;
        crate::tray::update(tray, true)?;
        Ok(result)
    }, Ok)
}

/// Returns `Some(message)` when TUN is already up, otherwise clears legacy proxy state.
fn prepare_tun(
    state: &XrayState,
    tray: &tauri::State<'_, crate::tray::TrayStatus>,
) -> Result<Option<String>, String> {
    // Already connected: the helper switches profiles in place, no legacy cleanup needed.
    if crate::helper::status().unwrap_or(false) { return Ok(None); }
    if vpn_core::xray::has_running_process() && !vpn_core::xray::is_tun_process() {
        vpn_core::xray::stop(state)?;
    }
    let proxy_journal = journal_path()?;
    if proxy_journal.exists() {
        vpn_core::proxy::restore_proxy(&vpn_core::proxy::MacNetworkSetup, &proxy_journal)?;
    }
    Ok(None)
}

pub fn connect_profile_inner(
    state: &XrayState,
    tray: &tauri::State<'_, crate::tray::TrayStatus>,
    server_id: &str,
    inbound_id: u64,
    email: &str,
) -> Result<String, String> {
    // Already connected: the helper switches profiles in place.
    let connected = crate::helper::status().unwrap_or(false);
    // Stop a legacy unprivileged Xray process before handing TUN ownership to the helper.
    if !connected {
        if vpn_core::xray::has_running_process() && !vpn_core::xray::is_tun_process() {
            vpn_core::xray::stop(state)?;
        }
        let proxy_journal = journal_path()?;
        if proxy_journal.exists() {
            vpn_core::proxy::restore_proxy(&vpn_core::proxy::MacNetworkSetup, &proxy_journal)?;
        }
    }
    let link = vpn_core::cached_client_share_link(server_id, inbound_id, email)?;
    let relay_link = if link.starts_with("hysteria2://") {
        let candidates = vpn_core::all_connectable_profiles()?;
        let relay = candidates.iter().find(|p| p["server_id"].as_str() != Some(server_id)
            && p["protocol"] == "vless" && p["transport"] == "xhttp" && p["has_local_config"] == true)
            .ok_or("Для Hysteria 2 в этой сети нужен доступный VLESS/XHTTP relay с другого сервера")?;
        Some(vpn_core::cached_client_share_link(
            relay["server_id"].as_str().ok_or("Relay server id is missing")?,
            relay["inbound_id"].as_u64().ok_or("Relay inbound id is missing")?,
            relay["email"].as_str().ok_or("Relay email is missing")?,
        )?)
    } else if vpn_core::profile::vless_config(&link, 10808)?["outbounds"][0]["streamSettings"]["security"] == "reality" {
        vpn_core::reality_relay_link()?
    } else { None };
    let result = crate::helper::start(&link, relay_link.as_deref())?;
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
pub fn xray_stop(
    state: tauri::State<'_, XrayState>,
    tray: tauri::State<'_, crate::tray::TrayStatus>,
    control: tauri::State<'_, crate::control::ControlState>,
) -> Result<(), String> {
    let _guard = control.operation.lock().map_err(|_| "Управление VPN недоступно")?;
    stop_vpn_inner(&state, &tray)
}

pub fn journal_path() -> Result<std::path::PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    Ok(std::path::PathBuf::from(home)
        .join("Library/Application Support/VpnClient/proxy-journal.json"))
}
