use crate::xray::XrayState;

pub fn connect_imported_inner(
    state: &XrayState,
    id: &str,
) -> Result<String, String> {
    prepare_tun(state)?.map_or_else(|| {
        let link = crate::imported_share_link(id)?;
        let relay = if link.starts_with(crate::awglink::SCHEME) {
            None
        } else if link.starts_with("hysteria2://") {
            Some(crate::imported_relay_link(id)?.ok_or("Для Hysteria 2 в этой сети нужен доступный VLESS/XHTTP relay: добавьте клиента VLESS/XHTTP на сервере или импортируйте vless-ссылку")?)
        } else if crate::profile::vless_config(&link, 10808)?["outbounds"][0]["streamSettings"]["security"] == "reality" {
            crate::reality_relay_link()?
        } else { None };
        let result = crate::helper::start(&link, relay.as_deref())?;
        Ok(result)
    }, Ok)
}

/// Returns `Some(message)` when TUN is already up, otherwise clears legacy proxy state.
fn prepare_tun(
    state: &XrayState,
) -> Result<Option<String>, String> {
    // Already connected: the helper switches profiles in place, no legacy cleanup needed.
    if crate::helper::status().unwrap_or(false) { return Ok(None); }
    if crate::xray::has_running_process() && !crate::xray::is_tun_process() {
        crate::xray::stop(state)?;
    }
    let proxy_journal = journal_path()?;
    if proxy_journal.exists() {
        crate::proxy::restore_proxy(&crate::proxy::MacNetworkSetup, &proxy_journal)?;
    }
    Ok(None)
}

pub fn connect_profile_inner(
    state: &XrayState,
    server_id: &str,
    inbound_id: u64,
    email: &str,
) -> Result<String, String> {
    // Already connected: the helper switches profiles in place.
    let connected = crate::helper::status().unwrap_or(false);
    // Stop a legacy unprivileged Xray process before handing TUN ownership to the helper.
    if !connected {
        if crate::xray::has_running_process() && !crate::xray::is_tun_process() {
            crate::xray::stop(state)?;
        }
        let proxy_journal = journal_path()?;
        if proxy_journal.exists() {
            crate::proxy::restore_proxy(&crate::proxy::MacNetworkSetup, &proxy_journal)?;
        }
    }
    let link = crate::cached_client_share_link(server_id, inbound_id, email)?;
    let relay_link = if link.starts_with("hysteria2://") {
        let candidates = crate::all_connectable_profiles()?;
        let relay = candidates.iter().find(|p| p["server_id"].as_str() != Some(server_id)
            && p["protocol"] == "vless" && p["transport"] == "xhttp" && p["has_local_config"] == true)
            .ok_or("Для Hysteria 2 в этой сети нужен доступный VLESS/XHTTP relay с другого сервера")?;
        Some(crate::cached_client_share_link(
            relay["server_id"].as_str().ok_or("Relay server id is missing")?,
            relay["inbound_id"].as_u64().ok_or("Relay inbound id is missing")?,
            relay["email"].as_str().ok_or("Relay email is missing")?,
        )?)
    } else if crate::profile::vless_config(&link, 10808)?["outbounds"][0]["streamSettings"]["security"] == "reality" {
        crate::reality_relay_link()?
    } else { None };
    let result = crate::helper::start(&link, relay_link.as_deref())?;
    Ok(result)
}

pub fn stop_vpn_inner(
    state: &XrayState,
) -> Result<(), String> {
    if crate::helper::status().is_ok() {
        crate::helper::stop()?;
    }
    let path = journal_path()?;
    if path.exists() {
        crate::proxy::restore_proxy(&crate::proxy::MacNetworkSetup, &path)?;
    }
    if crate::xray::has_running_process() {
        crate::xray::stop(state)?;
    }
    Ok(())
}

pub fn journal_path() -> Result<std::path::PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    Ok(std::path::PathBuf::from(home).join("Library/Application Support/VpnClient/proxy-journal.json"))
}
