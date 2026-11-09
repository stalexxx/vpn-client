use crate::{control, helper, install, tray, xray};

#[tauri::command]
fn get_bypass_settings() -> Result<vpn_core::profile::Bypass, String> { vpn_core::read_bypass() }

#[tauri::command]
fn set_bypass_settings(bittorrent: bool, entries: Vec<String>) -> Result<vpn_core::profile::Bypass, String> {
    let bypass = vpn_core::profile::Bypass { bittorrent, entries }.validated()?;
    // Packaged app: Contents/MacOS/VPNClient, databases in Contents/Resources (absent in development builds).
    if let Some(dir) = std::env::current_exe().ok().and_then(|exe| exe.parent()?.parent().map(|c| c.join("Resources"))) {
        vpn_core::check_geo_entries(&bypass.entries, &dir)?;
    }
    vpn_core::write_bypass(bypass)
}

#[tauri::command]
fn list_geo_lists() -> Result<serde_json::Value, String> {
    let dir = std::env::current_exe().ok().and_then(|exe| exe.parent()?.parent().map(|c| c.join("Resources")));
    match dir { Some(dir) => vpn_core::geo_lists(&dir), None => Ok(serde_json::json!({"geoip": [], "geosite": []})) }
}

#[tauri::command]
fn get_log_level() -> Result<String, String> { helper::log_level() }

#[tauri::command]
fn set_log_level(verbose: bool) -> Result<String, String> { helper::set_log_level(if verbose { "info" } else { "warning" }) }

#[tauri::command]
fn vpn_stats() -> Result<serde_json::Value, String> { helper::stats() }

#[tauri::command]
fn build_info() -> String {
    format!("v{} · сборка {}", env!("CARGO_PKG_VERSION"), env!("VPN_BUILD_STAMP"))
}

#[tauri::command]
fn panel_hostname(url: String) -> Result<String, String> { vpn_core::panel_hostname(&url) }
#[tauri::command]
fn list_servers() -> Result<Vec<vpn_core::Server>, String> { vpn_core::list_servers() }
#[tauri::command]
fn save_server(id: Option<String>, name: String, url: String, token: String, ssh_target: Option<String>, panel_host: Option<String>, country: Option<String>, ssh_key: Option<String>) -> Result<vpn_core::Server, String> {
    let ssh_key = ssh_key.filter(|k| !k.is_empty());
    // Only a newly chosen key must resolve; the one already saved may have vanished from ~/.ssh and must not block a rename.
    if let Some(name) = &ssh_key {
        let unchanged = id.as_deref().and_then(|i| vpn_core::list_servers().ok()?.into_iter().find(|s| s.id == i)).and_then(|s| s.panel.ssh_key).as_deref() == Some(name.as_str());
        if !unchanged { vpn_core::resolve_ssh_key(name)?; }
    }
    vpn_core::save_server(id, vpn_core::Panel { name, url, ssh_target, panel_host, ssh_key }, &token, country)
}
#[tauri::command]
fn list_ssh_keys() -> Vec<vpn_core::SshKeyInfo> { vpn_core::list_ssh_keys() }
#[tauri::command]
fn list_orphan_ssh_pubs() -> Vec<String> { vpn_core::list_orphan_ssh_pubs() }
/// App-wide default SSH key name (empty string = automatic); a stored key that is gone from ~/.ssh is still reported.
#[tauri::command]
fn get_default_ssh_key() -> Result<Option<String>, String> { vpn_core::get_default_ssh_key() }
#[tauri::command]
fn set_default_ssh_key(key: Option<String>) -> Result<(), String> { vpn_core::set_default_ssh_key(key.as_deref()) }
#[tauri::command]
fn new_wizard_id() -> Result<String, String> { vpn_core::new_wizard_id() }
#[tauri::command]
fn stage_wizard_token(wizard_id: String, token: String) -> Result<(), String> { vpn_core::stage_wizard_token(&wizard_id, &token) }
#[tauri::command]
fn clear_wizard_token(wizard_id: String) -> Result<(), String> { vpn_core::clear_wizard_token(&wizard_id) }
#[tauri::command]
fn save_wizard_server(wizard_id: String, panel: vpn_core::Panel, country: Option<String>) -> Result<vpn_core::Server, String> {
    vpn_core::save_wizard_server(&wizard_id, panel, country)
}
#[tauri::command]
async fn list_wizard_inbounds(wizard_id: String, panel: vpn_core::Panel) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || vpn_core::list_wizard_inbounds(&wizard_id, &panel)).await.map_err(|e| e.to_string())?
}
#[tauri::command]
async fn create_wizard_inbound(wizard_id: String, panel: vpn_core::Panel, target: String, template_id: String, params: vpn_core::InboundParams) -> Result<u64, String> {
    tauri::async_runtime::spawn_blocking(move || vpn_core::create_wizard_inbound(&wizard_id, &panel, &target, &template_id, &params)).await.map_err(|e| e.to_string())?
}
#[tauri::command]
fn list_inbound_templates() -> Vec<vpn_core::InboundTemplate> { vpn_core::list_inbound_templates() }
#[tauri::command]
async fn create_server_inbound(server_id: String, template_id: String, params: vpn_core::InboundParams) -> Result<u64, String> {
    tauri::async_runtime::spawn_blocking(move || vpn_core::create_server_inbound(&server_id, &template_id, &params)).await.map_err(|e| e.to_string())?
}
#[tauri::command]
async fn create_wizard_client(wizard_id: String, panel: vpn_core::Panel, inbound_id: u64, email: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || { vpn_core::create_wizard_client(&wizard_id, &panel, inbound_id, &email)?; Ok(format!("Клиент {email} создан.")) }).await.map_err(|e| e.to_string())?
}
#[tauri::command]
fn wizard_client_qr(wizard_id: String, panel: vpn_core::Panel, inbound_id: u64, email: String) -> Result<serde_json::Value, String> {
    let link = vpn_core::wizard_client_share_link(&wizard_id, &panel, inbound_id, &email)?;
    let code = qrcode::QrCode::new(link.as_bytes()).map_err(|e| e.to_string())?;
    let size = code.width();
    let pixels: Vec<bool> = code.to_colors().iter().map(|c| *c == qrcode::Color::Dark).collect();
    Ok(serde_json::json!({"link": link, "size": size, "pixels": pixels}))
}
#[tauri::command]
fn delete_server(server_id: String) -> Result<(), String> { vpn_core::delete_server(&server_id) }
#[tauri::command]
async fn list_client_profiles(server_id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || vpn_core::list_client_profiles(&server_id)).await.map_err(|e| e.to_string())?
}
#[tauri::command]
async fn refresh_client_profiles(server_id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || vpn_core::refresh_client_profiles(&server_id)).await.map_err(|e| e.to_string())?
}
#[tauri::command]
fn cached_server_inbounds(server_id: String) -> Result<serde_json::Value, String> { vpn_core::cached_server_inbounds(&server_id) }
#[tauri::command]
async fn list_inbounds(server_id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || vpn_core::server_inbounds(&server_id)).await.map_err(|e| e.to_string())?
}
#[tauri::command]
async fn delete_inbound(server_id: String, inbound_id: u64) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || vpn_core::delete_server_inbound(&server_id, inbound_id)).await.map_err(|e| e.to_string())?
}
#[tauri::command]
async fn server_warp_status(server_id: String) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || vpn_core::warp_status_for_server(&server_id)).await.map_err(|e| e.to_string())?
}
#[tauri::command]
async fn enable_server_warp(server_id: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || vpn_core::enable_warp_for_server(&server_id)).await.map_err(|e| e.to_string())?
}
#[tauri::command]
async fn disable_server_warp(server_id: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || vpn_core::disable_warp_for_server(&server_id)).await.map_err(|e| e.to_string())?
}
#[tauri::command]
async fn create_client(server_id: String, inbound_id: u64, email: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || { vpn_core::create_client(&server_id, inbound_id, &email)?; Ok(format!("Клиент {email} создан.")) }).await.map_err(|e| e.to_string())?
}
#[tauri::command]
fn client_qr(server_id: String, inbound_id: u64, email: String) -> Result<serde_json::Value, String> {
    let link = vpn_core::cached_client_share_link(&server_id, inbound_id, &email)?;
    let code = qrcode::QrCode::new(link.as_bytes()).map_err(|e| e.to_string())?;
    let size = code.width();
    let pixels: Vec<bool> = code.to_colors().iter().map(|c| *c == qrcode::Color::Dark).collect();
    Ok(serde_json::json!({"link": link, "size": size, "pixels": pixels}))
}
#[tauri::command]
fn connect_profile(state: tauri::State<'_, xray::XrayState>, tray: tauri::State<'_, tray::TrayStatus>, control: tauri::State<'_, control::ControlState>, server_id: String, inbound_id: u64, email: String) -> Result<String, String> {
    let _guard = control.operation.lock().map_err(|_| "Управление VPN недоступно")?;
    xray::connect_profile_inner(&state, &tray, &server_id, inbound_id, &email)
}

#[tauri::command]
fn import_profiles(text: String, name: Option<String>) -> Result<Vec<serde_json::Value>, String> { vpn_core::import_profiles(&text, name.as_deref()) }
#[tauri::command]
fn list_imported_profiles() -> Result<Vec<serde_json::Value>, String> { vpn_core::list_imported_profiles() }
#[tauri::command]
fn rename_imported_profile(id: String, name: String) -> Result<(), String> { vpn_core::rename_imported_profile(&id, &name) }
#[tauri::command]
fn delete_imported_profile(id: String) -> Result<(), String> { vpn_core::delete_imported_profile(&id) }
#[tauri::command]
fn connect_imported_profile(state: tauri::State<'_, xray::XrayState>, tray: tauri::State<'_, tray::TrayStatus>, control: tauri::State<'_, control::ControlState>, id: String) -> Result<String, String> {
    let _guard = control.operation.lock().map_err(|_| "Управление VPN недоступно")?;
    xray::connect_imported_inner(&state, &tray, &id)
}
#[tauri::command]
fn list_connectable_profiles() -> Result<Vec<serde_json::Value>, String> { vpn_core::list_connectable_profiles() }
#[tauri::command]
fn list_pinned_profiles() -> Result<Option<Vec<vpn_core::PinnedProfile>>, String> { vpn_core::list_pinned_profiles() }
#[tauri::command]
fn set_profile_pinned(server_id: String, inbound_id: u64, email: String, pinned: bool) -> Result<(), String> {
    vpn_core::set_profile_pinned(&server_id, inbound_id, &email, pinned)
}

pub(crate) fn open_admin_window(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
    if let Some(window) = app.get_webview_window("admin") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok(());
    }
    WebviewWindowBuilder::new(app, "admin", WebviewUrl::App("admin.html".into()))
        .title("Администрирование VPN")
        .inner_size(1100.0, 760.0)
        .resizable(true)
        .build()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn open_admin(app: tauri::AppHandle) -> Result<(), String> { open_admin_window(&app) }

pub fn main() {
    tauri::Builder::default()
        .setup(|app| {
            tray::install(app)?;
            control::start(app.handle().clone()).map_err(std::io::Error::other)?;
            Ok(())
        })
        .manage(vpn_core::probe::start())
        .manage(xray::XrayState::default())
        .manage(install::InstallState::default())
        .manage(control::ControlState::default())
        .invoke_handler(tauri::generate_handler![
            tray::get_vpn_mode,
            build_info,
            vpn_stats,
            list_geo_lists,
            get_log_level,
            set_log_level,
            get_bypass_settings,
            set_bypass_settings,
            install::install_panel,
            install::install_progress,
            install::clear_install,
            list_servers,
            panel_hostname,
            save_server,
            list_ssh_keys,
            list_orphan_ssh_pubs,
            get_default_ssh_key,
            set_default_ssh_key,
            new_wizard_id,
            stage_wizard_token,
            clear_wizard_token,
            save_wizard_server,
            list_wizard_inbounds,
            create_wizard_inbound,
            list_inbound_templates,
            create_server_inbound,
            create_wizard_client,
            wizard_client_qr,
            delete_server,
            list_inbounds,
            cached_server_inbounds,
            create_client,
            delete_inbound,
            server_warp_status,
            enable_server_warp,
            disable_server_warp,
            client_qr,
            list_client_profiles,
            refresh_client_profiles,
            xray::xray_stop,
            connect_profile
            ,list_connectable_profiles,
            import_profiles, list_imported_profiles, rename_imported_profile, delete_imported_profile, connect_imported_profile,
            list_pinned_profiles,
            set_profile_pinned,
            open_admin,
            crate::probes::get_probe_results,
            crate::probes::probe_now,
            crate::probes::get_exit_ip
            ,control::select_mcp_profile
            ,control::get_mcp_profile
        ])
        .run(tauri::generate_context!())
        .expect("failed to start VPN Client");
}
