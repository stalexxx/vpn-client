mod tray;
mod install;
mod helper;
mod xray;

#[tauri::command]
fn build_info() -> String {
    format!("v{} · сборка {}", env!("CARGO_PKG_VERSION"), env!("VPN_BUILD_STAMP"))
}

#[tauri::command]
fn panel_hostname(url: String) -> Result<String, String> { vpn_core::panel_hostname(&url) }
#[tauri::command]
fn list_servers() -> Result<Vec<vpn_core::Server>, String> { vpn_core::list_servers() }
#[tauri::command]
fn save_server(id: Option<String>, name: String, url: String, token: String, ssh_target: Option<String>, panel_host: Option<String>, country: Option<String>) -> Result<vpn_core::Server, String> {
    vpn_core::save_server(id, vpn_core::Panel { name, url, ssh_target, panel_host }, &token, country)
}
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
fn connect_profile(state: tauri::State<'_, xray::XrayState>, tray: tauri::State<'_, tray::TrayStatus>, server_id: String, inbound_id: u64, email: String) -> Result<String, String> {
    xray::connect_profile_inner(&state, &tray, &server_id, inbound_id, &email)
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

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            tray::install(app)?;
            Ok(())
        })
        .manage(xray::XrayState::default())
        .manage(install::InstallState::default())
        .invoke_handler(tauri::generate_handler![
            tray::get_vpn_mode,
            build_info,
            install::install_panel,
            install::install_progress,
            install::clear_install,
            list_servers,
            panel_hostname,
            save_server,
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
            client_qr,
            list_client_profiles,
            refresh_client_profiles,
            xray::xray_stop,
            connect_profile
            ,list_connectable_profiles,
            list_pinned_profiles,
            set_profile_pinned,
            open_admin
        ])
        .run(tauri::generate_context!())
        .expect("failed to start VPN Client");
}
