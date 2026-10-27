mod tray;
mod helper;
mod xray;

#[tauri::command]
fn build_info() -> String {
    format!("v{} · сборка {}", env!("CARGO_PKG_VERSION"), env!("VPN_BUILD_STAMP"))
}

#[tauri::command]
fn get_panel() -> Result<Option<vpn_core::Panel>, String> {
    vpn_core::load_panel()
}

#[tauri::command]
fn save_panel(
    name: String,
    url: String,
    token: String,
    ssh_target: Option<String>,
    panel_host: Option<String>,
) -> Result<(), String> {
    vpn_core::save_panel(
        &vpn_core::Panel {
            name,
            url,
            ssh_target,
            panel_host,
        },
        &token,
    )
}

#[tauri::command]
async fn list_client_profiles() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(vpn_core::list_client_profiles).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn refresh_client_profiles() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(vpn_core::refresh_client_profiles).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn list_inbounds() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(vpn_core::list_inbounds)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn validate_profile(link: String) -> Result<String, String> {
    vpn_core::profile::vless_xhttp_config(&link, 10808)?;
    Ok("Профиль VLESS / TLS / XHTTP корректен.".into())
}

#[tauri::command]
fn connect_profile(
    state: tauri::State<'_, xray::XrayState>,
    tray: tauri::State<'_, tray::TrayStatus>,
    inbound_id: u64,
    email: String,
) -> Result<String, String> {
    xray::connect_profile_inner(&state, &tray, inbound_id, &email)
}

#[tauri::command]
fn prepare_test_client() -> Result<vpn_core::PendingClient, String> {
    vpn_core::queue_client(6, "vpn-client-test")
}

#[tauri::command]
fn pending_client() -> Result<Option<vpn_core::PendingClient>, String> {
    vpn_core::pending_client()
}

#[tauri::command]
fn cancel_pending_client() -> Result<(), String> {
    vpn_core::cancel_pending_client()
}

#[tauri::command]
fn approve_pending_client(inbound_id: u64, email: String) -> Result<String, String> {
    vpn_core::approve_pending_client(inbound_id, &email)
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            tray::install(app)?;
            Ok(())
        })
        .manage(xray::XrayState::default())
        .invoke_handler(tauri::generate_handler![
            tray::get_vpn_status,
            tray::get_vpn_mode,
            build_info,
            get_panel,
            save_panel,
            list_inbounds,
            list_client_profiles,
            refresh_client_profiles,
            validate_profile,
            xray::xray_start,
            xray::xray_stop,
            xray::proxy_enable,
            xray::proxy_recover,
            xray::proxy_recovery_needed,
            prepare_test_client,
            connect_profile,
            pending_client,
            cancel_pending_client,
            approve_pending_client
        ])
        .run(tauri::generate_context!())
        .expect("failed to start VPN Client");
}
