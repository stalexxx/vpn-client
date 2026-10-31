use std::{fs, io::{BufRead, BufReader, Read, Write}, os::unix::{fs::{FileTypeExt, MetadataExt, PermissionsExt}, net::{UnixListener, UnixStream}}, sync::Mutex, time::Duration};
use tauri::{Emitter, Manager};
use vpn_core::PinnedProfile;

#[derive(Default)]
pub struct ControlState { selected: Mutex<Option<PinnedProfile>>, pub operation: Mutex<()> }

#[tauri::command]
pub fn select_mcp_profile(state: tauri::State<'_, ControlState>, profile: Option<PinnedProfile>) -> Result<(), String> {
    if let Some(p) = &profile {
        let eligible = vpn_core::list_connectable_profiles()?.iter().any(|item| item["server_id"] == p.server_id && item["inbound_id"] == p.inbound_id && item["email"] == p.email);
        if !eligible { return Err("Выбранная конфигурация недоступна".into()); }
    }
    *state.selected.lock().map_err(|_| "Выбор конфигурации недоступен")? = profile;
    Ok(())
}

#[tauri::command]
pub fn get_mcp_profile(state: tauri::State<'_, ControlState>) -> Result<Option<PinnedProfile>, String> {
    state.selected.lock().map(|p| p.clone()).map_err(|_| "Выбор конфигурации недоступен".into())
}

pub fn start(app: tauri::AppHandle) -> Result<(), String> {
    let path = vpn_core::mcp_control_socket_path()?;
    let dir = path.parent().ok_or("Некорректный путь MCP")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let meta = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if !meta.file_type().is_dir() || meta.uid() != unsafe { libc::geteuid() } { return Err("Каталог MCP должен принадлежать текущему пользователю".into()); }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } { return Err("Путь MCP занят посторонним файлом".into()); }
        if UnixStream::connect(&path).is_ok() { return Err("Приложение VPN уже запущено".into()); }
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&path).map_err(|e| format!("Не удалось открыть локальный сокет MCP: {e}"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    std::thread::spawn(move || { for stream in listener.incoming().flatten() { let app=app.clone(); std::thread::spawn(move || handle(stream, app)); } });
    Ok(())
}

fn handle(mut stream: UnixStream, app: tauri::AppHandle) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut line = String::new();
    let read = BufReader::new(&mut stream).take(4096).read_line(&mut line);
    let result = read.map_err(|_| "Не удалось прочитать запрос".to_owned()).and_then(|_| {
        let request: serde_json::Value = serde_json::from_str(&line).map_err(|_| "Некорректный запрос".to_owned())?;
        let state = app.state::<ControlState>();
        let _guard = state.operation.lock().map_err(|_| "Управление VPN недоступно")?;
        let xray = app.state::<crate::xray::XrayState>();
        let tray = app.state::<crate::tray::TrayStatus>();
        match request.get("action").and_then(|v| v.as_str()) {
            Some("connect") => {
                let requested = request.get("profile").map(|v| serde_json::from_value::<PinnedProfile>(v.clone()).map_err(|_| "Некорректная конфигурация".to_owned())).transpose()?;
                let profile = requested.clone().or(state.selected.lock().map_err(|_| "Выбор конфигурации недоступен")?.clone()).ok_or("Выберите конфигурацию в приложении")?;
                if !vpn_core::list_connectable_profiles()?.iter().any(|item| item["server_id"] == profile.server_id && item["inbound_id"] == profile.inbound_id && item["email"] == profile.email) { return Err("Выбранная конфигурация больше недоступна".into()); }
                if requested.is_some() { *state.selected.lock().map_err(|_| "Выбор конфигурации недоступен")? = Some(profile.clone()); }
                crate::xray::connect_profile_inner(&xray, &tray, &profile.server_id, profile.inbound_id, &profile.email)
            }
            Some("disconnect") => crate::xray::stop_vpn_inner(&xray, &tray).map(|_| "VPN отключён.".to_owned()),
            _ => Err("Неизвестная команда".into()),
        }
    });
    let _ = app.emit("vpn-mode-changed", ());
    let response = match result { Ok(message) => serde_json::json!({"ok":true,"message":message}), Err(message) => serde_json::json!({"ok":false,"message":message}) };
    let _ = writeln!(stream, "{response}");
}
