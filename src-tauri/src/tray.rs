use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIcon,
    AppHandle, Manager, State,
};

pub struct TrayStatus(pub Mutex<Option<TrayIcon<tauri::Wry>>>);
impl TrayStatus {
    pub fn set(&self, connected: bool) -> Result<(), String> {
        let tray = self
            .0
            .lock()
            .map_err(|_| "Menu bar status is unavailable")?;
        if let Some(tray) = tray.as_ref() {
            tray.set_title(Some(if connected { "VPN ●" } else { "VPN ○" }))
                .map_err(|e| e.to_string())?;
            tray.set_tooltip(Some(if connected {
                "VPN подключён"
            } else {
                "VPN отключён"
            }))
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

pub fn install(app: &mut tauri::App) -> tauri::Result<()> {
    let disconnect = MenuItem::with_id(app, "disconnect", "Отключить VPN", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Открыть VPN Client", true, None::<&str>)?;
    let admin = MenuItem::with_id(app, "admin", "Администрирование", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Завершить VPN Client", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&disconnect, &show, &admin, &quit])?;
    let connected = crate::helper::status().unwrap_or(false) || vpn_core::xray::has_running_process();
    let title = if connected { "VPN ●" } else { "VPN ○" };
    let tray = tauri::tray::TrayIconBuilder::with_id("vpn-status")
        .title(title)
        .tooltip(if connected {
            "VPN подключён"
        } else {
            "VPN отключён"
        })
        .menu(&menu)
        .on_menu_event(|app: &AppHandle, event| match event.id().as_ref() {
            "disconnect" => {
                let app = app.clone();
                tauri::async_runtime::spawn_blocking(move || {
                    let state = app.state::<crate::xray::XrayState>();
                    let tray = app.state::<TrayStatus>();
                    let _ = crate::xray::stop_vpn_inner(&state, &tray);
                });
            }
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "admin" => { let _ = crate::open_admin_window(app); }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    app.manage(TrayStatus(Mutex::new(Some(tray))));
    Ok(())
}

#[tauri::command]
pub fn get_vpn_mode() -> String {
    if crate::helper::status().unwrap_or(false) || vpn_core::xray::is_tun_process() { "tun".into() }
    else if vpn_core::xray::has_running_process() { "proxy".into() }
    else { "off".into() }
}

pub fn update(state: &State<'_, TrayStatus>, connected: bool) -> Result<(), String> {
    state.set(connected)
}
