//! Windows client: import links and connect through Xray's TUN (wintun). No administration features.
//!
//! The app is elevated by its manifest (`requireAdministrator`), so it starts `vpnclient-xray.exe` itself —
//! there is no separate helper service. The wintun adapter vanishes with the process, so no DNS/route
//! journal is needed: stopping Xray restores the network.
use std::{
    fs,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};
use serde_json::{json, Value};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const TUN_NAME: &str = "VPNClient";
const XRAY_EXE: &str = "vpnclient-xray.exe";

#[derive(Default)]
pub struct Engine {
    child: Mutex<Option<Child>>,
    /// (share link, relay) of the running tunnel and the loopback stats API port.
    current: Mutex<Option<(String, Option<String>, u16)>>,
    op: Mutex<()>,
}

fn exe_dir() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| e.to_string())?.parent().map(PathBuf::from).ok_or_else(|| "Путь приложения недоступен".to_owned())
}
fn bin_dir() -> Result<PathBuf, String> { Ok(exe_dir()?.join("bin")) }
fn resources_dir() -> Result<PathBuf, String> { Ok(exe_dir()?.join("resources")) }
fn runtime_dir() -> Result<PathBuf, String> {
    let dir = vpn_core::compat::data_dir()?.join("runtime");
    fs::create_dir_all(&dir).map_err(|e| format!("Не удалось создать {}: {e}", dir.display()))?;
    Ok(dir)
}
fn log_path() -> Result<PathBuf, String> { Ok(runtime_dir()?.join("xray.log")) }
fn log_level_path() -> Result<PathBuf, String> { Ok(runtime_dir()?.join("log-level")) }
fn verbose() -> bool { log_level_path().ok().and_then(|p| fs::read_to_string(p).ok()).is_some_and(|v| v.trim() == "info") }
fn hidden(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

fn running(engine: &Engine) -> bool {
    let mut guard = match engine.child.lock() { Ok(g) => g, Err(_) => return false };
    match guard.as_mut() {
        Some(child) => match child.try_wait() { Ok(None) => true, _ => { *guard = None; false } },
        None => false,
    }
}
fn kill_xray(engine: &Engine) {
    if let Ok(mut guard) = engine.child.lock() {
        if let Some(mut child) = guard.take() { let _ = child.kill(); let _ = child.wait(); }
    }
    if let Ok(mut current) = engine.current.lock() { *current = None; }
    vpn_core::probe::set_tunnel_up(false);
    // A previous crashed run may have left an orphan holding the adapter.
    let _ = hidden("taskkill").args(["/F", "/IM", XRAY_EXE]).stdout(Stdio::null()).stderr(Stdio::null()).status();
}

fn log_tail() -> String {
    let text = log_path().ok().and_then(|p| fs::read_to_string(p).ok()).unwrap_or_default();
    text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("нет сообщения журнала").to_owned()
}
fn adapter_exists() -> bool {
    hidden("netsh").args(["interface", "ipv4", "show", "interfaces"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(TUN_NAME)).unwrap_or(false)
}
fn set_tun_dns() {
    // Queries must go through the tunnel: pin public resolvers on the (temporary) TUN adapter only.
    let name = format!("name={TUN_NAME}");
    let _ = hidden("netsh").args(["interface", "ipv4", "set", "dnsservers", &name, "static", "1.1.1.1", "primary", "validate=no"]).status();
    let _ = hidden("netsh").args(["interface", "ipv4", "add", "dnsservers", &name, "1.0.0.1", "index=2", "validate=no"]).status();
}
fn tcp_probe(timeout: Duration) -> bool {
    let result = || -> std::io::Result<bool> {
        let addr = ("1.1.1.1", 80).to_socket_addrs()?.next().ok_or(std::io::ErrorKind::NotFound)?;
        let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(b"HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")?;
        let mut reply = [0u8; 16];
        let len = stream.read(&mut reply)?;
        Ok(reply[..len].starts_with(b"HTTP/"))
    };
    result().unwrap_or(false)
}

fn relay_for(id: &str, link: &str) -> Result<Option<String>, String> {
    if link.starts_with("hysteria2://") {
        Ok(Some(vpn_core::imported_relay_link(id)?.ok_or("Для Hysteria 2 в этой сети нужен доступный VLESS/XHTTP relay: импортируйте vless-ссылку (XHTTP)")?))
    } else if vpn_core::profile::vless_config(link, 10808)?["outbounds"][0]["streamSettings"]["security"] == "reality" {
        vpn_core::reality_relay_link()
    } else { Ok(None) }
}

/// Starts Xray with `link`; any failure leaves nothing running.
fn start(engine: &Engine, link: &str, relay: Option<&str>) -> Result<String, String> {
    let xray = bin_dir()?.join(XRAY_EXE);
    if !xray.is_file() { return Err(format!("Не найден {}: переустановите приложение", xray.display())); }
    let api_port = std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).map_err(|e| e.to_string())?;
    let bypass = vpn_core::read_bypass()?;
    let config = vpn_core::profile::vless_tun_config_with_options(link, TUN_NAME, relay, verbose(), Some(&vpn_core::profile::ApiListen::Tcp(api_port)), &bypass)?;
    let config_path = runtime_dir()?.join("config.json");
    fs::write(&config_path, config.to_string()).map_err(|e| format!("Не удалось записать конфигурацию: {e}"))?;
    let assets = resources_dir()?;
    let check = hidden(&xray).env("XRAY_LOCATION_ASSET", &assets).args(["run", "-test", "-config"]).arg(&config_path)
        .stdout(Stdio::null()).stderr(Stdio::piped()).output().map_err(|e| e.to_string())?;
    if !check.status.success() {
        let _ = fs::remove_file(&config_path);
        return Err(format!("Xray отклонил конфигурацию: {}", String::from_utf8_lossy(&check.stderr).trim()));
    }
    let log = fs::File::create(log_path()?).map_err(|e| e.to_string())?;
    let log_err = log.try_clone().map_err(|e| e.to_string())?;
    let mut child = hidden(&xray).current_dir(bin_dir()?).env("XRAY_LOCATION_ASSET", &assets)
        .args(["run", "-config"]).arg(&config_path).stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(log_err))
        .spawn().map_err(|e| format!("Не удалось запустить Xray: {e}"))?;
    let fail = |child: &mut Child, reason: String| -> Result<String, String> {
        let _ = child.kill(); let _ = child.wait();
        let _ = fs::remove_file(&config_path);
        Err(reason)
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut ready = false;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return fail(&mut child, format!("Xray завершился при запуске ({status}): {}. Приложение должно работать от имени администратора, рядом с ним должен лежать wintun.dll.", log_tail())),
            Ok(None) => {},
            Err(e) => return fail(&mut child, format!("Не удалось проверить процесс Xray: {e}")),
        }
        if adapter_exists() { ready = true; break; }
        thread::sleep(Duration::from_millis(300));
    }
    if !ready { let reason = format!("Xray не поднял TUN-адаптер: {}", log_tail()); return fail(&mut child, reason); }
    set_tun_dns();
    // Traffic must actually pass through the server before we call it connected.
    let probe_deadline = Instant::now() + Duration::from_secs(12);
    let mut ok = false;
    while Instant::now() < probe_deadline {
        if let Ok(Some(status)) = child.try_wait() { return fail(&mut child, format!("Xray завершился во время проверки ({status}): {}", log_tail())); }
        if tcp_probe(Duration::from_secs(4)) { ok = true; break; }
        thread::sleep(Duration::from_millis(500));
    }
    if !ok { return fail(&mut child, "VPN запущен, но трафик через сервер не проходит.".to_owned()); }
    *engine.child.lock().map_err(|_| "Состояние VPN недоступно")? = Some(child);
    vpn_core::probe::set_tunnel_up(true);
    *engine.current.lock().map_err(|_| "Состояние VPN недоступно")? = Some((link.to_owned(), relay.map(str::to_owned), api_port));
    Ok(format!("VPN подключён через адаптер {TUN_NAME}; системный трафик направлен в TUN."))
}

fn connect_imported(engine: &Engine, id: &str) -> Result<String, String> {
    let _op = engine.op.lock().map_err(|_| "Управление VPN недоступно")?;
    let link = vpn_core::imported_share_link(id)?;
    let relay = relay_for(id, &link)?;
    let was_running = running(engine);
    let previous = engine.current.lock().map_err(|_| "Состояние VPN недоступно")?.clone();
    if was_running {
        if previous.as_ref().is_some_and(|(l, r, _)| *l == link && *r == relay) { return Ok("VPN уже подключён к этому профилю.".into()); }
        kill_xray(engine);
    } else {
        kill_xray(engine);
    }
    match start(engine, &link, relay.as_deref()) {
        Ok(message) => Ok(message),
        Err(error) => {
            // A failed switch brings the previous profile back.
            if let (true, Some((old_link, old_relay, _))) = (was_running, previous) {
                return match start(engine, &old_link, old_relay.as_deref()) {
                    Ok(_) => Err(format!("{error}; возвращён прежний профиль")),
                    Err(second) => Err(format!("{error}; прежний профиль тоже не поднялся: {second}")),
                };
            }
            Err(error)
        }
    }
}

#[tauri::command]
fn get_vpn_mode(engine: tauri::State<'_, Engine>) -> &'static str { if running(&engine) { "tun" } else { "off" } }
#[tauri::command]
fn build_info() -> String { format!("v{} · сборка {} · Windows", env!("CARGO_PKG_VERSION"), env!("VPN_BUILD_STAMP")) }
#[tauri::command]
fn xray_stop(engine: tauri::State<'_, Engine>) -> Result<(), String> {
    let _op = engine.op.lock().map_err(|_| "Управление VPN недоступно")?;
    kill_xray(&engine);
    Ok(())
}
#[tauri::command]
async fn connect_imported_profile(app: tauri::AppHandle, id: String) -> Result<String, String> {
    // The call blocks for up to ~30 s (adapter + probe); keep it off the UI thread.
    tauri::async_runtime::spawn_blocking(move || {
        use tauri::Manager;
        connect_imported(&app.state::<Engine>(), &id)
    }).await.map_err(|e| e.to_string())?
}
#[tauri::command]
fn connect_profile() -> Result<String, String> { Err("В Windows-версии доступны только импортированные конфигурации.".into()) }
#[tauri::command]
fn list_connectable_profiles() -> Vec<Value> { Vec::new() }
#[tauri::command]
fn select_mcp_profile(_profile: Option<Value>) -> Result<(), String> { Ok(()) }
#[tauri::command]
fn get_mcp_profile() -> Option<Value> { None }
#[tauri::command]
fn open_admin() -> Result<(), String> { Err("Администрирование недоступно в Windows-версии.".into()) }
#[tauri::command]
fn import_profiles(text: String, name: Option<String>) -> Result<Vec<Value>, String> { vpn_core::import_profiles(&text, name.as_deref()) }
#[tauri::command]
fn list_imported_profiles() -> Result<Vec<Value>, String> { vpn_core::list_imported_profiles() }
#[tauri::command]
fn rename_imported_profile(id: String, name: String) -> Result<(), String> { vpn_core::rename_imported_profile(&id, &name) }
#[tauri::command]
fn delete_imported_profile(id: String) -> Result<(), String> { vpn_core::delete_imported_profile(&id) }
#[tauri::command]
fn get_bypass_settings() -> Result<vpn_core::profile::Bypass, String> { vpn_core::read_bypass() }
#[tauri::command]
fn set_bypass_settings(bittorrent: bool, entries: Vec<String>) -> Result<vpn_core::profile::Bypass, String> {
    let bypass = vpn_core::profile::Bypass { bittorrent, entries }.validated()?;
    if let Ok(dir) = resources_dir() { if dir.join("geoip.dat").is_file() { vpn_core::check_geo_entries(&bypass.entries, &dir)?; } }
    vpn_core::write_bypass(bypass)
}
#[tauri::command]
fn list_geo_lists() -> Result<Value, String> { vpn_core::geo_lists(&resources_dir()?) }
#[tauri::command]
fn get_log_level() -> String { if verbose() { "info" } else { "warning" }.to_owned() }
#[tauri::command]
fn set_log_level(verbose: bool) -> Result<String, String> {
    let level = if verbose { "info" } else { "warning" };
    fs::write(log_level_path()?, level).map_err(|e| e.to_string())?;
    Ok(format!("Уровень журнала: {level}; применится при следующем подключении"))
}

fn parse_stats(json_text: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(json_text).map_err(|_| "Некорректный ответ статистики Xray".to_owned())?;
    let mut totals = [[0u64; 2]; 2]; // [direct, vpn] x [up, down]
    for item in value["stat"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let (Some(name), amount) = (item["name"].as_str(), item["value"].as_u64().unwrap_or(0)) else { continue };
        let parts: Vec<&str> = name.split(">>>").collect();
        if parts.len() != 4 || parts[0] != "outbound" || parts[2] != "traffic" { continue }
        let row = match parts[1] { "direct" => 0, "vpn-out" => 1, _ => continue };
        let col = match parts[3] { "uplink" => 0, "downlink" => 1, _ => continue };
        totals[row][col] += amount;
    }
    let ts_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    Ok(json!({"direct":{"up":totals[0][0],"down":totals[0][1]},"vpn":{"up":totals[1][0],"down":totals[1][1]},"ts_ms":ts_ms}))
}
#[tauri::command]
fn vpn_stats(engine: tauri::State<'_, Engine>) -> Result<Value, String> {
    let port = engine.current.lock().map_err(|_| "Состояние VPN недоступно")?.as_ref().map(|c| c.2).ok_or("VPN не подключён")?;
    let out = hidden(bin_dir()?.join(XRAY_EXE)).args(["api", "statsquery", "-t", "2"]).arg(format!("--server=127.0.0.1:{port}"))
        .stdin(Stdio::null()).stderr(Stdio::null()).output().map_err(|e| e.to_string())?;
    if !out.status.success() { return Err("Статистика Xray недоступна".into()); }
    parse_stats(&String::from_utf8_lossy(&out.stdout))
}

pub fn main() {
    tauri::Builder::default()
        .manage(Engine::default())
        .manage(vpn_core::probe::start())
        .invoke_handler(tauri::generate_handler![
            get_vpn_mode, build_info, xray_stop, connect_imported_profile, connect_profile, list_connectable_profiles,
            select_mcp_profile, get_mcp_profile, open_admin, import_profiles, list_imported_profiles,
            rename_imported_profile, delete_imported_profile, get_bypass_settings, set_bypass_settings,
            list_geo_lists, get_log_level, set_log_level, vpn_stats,
            crate::probes::get_probe_results, crate::probes::probe_now, crate::probes::get_exit_ip,
        ])
        .build(tauri::generate_context!())
        .expect("failed to start VPN Client")
        .run(|app, event| {
            // Closing the app must not leave a tunnel (and its routes) behind.
            if let tauri::RunEvent::Exit = event {
                use tauri::Manager;
                kill_xray(&app.state::<Engine>());
            }
        });
}
