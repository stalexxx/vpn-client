use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    os::unix::{fs::{FileTypeExt, OpenOptionsExt, PermissionsExt}, net::UnixListener, prelude::AsRawFd},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const SOCKET: &str = "/var/run/vpnclient-tun.sock";
const HELPER_DIR: &str = "/Library/Application Support/VpnClientHelper";
const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize)]
struct Request { action: String, #[serde(default)] link: Option<String> }
#[derive(Serialize)]
struct Response { ok: bool, connected: bool, message: String, version: &'static str, connectivity_check: bool }
#[derive(Clone, Serialize, Deserialize)]
struct ProcessRecord { pid: u32, config_path: String, xray_path: String, tun_name: String, #[serde(default)] start_time: String }
#[derive(Serialize, Deserialize)]
struct DnsJournal { service: String, original: Vec<String>, applied: Vec<String> }
struct Tunnel { child: Option<Child>, record: ProcessRecord }
struct HelperState { uid: u32, xray: PathBuf, active: Option<Tunnel> }

#[derive(Debug, PartialEq, Eq)]
enum DnsRestoreAction { RestoreOriginal, AlreadyRestored, Conflict }

fn root_path(name: &str) -> PathBuf { Path::new(HELPER_DIR).join(name) }
fn response(ok: bool, connected: bool, message: impl Into<String>) -> Response { Response { ok, connected, message: message.into(), version: HELPER_VERSION, connectivity_check: true } }
fn process_info(pid: u32) -> Result<Option<(String, String)>, String> {
    let command = Command::new("/bin/ps").args(["-p", &pid.to_string(), "-o", "command="]).output().map_err(|e| e.to_string())?;
    if !command.status.success() { return Ok(None); }
    let command = String::from_utf8(command.stdout).map_err(|_| "Некорректный вывод ps")?.trim().to_owned();
    if command.is_empty() { return Ok(None); }
    let start = Command::new("/bin/ps").args(["-p", &pid.to_string(), "-o", "lstart="]).output().map_err(|e| e.to_string())?;
    if !start.status.success() { return Ok(None); }
    let start = String::from_utf8(start.stdout).map_err(|_| "Некорректное время старта процесса")?.trim().to_owned();
    if start.is_empty() { return Ok(None); }
    Ok(Some((command, start)))
}
fn matches_process_info(record: &ProcessRecord, command: &str, start_time: &str) -> bool {
    let command_matches = command.contains(&record.xray_path) && command.contains(&record.config_path) && command.contains("run -config");
    command_matches && !record.start_time.is_empty() && start_time == record.start_time
}
fn process_matches(record: &ProcessRecord) -> bool {
    process_info(record.pid).map(|info| info.is_some_and(|(command, start_time)| matches_process_info(record, &command, &start_time))).unwrap_or(true)
}
fn parse_uid(value: &str) -> Result<u32, String> {
    let uid = value.parse::<u32>().map_err(|_| "UID must be a valid unsigned integer")?;
    if uid == 0 { return Err("UID must not be root".into()); }
    Ok(uid)
}
fn read_record() -> Result<Option<ProcessRecord>, String> {
    match fs::read(root_path("process.json")) {
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|_| "Повреждён журнал VPN-помощника".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn write_secure(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).map_err(|e| e.to_string())?;
    f.write_all(data).and_then(|_| f.sync_all()).map_err(|e| e.to_string())
}
fn read_dns(service: &str) -> Result<Vec<String>, String> {
    let o = Command::new("/usr/sbin/networksetup").args(["-getdnsservers", service]).output().map_err(|e| e.to_string())?;
    if !o.status.success() { return Err(format!("Не удалось прочитать DNS: {}", String::from_utf8_lossy(&o.stderr).trim())); }
    let text = String::from_utf8(o.stdout).map_err(|_| "Некорректный вывод DNS")?;
    if text.to_lowercase().contains("there aren't any dns servers set") || text.to_lowercase().contains("no dns servers") { return Ok(Vec::new()); }
    text.lines().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.parse::<std::net::IpAddr>().map(|ip| ip.to_string()).map_err(|_| format!("Неизвестный адрес DNS: {s}"))).collect()
}
fn default_route_interface(route_output: &str) -> Result<String, String> {
    route_output.lines().find_map(|line| line.trim().strip_prefix("interface:").map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned))
        .ok_or_else(|| "Не удалось определить интерфейс маршрута по умолчанию".into())
}
fn service_for_interface(interface: &str, service_order: &str) -> Result<String, String> {
    let mut service = None;
    for line in service_order.lines().map(str::trim) {
        if !line.starts_with('(') { continue; }
        if let Some((prefix, detail)) = line.split_once(") ") {
            if prefix[1..].chars().all(|c| c.is_ascii_digit()) {
                service = Some(detail.trim_start_matches('*').trim().to_owned());
                continue;
            }
        }
        let device = line.split_once("Device:").map(|(_, value)| value.split([',', ')']).next().unwrap_or("").trim());
        if line.contains("Hardware Port:") && device == Some(interface) {
            return service.filter(|s| !s.is_empty()).ok_or_else(|| "Не найдено имя сетевой службы для интерфейса".into());
        }
    }
    Err(format!("Для интерфейса {interface} не найдена сетевая служба macOS"))
}
fn active_network_service() -> Result<String, String> {
    let route = Command::new("/sbin/route").args(["-n", "get", "default"]).output().map_err(|e| e.to_string())?;
    if !route.status.success() { return Err(format!("Не удалось прочитать маршрут по умолчанию: {}", String::from_utf8_lossy(&route.stderr).trim())); }
    let interface = default_route_interface(&String::from_utf8(route.stdout).map_err(|_| "Некорректный вывод route")?)?;
    let order = Command::new("/usr/sbin/networksetup").arg("-listnetworkserviceorder").output().map_err(|e| e.to_string())?;
    if !order.status.success() { return Err(format!("Не удалось прочитать сетевые службы: {}", String::from_utf8_lossy(&order.stderr).trim())); }
    service_for_interface(&interface, &String::from_utf8(order.stdout).map_err(|_| "Некорректный список сетевых служб")?)
}
fn set_dns(service: &str, values: &[String]) -> Result<(), String> {
    let mut c = Command::new("/usr/sbin/networksetup");
    c.arg("-setdnsservers").arg(service);
    if values.is_empty() { c.arg("Empty"); } else { c.args(values); }
    let o = c.output().map_err(|e| e.to_string())?;
    if !o.status.success() { return Err(format!("Не удалось настроить DNS: {}", String::from_utf8_lossy(&o.stderr).trim())); }
    Ok(())
}
fn dns_restore_action(current: &[String], journal: &DnsJournal) -> DnsRestoreAction {
    if current == journal.applied { DnsRestoreAction::RestoreOriginal }
    else if current == journal.original { DnsRestoreAction::AlreadyRestored }
    else { DnsRestoreAction::Conflict }
}
fn restore_dns_transaction(
    journal: &DnsJournal,
    mut read: impl FnMut() -> Result<Vec<String>, String>,
    mut set: impl FnMut(&[String]) -> Result<(), String>,
    mut remove_journal: impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    match dns_restore_action(&read()?, journal) {
        DnsRestoreAction::RestoreOriginal => set(&journal.original)?,
        DnsRestoreAction::AlreadyRestored => {},
        DnsRestoreAction::Conflict => return Err("DNS менялся во время VPN; настройки не перезаписаны, журнал оставлен.".into()),
    }
    if read()? != journal.original { return Err("Не удалось подтвердить восстановление DNS; журнал оставлен.".into()); }
    remove_journal()
}
fn restore_dns() -> Result<(), String> {
    let path = root_path("dns.json");
    let bytes = match fs::read(&path) { Ok(b) => b, Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()), Err(e) => return Err(e.to_string()) };
    let journal: DnsJournal = serde_json::from_slice(&bytes).map_err(|_| "Повреждён журнал восстановления DNS")?;
    restore_dns_transaction(&journal, || read_dns(&journal.service), |servers| set_dns(&journal.service, servers), || fs::remove_file(&path).map_err(|e| e.to_string()))
}
fn choose_utun() -> Result<String, String> {
    for i in 10..=1024 {
        let name = format!("utun{i}");
        if !Command::new("/sbin/ifconfig").arg(&name).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false) { return Ok(name); }
    }
    Err("Не найден свободный интерфейс utun".into())
}
fn xray_log() -> PathBuf { root_path("xray.log") }
fn terminate_child(child: &mut Child) -> Result<(), String> {
    if child.try_wait().ok().flatten().is_some() { return Ok(()); }
    if unsafe { libc::kill(child.id() as i32, libc::SIGTERM) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) { return Err(format!("Не удалось остановить Xray: {error}")); }
    }
    for _ in 0..20 {
        if child.try_wait().ok().flatten().is_some() { return Ok(()); }
        thread::sleep(Duration::from_millis(100));
    }
    if unsafe { libc::kill(child.id() as i32, libc::SIGKILL) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) { return Err(format!("Не удалось завершить Xray: {error}")); }
    }
    child.wait().map(|_| ()).map_err(|e| format!("Не удалось дождаться завершения Xray: {e}"))
}
fn rollback_start(child: Option<&mut Child>, config_path: &Path) -> Result<(), String> {
    if let Some(child) = child { terminate_child(child)?; }
    let _ = fs::remove_file(root_path("process.json"));
    let _ = fs::remove_file(config_path);
    restore_dns()
}
fn append_rollback_error(error: String, rollback: Result<(), String>) -> String {
    match rollback { Ok(()) => error, Err(e) => format!("{error}; не удалось полностью восстановить сеть: {e}") }
}
fn probe_decision(dns: Option<bool>, tcp: Option<bool>) -> Option<bool> {
    if dns == Some(true) || tcp == Some(true) { Some(true) }
    else if dns == Some(false) && tcp == Some(false) { Some(false) }
    else { None }
}
fn dns_probe(timeout: Duration) -> bool {
    let result = || -> std::io::Result<bool> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        socket.connect("1.1.1.1:53")?;
        // A query for example.com; the fixed identifier is checked in the reply.
        let query: [u8; 29] = [0x56, 0x50, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1];
        socket.send(&query)?;
        let mut reply = [0u8; 512];
        let len = socket.recv(&mut reply)?;
        Ok(len >= 12 && reply[0..2] == query[0..2] && reply[2] & 0x80 != 0 && reply[3] & 0x0f == 0)
    };
    result().unwrap_or(false)
}
// A bare connect() can succeed against the local TUN stack, so require response bytes from the far side.
fn tcp_probe(timeout: Duration) -> bool {
    let result = || -> std::io::Result<bool> {
        let target = SocketAddr::from(([1, 1, 1, 1], 80));
        let mut stream = TcpStream::connect_timeout(&target, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(b"HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")?;
        let mut reply = [0u8; 16];
        let len = stream.read(&mut reply)?;
        Ok(reply[..len].starts_with(b"HTTP/"))
    };
    result().unwrap_or(false)
}
fn route_uses_tun(tun: &str) -> Result<bool, String> {
    let output = Command::new("/sbin/route").args(["-n", "get", "1.1.1.1"]).output().map_err(|e| e.to_string())?;
    if !output.status.success() { return Err("Не удалось проверить маршрут до 1.1.1.1".into()); }
    let text = String::from_utf8(output.stdout).map_err(|_| "Некорректный вывод route")?;
    Ok(default_route_interface(&text)? == tun)
}
fn verify_tunnel_connectivity(tun: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let failure = "VPN запущен, но трафик через сервер не проходит: DNS и TCP недоступны.";
    match route_uses_tun(tun) {
        Ok(true) => {},
        Ok(false) => return Err("VPN запущен, но маршрут до 1.1.1.1 не проходит через TUN.".into()),
        Err(e) => return Err(format!("VPN запущен, но не удалось проверить маршрут через TUN: {e}")),
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() { return Err(failure.into()); }
    let (sender, receiver) = mpsc::channel();
    let dns_sender = sender.clone();
    thread::spawn(move || { let _ = dns_sender.send((true, dns_probe(remaining))); });
    thread::spawn(move || {
        let _ = sender.send((false, tcp_probe(remaining)));
    });
    let (mut dns, mut tcp) = (None, None);
    loop {
        match probe_decision(dns, tcp) {
            Some(true) => return match route_uses_tun(tun) {
                Ok(true) => Ok(()),
                Ok(false) => Err("VPN запущен, но маршрут до 1.1.1.1 больше не проходит через TUN.".into()),
                Err(e) => Err(format!("VPN запущен, но не удалось проверить маршрут через TUN: {e}")),
            },
            Some(false) => return Err(failure.into()),
            None => {},
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(failure.into()); }
        match receiver.recv_timeout(remaining) {
            Ok((true, ok)) => dns = Some(ok),
            Ok((false, ok)) => tcp = Some(ok),
            Err(_) => return Err(failure.into()),
        }
    }
}
fn start(state: &mut HelperState, link: &str) -> Result<String, String> {
    if let Some(t) = state.active.as_ref() { if process_matches(&t.record) { return Ok("VPN уже подключён через TUN.".into()); } }
    if let Some(mut old) = state.active.take() { if let Some(child) = old.child.as_mut() { let _ = child.try_wait(); } }
    if let Some(record) = read_record()? {
        if process_matches(&record) { return Ok("VPN уже подключён через TUN.".into()); }
        let _ = fs::remove_file(root_path("process.json"));
    }
    restore_dns()?;
    let _ = fs::remove_file(root_path("config.json"));
    let tun = choose_utun()?;
    let config = vpn_core::profile::vless_xhttp_tun_config(link, &tun)?;
    let config_path = root_path("config.json");
    write_secure(&config_path, config.to_string().as_bytes())?;
    let check = Command::new(&state.xray).args(["run", "-test", "-config"]).arg(&config_path).stdout(Stdio::null()).stderr(Stdio::piped()).output().map_err(|e| e.to_string())?;
    if !check.status.success() { let _ = fs::remove_file(&config_path); return Err(format!("Xray отклонил TUN-конфигурацию: {}", String::from_utf8_lossy(&check.stderr).trim())); }
    let service = active_network_service()?;
    let original = read_dns(&service)?;
    let applied = vec!["1.1.1.1".to_owned(), "1.0.0.1".to_owned()];
    let journal = DnsJournal { service, original, applied: applied.clone() };
    write_secure(&root_path("dns.json"), &serde_json::to_vec(&journal).map_err(|e| e.to_string())?)?;
    if let Err(e) = set_dns(&journal.service, &applied) {
        return Err(append_rollback_error(e, rollback_start(None, &config_path)));
    }
    let log = match OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(xray_log()) {
        Ok(file) => file,
        Err(e) => return Err(append_rollback_error(e.to_string(), rollback_start(None, &config_path))),
    };
    let log_err = match log.try_clone() {
        Ok(file) => file,
        Err(e) => return Err(append_rollback_error(e.to_string(), rollback_start(None, &config_path))),
    };
    let child = match Command::new(&state.xray).args(["run", "-config"]).arg(&config_path).stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(log_err)).spawn() {
        Ok(child) => child,
        Err(e) => return Err(append_rollback_error(e.to_string(), rollback_start(None, &config_path))),
    };
    let mut child = child;
    let start_time = match process_info(child.id()) {
        Ok(Some((_, start))) => start,
        Ok(None) => { let error = "Не удалось прочитать PID и время старта Xray".to_owned(); return Err(append_rollback_error(error, rollback_start(Some(&mut child), &config_path))); },
        Err(e) => return Err(append_rollback_error(e, rollback_start(Some(&mut child), &config_path))),
    };
    let record = ProcessRecord { pid: child.id(), config_path: config_path.to_string_lossy().into_owned(), xray_path: state.xray.to_string_lossy().into_owned(), tun_name: tun.clone(), start_time };
    let record_bytes = match serde_json::to_vec(&record) {
        Ok(bytes) => bytes,
        Err(e) => return Err(append_rollback_error(e.to_string(), rollback_start(Some(&mut child), &config_path))),
    };
    if let Err(e) = write_secure(&root_path("process.json"), &record_bytes) {
        return Err(append_rollback_error(e, rollback_start(Some(&mut child), &config_path)));
    }
    let mut ready = false;
    let mut startup_error = None;
    for _ in 0..100 {
        match child.try_wait() {
            Ok(Some(status)) => { startup_error = Some(format!("Xray завершился при запуске ({status})")); break; }
            Ok(None) => {},
            Err(e) => { startup_error = Some(format!("Не удалось проверить процесс Xray: {e}")); break; }
        }
        if Command::new("/sbin/ifconfig").arg(&tun).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false) { ready = true; break; }
        thread::sleep(Duration::from_millis(100));
    }
    if !ready {
        let log = fs::read_to_string(xray_log()).unwrap_or_default();
        let reason = startup_error.unwrap_or_else(|| format!("Xray не поднял TUN: {}", log.lines().last().unwrap_or("нет сообщения журнала")));
        return Err(append_rollback_error(reason, rollback_start(Some(&mut child), &config_path)));
    }
    if let Err(error) = verify_tunnel_connectivity(&tun) {
        return Err(append_rollback_error(error, rollback_start(Some(&mut child), &config_path)));
    }
    match child.try_wait() {
        Ok(None) => {},
        Ok(Some(status)) => return Err(append_rollback_error(format!("Xray завершился во время проверки VPN ({status})"), rollback_start(Some(&mut child), &config_path))),
        Err(e) => return Err(append_rollback_error(format!("Не удалось проверить процесс Xray: {e}"), rollback_start(Some(&mut child), &config_path))),
    }
    state.active = Some(Tunnel { child: Some(child), record: record.clone() });
    Ok(format!("VPN подключён через {tun}; системный трафик направлен в TUN."))
}
fn stop(state: &mut HelperState) -> Result<(), String> {
    let mut tunnel = state.active.take();
    let record = match tunnel.as_ref() { Some(t) => Some(t.record.clone()), None => read_record()? };
    let Some(record) = record else {
        restore_dns()?;
        let _ = fs::remove_file(root_path("config.json"));
        return Ok(());
    };
    if let Some(child) = tunnel.as_mut().and_then(|t| t.child.as_mut()) {
        terminate_child(child)?;
    } else if process_matches(&record) {
        unsafe { libc::kill(record.pid as i32, libc::SIGTERM); }
        for _ in 0..100 {
            if !process_matches(&record) { break; }
            thread::sleep(Duration::from_millis(100));
        }
        if process_matches(&record) { unsafe { libc::kill(record.pid as i32, libc::SIGKILL); } return Err("Xray не завершился; журнал сохранён.".into()); }
    }
    if let Some(mut t) = tunnel { if let Some(child) = t.child.as_mut() { let _ = child.wait(); } }
    let _ = fs::remove_file(root_path("process.json")); let _ = fs::remove_file(root_path("config.json"));
    restore_dns()?;
    Ok(())
}
fn connected(state: &HelperState) -> bool {
    state.active.as_ref().is_some_and(|t| process_matches(&t.record)) || read_record().ok().flatten().is_some_and(|r| process_matches(&r))
}
fn handle(state: &mut HelperState, req: Request) -> Response {
    match req.action.as_str() {
        "status" => { let is_connected = connected(state); response(true, is_connected, if is_connected { "TUN подключён" } else { "TUN отключён" }) },
        "start" => match req.link.as_deref() { Some(link) => match start(state, link) { Ok(m) => response(true, true, m), Err(e) => response(false, connected(state), e) }, None => response(false, connected(state), "Не передан профиль клиента") },
        "stop" => match stop(state) { Ok(()) => response(true, false, "VPN отключён; DNS восстановлен"), Err(e) => response(false, connected(state), e) },
        _ => response(false, connected(state), "Неизвестная команда помощника"),
    }
}
fn serve(uid: u32, xray: PathBuf) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 { return Err("Помощник должен работать от root".into()); }
    fs::create_dir_all(HELPER_DIR).map_err(|e| e.to_string())?;
    fs::set_permissions(HELPER_DIR, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let socket_path = Path::new(SOCKET);
    if let Ok(meta) = fs::symlink_metadata(socket_path) {
        if !meta.file_type().is_socket() { return Err("Путь сокета занят не сокетом".into()); }
        fs::remove_file(socket_path).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(socket_path).map_err(|e| e.to_string())?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    let cpath = std::ffi::CString::new(SOCKET).map_err(|e| e.to_string())?;
    if unsafe { libc::chown(cpath.as_ptr(), uid, 20) } != 0 { return Err("Не удалось назначить владельца сокета".into()); }
    let mut state = HelperState { uid, xray, active: None };
    if let Some(record) = read_record()? {
        if record.start_time.is_empty() {
            if let Some((command, _)) = process_info(record.pid)? {
                if command.contains(&record.xray_path) && command.contains(&record.config_path) && command.contains("run -config") {
                    return Err("У запущенного Xray отсутствует сохранённое время старта. Отключите VPN прежней версией клиента перед обновлением helper-а.".into());
                }
            }
        }
        if process_matches(&record) {
            state.active = Some(Tunnel { child: None, record });
        } else {
            let _ = fs::remove_file(root_path("process.json"));
            let _ = fs::remove_file(root_path("config.json"));
            if let Err(e) = restore_dns() { eprintln!("vpn-tun-helper: startup recovery: {e}"); }
        }
    } else if let Err(e) = restore_dns() { eprintln!("vpn-tun-helper: startup DNS recovery: {e}"); }
    let state = Arc::new(Mutex::new(state));
    let monitor_state = Arc::clone(&state);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        if let Ok(mut state) = monitor_state.lock() { reap_exited_process(&mut state); }
    });
    for incoming in listener.incoming() {
        let mut stream = match incoming { Ok(s) => s, Err(_) => continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let mut peer_uid: libc::uid_t = 0; let mut peer_gid: libc::gid_t = 0;
        let authorized = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut peer_uid, &mut peer_gid) } == 0
            && state.lock().map(|state| peer_uid == state.uid).unwrap_or(false);
        let reply = if authorized {
            let mut line = String::new();
            match BufReader::new(&stream).take(64 * 1024).read_line(&mut line) {
                Ok(_) => match serde_json::from_str::<Request>(&line) {
                    Ok(r) => match state.lock() { Ok(mut state) => handle(&mut state, r), Err(_) => response(false, false, "Состояние helper недоступно") },
                    Err(_) => response(false, state.lock().map(|s| connected(&s)).unwrap_or(false), "Некорректный запрос"),
                },
                Err(e) => response(false, state.lock().map(|s| connected(&s)).unwrap_or(false), e.to_string()),
            }
        } else { response(false, state.lock().map(|s| connected(&s)).unwrap_or(false), "Клиент не авторизован") };
        if let Ok(json) = serde_json::to_vec(&reply) { let _ = stream.write_all(&json); let _ = stream.write_all(b"\n"); }
    }
    Ok(())
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 || args[1] != "serve" { eprintln!("usage: vpn-tun-helper serve UID XRAY --system"); std::process::exit(2); }
    let uid = match parse_uid(&args[2]) { Ok(uid) => uid, Err(e) => { eprintln!("invalid UID: {e}"); std::process::exit(2); } };
    let xray = PathBuf::from(&args[3]);
    // The final arg is a fixed marker to reject malformed LaunchDaemon argument lists.
    if args[4] != "--system" { eprintln!("invalid helper scope"); std::process::exit(2); }
    if let Err(e) = serve(uid, xray) { eprintln!("vpn-tun-helper: {e}"); std::process::exit(1); }
}

fn reap_exited_process(state: &mut HelperState) {
    let record = state.active.as_ref().map(|t| t.record.clone()).or_else(|| read_record().ok().flatten());
    let Some(record) = record else { return; };
    let child_exited = state.active.as_mut().and_then(|t| t.child.as_mut())
        .and_then(|child| child.try_wait().ok().flatten()).is_some();
    if !child_exited && process_matches(&record) { return; }
    if let Some(mut tunnel) = state.active.take() {
        if let Some(child) = tunnel.child.as_mut() { let _ = child.try_wait(); }
    }
    let _ = fs::remove_file(root_path("process.json"));
    let _ = fs::remove_file(root_path("config.json"));
    if let Err(e) = restore_dns() { eprintln!("vpn-tun-helper: failed to restore DNS after Xray exit: {e}"); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connectivity_requires_at_least_one_successful_probe() {
        assert_eq!(probe_decision(None, None), None);
        assert_eq!(probe_decision(Some(false), None), None);
        assert_eq!(probe_decision(None, Some(false)), None);
        assert_eq!(probe_decision(Some(true), None), Some(true));
        assert_eq!(probe_decision(Some(false), Some(true)), Some(true));
        assert_eq!(probe_decision(Some(true), Some(false)), Some(true));
        assert_eq!(probe_decision(Some(false), Some(false)), Some(false));
    }

    #[test]
    fn uid_parser_rejects_invalid_and_root_values() {
        assert_eq!(parse_uid("501"), Ok(501));
        assert!(parse_uid("not-a-uid").is_err());
        assert!(parse_uid("0").is_err());
        assert!(parse_uid("-1").is_err());
    }

    #[test]
    fn parses_default_route_interface() {
        assert_eq!(default_route_interface("route to: default\ninterface: en7\n"), Ok("en7".into()));
        assert!(default_route_interface("route to: default\n").is_err());
    }

    #[test]
    fn maps_interface_to_network_service() {
        let services = "(1) Ethernet Adapter\n(Hardware Port: Ethernet, Device: en0)\n(2) USB LAN\n(Hardware Port: USB 10/100/1000 LAN, Device: en7)\n";
        assert_eq!(service_for_interface("en7", services), Ok("USB LAN".into()));
        assert!(service_for_interface("en9", services).is_err());
        assert!(service_for_interface("en1", "(1) Ethernet\n(Hardware Port: Ethernet, Device: en10)\n").is_err());
    }

    #[test]
    fn dns_restore_keeps_conflicting_user_changes() {
        let journal = DnsJournal { service: "Ethernet".into(), original: vec!["192.0.2.1".into()], applied: vec!["1.1.1.1".into()] };
        assert_eq!(dns_restore_action(&journal.applied, &journal), DnsRestoreAction::RestoreOriginal);
        assert_eq!(dns_restore_action(&journal.original, &journal), DnsRestoreAction::AlreadyRestored);
        assert_eq!(dns_restore_action(&["203.0.113.2".into()], &journal), DnsRestoreAction::Conflict);
    }

    #[test]
    fn dns_journal_survives_failed_restoration() {
        use std::cell::Cell;
        let journal = DnsJournal { service: "Ethernet".into(), original: vec![], applied: vec!["1.1.1.1".into()] };
        let removed = Cell::new(false);
        let result = restore_dns_transaction(&journal, || Ok(journal.applied.clone()), |_| Err("set failed".into()), || { removed.set(true); Ok(()) });
        assert_eq!(result, Err("set failed".into()));
        assert!(!removed.get());
    }

    #[test]
    fn dns_journal_is_removed_only_after_verified_restoration() {
        use std::cell::{Cell, RefCell};
        let journal = DnsJournal { service: "Ethernet".into(), original: vec![], applied: vec!["1.1.1.1".into()] };
        let current = RefCell::new(journal.applied.clone());
        let removed = Cell::new(false);
        let result = restore_dns_transaction(&journal, || Ok(current.borrow().clone()), |values| { *current.borrow_mut() = values.to_vec(); Ok(()) }, || { removed.set(true); Ok(()) });
        assert!(result.is_ok());
        assert!(removed.get());
        assert_eq!(*current.borrow(), journal.original);
    }

    #[test]
    fn process_identity_includes_start_time() {
        let record = ProcessRecord { pid: 42, config_path: "/secure/config.json".into(), xray_path: "/secure/xray".into(), tun_name: "utun10".into(), start_time: "Tue Oct 27 12:00:00 2026".into() };
        let command = "/secure/xray run -config /secure/config.json";
        assert!(matches_process_info(&record, command, "Tue Oct 27 12:00:00 2026"));
        assert!(!matches_process_info(&record, command, "Tue Oct 27 12:00:01 2026"));
        let mut old = record;
        old.start_time.clear();
        assert!(!matches_process_info(&old, command, "Tue Oct 27 12:00:00 2026"));
    }
}
