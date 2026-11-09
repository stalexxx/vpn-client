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
const ASSET_DIR: &str = "/Library/PrivilegedHelperTools/vpnclient-assets";
const AWG_BIN: &str = "/Library/PrivilegedHelperTools/local.vpn-client.awgsocks";
const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize)]
struct Request { action: String, #[serde(default)] link: Option<String>, #[serde(default)] relay_link: Option<String>, #[serde(default)] lines: Option<usize>, #[serde(default)] filter: Option<String>, #[serde(default)] level: Option<String>, #[serde(default)] bypass: Option<vpn_core::profile::Bypass> }
#[derive(Serialize)]
struct Response { ok: bool, connected: bool, message: String, version: &'static str, connectivity_check: bool, reality_support: bool, hysteria2_support: bool, hysteria_chain_support: bool, awg_support: bool }
#[derive(Clone, Serialize, Deserialize)]
struct ProcessRecord { pid: u32, config_path: String, xray_path: String, tun_name: String, #[serde(default)] start_time: String }
#[derive(Serialize, Deserialize)]
struct DnsJournal { service: String, original: Vec<String>, applied: Vec<String> }
struct Tunnel { child: Option<Child>, record: ProcessRecord }
struct HelperState { uid: u32, xray: PathBuf, active: Option<Tunnel>, last: Option<(String, Option<String>, vpn_core::profile::Bypass)> }

#[derive(Debug, PartialEq, Eq)]
enum DnsRestoreAction { RestoreOriginal, AlreadyRestored, Conflict }

fn root_path(name: &str) -> PathBuf { Path::new(HELPER_DIR).join(name) }
fn response(ok: bool, connected: bool, message: impl Into<String>) -> Response { Response { ok, connected, message: message.into(), version: HELPER_VERSION, connectivity_check: true, reality_support: true, hysteria2_support: true, hysteria_chain_support: true, awg_support: true } }
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
/// Diagnostic log level, chosen over MCP/UI and applied at the next connection.
fn verbose_log() -> bool { fs::read_to_string(root_path("log-level")).map(|v| v.trim() == "info").unwrap_or(false) }
/// Sum the per-outbound counters from `xray api statsquery` into {direct, vpn} totals.
fn parse_stats(json_text: &str) -> Result<serde_json::Value, String> {
    let value: serde_json::Value = serde_json::from_str(json_text).map_err(|_| "Некорректный ответ статистики Xray".to_owned())?;
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
    Ok(serde_json::json!({"direct":{"up":totals[0][0],"down":totals[0][1]},"vpn":{"up":totals[1][0],"down":totals[1][1]},"ts_ms":ts_ms}))
}
fn tail_log(text: &str, lines: usize, filter: Option<&str>) -> String {
    let mut picked: Vec<&str> = text.lines().filter(|l| filter.map_or(true, |f| l.contains(f))).collect();
    if picked.len() > lines { picked.drain(..picked.len() - lines); }
    let mut out = picked.join("\n");
    if out.len() > 8000 {
        let mut cut = out.len() - 8000;
        while !out.is_char_boundary(cut) { cut += 1; }
        out = out[cut..].to_owned();
    }
    out
}
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
    kill_awg();
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
struct AwgProc { child: Child, port: u16 }
static AWG_ACTIVE: Mutex<Option<AwgProc>> = Mutex::new(None);
/// Physical interface seen before the tunnel came up (the default route points into the TUN afterwards).
static PHYS_IFACE: Mutex<Option<String>> = Mutex::new(None);
fn remember_physical_interface() -> Result<String, String> {
    let route = Command::new("/sbin/route").args(["-n", "get", "default"]).output().map_err(|e| e.to_string())?;
    match default_route_interface(&String::from_utf8_lossy(&route.stdout)) {
        Ok(iface) if !iface.starts_with("utun") => { if let Ok(mut g) = PHYS_IFACE.lock() { *g = Some(iface.clone()); } Ok(iface) }
        _ => PHYS_IFACE.lock().ok().and_then(|g| g.clone()).ok_or_else(|| "Маршрут по умолчанию ведёт в другой туннель: отключите его перед подключением AmneziaWG.".to_owned()),
    }
}
/// Stops the active embedded AmneziaWG client (and removes its files), also one left over by a previous helper process.
fn kill_awg() {
    let active = AWG_ACTIVE.lock().ok().and_then(|mut g| g.take());
    if let Some(mut a) = active { let _ = terminate_child(&mut a.child); }
    else if let Some(pid) = fs::read_to_string(root_path("awg.pid")).ok().and_then(|v| v.trim().parse::<u32>().ok()) {
        if process_info(pid).ok().flatten().is_some_and(|(command, _)| command.contains(AWG_BIN)) {
            unsafe { libc::kill(pid as i32, libc::SIGTERM); }
            thread::sleep(Duration::from_millis(300));
            if process_info(pid).ok().flatten().is_some_and(|(command, _)| command.contains(AWG_BIN)) { unsafe { libc::kill(pid as i32, libc::SIGKILL); } }
        }
    }
    let _ = fs::remove_file(root_path("awg.pid"));
}
/// Spawns the AmneziaWG client of an `awg://` profile as a loopback SOCKS5 proxy whose UDP sockets are pinned to the
/// physical interface (so the tunnel to the server never enters our own TUN). Does not touch the active one.
fn spawn_awg(link: &str) -> Result<AwgProc, String> {
    let conf = vpn_core::awglink::link_to_conf(link)?;
    let iface = remember_physical_interface()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).map_err(|e| e.to_string())?;
    let conf_path = root_path(&format!("awg-{port}.conf"));
    write_secure(&conf_path, conf.as_bytes())?;
    let log = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(root_path("awg.log")).map_err(|e| e.to_string())?;
    let log_err = log.try_clone().map_err(|e| e.to_string())?;
    let spawned = Command::new(AWG_BIN).arg(&conf_path).arg(format!("127.0.0.1:{port}")).env("AWG_BIND_IFACE", &iface)
        .stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(log_err)).spawn();
    let mut child = match spawned { Ok(c) => c, Err(e) => { let _ = fs::remove_file(&conf_path); return Err(format!("Не удалось запустить клиент AmneziaWG: {e}")); } };
    let result = (|| {
        for _ in 0..100 {
            if let Ok(Some(status)) = child.try_wait() {
                let log = fs::read_to_string(root_path("awg.log")).unwrap_or_default();
                return Err(format!("Клиент AmneziaWG завершился ({status}): {}", log.lines().last().unwrap_or("нет сообщения")));
            }
            if TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(100)).is_ok() { return Ok(()); }
            thread::sleep(Duration::from_millis(100));
        }
        Err("Клиент AmneziaWG не запустился за 10 секунд".to_owned())
    })();
    let _ = fs::remove_file(&conf_path); // the client has read it; the private key must not stay on disk
    match result { Ok(()) => Ok(AwgProc { child, port }), Err(e) => { let _ = terminate_child(&mut child); Err(e) } }
}
/// Makes `new` the active client and stops the previous one.
fn commit_awg(new: AwgProc) {
    let _ = write_secure(&root_path("awg.pid"), new.child.id().to_string().as_bytes());
    let old = AWG_ACTIVE.lock().ok().and_then(|mut g| g.replace(new));
    if let Some(mut o) = old { let _ = terminate_child(&mut o.child); }
}
fn active_awg_port() -> Option<u16> { AWG_ACTIVE.lock().ok().and_then(|g| g.as_ref().map(|a| a.port)) }
fn socks_link(port: u16) -> String { format!("socks5://127.0.0.1:{port}") }
fn tunnel_running(state: &HelperState) -> bool {
    state.active.as_ref().is_some_and(|t| process_matches(&t.record)) || read_record().ok().flatten().is_some_and(|r| process_matches(&r))
}
fn start(state: &mut HelperState, link: &str, relay_link: Option<&str>, bypass: &vpn_core::profile::Bypass, hot: bool) -> Result<String, String> {
    if tunnel_running(state) { return Ok("VPN уже подключён через TUN.".into()); }
    let _ = remember_physical_interface();
    if !link.starts_with(vpn_core::awglink::SCHEME) { return start_tunnel(state, link, relay_link, bypass, hot); }
    kill_awg();
    let awg = spawn_awg(link)?;
    let port = awg.port;
    commit_awg(awg);
    match start_tunnel(state, &socks_link(port), None, bypass, hot) { Ok(m) => Ok(m), Err(e) => { kill_awg(); Err(e) } }
}
/// `hot`: DNS is already pinned by the previous tunnel (kept by `stop(.., true)`), so it is neither restored nor re-journaled.
fn start_tunnel(state: &mut HelperState, link: &str, relay_link: Option<&str>, bypass: &vpn_core::profile::Bypass, hot: bool) -> Result<String, String> {
    if let Some(t) = state.active.as_ref() { if process_matches(&t.record) { return Ok("VPN уже подключён через TUN.".into()); } }
    if let Some(mut old) = state.active.take() { if let Some(child) = old.child.as_mut() { let _ = child.try_wait(); } }
    if let Some(record) = read_record()? {
        if process_matches(&record) { return Ok("VPN уже подключён через TUN.".into()); }
        let _ = fs::remove_file(root_path("process.json"));
    }
    if !hot { restore_dns()?; }
    let _ = fs::remove_file(root_path("config.json"));
    let tun = choose_utun()?;
    let api_port = std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).map_err(|e| e.to_string())?;
    write_secure(&root_path("api-port"), api_port.to_string().as_bytes())?;
    let config = vpn_core::profile::vless_tun_config_with_options(link, &tun, relay_link, verbose_log(), Some(api_port), bypass)?;
    let config_path = root_path("config.json");
    write_secure(&config_path, config.to_string().as_bytes())?;
    let check = Command::new(&state.xray).env("XRAY_LOCATION_ASSET", ASSET_DIR).args(["run", "-test", "-config"]).arg(&config_path).stdout(Stdio::null()).stderr(Stdio::piped()).output().map_err(|e| e.to_string())?;
    if !check.status.success() { let _ = fs::remove_file(&config_path); return Err(format!("Xray отклонил TUN-конфигурацию: {}", String::from_utf8_lossy(&check.stderr).trim())); }
    if !hot {
        let service = active_network_service()?;
        let original = read_dns(&service)?;
        let applied = vec!["1.1.1.1".to_owned(), "1.0.0.1".to_owned()];
        let journal = DnsJournal { service, original, applied: applied.clone() };
        write_secure(&root_path("dns.json"), &serde_json::to_vec(&journal).map_err(|e| e.to_string())?)?;
        if let Err(e) = set_dns(&journal.service, &applied) {
            return Err(append_rollback_error(e, rollback_start(None, &config_path)));
        }
    }
    let log = match OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(xray_log()) {
        Ok(file) => file,
        Err(e) => return Err(append_rollback_error(e.to_string(), rollback_start(None, &config_path))),
    };
    let log_err = match log.try_clone() {
        Ok(file) => file,
        Err(e) => return Err(append_rollback_error(e.to_string(), rollback_start(None, &config_path))),
    };
    let child = match Command::new(&state.xray).env("XRAY_LOCATION_ASSET", ASSET_DIR).args(["run", "-config"]).arg(&config_path).stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(log_err)).spawn() {
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
/// `keep_dns`: stop only Xray and leave the pinned DNS in place (used by a hot profile switch).
fn stop(state: &mut HelperState, keep_dns: bool) -> Result<(), String> {
    let mut tunnel = state.active.take();
    let record = match tunnel.as_ref() { Some(t) => Some(t.record.clone()), None => read_record()? };
    let Some(record) = record else {
        kill_awg();
        if !keep_dns { restore_dns()?; }
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
    kill_awg();
    let _ = fs::remove_file(root_path("process.json")); let _ = fs::remove_file(root_path("config.json"));
    if !keep_dns { restore_dns()?; }
    Ok(())
}
/// Seamless profile change: restart Xray with the new profile while DNS stays pinned (no restore/re-apply flicker).
/// If the new profile fails, the previous one is brought back with a normal start.
fn switch(state: &mut HelperState, link: &str, relay_link: Option<&str>, bypass: &vpn_core::profile::Bypass) -> Response {
    let relay = relay_link.map(str::to_owned);
    if !connected(state) {
        return match start(state, link, relay_link, bypass, false) {
            Ok(m) => { state.last = Some((link.to_owned(), relay, bypass.clone())); response(true, true, m) }
            Err(e) => response(false, connected(state), e),
        };
    }
    if state.last.as_ref().is_some_and(|(l, r, _)| l == link && *r == relay) { return response(true, true, "VPN уже подключён к этому профилю."); }
    // Preferred path: replace the VPN outbound inside the running Xray; the TUN, routes and DNS stay up, and every
    // intermediate state of the swap blackholes traffic instead of letting it around the tunnel.
    match hot_switch(state, link, relay_link, bypass) {
        HotSwitch::Switched => { state.last = Some((link.to_owned(), relay, bypass.clone())); return response(true, true, "VPN переключён на новый профиль без разрыва туннеля."); }
        HotSwitch::Failed(error) => return response(false, connected(state), error),
        HotSwitch::NotApplicable(reason) => eprintln!("горячая замена профиля недоступна ({reason}); перезапускаем Xray"),
    }
    // Fallback (different exclusions, Xray started by an older helper, API unavailable): restart Xray.
    let previous = state.last.clone();
    if let Err(e) = stop(state, true) { return response(false, connected(state), e); }
    match start(state, link, relay_link, bypass, true) {
        Ok(m) => { state.last = Some((link.to_owned(), relay, bypass.clone())); response(true, true, m) }
        Err(e) => {
            // start() already rolled the network back (DNS restored); try to restore the old tunnel.
            if let Some((old_link, old_relay, old_bypass)) = previous {
                match start(state, &old_link, old_relay.as_deref(), &old_bypass, false) {
                    Ok(_) => { state.last = Some((old_link, old_relay, old_bypass)); return response(false, true, format!("{e}; возвращён прежний профиль")); }
                    Err(e2) => { state.last = None; return response(false, connected(state), format!("{e}; прежний профиль тоже не поднялся: {e2}")); }
                }
            }
            state.last = None;
            response(false, connected(state), e)
        }
    }
}

enum HotSwitch { Switched, /** nothing was changed */ NotApplicable(String), /** the tunnel may be blocked or restored */ Failed(String) }

/// `xray api <sub>` against the running instance's loopback API (flags first, then positional arguments).
fn xray_api(state: &HelperState, port: u16, sub: &str, flags: &[&str], args: &[&str]) -> Result<(), String> {
    let output = Command::new(&state.xray).args(["api", sub]).args(flags).args(["-s", &format!("127.0.0.1:{port}"), "-t", "5"]).args(args)
        .stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
    if output.status.success() { Ok(()) }
    else { Err(format!("xray api {sub}: {}", String::from_utf8_lossy(&output.stderr).lines().last().unwrap_or("ошибка").trim())) }
}
fn swap_file(name: &str, value: &serde_json::Value) -> Result<String, String> {
    let path = root_path(name);
    write_secure(&path, value.to_string().as_bytes())?;
    Ok(path.to_string_lossy().into_owned())
}
/// Parks a rule that blackholes everything behind the tail rule, then removes the tail rule: from here on all
/// non-excluded traffic is dropped until `unpark`.
fn park(state: &HelperState, port: u16) -> Result<(), String> {
    let kill = swap_file("swap-kill.json", &serde_json::json!({"routing": {"rules": [vpn_core::profile::kill_rule()]}}))?;
    xray_api(state, port, "adrules", &["-append"], &[&kill])?;
    if let Err(e) = xray_api(state, port, "rmrules", &[], &["tail"]) { let _ = xray_api(state, port, "rmrules", &[], &["kill"]); return Err(e); }
    Ok(())
}
/// Restores the tail rule behind the kill rule (still blocking), then removes the kill rule.
fn unpark(state: &HelperState, port: u16) -> Result<(), String> {
    let tail = swap_file("swap-tail.json", &serde_json::json!({"routing": {"rules": [vpn_core::profile::tail_rule()]}}))?;
    xray_api(state, port, "adrules", &["-append"], &[&tail])?;
    xray_api(state, port, "rmrules", &[], &["kill"])
}
fn replace_vpn_outbounds(state: &HelperState, port: u16, outbounds: &serde_json::Value) -> Result<(), String> {
    let file = swap_file("swap-out.json", outbounds)?;
    let _ = xray_api(state, port, "rmo", &[], &["vpn-relay"]); // absent unless a relay is configured
    xray_api(state, port, "rmo", &[], &["vpn-out"])?;
    xray_api(state, port, "ado", &[], &[&file])
}
/// The VPN-related outbounds (relay first) of the TUN config for a profile.
fn vpn_outbounds(tun: &str, link: &str, relay: Option<&str>, bypass: &vpn_core::profile::Bypass, port: u16) -> Result<serde_json::Value, String> {
    let config = vpn_core::profile::vless_tun_config_with_options(link, tun, relay, verbose_log(), Some(port), bypass)?;
    let mut list: Vec<serde_json::Value> = config["outbounds"].as_array().map(|o| o.iter().filter(|o| o["tag"] == "vpn-out" || o["tag"] == "vpn-relay").cloned().collect()).unwrap_or_default();
    list.sort_by_key(|o| o["tag"] != "vpn-relay");
    if !list.iter().any(|o| o["tag"] == "vpn-out") { return Err("В конфигурации нет outbound-а vpn-out".into()); }
    Ok(serde_json::json!({"outbounds": list}))
}
fn hot_switch(state: &HelperState, link: &str, relay_link: Option<&str>, bypass: &vpn_core::profile::Bypass) -> HotSwitch {
    let Some((old_link, old_relay, old_bypass)) = state.last.clone() else { return HotSwitch::NotApplicable("профиль не отслеживается".into()) };
    // Exclusion rules live in the config Xray was started with; if they changed, only a restart can apply them.
    if old_bypass != *bypass { return HotSwitch::NotApplicable("исключения изменились".into()); }
    let Some(port) = fs::read_to_string(root_path("api-port")).ok().and_then(|v| v.trim().parse::<u16>().ok()) else { return HotSwitch::NotApplicable("порт API не записан".into()) };
    let Ok(Some(record)) = read_record() else { return HotSwitch::NotApplicable("нет записи о процессе".into()) };
    // AmneziaWG profiles are SOCKS outbounds to a local client: start the new one beside the old one first.
    let new_awg = if link.starts_with(vpn_core::awglink::SCHEME) { match spawn_awg(link) { Ok(a) => Some(a), Err(e) => return HotSwitch::NotApplicable(e) } } else { None };
    let new_eff = new_awg.as_ref().map(|a| socks_link(a.port)).unwrap_or_else(|| link.to_owned());
    let old_eff = if old_link.starts_with(vpn_core::awglink::SCHEME) { match active_awg_port() { Some(p) => socks_link(p), None => return HotSwitch::NotApplicable("клиент AmneziaWG не найден".into()) } } else { old_link.clone() };
    let (Ok(new), Ok(old)) = (vpn_outbounds(&record.tun_name, &new_eff, if new_awg.is_some() { None } else { relay_link }, bypass, port), vpn_outbounds(&record.tun_name, &old_eff, if old_link.starts_with(vpn_core::awglink::SCHEME) { None } else { old_relay.as_deref() }, &old_bypass, port)) else {
        if let Some(mut a) = new_awg { let _ = terminate_child(&mut a.child); }
        return HotSwitch::NotApplicable("не удалось собрать outbound".into());
    };
    if let Err(e) = park(state, port) { if let Some(mut a) = new_awg { let _ = terminate_child(&mut a.child); } return HotSwitch::NotApplicable(e); }
    // From here on traffic is blocked; every exit path either restores the tunnel or leaves it blocked (never open).
    // `parked` tracks whether the kill rule is still in force so the rollback never parks twice (a second park could
    // remove the kill rule while the tail rule is already gone, which would open the tunnel).
    let mut parked = true;
    let swapped = replace_vpn_outbounds(state, port, &new).and_then(|_| unpark(state, port)).and_then(|_| {
        parked = false;
        if tcp_probe(Duration::from_secs(6)) { Ok(()) } else { Err("новый профиль не пропускает трафик".to_owned()) }
    });
    if swapped.is_ok() {
        // Committed: the old client (if any) goes away; a non-AmneziaWG profile leaves none running.
        match new_awg { Some(a) => commit_awg(a), None => kill_awg() }
        return HotSwitch::Switched;
    }
    let Err(error) = swapped else { return HotSwitch::Switched };
    if let Some(mut a) = new_awg { let _ = terminate_child(&mut a.child); }
    // Roll back to the previous profile.
    if !parked { if let Err(e) = park(state, port) { return HotSwitch::Failed(format!("Не удалось переключить профиль: {error}; откат не удался ({e}); текущий профиль не работает, переподключите VPN")); } }
    let restored = replace_vpn_outbounds(state, port, &old).and_then(|_| unpark(state, port));
    match restored {
        Ok(()) if tcp_probe(Duration::from_secs(6)) => HotSwitch::Failed(format!("Не удалось переключить профиль: {error}; возвращён прежний профиль")),
        Ok(()) => HotSwitch::Failed(format!("Не удалось переключить профиль: {error}; прежний профиль тоже не пропускает трафик")),
        Err(e) => HotSwitch::Failed(format!("Не удалось переключить профиль: {error}; не удалось вернуть прежний ({e}). Трафик заблокирован: отключите и подключите VPN заново")),
    }
}
fn connected(state: &HelperState) -> bool { tunnel_running(state) }
fn handle(state: &mut HelperState, req: Request) -> Response {
    match req.action.as_str() {
        "status" => { let is_connected = connected(state); response(true, is_connected, if is_connected { "TUN подключён" } else { "TUN отключён" }) },
        "start" => match req.link.as_deref() { Some(link) => match { let was = connected(state); start(state, link, req.relay_link.as_deref(), &req.bypass.clone().unwrap_or_default(), false).map(|m| (was, m)) } { Ok((was, m)) => { if !was { state.last = Some((link.to_owned(), req.relay_link.clone(), req.bypass.clone().unwrap_or_default())); } response(true, true, m) }, Err(e) => response(false, connected(state), e) }, None => response(false, connected(state), "Не передан профиль клиента") },
        "switch" => match req.link.as_deref() { Some(link) => switch(state, link, req.relay_link.as_deref(), &req.bypass.clone().unwrap_or_default()), None => response(false, connected(state), "Не передан профиль клиента") },
        "stop" => match stop(state, false) { Ok(()) => response(true, false, "VPN отключён; DNS восстановлен"), Err(e) => response(false, connected(state), e) },
        "log" => {
            let lines = req.lines.unwrap_or(50).clamp(1, 300);
            let filter = req.filter.as_deref().filter(|f| !f.is_empty() && f.len() <= 64);
            match fs::read_to_string(xray_log()) {
                Ok(text) => { let out = tail_log(&text, lines, filter); response(true, connected(state), if out.is_empty() { "Нет строк журнала".to_owned() } else { out }) }
                Err(_) => response(true, connected(state), "Журнал Xray пуст или ещё не создан"),
            }
        }
        "stats" => {
            if !connected(state) { return response(false, false, "VPN не подключён"); }
            let port = match fs::read_to_string(root_path("api-port")).ok().and_then(|v| v.trim().parse::<u16>().ok()) { Some(p) => p, None => return response(false, true, "Статистика недоступна: порт API не записан") };
            match Command::new(&state.xray).args(["api", "statsquery", "-t", "2"]).arg(format!("--server=127.0.0.1:{port}")).stdin(Stdio::null()).stderr(Stdio::null()).output() {
                Ok(out) if out.status.success() => match parse_stats(&String::from_utf8_lossy(&out.stdout)) { Ok(v) => response(true, true, v.to_string()), Err(e) => response(false, true, e) },
                _ => response(false, true, "Статистика Xray недоступна"),
            }
        }
        "get_log_level" => response(true, connected(state), if verbose_log() { "info" } else { "warning" }),
        "set_log_level" => match req.level.as_deref() {
            Some(level @ ("info" | "warning")) => match write_secure(&root_path("log-level"), level.as_bytes()) {
                Ok(()) => response(true, connected(state), format!("Уровень журнала: {level}; применится при следующем подключении")),
                Err(e) => response(false, connected(state), e),
            },
            _ => response(false, connected(state), "Допустимые уровни: info, warning"),
        },
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
    let mut state = HelperState { uid, xray, active: None, last: None };
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
    if state.active.is_none() { kill_awg(); }
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
    // The embedded AmneziaWG client died while the tunnel is up: traffic is already blocked (no direct fallback), so
    // take the VPN down cleanly instead of leaving a silent blackhole.
    let awg_dead = AWG_ACTIVE.lock().ok().is_some_and(|mut g| g.as_mut().is_some_and(|a| a.child.try_wait().ok().flatten().is_some()));
    if awg_dead && connected(state) {
        eprintln!("vpn-tun-helper: клиент AmneziaWG завершился; VPN отключается");
        if let Err(e) = stop(state, false) { eprintln!("vpn-tun-helper: {e}"); }
        state.last = None;
        return;
    }
    let record = state.active.as_ref().map(|t| t.record.clone()).or_else(|| read_record().ok().flatten());
    let Some(record) = record else { return; };
    let child_exited = state.active.as_mut().and_then(|t| t.child.as_mut())
        .and_then(|child| child.try_wait().ok().flatten()).is_some();
    if !child_exited && process_matches(&record) { return; }
    if let Some(mut tunnel) = state.active.take() {
        if let Some(child) = tunnel.child.as_mut() { let _ = child.try_wait(); }
    }
    kill_awg();
    let _ = fs::remove_file(root_path("process.json"));
    let _ = fs::remove_file(root_path("config.json"));
    if let Err(e) = restore_dns() { eprintln!("vpn-tun-helper: failed to restore DNS after Xray exit: {e}"); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_sum_direct_and_vpn_outbounds_only() {
        let text = r#"{"stat":[{"name":"outbound>>>vpn-out>>>traffic>>>uplink","value":5},{"name":"outbound>>>vpn-out>>>traffic>>>downlink","value":70},{"name":"outbound>>>direct>>>traffic>>>downlink","value":900},{"name":"outbound>>>direct>>>traffic>>>uplink"},{"name":"outbound>>>vpn-relay>>>traffic>>>downlink","value":99},{"name":"user>>>x>>>traffic>>>uplink","value":1}]}"#;
        let v = parse_stats(text).unwrap();
        assert_eq!(v["direct"], serde_json::json!({"up":0,"down":900}));
        assert_eq!(v["vpn"], serde_json::json!({"up":5,"down":70}));
        assert!(parse_stats("nope").is_err());
    }

    #[test]
    fn log_tail_filters_limits_and_caps_size() {
        let text = "a direct bittorrent\nb vpn-out\nc direct bittorrent\nd direct bittorrent";
        assert_eq!(tail_log(text, 2, Some("bittorrent")), "c direct bittorrent\nd direct bittorrent");
        assert_eq!(tail_log(text, 10, Some("nothing")), "");
        let big = "я".repeat(20_000);
        let out = tail_log(&big, 1, None);
        assert!(out.len() <= 8000 && out.chars().all(|c| c == 'я'));
    }

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

    #[test]
    fn hot_switch_outbounds_contain_only_the_vpn_side() {
        let link = "vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=xhttp&security=tls&sni=example.org&path=%2F";
        let out = vpn_outbounds("utun9", link, None, &vpn_core::profile::Bypass::default(), 18000).unwrap();
        let tags: Vec<_> = out["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap().to_owned()).collect();
        // direct/block stay in the running config; only the replaceable outbound is swapped.
        assert_eq!(tags, vec!["vpn-out"]);
        assert!(vpn_outbounds("utun9", "not a link", None, &vpn_core::profile::Bypass::default(), 18000).is_err());
    }
}
