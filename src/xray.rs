use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Write,
    net::{TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};

#[derive(Default)]
pub struct XrayState(Mutex<Option<ActiveXray>>);

struct ActiveXray { child: Option<Child>, record: ProcessRecord }
#[derive(Clone, Serialize, Deserialize)]
struct ProcessRecord {
    pid: u32,
    executable: String,
    config_path: String,
    #[serde(default)] port: u16,
    #[serde(default)] privileged: bool,
    #[serde(default)] tun_name: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct DnsJournal { service: String, original: Vec<String>, applied: Vec<String> }

fn app_support_path(name: &str) -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    Ok(PathBuf::from(home).join("Library/Application Support/VpnClient").join(name))
}
fn record_path() -> Result<PathBuf, String> { app_support_path("xray-process.json") }
fn dns_journal_path() -> Result<PathBuf, String> { app_support_path("tun-dns-journal.json") }
fn read_record() -> Result<Option<ProcessRecord>, String> {
    match std::fs::read(record_path()?) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| "Invalid Xray process record".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn process_matches(record: &ProcessRecord) -> bool {
    Command::new("/bin/ps").args(["-p", &record.pid.to_string(), "-o", "command="]).output().ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|cmd| cmd.contains(&record.executable) && cmd.contains(&record.config_path) && cmd.contains("run -config"))
}
fn persist_record(record: &ProcessRecord) -> Result<(), String> {
    let path = record_path()?;
    std::fs::create_dir_all(path.parent().ok_or("Invalid Xray record path")?).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
        .map_err(|e| format!("Xray process record already exists: {e}"))?;
    file.write_all(&serde_json::to_vec(record).map_err(|e| e.to_string())?)
        .and_then(|_| file.sync_all()).map_err(|e| e.to_string())
}
fn remove_record() -> Result<(), String> {
    match std::fs::remove_file(record_path()?) { Ok(()) => Ok(()), Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), Err(e) => Err(e.to_string()) }
}
fn shell_quote(value: &str) -> String { format!("'{}'", value.replace('\'', "'\\''")) }
fn run_admin_shell(command: &str) -> Result<String, String> {
    let apple = format!("do shell script \"{}\" with administrator privileges", command.replace('\\', "\\\\").replace('"', "\\\""));
    let output = Command::new("/usr/bin/osascript").args(["-e", &apple]).output().map_err(|e| format!("Не удалось запросить права администратора: {e}"))?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if error.contains("-128") || error.to_lowercase().contains("cancel") { "Запрос пароля администратора отменён.".into() } else { format!("Не удалось выполнить действие с правами администратора: {error}") });
    }
    String::from_utf8(output.stdout).map(|s| s.trim().to_owned()).map_err(|_| "osascript вернул некорректный вывод".into())
}
fn persist_dns_journal(journal: &DnsJournal) -> Result<(), String> {
    let path = dns_journal_path()?;
    std::fs::create_dir_all(path.parent().ok_or("Invalid DNS journal path")?).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
        .map_err(|e| format!("Журнал восстановления DNS уже существует: {e}"))?;
    file.write_all(&serde_json::to_vec(journal).map_err(|e| e.to_string())?)
        .and_then(|_| file.sync_all()).map_err(|e| e.to_string())
}
fn read_dns(service: &str) -> Result<Vec<String>, String> {
    let output = Command::new("/usr/sbin/networksetup").args(["-getdnsservers", service]).output().map_err(|e| e.to_string())?;
    if !output.status.success() { return Err(format!("Не удалось прочитать DNS: {}", String::from_utf8_lossy(&output.stderr).trim())); }
    let text = String::from_utf8(output.stdout).map_err(|_| "networksetup вернул некорректный DNS")?;
    if text.to_lowercase().contains("there aren't any dns servers set") || text.to_lowercase().contains("no dns servers") { return Ok(Vec::new()); }
    let mut servers = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let ip = line.parse::<std::net::IpAddr>().map_err(|_| format!("Неизвестное значение DNS: {line}"))?;
        servers.push(ip.to_string());
    }
    Ok(servers)
}
fn set_dns_command(service: &str, servers: &[String]) -> String {
    if servers.is_empty() { format!("/usr/sbin/networksetup -setdnsservers {} Empty", shell_quote(service)) }
    else { format!("/usr/sbin/networksetup -setdnsservers {} {}", shell_quote(service), servers.iter().map(|s| shell_quote(s)).collect::<Vec<_>>().join(" ")) }
}
fn restore_tun_dns() -> Result<(), String> {
    let path = dns_journal_path()?;
    let data = match std::fs::read(&path) { Ok(data) => data, Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()), Err(e) => return Err(e.to_string()) };
    let journal: DnsJournal = serde_json::from_slice(&data).map_err(|_| "Журнал DNS повреждён")?;
    let current = read_dns(&journal.service)?;
    if current != journal.applied { return Err("DNS изменён во время работы VPN; журнал сохранён, чтобы не перезаписать ваши настройки.".into()); }
    run_admin_shell(&set_dns_command(&journal.service, &journal.original))?;
    if read_dns(&journal.service)? != journal.original { return Err("Не удалось проверить восстановление DNS; журнал сохранён.".into()); }
    std::fs::remove_file(path).map_err(|e| e.to_string())
}
fn recover_dns_after_failed_start(journal: &DnsJournal) -> Result<(), String> {
    let current = read_dns(&journal.service)?;
    if current == journal.applied {
        run_admin_shell(&set_dns_command(&journal.service, &journal.original))?;
        if read_dns(&journal.service)? != journal.original { return Err("Не удалось проверить восстановление DNS; журнал сохранён.".into()); }
    } else if current != journal.original {
        return Err("DNS изменён посторонним процессом; журнал сохранён.".into());
    }
    std::fs::remove_file(dns_journal_path()?).map_err(|e| e.to_string())
}
fn choose_tun_name() -> Result<String, String> {
    for index in 10..=1024 {
        let name = format!("utun{index}");
        let exists = Command::new("/sbin/ifconfig").arg(&name).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
        if !exists { return Ok(name); }
    }
    Err("Не удалось найти свободный интерфейс utun".into())
}
fn ensure_startable(state: &mut Option<ActiveXray>) -> Result<(), String> {
    if let Some(active) = state.as_ref() {
        if process_matches(&active.record) { return Err("Xray уже запущен".into()); }
        *state = None;
    }
    if let Some(record) = read_record()? {
        if process_matches(&record) { return Err("Уже работает предыдущий процесс Xray. Отключите VPN перед подключением.".into()); }
        remove_record()?;
    }
    Ok(())
}
fn config_file(config: &serde_json::Value) -> Result<(tempfile::TempDir, PathBuf), String> {
    let dir = tempfile::Builder::new().prefix("vpn-xray-").tempdir().map_err(|e| e.to_string())?;
    let path = dir.path().join("config.json");
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).map_err(|e| e.to_string())?;
    file.write_all(config.to_string().as_bytes()).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    Ok((dir, path))
}
fn validate_xray(executable: &str, config: &std::path::Path) -> Result<(), String> {
    let check = Command::new(executable).args(["run", "-test", "-config"]).arg(config).stdout(Stdio::null()).stderr(Stdio::null()).status().map_err(|e| format!("Не удалось запустить Xray: {e}"))?;
    if check.success() { Ok(()) } else { Err("Xray отклонил конфигурацию".into()) }
}
fn stop_record(record: &ProcessRecord) -> Result<(), String> {
    if process_matches(record) {
        if record.privileged {
            run_admin_shell(&format!("/bin/kill -TERM {}", record.pid))?;
        } else {
            let status = Command::new("/bin/kill").args(["-TERM", &record.pid.to_string()]).status().map_err(|e| e.to_string())?;
            if !status.success() { return Err("Не удалось остановить Xray".into()); }
        }
        for _ in 0..100 {
            if !process_matches(record) { break; }
            std::thread::sleep(Duration::from_millis(100));
        }
        if process_matches(record) { return Err("Xray не остановился; журнал процесса сохранён.".into()); }
    }
    remove_record()?;
    Ok(())
}

pub fn start(state: &XrayState, executable: String, link: String) -> Result<String, String> {
    let mut active = state.0.lock().map_err(|_| "Xray state is unavailable")?;
    ensure_startable(&mut active)?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("Не удалось выбрать локальный порт: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let config = crate::profile::vless_xhttp_config(&link, port)?;
    let (dir, path) = config_file(&config)?;
    validate_xray(&executable, &path)?;
    drop(listener);
    let mut child = Command::new(&executable).args(["run", "-config"]).arg(&path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("Не удалось запустить Xray: {e}"))?;
    let mut ready = false;
    for _ in 0..50 {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() { return Err("Xray завершился при запуске".into()); }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() { ready = true; break; }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !ready { let _ = child.kill(); let _ = child.wait(); return Err("Xray не открыл локальный SOCKS-прокси".into()); }
    let record = ProcessRecord { pid: child.id(), executable, config_path: path.to_string_lossy().into_owned(), port, privileged: false, tun_name: None };
    if let Err(error) = persist_record(&record) { let _ = child.kill(); let _ = child.wait(); return Err(error); }
    let config_path = path.to_string_lossy().into_owned();
    if let Err(error) = dir.close() { let _ = child.kill(); let _ = child.wait(); let _ = remove_record(); return Err(format!("Не удалось удалить временную конфигурацию: {error}")); }
    let record = ProcessRecord { config_path, ..record };
    *active = Some(ActiveXray { child: Some(child), record });
    Ok(format!("Xray запущен; SOCKS-прокси: 127.0.0.1:{port}."))
}

pub fn start_tun(state: &XrayState, executable: String, link: String, service: &str) -> Result<String, String> {
    if service.trim().is_empty() || !service.chars().all(|c| c.is_ascii_alphanumeric() || " -_".contains(c)) { return Err("Недопустимое имя сетевой службы macOS".into()); }
    let mut active = state.0.lock().map_err(|_| "Xray state is unavailable")?;
    ensure_startable(&mut active)?;
    let dns_path = dns_journal_path()?;
    if dns_path.exists() { return Err("Найден журнал DNS предыдущего подключения. Отключите или восстановите TUN перед подключением.".into()); }
    let original_dns = read_dns(service)?;
    let applied_dns = vec!["1.1.1.1".to_owned(), "1.0.0.1".to_owned()];
    let journal = DnsJournal { service: service.to_owned(), original: original_dns, applied: applied_dns.clone() };
    persist_dns_journal(&journal)?;
    let tun_name = choose_tun_name()?;
    let config = crate::profile::vless_xhttp_tun_config(&link, &tun_name)?;
    let (dir, path) = config_file(&config)?;
    validate_xray(&executable, &path)?;
    let config_path = path.to_string_lossy().into_owned();
    let log_path = dir.path().join("xray.log");
    let shell = format!("set -e; {}; {} run -config {} > {} 2>&1 < /dev/null & echo $!", set_dns_command(service, &applied_dns), shell_quote(&executable), shell_quote(&config_path), shell_quote(&log_path.to_string_lossy()));
    let pid_text = match run_admin_shell(&shell) {
        Ok(pid) => pid,
        Err(error) => { let recovery = recover_dns_after_failed_start(&journal); return Err(recovery.err().unwrap_or(error)); }
    };
    let pid = pid_text.lines().last().unwrap_or("").trim().parse::<u32>().map_err(|_| "Не удалось получить PID процесса Xray".to_owned())?;
    let record = ProcessRecord { pid, executable, config_path: config_path.clone(), port: 0, privileged: true, tun_name: Some(tun_name.clone()) };
    let mut ready = false;
    for _ in 0..100 {
        if !process_matches(&record) { break; }
        if Command::new("/sbin/ifconfig").arg(&tun_name).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false) { ready = true; break; }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !ready {
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        if process_matches(&record) { let _ = stop_record(&record); }
        let recovery = recover_dns_after_failed_start(&journal);
        let problem = if log.trim().is_empty() { "Xray не создал TUN. Проверьте права администратора и маршрут до сервера.".into() } else { format!("Xray не поднял TUN: {}", log.lines().last().unwrap_or("ошибка запуска")) };
        return Err(recovery.err().map(|e| format!("{problem} {e}")).unwrap_or(problem));
    }
    if let Err(error) = persist_record(&record) {
        let _ = stop_record(&record);
        let recovery = recover_dns_after_failed_start(&journal);
        return Err(recovery.err().map(|e| format!("{error}. {e}")).unwrap_or(error));
    }
    if let Err(error) = dir.close() {
        let _ = stop_record(&record); let _ = remove_record();
        let recovery = recover_dns_after_failed_start(&journal);
        return Err(recovery.err().map(|e| format!("Не удалось удалить временную конфигурацию: {error}. {e}")).unwrap_or_else(|| format!("Не удалось удалить временную конфигурацию: {error}")));
    }
    *active = Some(ActiveXray { child: None, record });
    Ok(format!("VPN подключён через {tun_name}; системный трафик направлен через TUN."))
}

pub fn stop(state: &XrayState) -> Result<(), String> {
    let mut active = state.0.lock().map_err(|_| "Xray state is unavailable")?;
    if let Some(mut running) = active.take() {
        if let Some(child) = running.child.as_mut() {
            if child.try_wait().map_err(|e| e.to_string())?.is_none() { child.kill().map_err(|e| e.to_string())?; }
            child.wait().map_err(|e| e.to_string())?;
            remove_record()?;
        } else {
            stop_record(&running.record)?;
        }
    } else if let Some(record) = read_record()? {
        stop_record(&record)?;
    }
    restore_tun_dns()
}
impl Drop for XrayState { fn drop(&mut self) { let _ = stop(self); } }
pub fn active_port(state: &XrayState) -> Result<u16, String> {
    let mut active = state.0.lock().map_err(|_| "Xray state is unavailable")?;
    match active.as_mut() {
        Some(process) if process.child.is_some() && process_matches(&process.record) => Ok(process.record.port),
        _ => Err("Xray SOCKS-прокси не запущен".into()),
    }
}
pub fn has_running_process() -> bool { read_record().ok().flatten().is_some_and(|record| process_matches(&record)) }
pub fn is_tun_process() -> bool { read_record().ok().flatten().is_some_and(|record| record.privileged && record.tun_name.is_some() && process_matches(&record)) }
