use serde::{Deserialize, Serialize};
use std::{fs, os::unix::fs::OpenOptionsExt, path::PathBuf, time::Duration};

const SERVICE: &str = "local.vpn-client.3x-ui";

// Tokens are stored per user. Keychain is consulted only when migrating an
// existing account for the first time; new and migrated tokens use this file.
fn token_store<F, T>(f: F) -> Result<T, String>
where F: FnOnce(&mut std::collections::BTreeMap<String, String>) -> Result<(T, bool), String> {
    token_store_at(&config_path()?.with_file_name("panel-tokens.json"), f)
}
fn token_store_at<F, T>(path: &std::path::Path, f: F) -> Result<T, String>
where F: FnOnce(&mut std::collections::BTreeMap<String, String>) -> Result<(T, bool), String> {
    use std::os::fd::AsRawFd;
    let dir = path.parent().ok_or("Некорректный путь хранилища токенов")?;
    fs::create_dir_all(dir).map_err(|_| "Не удалось создать каталог токенов")?;
    let lock = fs::OpenOptions::new().read(true).write(true).create(true).mode(0o600)
        .open(dir.join("panel-tokens.lock")).map_err(|_| "Не удалось открыть хранилище токенов")?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 { return Err("Не удалось заблокировать хранилище токенов".into()); }
    let mut tokens = match fs::read(path) {
        Ok(data) => serde_json::from_slice(&data).map_err(|_| "Некорректное хранилище токенов")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::collections::BTreeMap::new(),
        Err(_) => return Err("Не удалось прочитать хранилище токенов".into()),
    };
    let (result, changed) = f(&mut tokens)?;
    if changed {
        let mut temp = tempfile::NamedTempFile::new_in(dir).map_err(|_| "Не удалось сохранить токены")?;
        serde_json::to_writer(&mut temp, &tokens).map_err(|_| "Не удалось сохранить токены")?;
        temp.persist(path).map_err(|_| "Не удалось сохранить токены")?;
    }
    Ok(result)
}

fn token_set(account: &str, token: &str) -> Result<(), String> {
    token_store(|tokens| { tokens.insert(account.to_owned(), token.to_owned()); Ok(((), true)) })
}
fn token_get(account: &str) -> Result<String, String> {
    token_store(|tokens| {
        if let Some(token) = tokens.get(account) { return Ok((token.clone(), false)); }
        let bytes = security_framework::passwords::get_generic_password(SERVICE, account)
            .map_err(|_| "Токен не найден; при необходимости укажите его в настройках сервера".to_owned())?;
        let token = String::from_utf8(bytes).map_err(|_| "Некорректный сохранённый токен")?;
        tokens.insert(account.to_owned(), token.clone());
        Ok((token, true))
    })
}
fn token_delete(account: &str) -> Result<(), String> {
    token_store(|tokens| { let changed = tokens.remove(account).is_some(); Ok(((), changed)) })
}

pub fn mcp_control_socket_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    Ok(PathBuf::from(home).join("Library/Application Support/VpnClient/mcp/control.sock"))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Panel {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub ssh_target: Option<String>,
    #[serde(default)]
    pub panel_host: Option<String>,
}

fn config_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    Ok(PathBuf::from(home).join("Library/Application Support/VpnClient/panel.json"))
}

pub fn validate_panel(panel: &Panel) -> Result<(), String> {
    if panel.name.trim().is_empty() || panel.name.len() > 128 {
        return Err("Panel name must contain 1–128 characters".into());
    }
    let url = url::Url::parse(&panel.url).map_err(|_| "Invalid panel URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("URL must not contain credentials, query or fragment".into());
    }
    if let Some(host) = panel.panel_host.as_deref() {
        if panel.ssh_target.is_none() || !valid_http_host(host) {
            return Err("Invalid panel host".into());
        }
    }
    match (url.scheme(), url.host_str(), panel.ssh_target.as_deref()) {
        ("https", Some(_), None) => {}
        ("https", Some(_), Some(target)) if valid_ssh_target(target) => {}
        ("http", Some("127.0.0.1"), Some(target)) if url.port().is_some() && valid_ssh_target(target) => {}
        _ => return Err("Use HTTPS, or HTTP on 127.0.0.1 with an SSH target and port".into()),
    }
    Ok(())
}

fn valid_http_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
        && !host.starts_with('-')
}

/// Splits an optional `:port` suffix off an SSH target (`root@host:2222` -> (`root@host`, Some(2222))).
pub fn split_ssh_target(target: &str) -> (&str, Option<u16>) {
    if let Some((dest, port)) = target.rsplit_once(':') {
        if !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(p) = port.parse::<u16>() { if p >= 1 { return (dest, Some(p)); } }
        }
    }
    (target, None)
}

/// Host part of an SSH target, without user and port.
pub fn ssh_host(target: &str) -> &str {
    split_ssh_target(target).0.rsplit('@').next().unwrap_or(target)
}

pub fn valid_ssh_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 255 || target.starts_with('-') {
        return false;
    }
    let (dest, _) = split_ssh_target(target);
    let parts: Vec<_> = dest.split('@').collect();
    parts.len() <= 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        })
}

fn wizard_token_account(id: &str) -> Result<String, String> {
    if !valid_server_id(id) { return Err("Некорректный идентификатор мастера".into()); }
    Ok(format!("wizard-{id}"))
}

pub fn new_wizard_id() -> Result<String, String> { new_server_id() }

pub fn stage_wizard_token(id: &str, token: &str) -> Result<(), String> {
    if token.trim().is_empty() { return Err("Укажите API-токен панели".into()); }
    let account = wizard_token_account(id)?;
    token_set(&account, token)
}

fn staged_wizard_token(id: &str) -> Result<String, String> {
    let account = wizard_token_account(id)?;
    token_get(&account).map_err(|_| "Токен мастера отсутствует. Вернитесь к шагу 1.".to_owned())
}

pub fn clear_wizard_token(id: &str) -> Result<(), String> {
    let account = wizard_token_account(id)?;
    token_delete(&account)
}

struct Tunnel(std::process::Child);
impl Drop for Tunnel {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn ssh_tunnel(target: &str, port: u16) -> Result<(Tunnel, u16), String> {
    use std::{
        net::{TcpListener, TcpStream},
        process::{Command, Stdio},
    };
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    let local = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    let forward = format!("127.0.0.1:{local}:127.0.0.1:{port}");
    let mut ssh = Command::new("/usr/bin/ssh");
    if let Some(home) = std::env::var_os("HOME") {
        let key = PathBuf::from(home).join(".ssh/id_ed25519_vpn_client");
        if key.is_file() { ssh.arg("-i").arg(key); }
    }
    let (dest, ssh_port) = split_ssh_target(target);
    if let Some(p) = ssh_port { ssh.args(["-p", &p.to_string()]); }
    let child = ssh.args([
            "-N",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ConnectTimeout=10",
            "-L",
            &forward,
            "--",
            dest,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("SSH tunnel failed: {e}"))?;
    let mut tunnel = Tunnel(child);
    for _ in 0..100 {
        if tunnel.0.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Err("SSH-туннель к панели не поднялся: проверьте, что ваш публичный SSH-ключ добавлен на сервер (вход по паролю туннель не поддерживает) и что ключ сервера в ~/.ssh/known_hosts не изменился.".into());
        }
        if TcpStream::connect(("127.0.0.1", local)).is_ok() {
            return Ok((tunnel, local));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("SSH tunnel timed out".into())
}

pub fn save_panel(panel: &Panel, token: &str) -> Result<(), String> {
    validate_panel(panel)?;
    if token.trim().is_empty() {
        return Err("API token is required".into());
    }
    let path = config_path()?;
    let dir = path.parent().ok_or("Invalid configuration path")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    token_set(&panel.url, token)?;
    fs::write(
        path,
        serde_json::to_vec_pretty(panel).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

pub fn load_panel() -> Result<Option<Panel>, String> {
    let path = config_path()?;
    match fs::read(path) {
        Ok(bytes) => {
            let panel: Panel = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            validate_panel(&panel)?;
            Ok(Some(panel))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

const COUNTRY_CODES: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW";

pub fn panel_hostname(raw: &str) -> Result<String, String> {
    url::Url::parse(raw).map_err(|_| "Некорректный адрес панели".to_owned())?.host_str().map(str::to_owned).ok_or_else(|| "В адресе панели отсутствует хост".into())
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(flatten)]
    pub panel: Panel,
}

fn servers_path() -> Result<PathBuf, String> { Ok(config_path()?.with_file_name("servers.json")) }
fn valid_server_id(id: &str) -> bool { id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) }
fn new_server_id() -> Result<String, String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).map_err(|e| e.to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn write_servers(path: &std::path::Path, servers: &[Server]) -> Result<(), String> {
    let dir = path.parent().ok_or("Invalid configuration path")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut temp = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut temp, servers).map_err(|e| e.to_string())?;
    temp.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}
fn migrate_panel<F>(legacy: &std::path::Path, destination: &std::path::Path, mut copy_token: F) -> Result<Vec<Server>, String>
where F: FnMut(&str, &str) -> Result<(), String> {
    if destination.exists() {
        let servers: Vec<Server> = serde_json::from_slice(&fs::read(destination).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        for server in &servers { if !valid_server_id(&server.id) { return Err("Invalid server ID".into()); } validate_panel(&server.panel)?; }
        return Ok(servers);
    }
    let data = match fs::read(legacy) { Ok(data) => data, Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]), Err(e) => return Err(e.to_string()) };
    let panel: Panel = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    validate_panel(&panel)?;
    let server = Server { id: new_server_id()?, country: None, panel };
    copy_token(&server.panel.url, &server.id)?;
    // Copy the old cache only if it belongs to this panel.
    let old_cache = legacy.with_file_name("client-profiles.json");
    if let Ok(data) = fs::read(old_cache) {
        if serde_json::from_slice::<ProfileCache>(&data).map(|c| c.panel_url == server.panel.url).unwrap_or(false) {
            let path = legacy.with_file_name(format!("client-profiles-{}.json", server.id));
            use std::io::Write;
            let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| e.to_string())?;
            file.write_all(&data).map_err(|e| e.to_string())?;
        }
    }
    let servers = vec![server];
    write_servers(destination, &servers)?;
    Ok(servers)
}
pub fn list_servers() -> Result<Vec<Server>, String> {
    migrate_panel(&config_path()?, &servers_path()?, |url, id| {
        let token = token_get(url)?;
        token_set(id, &token)
    })
}
pub fn save_server(id: Option<String>, panel: Panel, token: &str, country: Option<String>) -> Result<Server, String> {
    validate_panel(&panel)?;
    let country = country.filter(|s| !s.is_empty());
    if country.as_ref().is_some_and(|c| !COUNTRY_CODES.split_whitespace().any(|v| v == c)) { return Err("Выберите страну из списка".into()); }
    let mut servers = list_servers()?;
    let id = match id { Some(id) if servers.iter().any(|s| s.id == id) => id, Some(_) => return Err("Сервер не найден".into()), None => new_server_id()? };
    let existing = servers.iter().position(|s| s.id == id);
    if existing.is_none() && token.trim().is_empty() { return Err("Укажите API-токен".into()); }
    if !token.trim().is_empty() { token_set(&id, token)?; }
    let server = Server { id, panel, country };
    if let Some(index) = existing { servers[index] = server.clone(); } else { servers.push(server.clone()); }
    write_servers(&servers_path()?, &servers)?;
    Ok(server)
}
pub fn delete_server(id: &str) -> Result<(), String> {
    let mut servers = list_servers()?;
    let server = servers.iter().find(|s| s.id == id).ok_or("Сервер не найден")?;
    clear_pending_for_server(&pending_path()?, &config_path()?, server)?;
    token_delete(id)?;
    match fs::remove_file(profile_cache_path(id)?) { Ok(()) => (), Err(e) if e.kind() == std::io::ErrorKind::NotFound => (), Err(e) => return Err(e.to_string()) }
    let _guard = PIN_LOCK.lock().map_err(|_| "Не удалось заблокировать список избранного")?;
    remove_server_pins(&pins_path()?, id)?;
    servers.retain(|s| s.id != id);
    write_servers(&servers_path()?, &servers)
}
fn server_for(id: &str) -> Result<Server, String> { list_servers()?.into_iter().find(|s| s.id == id).ok_or_else(|| "Сервер не найден".into()) }
fn server_token(id: &str) -> Result<String, String> {
    token_get(id)
}
pub fn server_inbounds(id: &str) -> Result<serde_json::Value, String> { let s = server_for(id)?; list_inbounds_for(&s.panel, &server_token(id)?) }

pub fn list_inbounds_for_host(host: &str) -> Result<serde_json::Value, String> {
    if !valid_http_host(host) { return Err("Некорректный хост".into()); }
    let servers: Vec<_> = list_servers()?.into_iter().filter(|s| s.panel.panel_host.as_deref() == Some(host) || s.panel.ssh_target.as_deref().map(ssh_host) == Some(host)).collect();
    if servers.len() != 1 { return Err("Нужна ровно одна сохранённая панель для указанного хоста".into()); }
    let server = &servers[0];
    list_inbounds_for(&server.panel, &server_token(&server.id)?)
}

/// Deletes an inbound (and with it its clients) on the panel of a saved server, then refreshes the local profile cache.
pub fn delete_server_inbound(server_id: &str, inbound_id: u64) -> Result<String, String> {
    if inbound_id == 0 { return Err("Некорректный ID inbound-а".into()); }
    let server = server_for(server_id)?;
    let message = delete_inbound_on(&server, inbound_id)?;
    // The deleted inbound's clients must disappear from the local cache; the deletion itself already succeeded.
    let _ = refresh_client_profiles(&server.id);
    Ok(message)
}

pub fn delete_inbound_for_host(host: &str, inbound_id: u64) -> Result<String, String> {
    if !valid_http_host(host) || inbound_id == 0 { return Err("Некорректный хост или ID inbound-а".into()); }
    let servers: Vec<_> = list_servers()?.into_iter().filter(|s| s.panel.panel_host.as_deref() == Some(host) || s.panel.ssh_target.as_deref().map(ssh_host) == Some(host)).collect();
    if servers.len() != 1 { return Err("Нужна ровно одна сохранённая панель для указанного хоста".into()); }
    delete_inbound_on(&servers[0], inbound_id)
}

fn delete_inbound_on(server: &Server, inbound_id: u64) -> Result<String, String> {
    let token = server_token(&server.id)?;
    let list = list_inbounds_for(&server.panel, &token)?;
    let inbound = list.as_array().and_then(|a| a.iter().find(|v| v["id"].as_u64() == Some(inbound_id))).ok_or("Inbound с таким ID не найден на этом сервере")?;
    let remark = inbound["remark"].as_str().unwrap_or("(без имени)");
    panel_request(&server.panel, &token, &format!("inbounds/del/{inbound_id}"), Some(serde_json::json!({})))?;
    Ok(format!("Удалён inbound {inbound_id} ({remark}) с сервера {}", server.panel.name))
}

pub fn delete_reality_inbound(host: &str) -> Result<String, String> {
    if !valid_http_host(host) { return Err("Некорректный хост".into()); }
    let servers: Vec<_> = list_servers()?.into_iter().filter(|s| s.panel.panel_host.as_deref() == Some(host) || s.panel.ssh_target.as_deref().map(ssh_host) == Some(host)).collect();
    if servers.len() != 1 { return Err("Нужна ровно одна сохранённая панель для указанного хоста".into()); }
    let server = &servers[0];
    let token = server_token(&server.id)?;
    let list = panel_request(&server.panel, &token, "inbounds/list", None)?;
    let items = list.get("obj").and_then(|v| v.as_array()).ok_or("Некорректный список inbound-ов")?;
    let candidates: Vec<_> = items.iter().filter(|v| v["port"] == 443 && v["remark"] == "VLESS-REALITY-443" && v["protocol"] == "vless").collect();
    if candidates.len() != 1 { return Err("Найдено не ровно одно целевое Reality подключение; ничего не удалено".into()); }
    let target = candidates[0];
    let stream_raw = target.get("streamSettings").cloned().unwrap_or(serde_json::json!({}));
    let stream = if let Some(s) = stream_raw.as_str() { serde_json::from_str::<serde_json::Value>(s).map_err(|_| "Повреждены настройки inbound-а")? } else { stream_raw };
    if stream["network"] != "tcp" || stream["security"] != "reality" { return Err("Целевой inbound не является TCP Reality; ничего не удалено".into()); }
    let id = target["id"].as_u64().ok_or("Некорректный ID inbound-а")?;
    panel_request(&server.panel, &token, &format!("inbounds/del/{id}"), Some(serde_json::json!({})))?;
    Ok(format!("Удалён VLESS TCP Reality inbound {id} на сервере {}", server.panel.name))
}

pub fn list_inbounds() -> Result<serde_json::Value, String> {
    let panel = load_panel()?.ok_or("No panel configured")?;
    let token = token_get(&panel.url)?;
    list_inbounds_for(&panel, &token)
}

fn panel_request(
    panel: &Panel,
    token: &str,
    route: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    validate_panel(panel)?;
    let mut url = url::Url::parse(&panel.url).map_err(|_| "Invalid panel URL")?;
    let tunnel_target = if url.host_str() == Some("127.0.0.1") { panel.ssh_target.as_deref() } else { None };
    let _tunnel = if let Some(target) = tunnel_target {
        let remote_port = url.port().ok_or("Missing panel port")?;
        let (tunnel, local_port) = ssh_tunnel(target, remote_port)?;
        url.set_port(Some(local_port))
            .map_err(|_| "Invalid tunnel port")?;
        Some(tunnel)
    } else {
        None
    };
    let endpoint = format!("{}/panel/api/{route}", url.as_str().trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let mut request = if let Some(body) = body {
        client.post(endpoint).json(&body)
    } else {
        client.get(endpoint)
    }
    .bearer_auth(token);
    if let Some(target) = tunnel_target {
        let host = panel
            .panel_host
            .as_deref()
            .unwrap_or_else(|| ssh_host(target));
        if !valid_http_host(host) {
            return Err("Invalid panel host".into());
        }
        request = request.header(reqwest::header::HOST, host);
    }
    let response = request
        .send()
        .map_err(|e| format!("Panel request failed: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Panel returned HTTP {status}"));
    }
    let value: serde_json::Value = response.json().map_err(|_| "Panel returned invalid JSON")?;
    if value.get("success").and_then(|v| v.as_bool()) != Some(true) {
        let reason = value.get("msg").and_then(|v| v.as_str()).unwrap_or("unknown panel error");
        return Err(format!("Panel did not report success: {}", reason.chars().take(160).collect::<String>()));
    }
    Ok(value)
}

#[derive(Clone, Serialize, Deserialize)]
struct CachedClientProfile {
    inbound_id: u64,
    inbound_name: String,
    port: u64,
    protocol: String,
    transport: String,
    inbound_enabled: bool,
    email: String,
    enabled: bool,
    share_link: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct ProfileCache {
    panel_url: String,
    profiles: Vec<CachedClientProfile>,
    #[serde(default)]
    inbounds: Vec<serde_json::Value>,
}
fn profile_cache_path(id: &str) -> Result<PathBuf, String> {
    if !valid_server_id(id) { return Err("Invalid server ID".into()); }
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    Ok(PathBuf::from(home).join(format!("Library/Application Support/VpnClient/client-profiles-{id}.json")))
}
fn public_profiles(profiles: &[CachedClientProfile]) -> Result<serde_json::Value, String> {
    let value = profiles.iter().map(|p| serde_json::json!({
        "inbound_id": p.inbound_id, "inbound_name": p.inbound_name, "port": p.port,
        "protocol": p.protocol, "transport": p.transport,
        "inbound_enabled": p.inbound_enabled, "email": p.email, "enabled": p.enabled,
        "has_local_config": p.share_link.as_ref().is_some_and(|link| crate::profile::vless_config(link, 10808).is_ok())
    })).collect::<Vec<_>>();
    Ok(serde_json::Value::Array(value))
}
pub fn list_client_profiles(id: &str) -> Result<serde_json::Value, String> {
    let panel = server_for(id)?.panel;
    let path = profile_cache_path(id)?;
    match std::fs::read(path) {
        Ok(data) => {
            let cache: ProfileCache = serde_json::from_slice(&data).map_err(|_| "Invalid local client profile cache")?;
            if cache.panel_url == panel.url { public_profiles(&cache.profiles) } else { Ok(serde_json::Value::Array(Vec::new())) }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::Value::Array(Vec::new())),
        Err(error) => Err(error.to_string()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedProfile { pub server_id: String, pub inbound_id: u64, pub email: String }
static PIN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let (mut value, mut shift) = (0u64, 0);
    loop {
        let byte = *buf.get(*pos)?; *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 { return Some(value); }
        shift += 7;
        if shift > 63 { return None; }
    }
}
/// List codes (upper-case) in an Xray geoip.dat / geosite.dat: a protobuf of repeated entries whose field 1 is the code.
pub fn geo_codes(path: &std::path::Path) -> Result<std::collections::HashSet<String>, String> {
    let data = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bad = || format!("Некорректная база: {}", path.display());
    let (mut pos, mut codes) = (0usize, std::collections::HashSet::new());
    while pos < data.len() {
        let tag = read_varint(&data, &mut pos).ok_or_else(bad)?;
        if tag & 7 != 2 { return Err(bad()); }
        let len = read_varint(&data, &mut pos).ok_or_else(bad)? as usize;
        let end = pos.checked_add(len).filter(|e| *e <= data.len()).ok_or_else(bad)?;
        if tag >> 3 == 1 {
            let entry = &data[pos..end]; let mut p = 0;
            if read_varint(entry, &mut p) == Some(0x0a) {
                let n = read_varint(entry, &mut p).ok_or_else(bad)? as usize;
                if let Some(code) = entry.get(p..p + n) { codes.insert(String::from_utf8_lossy(code).to_ascii_uppercase()); }
            }
        }
        pos = end;
    }
    Ok(codes)
}
/// Reject `geoip:`/`geosite:` entries whose list is missing from the databases in `dir` (skipped when `dir` has none).
pub fn check_geo_entries(entries: &[String], dir: &std::path::Path) -> Result<(), String> {
    for (prefix, file) in [("geoip:", "geoip.dat"), ("geosite:", "geosite.dat")] {
        let wanted: Vec<&str> = entries.iter().filter_map(|e| e.strip_prefix(prefix)).collect();
        if wanted.is_empty() || !dir.join(file).exists() { continue; }
        let codes = geo_codes(&dir.join(file))?;
        for name in wanted {
            let code = name.split('@').next().unwrap_or(name).to_ascii_uppercase();
            if !codes.contains(&code) { return Err(format!("В базе {file} нет списка «{prefix}{name}»")); }
        }
    }
    Ok(())
}
/// Names of the lists available in the shipped geoip.dat / geosite.dat (lower-case, sorted); empty when a database is absent.
pub fn geo_lists(dir: &std::path::Path) -> Result<serde_json::Value, String> {
    let names = |file: &str| -> Result<Vec<String>, String> {
        let path = dir.join(file);
        if !path.exists() { return Ok(Vec::new()); }
        let mut list: Vec<String> = geo_codes(&path)?.into_iter().map(|c| c.to_ascii_lowercase()).collect();
        list.sort();
        Ok(list)
    };
    Ok(serde_json::json!({"geoip": names("geoip.dat")?, "geosite": names("geosite.dat")?}))
}
static BYPASS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn bypass_path() -> Result<PathBuf, String> { Ok(config_path()?.with_file_name("bypass.json")) }
/// Traffic that must not go through the tunnel (defaults: BitTorrent direct, no extra entries).
pub fn read_bypass() -> Result<profile::Bypass, String> {
    match fs::read(bypass_path()?) {
        Ok(data) => serde_json::from_slice::<profile::Bypass>(&data).map_err(|_| "Некорректный файл исключений".to_owned())?.validated(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(profile::Bypass::default()),
        Err(e) => Err(e.to_string()),
    }
}
pub fn write_bypass(bypass: profile::Bypass) -> Result<profile::Bypass, String> {
    use std::os::unix::fs::PermissionsExt;
    let bypass = bypass.validated()?;
    let _guard = BYPASS_LOCK.lock().map_err(|_| "Не удалось заблокировать настройки")?;
    let path = bypass_path()?;
    let dir = path.parent().ok_or("Некорректный путь настроек")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    file.as_file().set_permissions(fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut file, &bypass).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(&path).map_err(|e| e.to_string())?;
    Ok(bypass)
}
fn pins_path() -> Result<PathBuf, String> { Ok(config_path()?.with_file_name("pinned-profiles.json")) }
fn read_pins(path: &std::path::Path) -> Result<Option<Vec<PinnedProfile>>, String> {
    match fs::read(path) {
        Ok(data) => serde_json::from_slice(&data).map(Some).map_err(|_| "Некорректный список конфигураций главного экрана".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn write_pins(path: &std::path::Path, pins: &[PinnedProfile]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().ok_or("Некорректный путь к списку конфигураций")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    file.as_file().set_permissions(fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut file, pins).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}
fn change_pins(path: &std::path::Path, initial: &[PinnedProfile], key: PinnedProfile, pinned: bool) -> Result<(), String> {
    let mut pins = read_pins(path)?.unwrap_or_else(|| initial.to_vec());
    pins.retain(|p| p != &key);
    if pinned { pins.push(key); }
    write_pins(path, &pins)
}
fn remove_server_pins(path: &std::path::Path, id: &str) -> Result<(), String> {
    if let Some(mut pins) = read_pins(path)? { pins.retain(|p| p.server_id != id); write_pins(path, &pins)?; }
    Ok(())
}
pub fn list_pinned_profiles() -> Result<Option<Vec<PinnedProfile>>, String> {
    let _guard = PIN_LOCK.lock().map_err(|_| "Не удалось заблокировать список избранного")?;
    read_pins(&pins_path()?)
}
pub fn all_connectable_profiles() -> Result<Vec<serde_json::Value>, String> {
    let mut result = Vec::new();
    for server in list_servers()? {
        let profiles = list_client_profiles(&server.id)?;
        if let Some(items) = profiles.as_array() { for profile in items {
            if profile["enabled"] != true || profile["inbound_enabled"] != true || !["vless", "hysteria"].contains(&profile["protocol"].as_str().unwrap_or("")) || profile["has_local_config"] != true { continue; }
            let mut item = profile.clone();
            if let Some(object) = item.as_object_mut() {
                object.insert("server_id".into(), serde_json::json!(server.id));
                object.insert("server_name".into(), serde_json::json!(server.panel.name));
                object.insert("country".into(), serde_json::json!(server.country));
            }
            result.push(item);
        }}
    }
    Ok(result)
}
fn profile_key(profile: &serde_json::Value) -> Option<PinnedProfile> {
    Some(PinnedProfile { server_id: profile["server_id"].as_str()?.to_owned(), inbound_id: profile["inbound_id"].as_u64()?, email: profile["email"].as_str()?.to_owned() })
}
pub fn list_connectable_profiles() -> Result<Vec<serde_json::Value>, String> {
    let _guard = PIN_LOCK.lock().map_err(|_| "Не удалось заблокировать список избранного")?;
    let pins = read_pins(&pins_path()?)?;
    Ok(all_connectable_profiles()?.into_iter().filter(|p| pins.as_ref().is_none_or(|pins| profile_key(p).is_some_and(|key| pins.contains(&key)))).collect())
}
pub fn set_profile_pinned(server_id: &str, inbound_id: u64, email: &str, pinned: bool) -> Result<(), String> {
    if !valid_server_id(server_id) || inbound_id == 0 || email.is_empty() || email.len() > 128 { return Err("Некорректный клиент".into()); }
    let _guard = PIN_LOCK.lock().map_err(|_| "Не удалось заблокировать список избранного")?;
    let all: Vec<PinnedProfile> = all_connectable_profiles()?.iter().filter_map(profile_key).collect();
    let key = PinnedProfile { server_id:server_id.into(), inbound_id, email:email.into() };
    if pinned && !all.contains(&key) { return Err("У клиента нет доступной локальной конфигурации".into()); }
    change_pins(&pins_path()?, &all, key, pinned)
}
pub fn cached_server_inbounds(id: &str) -> Result<serde_json::Value, String> {
    let panel = server_for(id)?.panel;
    match fs::read(profile_cache_path(id)?) {
        Ok(data) => { let cache: ProfileCache = serde_json::from_slice(&data).map_err(|_| "Invalid local client profile cache")?;
            if cache.panel_url == panel.url { Ok(serde_json::Value::Array(cache.inbounds)) } else { Ok(serde_json::json!([])) } }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::json!([])),
        Err(e) => Err(e.to_string()),
    }
}
pub fn refresh_client_profiles(id: &str) -> Result<serde_json::Value, String> {
    let panel = server_for(id)?.panel;
    let token = server_token(id)?;
    let token = token.as_str();
    let response = panel_request(&panel, token, "inbounds/list", None)?;
    let inbounds = response.get("obj").and_then(|v| v.as_array()).ok_or("Panel returned an invalid inbound list")?;
    let mut profiles = Vec::new();
    for inbound in inbounds {
        let id = inbound.get("id").and_then(|v| v.as_u64()).ok_or("Inbound has invalid ID")?;
        let mut settings = inbound.get("settings").cloned().unwrap_or(serde_json::json!({}));
        if let Some(raw) = settings.as_str() { settings = serde_json::from_str(raw).map_err(|_| "Panel returned invalid inbound settings")?; }
        let clients = settings.get("clients").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let mut stream = inbound.get("streamSettings").cloned().unwrap_or(serde_json::json!({}));
        if let Some(raw) = stream.as_str() { stream = serde_json::from_str(raw).unwrap_or(serde_json::json!({})); }
        let protocol = inbound.get("protocol").and_then(|v| v.as_str()).unwrap_or("unknown");
        let transport = stream.get("network").and_then(|v| v.as_str()).unwrap_or("unknown");
        let security = stream.get("security").and_then(|v| v.as_str()).unwrap_or("unknown");
        for client in clients {
            let Some(email) = client.get("email").and_then(|v| v.as_str()).filter(|v| !v.is_empty()) else { continue; };
            let enabled = client.get("enable").and_then(|v| v.as_bool()).unwrap_or(true);
            let inbound_enabled = inbound.get("enable").and_then(|v| v.as_bool()).unwrap_or(false);
            let share_link = if ((protocol == "vless" && ((transport == "xhttp" && security == "tls") || (transport == "tcp" && security == "reality"))) || (protocol == "hysteria" && transport == "hysteria" && security == "tls")) && inbound_enabled && enabled {
                client_share_link_with_token(&panel, token, email, id).ok().filter(|link| crate::profile::vless_config(link, 10808).is_ok())
            } else { None };
            profiles.push(CachedClientProfile {
                inbound_id: id,
                inbound_name: inbound.get("remark").and_then(|v| v.as_str()).unwrap_or("Подключение").to_owned(),
                port: inbound.get("port").and_then(|v| v.as_u64()).unwrap_or(0),
                protocol: protocol.to_owned(), transport: transport.to_owned(), inbound_enabled,
                email: email.to_owned(), enabled, share_link,
            });
        }
    }
    let cached_inbounds = inbounds.iter().map(|v| serde_json::json!({"id":v.get("id"),"remark":v.get("remark"),"protocol":v.get("protocol"),"port":v.get("port"),"enable":v.get("enable")})).collect();
    let cache = ProfileCache { panel_url: panel.url.clone(), profiles, inbounds: cached_inbounds };
    let path = profile_cache_path(id)?;
    let parent = path.parent().ok_or("Invalid profile cache path")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&cache).map_err(|e| e.to_string())?).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
    public_profiles(&cache.profiles)
}
pub fn cached_client_share_link(id: &str, inbound_id: u64, email: &str) -> Result<String, String> {
    let panel = server_for(id)?.panel;
    let data = std::fs::read(profile_cache_path(id)?).map_err(|_| "No locally saved client profiles. Refresh the list from 3x-ui first.")?;
    let cache: ProfileCache = serde_json::from_slice(&data).map_err(|_| "Invalid local client profile cache")?;
    if cache.panel_url != panel.url { return Err("Local profiles belong to a different panel. Refresh the profile list.".into()); }
    cache.profiles.into_iter().find(|p| p.inbound_id == inbound_id && p.email == email)
        .and_then(|p| p.share_link).filter(|link| crate::profile::vless_config(link, 10808).is_ok()).ok_or_else(|| "У клиента нет подходящей локальной конфигурации VLESS. Обновите список клиентов.".into())
}

pub fn list_inbounds_for(panel: &Panel, token: &str) -> Result<serde_json::Value, String> {
    let value = panel_request(panel, token, "inbounds/list", None)?;
    let list = value
        .get("obj")
        .and_then(|v| v.as_array())
        .ok_or("Panel returned an invalid inbound list")?;
    Ok(serde_json::Value::Array(list.iter().map(|v| serde_json::json!({"id":v.get("id"),"remark":v.get("remark"),"protocol":v.get("protocol"),"port":v.get("port"),"enable":v.get("enable")})).collect()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboundParams {
    pub remark: String,
    pub port: u32,
    pub server_name: String,
    pub path: String,
}

fn valid_domain_name(domain: &str) -> bool {
    domain.len() <= 253 && !domain.is_empty() && domain.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

pub fn validate_inbound_params(params: &InboundParams) -> Result<(), String> {
    if params.remark.trim().is_empty() || params.remark.len() > 128 {
        return Err("Укажите название inbound-а (до 128 символов)".into());
    }
    if !(1..=65535).contains(&params.port) { return Err("Порт должен быть от 1 до 65535".into()); }
    if !params.path.starts_with('/') || params.path.len() > 2048 || params.path.chars().any(char::is_control) {
        return Err("Путь XHTTP должен начинаться с / и не содержать управляющих символов".into());
    }
    if !valid_domain_name(&params.server_name) { return Err("Укажите корректное доменное имя для SNI".into()); }
    Ok(())
}

#[derive(Serialize)]
pub struct InboundTemplate { pub id: &'static str, pub name: &'static str, pub description: &'static str, pub remark: &'static str, pub port: u32, pub path: &'static str, #[serde(skip)] build: fn(&InboundParams) -> serde_json::Value }
fn xhttp_stream(p: &InboundParams) -> serde_json::Value { let mut s = base_tls_stream(p, "xhttp", &["h2", "http/1.1"]); s["xhttpSettings"] = serde_json::json!({"path":p.path,"host":"","headers":{}}); s }
fn vision_stream(p: &InboundParams) -> serde_json::Value { let mut s = base_tls_stream(p, "tcp", &["h2"]); s["tcpSettings"] = serde_json::json!({"header":{"type":"none"}}); s }
fn base_tls_stream(p: &InboundParams, network: &str, alpn: &[&str]) -> serde_json::Value {
    let dir = format!("/root/cert/{}", p.server_name);
    serde_json::json!({"network":network,"security":"tls","tlsSettings":{"serverName":p.server_name,"minVersion":"1.2","maxVersion":"1.3","alpn":alpn,"rejectUnknownSni":false,"certificates":[{"certificateFile":format!("{dir}/fullchain.pem"),"keyFile":format!("{dir}/privkey.pem"),"oneTimeLoading":false,"usage":"encipherment","buildChain":false}],"settings":{"fingerprint":"","echConfigList":""}}})
}
pub fn list_inbound_templates() -> Vec<InboundTemplate> { vec![
    InboundTemplate { id:"VLESS-XHTTP-443", name:"VLESS-XHTTP-443", description:"VLESS, XHTTP и TLS", remark:"VLESS-XHTTP-443", port:443, path:"/", build:xhttp_stream },
    InboundTemplate { id:"VLESS-VISION-8443", name:"VLESS-VISION-8443", description:"VLESS, TCP и TLS (Vision)", remark:"VLESS-VISION-8443", port:8443, path:"/", build:vision_stream },
] }
pub fn build_inbound_request(template_id: &str, params: &InboundParams) -> Result<serde_json::Value, String> {
    validate_inbound_params(params)?;
    let template = list_inbound_templates().into_iter().find(|t| t.id == template_id).ok_or("Неизвестный шаблон inbound-а")?;
    let settings = serde_json::json!({"clients":[],"decryption":"none","encryption":"none","fallbacks":[]});
    let stream_settings = (template.build)(params);
    Ok(serde_json::json!({"up":0,"down":0,"total":0,"remark":params.remark,"enable":true,"expiryTime":0,"listen":"","port":params.port,"protocol":"vless","settings":settings.to_string(),"streamSettings":stream_settings.to_string(),"sniffing":serde_json::json!({"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":false}).to_string()}))
}

/// Obtain a Let's Encrypt cert using the same acme.sh and /root/cert/<domain>
/// layout used by 3x-ui's SSL certificate manager. Secrets and raw command
/// output are deliberately never returned to the UI.
pub fn ensure_wizard_certificate(target: &str, domain: &str) -> Result<(), String> {
    if !target.starts_with("root@") || !valid_ssh_target(target) { return Err("Проверьте SSH-цель root@хост".into()); }
    if !valid_domain_name(domain) { return Err("Некорректное доменное имя сертификата".into()); }
    let command = format!(r#"set -eu
ACME=/root/.acme.sh/acme.sh
if [ ! -x "$ACME" ]; then curl -fsSL https://get.acme.sh | sh >/dev/null 2>&1; fi
[ -x "$ACME" ] || exit 40
CERT_DIR=/root/cert/{domain}
mkdir -p "$CERT_DIR"
"$ACME" --set-default-ca --server letsencrypt --force >/dev/null 2>&1
"$ACME" --issue -d {domain} --standalone --httpport 80 --force >/dev/null 2>&1 || exit 41
"$ACME" --installcert --force -d {domain} --key-file "$CERT_DIR/privkey.pem" --fullchain-file "$CERT_DIR/fullchain.pem" --reloadcmd "systemctl restart x-ui" >/dev/null 2>&1 || exit 42
chmod 600 "$CERT_DIR/privkey.pem"
chmod 644 "$CERT_DIR/fullchain.pem"
test -s "$CERT_DIR/privkey.pem" -a -s "$CERT_DIR/fullchain.pem""#);
    let mut ssh = std::process::Command::new("/usr/bin/ssh");
    if let Some(home) = std::env::var_os("HOME") {
        let key = PathBuf::from(home).join(".ssh/id_ed25519_vpn_client");
        if key.is_file() { ssh.arg("-i").arg(key); }
    }
    let (dest, ssh_port) = split_ssh_target(target);
    if let Some(p) = ssh_port { ssh.args(["-p", &p.to_string()]); }
    let output = ssh.args(["-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "--", dest, &command])
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map_err(|_| "Не удалось запустить системный SSH для сертификата".to_owned())?;
    match status_code(output.code()) {
        0 => Ok(()),
        40 => Err("Не удалось установить acme.sh. Проверьте доступность get.acme.sh с сервера.".into()),
        41 => Err("Не удалось выпустить сертификат: проверьте, что SNI указывает на этот сервер и входящий порт 80 доступен из интернета.".into()),
        42 => Err("acme.sh не смог установить сертификат в каталог 3x-ui.".into()),
        _ => Err("Не удалось подготовить TLS-сертификат через SSH. Проверьте доступ к серверу и свободный порт 80.".into()),
    }
}

fn status_code(code: Option<i32>) -> i32 { code.unwrap_or(-1) }

pub fn list_wizard_inbounds(id: &str, panel: &Panel) -> Result<serde_json::Value, String> {
    validate_panel(panel)?;
    let token = staged_wizard_token(id)?;
    list_inbounds_for(panel, &token)
}

pub fn create_inbound(panel: &Panel, token: &str, template_id: &str, params: &InboundParams) -> Result<u64, String> {
    validate_panel(panel)?;
    let body = build_inbound_request(template_id, params)?;
    let response = panel_request(panel, token, "inbounds/add", Some(body))?;
    if let Some(id) = response.get("obj").and_then(serde_json::Value::as_u64) { return Ok(id); }
    list_inbounds_for(panel, token)?.as_array().and_then(|items| items.iter().find(|item| item["remark"] == params.remark && item["port"] == params.port))
        .and_then(|item| item["id"].as_u64()).ok_or_else(|| "Панель создала inbound, но не вернула его ID".into())
}

pub fn create_wizard_inbound(id: &str, panel: &Panel, target: &str, template_id: &str, params: &InboundParams) -> Result<u64, String> {
    validate_panel(panel)?;
    build_inbound_request(template_id, params)?;
    let token = staged_wizard_token(id)?;
    ensure_wizard_certificate(target, &params.server_name)?;
    create_inbound(panel, &token, template_id, params)
}

pub fn create_server_inbound(id: &str, template_id: &str, params: &InboundParams) -> Result<u64, String> {
    let server = server_for(id)?;
    build_inbound_request(template_id, params)?;
    let token = server_token(id)?;
    let target = server.panel.ssh_target.as_deref().ok_or("Для выпуска сертификата укажите SSH-цель в настройках сервера")?;
    ensure_wizard_certificate(target, &params.server_name)?;
    create_inbound(&server.panel, &token, template_id, params)
}

fn create_client_with_token(panel: &Panel, token: &str, inbound_id: u64, email: &str) -> Result<(), String> {
    let inbounds = list_inbounds_for(panel, token)?;
    crate::client_plan::prepare(&inbounds, inbound_id, email)?;
    let body = serde_json::json!({"client":{"email":email,"enable":true,"totalGB":0,"expiryTime":0,"limitIp":0},"inboundIds":[inbound_id]});
    panel_request(panel, token, "clients/add", Some(body))?;
    Ok(())
}

pub fn create_xhttp_relay_client(host: &str, email: &str, sni: &str, port: u16) -> Result<(String, u64), String> {
    if !valid_http_host(host) || !valid_domain_name(sni) || port == 0 { return Err("Некорректный хост, SNI или порт".into()); }
    if email.is_empty() || email.len() > 128 || !email.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c)) { return Err("Некорректное имя клиента".into()); }
    let servers: Vec<_> = list_servers()?.into_iter().filter(|s| s.panel.panel_host.as_deref() == Some(host) || s.panel.ssh_target.as_deref().map(ssh_host) == Some(host)).collect();
    if servers.len() != 1 { return Err("Нужна ровно одна сохранённая панель для указанного хоста".into()); }
    let server = &servers[0]; let token = server_token(&server.id)?;
    let remark = format!("VLESS-XHTTP-RELAY-{port}");
    let items = panel_request(&server.panel, &token, "inbounds/list", None)?;
    let items = items.get("obj").and_then(|v| v.as_array()).ok_or("Некорректный список inbound-ов")?;
    let id = if let Some(existing) = items.iter().find(|v| v["port"] == port) {
        if existing["remark"] != remark || existing["protocol"] != "vless" { return Err(format!("Порт {port} уже занят другим inbound-ом")); }
        existing["id"].as_u64().ok_or("Некорректный ID inbound-а")?
    } else {
        let params = InboundParams { remark: remark.clone(), port: port.into(), server_name: sni.into(), path: "/".into() };
        let mut body = build_inbound_request("VLESS-XHTTP-443", &params)?;
        body["sniffing"] = serde_json::json!({"enabled":false,"destOverride":[],"metadataOnly":false,"routeOnly":false}).to_string().into();
        let response = panel_request(&server.panel, &token, "inbounds/add", Some(body))?;
        response.get("obj").and_then(|v| v.as_u64()).or_else(|| list_inbounds_for(&server.panel, &token).ok()?.as_array()?.iter().find(|i| i["remark"] == remark && i["port"] == port)?.get("id")?.as_u64()).ok_or("Панель создала inbound, но не вернула его ID")?
    };
    create_client_with_token(&server.panel, &token, id, email)?;
    refresh_client_profiles(&server.id)?;
    Ok((server.id.clone(), id))
}

fn reality_inbound_body(sni: &str, private: &str, public: &str, short_id: &str, port: u16) -> serde_json::Value {
    let stream = serde_json::json!({"network":"tcp","security":"reality","realitySettings":{"show":false,"xver":0,"target":format!("{sni}:443"),"serverNames":[sni],"privateKey":private,"shortIds":[short_id],"settings":{"publicKey":public,"fingerprint":"chrome","serverName":sni,"spiderX":"/"}},"tcpSettings":{"header":{"type":"none"}}});
    serde_json::json!({"up":0,"down":0,"total":0,"remark":format!("VLESS-REALITY-{port}"),"enable":true,"expiryTime":0,"listen":"","port":port,"protocol":"vless","settings":serde_json::json!({"clients":[],"decryption":"none","encryption":"none","fallbacks":[]}).to_string(),"streamSettings":stream.to_string(),"sniffing":serde_json::json!({"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":false}).to_string()})
}

fn hysteria2_inbound_body(sni: &str) -> serde_json::Value {
    let stream = serde_json::json!({"network":"hysteria","security":"tls","tlsSettings":{"serverName":sni,"alpn":["h3"],"certificates":[{"certificateFile":format!("/root/cert/{sni}/fullchain.pem"),"keyFile":format!("/root/cert/{sni}/privkey.pem"),"oneTimeLoading":false,"usage":"encipherment","buildChain":false}]},"hysteriaSettings":{"version":2,"udpIdleTimeout":60}});
    serde_json::json!({"up":0,"down":0,"total":0,"remark":"HYSTERIA2-UDP-443","enable":true,"expiryTime":0,"listen":"","port":443,"protocol":"hysteria","settings":serde_json::json!({"version":2,"clients":[]}).to_string(),"streamSettings":stream.to_string(),"sniffing":serde_json::json!({"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":false}).to_string()})
}

pub fn create_hysteria2_client(host: &str, email: &str, sni: &str) -> Result<(String, u64), String> {
    if !valid_http_host(host) || !valid_domain_name(sni) { return Err("Некорректный хост или SNI".into()); }
    if email.is_empty() || email.len() > 128 || !email.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c)) { return Err("Некорректное имя клиента".into()); }
    let servers: Vec<_> = list_servers()?.into_iter().filter(|s| s.panel.panel_host.as_deref() == Some(host) || s.panel.ssh_target.as_deref().map(ssh_host) == Some(host)).collect();
    if servers.len() != 1 { return Err("Нужна ровно одна сохранённая панель для указанного хоста".into()); }
    let server = &servers[0]; let token = server_token(&server.id)?;
    let target = server.panel.ssh_target.as_deref().ok_or("Для выпуска сертификата укажите SSH-цель в настройках сервера")?;
    ensure_wizard_certificate(target, sni)?;
    let list = panel_request(&server.panel, &token, "inbounds/list", None)?;
    let items = list.get("obj").and_then(|v| v.as_array()).ok_or("Некорректный список inbound-ов")?;
    let id = if let Some(existing) = items.iter().find(|v| v["remark"] == "HYSTERIA2-UDP-443" && v["port"] == 443 && v["protocol"] == "hysteria") {
        existing["id"].as_u64().ok_or("Некорректный ID inbound-а")?
    } else {
        if items.iter().any(|v| v["port"] == 443 && v["protocol"] != "hysteria") { /* TCP and UDP listeners can share a port. */ }
        let response = panel_request(&server.panel, &token, "inbounds/add", Some(hysteria2_inbound_body(sni)))?;
        response.get("obj").and_then(serde_json::Value::as_u64).or_else(|| list_inbounds_for(&server.panel, &token).ok()?.as_array()?.iter().find(|v| v["remark"] == "HYSTERIA2-UDP-443" && v["port"] == 443)?.get("id")?.as_u64()).ok_or("Панель создала inbound, но не вернула его ID")?
    };
    create_client_with_token(&server.panel, &token, id, email)?;
    refresh_client_profiles(&server.id)?;
    set_profile_pinned(&server.id, id, email, true)?;
    Ok((server.id.clone(), id))
}

pub fn create_reality_client(host: &str, email: &str, sni: &str) -> Result<(String, u64), String> {
    create_reality_client_on_port(host, email, sni, 443)
}

pub fn create_reality_client_on_port(host: &str, email: &str, sni: &str, port: u16) -> Result<(String, u64), String> {
    if port == 0 { return Err("Некорректный порт".into()); }
    if !valid_http_host(host) || !valid_domain_name(sni) { return Err("Некорректный хост или SNI".into()); }
    if email.is_empty() || email.len() > 128 || !email.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c)) { return Err("Некорректное имя клиента".into()); }
    let servers: Vec<_> = list_servers()?.into_iter().filter(|s| s.panel.panel_host.as_deref() == Some(host) || s.panel.ssh_target.as_deref().map(ssh_host) == Some(host)).collect();
    if servers.len() != 1 { return Err("Нужна ровно одна сохранённая панель для указанного хоста".into()); }
    let server = &servers[0]; let token = server_token(&server.id)?;
    let list = panel_request(&server.panel, &token, "inbounds/list", None)?;
    let items = list.get("obj").and_then(|v| v.as_array()).ok_or("Некорректный список inbound-ов")?;
    let inbound_id = if let Some(existing) = items.iter().find(|v| v["port"] == port) {
        let raw = existing.get("streamSettings").cloned().unwrap_or(serde_json::json!({}));
        let stream = if let Some(s) = raw.as_str() { serde_json::from_str::<serde_json::Value>(s).unwrap_or_default() } else { raw };
        if existing["remark"] != format!("VLESS-REALITY-{port}") || existing["protocol"] != "vless" || stream["security"] != "reality" || stream["network"] != "tcp" { return Err(format!("Порт {port} уже занят другим inbound-ом")); }
        if !stream["realitySettings"]["serverNames"].as_array().is_some_and(|names| names.iter().any(|name| name == sni)) { return Err("На порту 443 уже есть Reality inbound с другим SNI".into()); }
        existing["id"].as_u64().ok_or("Некорректный ID inbound-а")?
    } else {
        let output = std::process::Command::new("/Applications/VPNClient.app/Contents/Helpers/xray").arg("x25519").output().map_err(|_| "Не удалось запустить генератор ключей Xray")?;
        if !output.status.success() { return Err("Не удалось создать ключи Reality".into()); }
        let text = String::from_utf8(output.stdout).map_err(|_| "Некорректный ответ генератора ключей")?;
        let private = text.lines().find_map(|line| line.strip_prefix("PrivateKey:").map(str::trim)).filter(|v| !v.is_empty()).ok_or("Генератор не вернул закрытый ключ")?;
        let public = text.lines().find_map(|line| line.strip_prefix("Password (PublicKey):").or_else(|| line.strip_prefix("PublicKey:")).map(str::trim)).filter(|v| !v.is_empty()).ok_or("Генератор не вернул открытый ключ")?;
        use std::io::Read;
        let mut bytes = [0u8; 8]; fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).map_err(|_| "Не удалось создать short ID")?;
        let short_id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let response = panel_request(&server.panel, &token, "inbounds/add", Some(reality_inbound_body(sni, private, public, &short_id, port)))?;
        response.get("obj").and_then(|v| v.as_u64()).or_else(|| list_inbounds_for(&server.panel, &token).ok()?.as_array()?.iter().find(|i| i["remark"] == format!("VLESS-REALITY-{port}") && i["port"] == port)?.get("id")?.as_u64()).ok_or("Панель создала inbound, но не вернула его ID")?
    };
    let list = panel_request(&server.panel, &token, "inbounds/list", None)?;
    let exists = list.get("obj").and_then(|v| v.as_array()).and_then(|a| a.iter().find(|i| i["id"] == inbound_id)).and_then(|i| i.get("settings")).map(|v| if let Some(s)=v.as_str() { serde_json::from_str::<serde_json::Value>(s).unwrap_or_default() } else { v.clone() }).and_then(|s| s.get("clients").and_then(|c| c.as_array()).map(|c| c.iter().any(|c| c["email"] == email))).unwrap_or(false);
    if !exists { create_client_with_token(&server.panel, &token, inbound_id, email)?; }
    refresh_client_profiles(&server.id)?;
    set_profile_pinned(&server.id, inbound_id, email, true)?;
    Ok((server.id.clone(), inbound_id))
}

pub fn create_wizard_client(id: &str, panel: &Panel, inbound_id: u64, email: &str) -> Result<(), String> {
    validate_panel(panel)?;
    create_client_with_token(panel, &staged_wizard_token(id)?, inbound_id, email)
}

pub fn wizard_client_share_link(id: &str, panel: &Panel, inbound_id: u64, email: &str) -> Result<String, String> {
    validate_panel(panel)?;
    client_share_link_with_token(panel, &staged_wizard_token(id)?, email, inbound_id)
}

pub fn save_wizard_server(id: &str, panel: Panel, country: Option<String>) -> Result<Server, String> {
    validate_panel(&panel)?;
    let country = country.filter(|s| !s.is_empty());
    if country.as_ref().is_some_and(|c| !COUNTRY_CODES.split_whitespace().any(|v| v == c)) { return Err("Выберите страну из списка".into()); }
    let token = staged_wizard_token(id)?;
    let mut servers = list_servers()?;
    if servers.iter().any(|s| s.id == id) { return Err("Идентификатор сервера уже используется".into()); }
    token_set(id, &token)?;
    let server = Server { id: id.to_owned(), country, panel };
    servers.push(server.clone());
    if let Err(error) = write_servers(&servers_path()?, &servers) {
        let _ = token_delete(id);
        return Err(error);
    }
    clear_wizard_token(id)?;
    Ok(server)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PendingClient {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    pub inbound_id: u64,
    pub email: String,
    pub inbound_name: String,
    pub panel_name: String,
}
fn clear_pending_for_server(pending_path: &std::path::Path, legacy_path: &std::path::Path, server: &Server) -> Result<(), String> {
    let data = match fs::read(pending_path) { Ok(data) => data, Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()), Err(e) => return Err(e.to_string()) };
    let pending: PendingClient = serde_json::from_slice(&data).map_err(|_| "Некорректная ожидающая заявка клиента")?;
    let belongs = match pending.server_id.as_deref() {
        Some(id) => id == server.id,
        None => fs::read(legacy_path).ok().and_then(|data| serde_json::from_slice::<Panel>(&data).ok()).is_some_and(|legacy| legacy.url == server.panel.url && legacy.name == pending.panel_name),
    };
    if belongs { fs::remove_file(pending_path).map_err(|e| e.to_string())?; }
    Ok(())
}
fn pending_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    Ok(PathBuf::from(home).join("Library/Application Support/VpnClient/pending-client.json"))
}
pub fn queue_client(inbound_id: u64, email: &str) -> Result<PendingClient, String> {
    let panel = load_panel()?.ok_or("No panel configured")?;
    let list = list_inbounds()?;
    let plan = crate::client_plan::prepare(&list, inbound_id, email)?;
    let pending = PendingClient {
        server_id: None,
        inbound_id,
        email: email.into(),
        inbound_name: plan.inbound_name,
        panel_name: panel.name,
    };
    let path = pending_path()?;
    std::fs::create_dir_all(path.parent().ok_or("Invalid pending path")?)
        .map_err(|e| e.to_string())?;
    let data = serde_json::to_vec(&pending).map_err(|e| e.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "A client request is already waiting for review".to_owned())?;
    use std::io::Write;
    file.write_all(&data)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(pending)
}
pub fn pending_client() -> Result<Option<PendingClient>, String> {
    match std::fs::read(pending_path()?) {
        Ok(data) => serde_json::from_slice(&data)
            .map(Some)
            .map_err(|_| "Invalid pending client request".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
pub fn cancel_pending_client() -> Result<(), String> {
    match std::fs::remove_file(pending_path()?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
pub fn client_share_link(email: &str, inbound_id: u64) -> Result<String, String> {
    let panel = load_panel()?.ok_or("No panel configured")?;
    let token = token_get(&panel.url)?;
    client_share_link_with_token(&panel, &token, email, inbound_id)
}
fn client_share_link_with_token(panel: &Panel, token: &str, email: &str, inbound_id: u64) -> Result<String, String> {
    if inbound_id == 0 || email.is_empty() || email.len() > 128 || !email.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c)) { return Err("Invalid client selection".into()); }
    let encoded_email: String = url::form_urlencoded::byte_serialize(email.as_bytes()).collect();
    let client = panel_request(panel, token, &format!("clients/get/{encoded_email}"), None)?;
    let client = client.get("obj").and_then(|v| v.get("client")).ok_or("Client not found")?;
    let attached = panel_request(panel, token, &format!("inbounds/get/{inbound_id}"), None)?;
    let inbound = attached.get("obj").ok_or("Inbound not found")?;
    if inbound.get("protocol").and_then(|v| v.as_str()) == Some("hysteria") {
        let auth = client.get("auth").and_then(|v| v.as_str()).filter(|v| !v.is_empty()).ok_or("Hysteria 2 client has no authentication")?;
        return build_hysteria2_share_link(panel, email, auth, inbound);
    }
    let uuid = client.get("uuid").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).ok_or("Client has no VLESS UUID")?;
    build_client_share_link(panel, email, uuid, inbound)
}
fn build_hysteria2_share_link(panel: &Panel, email: &str, auth: &str, inbound: &serde_json::Value) -> Result<String, String> {
    if inbound.get("enable").and_then(|v| v.as_bool()) != Some(true) || inbound.get("protocol").and_then(|v| v.as_str()) != Some("hysteria") { return Err("Selected inbound is not an enabled Hysteria service".into()); }
    let stream = inbound.get("streamSettings").cloned().unwrap_or(serde_json::json!({}));
    let stream = if let Some(raw) = stream.as_str() { serde_json::from_str(raw).map_err(|_| "Invalid Hysteria transport settings")? } else { stream };
    let tls = stream.get("tlsSettings").ok_or("Hysteria TLS settings are missing")?;
    let sni = tls.get("serverName").and_then(|v| v.as_str()).filter(|v| !v.is_empty()).ok_or("Hysteria SNI is missing")?;
    let host = inbound.get("shareAddr").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).or(panel.panel_host.as_deref()).or_else(|| panel.ssh_target.as_deref().map(ssh_host)).ok_or("Public server address is missing")?;
    if !valid_http_host(host) { return Err("Invalid public server address".into()); }
    let port = inbound.get("port").and_then(|v| v.as_u64()).filter(|p| *p > 0 && *p <= 65535).ok_or("Invalid Hysteria port")?;
    let user = url::form_urlencoded::byte_serialize(auth.as_bytes()).collect::<String>();
    let query = url::form_urlencoded::Serializer::new(String::new()).append_pair("sni", sni).finish();
    Ok(format!("hysteria2://{user}@{host}:{port}/?{query}#{}", url::form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>()))
}
fn build_client_share_link(panel: &Panel, email: &str, uuid: &str, inbound: &serde_json::Value) -> Result<String, String> {
    if inbound.get("enable").and_then(|v| v.as_bool()) != Some(true) || inbound.get("protocol").and_then(|v| v.as_str()) != Some("vless") { return Err("Selected inbound is not an enabled VLESS service".into()); }
    let settings = inbound.get("streamSettings").cloned().unwrap_or(serde_json::json!({}));
    let settings = if let Some(raw) = settings.as_str() { serde_json::from_str(raw).map_err(|_| "Invalid inbound transport settings")? } else { settings };
    let network = settings.get("network").and_then(|v| v.as_str()).unwrap_or("");
    let host = inbound.get("shareAddr").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).or(panel.panel_host.as_deref()).or_else(|| panel.ssh_target.as_deref().map(ssh_host)).ok_or("Public server address is missing")?;
    if !valid_http_host(host) { return Err("Invalid public server address".into()); }
    let port = inbound.get("port").and_then(|v| v.as_u64()).filter(|p| *p > 0 && *p <= 65535).ok_or("Invalid VLESS port")?;
    if network == "tcp" && settings.get("security").and_then(|v| v.as_str()) == Some("reality") {
        let reality = settings.get("realitySettings").ok_or("REALITY settings are missing")?;
        let client = reality.get("settings").ok_or("REALITY client settings are missing")?;
        let key = client.get("publicKey").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).ok_or("REALITY public key is missing")?;
        let sni = client.get("serverName").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).or_else(|| reality.get("serverNames").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|v| v.as_str())).filter(|s| !s.is_empty()).ok_or("REALITY server name is missing")?;
        let sid = reality.get("shortIds").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|v| v.as_str()).ok_or("REALITY short ID is missing")?;
        let fp = client.get("fingerprint").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("chrome");
        let spx = client.get("spiderX").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("/");
        let mut query = vec![("type", "tcp"), ("security", "reality"), ("sni", sni), ("pbk", key), ("sid", sid), ("fp", fp), ("spx", spx)];
        let raw = inbound.get("settings").cloned().unwrap_or(serde_json::json!({}));
        let client_settings = if let Some(text) = raw.as_str() { serde_json::from_str(text).unwrap_or(serde_json::json!({})) } else { raw };
        let flow = client_settings.get("clients").and_then(|v| v.as_array()).and_then(|a| a.iter().find(|c| c["email"] == email)).and_then(|c| c.get("flow")).and_then(|v| v.as_str()).unwrap_or("");
        if !flow.is_empty() { query.push(("flow", flow)); }
        let query = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(query).finish();
        return Ok(format!("vless://{uuid}@{host}:{port}?{query}#{}", url::form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>()));
    }
    if !["xhttp", "tcp"].contains(&network) || settings.get("security").and_then(|v| v.as_str()) != Some("tls") { return Err("Selected inbound is not VLESS/TLS/XHTTP or TCP".into()); }
    let tls = settings.get("tlsSettings").ok_or("TLS settings are missing")?;
    let empty = serde_json::json!({});
    let xhttp = settings.get("xhttpSettings").unwrap_or(&empty);
    let sni = tls.get("serverName").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).ok_or("TLS server name is missing")?;
    let path = xhttp.get("path").and_then(|v| v.as_str()).unwrap_or("/");
    let mut query = vec![("type", network.to_owned()), ("security", "tls".to_owned()), ("sni", sni.to_owned())];
    if network == "xhttp" { query.push(("path", path.to_owned())); }
    if let Some(alpn) = tls.get("alpn").and_then(|v| v.as_array()) { let values: Vec<&str> = alpn.iter().filter_map(|v| v.as_str()).collect(); if !values.is_empty() { query.push(("alpn", values.join(","))); } }
    if let Some(fp) = tls.get("settings").and_then(|v| v.get("fingerprint")).and_then(|v| v.as_str()).filter(|v| !v.is_empty()) { query.push(("fp", fp.to_owned())); }
    if let Some(mode) = xhttp.get("mode").and_then(|v| v.as_str()) { query.push(("mode", mode.to_owned())); }
    if let Some(host) = xhttp.get("host").and_then(|v| v.as_str()).filter(|h| !h.is_empty()) { query.push(("host", host.to_owned())); }
    let query = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(query).finish();
    Ok(format!("vless://{uuid}@{host}:{port}?{query}#{}", url::form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>()))
}

pub fn create_client(id: &str, inbound_id: u64, email: &str) -> Result<(), String> {
    let panel = server_for(id)?.panel;
    let token = server_token(id)?;
    create_client_with_token(&panel, &token, inbound_id, email)
}

pub fn approve_pending_client(inbound_id: u64, email: &str) -> Result<String, String> {
    let pending = pending_client()?.ok_or("No client request is waiting")?;
    if pending.inbound_id != inbound_id || pending.email != email {
        return Err("Request details changed; review it again".into());
    }
    let panel = load_panel()?.ok_or("No panel configured")?;
    if panel.name != pending.panel_name {
        return Err("Configured panel changed; review the request again".into());
    }
    let token = token_get(&panel.url)?;
    let inbounds = list_inbounds_for(&panel, &token)?;
    crate::client_plan::prepare(&inbounds, inbound_id, email)?;
    let body = serde_json::json!({"client":{"email":email,"enable":true,"totalGB":0,"expiryTime":0,"limitIp":0},"inboundIds":[inbound_id]});
    let _result = panel_request(&panel, &token, "clients/add", Some(body))?;
    cancel_pending_client()?;
    Ok(format!(
        "Client {email} created. Client secrets were not returned."
    ))
}

// Connections imported from a share link, not tied to any saved server.
#[derive(Clone, Serialize, Deserialize)]
struct ImportedProfile { id: String, name: String, share_link: String, added_at: u64 }
static IMPORT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn imported_path() -> Result<PathBuf, String> { Ok(config_path()?.with_file_name("imported-profiles.json")) }
fn read_imported(path: &std::path::Path) -> Result<Vec<ImportedProfile>, String> {
    match fs::read(path) {
        Ok(data) => serde_json::from_slice(&data).map_err(|_| "Список импортированных конфигураций повреждён".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}
fn write_imported(path: &std::path::Path, items: &[ImportedProfile]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().ok_or("Некорректный путь к импортированным конфигурациям")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    file.as_file().set_permissions(fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut file, items).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}
fn imported_summary(item: &ImportedProfile) -> serde_json::Value {
    let url = url::Url::parse(&item.share_link).ok();
    let hysteria = url.as_ref().is_some_and(|u| u.scheme() == "hysteria2");
    let query = |name: &str| url.as_ref().and_then(|u| u.query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.into_owned()));
    serde_json::json!({
        "id": item.id, "name": item.name,
        "host": url.as_ref().and_then(|u| u.host_str()).unwrap_or(""),
        "port": url.as_ref().and_then(|u| u.port()).unwrap_or(443),
        "transport": if hysteria { "hysteria2".into() } else { query("type").unwrap_or_else(|| "tcp".into()) },
        "security": query("security").unwrap_or_default(),
    })
}
fn valid_import_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 128 || name.chars().any(char::is_control) { return Err("Название должно быть от 1 до 128 символов".into()); }
    Ok(name.to_owned())
}
fn extract_share_links(text: &str) -> Vec<String> {
    text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',')
        .filter(|part| part.starts_with("vless://") || part.starts_with("hysteria2://") || part.starts_with("hy2://"))
        .map(str::to_owned).collect()
}
fn import_profiles_at(path: &std::path::Path, text: &str, name: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let links = extract_share_links(text);
    if links.is_empty() { return Err("В тексте нет ссылки vless:// или hysteria2://".into()); }
    if name.is_some() && links.len() > 1 { return Err("Название можно задать только для одной ссылки".into()); }
    let _guard = IMPORT_LOCK.lock().map_err(|_| "Не удалось заблокировать список импортированных конфигураций")?;
    let mut items = read_imported(path)?;
    let mut added = Vec::new();
    let mut last_error = None;
    for link in links {
        let link = match link.strip_prefix("hy2://") { Some(rest) => format!("hysteria2://{rest}"), None => link };
        if let Err(e) = crate::profile::vless_config(&link, 10808) { last_error = Some(format!("Некорректная ссылка: {e}")); continue; }
        if items.iter().any(|item| item.share_link == link) { last_error = Some("Эта конфигурация уже импортирована".into()); continue; }
        let parsed = url::Url::parse(&link).map_err(|_| "Некорректная ссылка")?;
        let fragment: String = url::form_urlencoded::parse(parsed.fragment().unwrap_or("").replace('+', "%2B").as_bytes()).map(|(k, v)| if v.is_empty() { k.into_owned() } else { format!("{k}={v}") }).collect();
        let chosen = match name { Some(n) => valid_import_name(n)?, None => valid_import_name(&fragment).or_else(|_| valid_import_name(parsed.host_str().unwrap_or("Импорт")))? };
        let item = ImportedProfile { id: new_server_id()?, name: chosen, share_link: link, added_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) };
        added.push(imported_summary(&item));
        items.push(item);
    }
    if added.is_empty() { return Err(last_error.unwrap_or_else(|| "Не удалось импортировать конфигурацию".into())); }
    write_imported(path, &items)?;
    Ok(added)
}
pub fn import_profiles(text: &str, name: Option<&str>) -> Result<Vec<serde_json::Value>, String> { import_profiles_at(&imported_path()?, text, name) }
pub fn list_imported_profiles() -> Result<Vec<serde_json::Value>, String> {
    let _guard = IMPORT_LOCK.lock().map_err(|_| "Не удалось заблокировать список импортированных конфигураций")?;
    Ok(read_imported(&imported_path()?)?.iter().map(imported_summary).collect())
}
fn update_imported(path: &std::path::Path, id: &str, change: impl FnOnce(&mut Vec<ImportedProfile>, usize) -> Result<(), String>) -> Result<(), String> {
    if !valid_server_id(id) { return Err("Некорректный идентификатор конфигурации".into()); }
    let _guard = IMPORT_LOCK.lock().map_err(|_| "Не удалось заблокировать список импортированных конфигураций")?;
    let mut items = read_imported(path)?;
    let index = items.iter().position(|item| item.id == id).ok_or("Конфигурация не найдена")?;
    change(&mut items, index)?;
    write_imported(path, &items)
}
pub fn rename_imported_profile(id: &str, name: &str) -> Result<(), String> {
    let name = valid_import_name(name)?;
    update_imported(&imported_path()?, id, |items, i| { items[i].name = name; Ok(()) })
}
pub fn delete_imported_profile(id: &str) -> Result<(), String> {
    update_imported(&imported_path()?, id, |items, i| { items.remove(i); Ok(()) })
}
/// Hysteria 2 needs a VLESS/XHTTP relay to reach its server: prefer a saved-server client, then an imported one.
pub fn imported_relay_link(exclude_id: &str) -> Result<Option<String>, String> {
    for p in all_connectable_profiles()? {
        if p["protocol"] == "vless" && p["transport"] == "xhttp" && p["has_local_config"] == true {
            if let (Some(server), Some(inbound), Some(email)) = (p["server_id"].as_str(), p["inbound_id"].as_u64(), p["email"].as_str()) {
                if let Ok(link) = cached_client_share_link(server, inbound, email) { return Ok(Some(link)); }
            }
        }
    }
    let _guard = IMPORT_LOCK.lock().map_err(|_| "Не удалось заблокировать список импортированных конфигураций")?;
    Ok(read_imported(&imported_path()?)?.into_iter()
        .find(|item| item.id != exclude_id && item.share_link.starts_with("vless://") && crate::profile::vless_xhttp_config(&item.share_link, 10808).is_ok())
        .map(|item| item.share_link))
}

/// Optional explicit relay for REALITY profiles; the file contains a secret share link.
pub fn reality_relay_link() -> Result<Option<String>, String> {
    let path = config_path()?.with_file_name("reality-relay.json");
    let data = match fs::read(path) { Ok(data) => data, Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None), Err(e) => return Err(e.to_string()) };
    let value: serde_json::Value = serde_json::from_slice(&data).map_err(|_| "Некорректная конфигурация Reality relay")?;
    let link = value.get("share_link").and_then(|v| v.as_str()).ok_or("Не указан Reality relay")?;
    crate::profile::vless_xhttp_config(link, 10808).map_err(|_| "Некорректный XHTTP relay для Reality")?;
    Ok(Some(link.to_owned()))
}
pub fn imported_share_link(id: &str) -> Result<String, String> {
    if !valid_server_id(id) { return Err("Некорректный идентификатор конфигурации".into()); }
    let _guard = IMPORT_LOCK.lock().map_err(|_| "Не удалось заблокировать список импортированных конфигураций")?;
    read_imported(&imported_path()?)?.into_iter().find(|item| item.id == id).map(|item| item.share_link).ok_or_else(|| "Конфигурация не найдена".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ssh_target_accepts_optional_port() {
        assert_eq!(split_ssh_target("root@example.com:2222"), ("root@example.com", Some(2222)));
        assert_eq!(split_ssh_target("root@example.com"), ("root@example.com", None));
        assert_eq!(ssh_host("root@example.com:2222"), "example.com");
        assert_eq!(ssh_host("example.com"), "example.com");
        assert!(valid_ssh_target("root@example.com:22") && valid_ssh_target("root@10.0.0.1:65535"));
        for bad in ["root@example.com:0", "root@example.com:65536", "root@example.com:", "root@example.com:abc", "root@:22", "root@a:b:22", "-oProxy@x:22"] {
            assert!(!valid_ssh_target(bad), "{bad}");
        }
    }

    use super::*;
    #[test]
    fn token_file_keeps_accounts_separate_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("panel-tokens.json");
        token_store_at(&path, |t| { t.insert("one".into(), "first".into()); Ok(((), true)) }).unwrap();
        token_store_at(&path, |t| { t.insert("two".into(), "second".into()); Ok(((), true)) }).unwrap();
        token_store_at(&path, |t| { t.remove("one"); Ok(((), true)) }).unwrap();
        token_store_at(&path, |t| { assert!(!t.contains_key("one")); assert_eq!(t.get("two").map(String::as_str), Some("second")); Ok(((), false)) }).unwrap();
        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    #[test]
    fn reality_share_link_round_trips_into_client_config() {
        let panel = Panel { name:"test".into(), url:"http://127.0.0.1:2053/".into(), ssh_target:Some("root@198.51.100.2".into()), panel_host:None };
        let stream = serde_json::json!({"network":"tcp","security":"reality","realitySettings":{"serverNames":["www.microsoft.com"],"shortIds":["01234567"],"settings":{"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","fingerprint":"chrome","spiderX":"/"}}});
        let inbound = serde_json::json!({"enable":true,"protocol":"vless","port":443,"streamSettings":stream,"settings":{"clients":[{"email":"client-1","flow":"xtls-rprx-vision"}]}});
        let link = build_client_share_link(&panel,"client-1","12345678-1234-1234-1234-123456789abc",&inbound).unwrap();
        let config = profile::vless_config(&link,10808).unwrap();
        assert_eq!(config["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"],"01234567");
        assert_eq!(config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],"xtls-rprx-vision");
    }

    #[test]
    fn hysteria2_inbound_uses_udp_tls_and_certificate_paths() {
        let body = hysteria2_inbound_body("203-0-113-8.sslip.io");
        assert_eq!(body["protocol"], "hysteria");
        assert_eq!(body["port"], 443);
        let stream: serde_json::Value = serde_json::from_str(body["streamSettings"].as_str().unwrap()).unwrap();
        assert_eq!(stream["network"], "hysteria");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["tlsSettings"]["alpn"], serde_json::json!(["h3"]));
        assert_eq!(stream["tlsSettings"]["certificates"][0]["certificateFile"], "/root/cert/203-0-113-8.sslip.io/fullchain.pem");
        assert_eq!(stream["hysteriaSettings"]["version"], 2);
    }
    #[test]
    fn geo_database_lists_are_read_and_missing_ones_rejected() {
        // Two entries: [field1 { field1: "RU" }, field1 { field1: "PRIVATE" }].
        let entry = |code: &str| { let mut inner = vec![0x0a, code.len() as u8]; inner.extend(code.bytes()); let mut e = vec![0x0a, inner.len() as u8]; e.extend(inner); e };
        let dir = tempfile::tempdir().unwrap();
        let mut data = entry("RU"); data.extend(entry("PRIVATE"));
        fs::write(dir.path().join("geoip.dat"), &data).unwrap();
        let codes = geo_codes(&dir.path().join("geoip.dat")).unwrap();
        assert!(codes.contains("RU") && codes.contains("PRIVATE") && codes.len() == 2);
        assert!(check_geo_entries(&["geoip:ru".into(), "example.com".into()], dir.path()).is_ok());
        assert!(check_geo_entries(&["geoip:xx".into()], dir.path()).unwrap_err().contains("geoip:xx"));
        // No geosite.dat in the directory: geosite entries are not checked (development builds).
        assert!(check_geo_entries(&["geosite:whatever".into()], dir.path()).is_ok());
        // The picker lists names lower-case and sorted; an absent database yields an empty list.
        let lists = geo_lists(dir.path()).unwrap();
        assert_eq!(lists["geoip"], serde_json::json!(["private", "ru"]));
        assert_eq!(lists["geosite"], serde_json::json!([]));
        fs::write(dir.path().join("geoip.dat"), [0x0a, 0x7f]).unwrap();
        assert!(geo_codes(&dir.path().join("geoip.dat")).is_err());
    }

    #[test]
    fn imports_links_from_text_and_manages_them() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("imported-profiles.json");
        let a = "vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=xhttp&security=tls&sni=example.org&path=%2Fa#Home%20NL";
        let b = "vless://12345678-1234-1234-1234-123456789abd@example.net:443?type=xhttp&security=tls&sni=example.net&path=%2Fb";
        let added = import_profiles_at(&path, &format!("  {a}\n\n{b} \n"), None).unwrap();
        assert_eq!(added.len(), 2);
        assert_eq!(added[0]["name"], "Home NL");
        assert_eq!(added[1]["name"], "example.net");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(import_profiles_at(&path, a, None).unwrap_err().contains("уже"));
        assert!(import_profiles_at(&path, "hello", None).is_err());
        let hy = import_profiles_at(&path, "hy2://secret%3Aauth@example.com:443/?sni=example.com#HY", None).unwrap();
        assert_eq!(hy[0]["transport"], "hysteria2");
        assert!(read_imported(&path).unwrap().last().unwrap().share_link.starts_with("hysteria2://"));
        assert!(import_profiles_at(&path, "hysteria2://@example.com:443", None).is_err());
        update_imported(&path, hy[0]["id"].as_str().unwrap(), |items, i| { items.remove(i); Ok(()) }).unwrap();
        assert!(import_profiles_at(&path, "vless://bad@example.org:443", None).is_err());
        assert!(import_profiles_at(&path, &format!("{a} {b}"), Some("x")).is_err());
        let id = added[0]["id"].as_str().unwrap().to_owned();
        update_imported(&path, &id, |items, i| { items[i].name = "Renamed".into(); Ok(()) }).unwrap();
        assert_eq!(read_imported(&path).unwrap()[0].name, "Renamed");
        update_imported(&path, &id, |items, i| { items.remove(i); Ok(()) }).unwrap();
        assert_eq!(read_imported(&path).unwrap().len(), 1);
        assert!(update_imported(&path, "../x", |_, _| Ok(())).is_err());
    }
    #[test]
    fn pinned_profiles_default_toggle_and_server_cleanup() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pinned-profiles.json");
        let a = PinnedProfile { server_id:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(), inbound_id:1, email:"alice".into() };
        let b = PinnedProfile { server_id:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(), inbound_id:2, email:"bob".into() };
        assert_eq!(read_pins(&path).unwrap(), None);
        remove_server_pins(&path, &a.server_id).unwrap();
        assert!(!path.exists());
        change_pins(&path, &[a.clone(),b.clone()], a.clone(), false).unwrap();
        assert_eq!(read_pins(&path).unwrap(), Some(vec![b.clone()]));
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        change_pins(&path, &[], a.clone(), true).unwrap();
        remove_server_pins(&path, &a.server_id).unwrap();
        assert_eq!(read_pins(&path).unwrap(), Some(vec![b]));
    }
    #[test]
    fn removes_only_pending_client_for_deleted_server() {
        let dir = tempfile::tempdir().unwrap();
        let pending = dir.path().join("pending-client.json");
        let legacy = dir.path().join("panel.json");
        let server = Server { id:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(), country:None, panel:Panel {name:"A".into(),url:"https://a.example".into(),ssh_target:None,panel_host:None} };
        fs::write(&legacy, serde_json::to_vec(&server.panel).unwrap()).unwrap();
        let write_pending = |id: Option<&str>| fs::write(&pending, serde_json::to_vec(&PendingClient {server_id:id.map(str::to_owned), inbound_id:1, email:"client".into(), inbound_name:"inbound".into(),panel_name:"A".into()}).unwrap()).unwrap();
        write_pending(Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        clear_pending_for_server(&pending, &legacy, &server).unwrap();
        assert!(pending.exists());
        write_pending(Some(&server.id));
        clear_pending_for_server(&pending, &legacy, &server).unwrap();
        assert!(!pending.exists());
        write_pending(None);
        clear_pending_for_server(&pending, &legacy, &server).unwrap();
        assert!(!pending.exists());
        write_pending(None);
        fs::write(&legacy, br#"{"name":"A","url":"https://other.example"}"#).unwrap();
        clear_pending_for_server(&pending, &legacy, &server).unwrap();
        assert!(pending.exists());
    }
    #[test]
    fn migrates_legacy_panel_and_copies_token() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("panel.json"); let new = dir.path().join("servers.json");
        fs::write(&old, r#"{"name":"Первый","url":"https://example.com"}"#).unwrap();
        let mut copied = None;
        let servers = migrate_panel(&old, &new, |url, id| { copied = Some((url.to_owned(), id.to_owned())); Ok(()) }).unwrap();
        assert_eq!(servers.len(), 1); assert_eq!(servers[0].panel.name, "Первый");
        assert_eq!(copied, Some(("https://example.com".into(), servers[0].id.clone())));
        assert!(old.exists());
        let again = migrate_panel(&old, &new, |_, _| panic!("migration repeated")).unwrap();
        assert_eq!(again[0].id, servers[0].id);
    }
    #[test]
    fn cache_paths_and_profiles_are_isolated_by_server() {
        let dir = tempfile::tempdir().unwrap();
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert_ne!(profile_cache_path(a).unwrap(), profile_cache_path(b).unwrap());
        let profile = CachedClientProfile { inbound_id: 1, inbound_name: "test".into(), port: 443, protocol: "vless".into(), transport: "xhttp".into(), inbound_enabled: true, email: "alice".into(), enabled: true, share_link: None };
        let cache = ProfileCache { panel_url: "https://a.example".into(), profiles: vec![profile], inbounds: vec![] };
        let path = dir.path().join(format!("client-profiles-{a}.json")); fs::write(&path, serde_json::to_vec(&cache).unwrap()).unwrap();
        assert!(!dir.path().join(format!("client-profiles-{b}.json")).exists());
        let loaded: ProfileCache = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(loaded.profiles[0].email, "alice");
    }
    #[test]
    fn panel_hostname_extracts_host_without_port_or_path() {
        assert_eq!(panel_hostname("https://panel.example.com:2053/path").unwrap(), "panel.example.com");
        assert_eq!(panel_hostname("http://127.0.0.1:28004/").unwrap(), "127.0.0.1");
        assert!(panel_hostname("not a URL").is_err());
    }
    #[test]
    fn old_server_without_country_deserializes_as_empty() {
        let old = r#"{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"Сервер","url":"https://example.com"}"#;
        let server: Server = serde_json::from_str(old).unwrap();
        assert_eq!(server.country, None);
        let with_country: Server = serde_json::from_str(&old.replace("{", "{\"country\":\"NL\"," )).unwrap();
        assert_eq!(with_country.country.as_deref(), Some("NL"));
    }
    #[test]
    fn ssh_panel_is_restricted_to_loopback_and_safe_target() {
        let panel = |url: &str, target: &str| Panel {
            name: "test".into(),
            url: url.into(),
            ssh_target: Some(target.into()),
            panel_host: None,
        };
        assert!(validate_panel(&panel("http://127.0.0.1:28004/path/", "root@203.0.113.10")).is_ok());
        assert!(validate_panel(&panel(
            "http://other.example:28004/path/",
            "root@203.0.113.10"
        ))
        .is_err());
        assert!(validate_panel(&panel(
            "http://127.0.0.1:28004/path/",
            "-oProxyCommand=evil"
        ))
        .is_err());
        assert!(validate_panel(&panel("http://127.0.0.1/path/", "root@203.0.113.10")).is_err());
    }
    #[test]
    fn only_https_urls_without_credentials_are_accepted() {
        for url in [
            "http://example.com",
            "https://u:p@example.com",
            "https://example.com/?token=secret",
            "not a url",
        ] {
            assert!(
                validate_panel(&Panel {
                    name: "x".into(),
                    url: url.into(),
                    ssh_target: None,
                    panel_host: None
                })
                .is_err(),
                "{url}"
            );
        }
        assert!(validate_panel(&Panel {
            name: "x".into(),
            url: "https://example.com:2053/custom".into(),
            ssh_target: None,
            panel_host: None
        })
        .is_ok());
    }
    #[test]
    fn inbound_request_builds_vless_xhttp_tls_body_with_3x_ui_certificate_paths() {
        let params = InboundParams { remark: "xhttp-443".into(), port: 443, server_name: "203-0-113-8.sslip.io".into(), path: "/a1b2c3".into() };
        let body = build_inbound_request("VLESS-XHTTP-443", &params).unwrap();
        assert_eq!(body["protocol"], "vless");
        assert_eq!(body["port"], 443);
        let settings: serde_json::Value = serde_json::from_str(body["settings"].as_str().unwrap()).unwrap();
        assert_eq!(settings["decryption"], "none");
        let stream: serde_json::Value = serde_json::from_str(body["streamSettings"].as_str().unwrap()).unwrap();
        assert_eq!(stream["network"], "xhttp");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["tlsSettings"]["serverName"], params.server_name);
        assert_eq!(stream["tlsSettings"]["certificates"][0]["certificateFile"], "/root/cert/203-0-113-8.sslip.io/fullchain.pem");
        assert_eq!(stream["tlsSettings"]["certificates"][0]["keyFile"], "/root/cert/203-0-113-8.sslip.io/privkey.pem");
        assert_eq!(stream["xhttpSettings"]["path"], "/a1b2c3");
    }

    #[test]
    fn xhttp_template_matches_reference_and_link_preserves_alpn() {
        let p = InboundParams { remark:"VLESS-XHTTP-443".into(), port:443, server_name:"example.com".into(), path:"/".into() };
        let body=build_inbound_request("VLESS-XHTTP-443", &p).unwrap();
        let settings: serde_json::Value=serde_json::from_str(body["settings"].as_str().unwrap()).unwrap();
        assert_eq!(settings, serde_json::json!({"clients":[],"decryption":"none","encryption":"none","fallbacks":[]}));
        let stream: serde_json::Value=serde_json::from_str(body["streamSettings"].as_str().unwrap()).unwrap();
        assert_eq!(stream, serde_json::json!({"network":"xhttp","security":"tls","tlsSettings":{"serverName":"example.com","minVersion":"1.2","maxVersion":"1.3","alpn":["h2","http/1.1"],"rejectUnknownSni":false,"certificates":[{"certificateFile":"/root/cert/example.com/fullchain.pem","keyFile":"/root/cert/example.com/privkey.pem","oneTimeLoading":false,"usage":"encipherment","buildChain":false}],"settings":{"fingerprint":"","echConfigList":""}},"xhttpSettings":{"path":"/","host":"","headers":{}}}));
        let sniff: serde_json::Value=serde_json::from_str(body["sniffing"].as_str().unwrap()).unwrap();
        assert_eq!(sniff,serde_json::json!({"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":false}));
        let panel=Panel{name:"test".into(),url:"https://example.com".into(),ssh_target:Some("root@example.com".into()),panel_host:None};
        let inbound=serde_json::json!({"enable":true,"protocol":"vless","port":443,"streamSettings":stream});
        let link=build_client_share_link(&panel,"client","00000000-0000-0000-0000-000000000000",&inbound).unwrap();
        let config=crate::profile::vless_xhttp_config(&link,10808).unwrap();
        assert_eq!(config["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"],serde_json::json!(["h2","http/1.1"]));
        assert!(build_inbound_request("unknown",&p).is_err());
        let vision=build_inbound_request("VLESS-VISION-8443",&p).unwrap();
        let stream: serde_json::Value=serde_json::from_str(vision["streamSettings"].as_str().unwrap()).unwrap();
        assert_eq!(stream["network"],"tcp"); assert_eq!(stream["tlsSettings"]["alpn"],serde_json::json!(["h2"]));
    }

    #[test]
    fn inbound_request_rejects_invalid_ports_paths_remarks_and_sni() {
        let params = |remark: &str, port: u32, sni: &str, path: &str| InboundParams { remark: remark.into(), port, server_name: sni.into(), path: path.into() };
        assert!(validate_inbound_params(&params("xhttp", 1, "example.com", "/x")).is_ok());
        assert!(validate_inbound_params(&params("xhttp", 0, "example.com", "/x")).is_err());
        assert!(validate_inbound_params(&params("xhttp", 65536, "example.com", "/x")).is_err());
        assert!(validate_inbound_params(&params(" ", 443, "example.com", "/x")).is_err());
        assert!(validate_inbound_params(&params("xhttp", 443, "example.com", "x")).is_err());
        assert!(validate_inbound_params(&params("xhttp", 443, "bad..domain", "/x")).is_err());
    }
}

pub mod profile;

pub mod xray;

pub mod proxy;

pub mod client_plan;
