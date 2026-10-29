use serde::{Deserialize, Serialize};
use std::{fs, os::unix::fs::OpenOptionsExt, path::PathBuf, time::Duration};

const SERVICE: &str = "local.vpn-client.3x-ui";

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

pub fn valid_ssh_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 255 || target.starts_with('-') {
        return false;
    }
    let parts: Vec<_> = target.split('@').collect();
    parts.len() <= 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        })
}

fn wizard_keychain_account(id: &str) -> Result<String, String> {
    if !valid_server_id(id) { return Err("Некорректный идентификатор мастера".into()); }
    Ok(format!("wizard-{id}"))
}

pub fn new_wizard_id() -> Result<String, String> { new_server_id() }

pub fn stage_wizard_token(id: &str, token: &str) -> Result<(), String> {
    if token.trim().is_empty() { return Err("Укажите API-токен панели".into()); }
    let account = wizard_keychain_account(id)?;
    security_framework::passwords::set_generic_password(SERVICE, &account, token.as_bytes())
        .map_err(|e| format!("Keychain: {e}"))
}

fn staged_wizard_token(id: &str) -> Result<String, String> {
    let account = wizard_keychain_account(id)?;
    let token = security_framework::passwords::get_generic_password(SERVICE, &account)
        .map_err(|_| "Токен мастера отсутствует в Keychain. Вернитесь к шагу 1.".to_owned())?;
    String::from_utf8(token).map_err(|_| "Некорректный токен в Keychain".into())
}

pub fn clear_wizard_token(id: &str) -> Result<(), String> {
    let account = wizard_keychain_account(id)?;
    match security_framework::passwords::delete_generic_password(SERVICE, &account) {
        Ok(()) => Ok(()),
        Err(_) => Ok(()),
    }
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
    let child = Command::new("/usr/bin/ssh")
        .args([
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
            target,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("SSH tunnel failed: {e}"))?;
    let mut tunnel = Tunnel(child);
    for _ in 0..100 {
        if tunnel.0.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Err("SSH tunnel failed; check SSH key, host key and server access".into());
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
    security_framework::passwords::set_generic_password(SERVICE, &panel.url, token.as_bytes())
        .map_err(|e| format!("Keychain: {e}"))?;
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
        let token = security_framework::passwords::get_generic_password(SERVICE, url).map_err(|e| format!("Keychain: {e}"))?;
        security_framework::passwords::set_generic_password(SERVICE, id, &token).map_err(|e| format!("Keychain: {e}"))
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
    if !token.trim().is_empty() { security_framework::passwords::set_generic_password(SERVICE, &id, token.as_bytes()).map_err(|e| format!("Keychain: {e}"))?; }
    let server = Server { id, panel, country };
    if let Some(index) = existing { servers[index] = server.clone(); } else { servers.push(server.clone()); }
    write_servers(&servers_path()?, &servers)?;
    Ok(server)
}
pub fn delete_server(id: &str) -> Result<(), String> {
    let mut servers = list_servers()?;
    let server = servers.iter().find(|s| s.id == id).ok_or("Сервер не найден")?;
    clear_pending_for_server(&pending_path()?, &config_path()?, server)?;
    security_framework::passwords::delete_generic_password(SERVICE, id).map_err(|e| format!("Keychain: {e}"))?;
    match fs::remove_file(profile_cache_path(id)?) { Ok(()) => (), Err(e) if e.kind() == std::io::ErrorKind::NotFound => (), Err(e) => return Err(e.to_string()) }
    let _guard = PIN_LOCK.lock().map_err(|_| "Не удалось заблокировать список избранного")?;
    remove_server_pins(&pins_path()?, id)?;
    servers.retain(|s| s.id != id);
    write_servers(&servers_path()?, &servers)
}
fn server_for(id: &str) -> Result<Server, String> { list_servers()?.into_iter().find(|s| s.id == id).ok_or_else(|| "Сервер не найден".into()) }
fn server_token(id: &str) -> Result<String, String> {
    let token = security_framework::passwords::get_generic_password(SERVICE, id).map_err(|e| format!("Keychain: {e}"))?;
    String::from_utf8(token).map_err(|_| "Некорректный токен в Keychain".into())
}
pub fn server_inbounds(id: &str) -> Result<serde_json::Value, String> { let s = server_for(id)?; list_inbounds_for(&s.panel, &server_token(id)?) }

pub fn list_inbounds() -> Result<serde_json::Value, String> {
    let panel = load_panel()?.ok_or("No panel configured")?;
    let token = security_framework::passwords::get_generic_password(SERVICE, &panel.url)
        .map_err(|e| format!("Keychain: {e}"))?;
    let token = std::str::from_utf8(&token).map_err(|_| "Invalid token in Keychain")?;
    list_inbounds_for(&panel, token)
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
            .unwrap_or_else(|| target.rsplit('@').next().unwrap_or(target));
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
        return Err("Panel did not report success".into());
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
        "has_local_config": p.share_link.as_ref().is_some_and(|link| crate::profile::vless_xhttp_config(link, 10808).is_ok())
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
            if profile["enabled"] != true || profile["inbound_enabled"] != true || profile["protocol"] != "vless" || profile["transport"] != "xhttp" || profile["has_local_config"] != true { continue; }
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
    if pinned && !all.contains(&key) { return Err("У клиента нет доступной локальной конфигурации VLESS/TLS/XHTTP".into()); }
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
            let share_link = if protocol == "vless" && transport == "xhttp" && security == "tls" && inbound_enabled && enabled {
                client_share_link_with_token(&panel, token, email, id).ok().filter(|link| crate::profile::vless_xhttp_config(link, 10808).is_ok())
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
        .and_then(|p| p.share_link).filter(|link| crate::profile::vless_xhttp_config(link, 10808).is_ok()).ok_or_else(|| "У клиента нет локальной конфигурации VLESS/TLS/XHTTP. Обновите список клиентов.".into())
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
    let output = std::process::Command::new("/usr/bin/ssh")
        .args(["-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "--", target, &command])
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
    security_framework::passwords::set_generic_password(SERVICE, id, token.as_bytes()).map_err(|e| format!("Keychain: {e}"))?;
    let server = Server { id: id.to_owned(), country, panel };
    servers.push(server.clone());
    if let Err(error) = write_servers(&servers_path()?, &servers) {
        let _ = security_framework::passwords::delete_generic_password(SERVICE, id);
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
    let token = security_framework::passwords::get_generic_password(SERVICE, &panel.url).map_err(|e| format!("Keychain: {e}"))?;
    let token = std::str::from_utf8(&token).map_err(|_| "Invalid token in Keychain")?;
    client_share_link_with_token(&panel, token, email, inbound_id)
}
fn client_share_link_with_token(panel: &Panel, token: &str, email: &str, inbound_id: u64) -> Result<String, String> {
    if inbound_id == 0 || email.is_empty() || email.len() > 128 || !email.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c)) { return Err("Invalid client selection".into()); }
    let encoded_email: String = url::form_urlencoded::byte_serialize(email.as_bytes()).collect();
    let client = panel_request(panel, token, &format!("clients/get/{encoded_email}"), None)?;
    let client = client.get("obj").and_then(|v| v.get("client")).ok_or("Client not found")?;
    let uuid = client.get("uuid").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).ok_or("Client has no VLESS UUID")?;
    let attached = panel_request(panel, token, &format!("inbounds/get/{inbound_id}"), None)?;
    let inbound = attached.get("obj").ok_or("Inbound not found")?;
    build_client_share_link(panel, email, uuid, inbound)
}
fn build_client_share_link(panel: &Panel, email: &str, uuid: &str, inbound: &serde_json::Value) -> Result<String, String> {
    if inbound.get("enable").and_then(|v| v.as_bool()) != Some(true) || inbound.get("protocol").and_then(|v| v.as_str()) != Some("vless") { return Err("Selected inbound is not an enabled VLESS service".into()); }
    let settings = inbound.get("streamSettings").cloned().unwrap_or(serde_json::json!({}));
    let settings = if let Some(raw) = settings.as_str() { serde_json::from_str(raw).map_err(|_| "Invalid inbound transport settings")? } else { settings };
    let network = settings.get("network").and_then(|v| v.as_str()).unwrap_or("");
    if !["xhttp", "tcp"].contains(&network) || settings.get("security").and_then(|v| v.as_str()) != Some("tls") { return Err("Selected inbound is not VLESS/TLS/XHTTP or TCP".into()); }
    let tls = settings.get("tlsSettings").ok_or("TLS settings are missing")?;
    let empty = serde_json::json!({});
    let xhttp = settings.get("xhttpSettings").unwrap_or(&empty);
    let host = inbound.get("shareAddr").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).or(panel.panel_host.as_deref()).or_else(|| panel.ssh_target.as_deref().map(|s| s.rsplit('@').next().unwrap_or(s))).ok_or("Public server address is missing")?;
    if !valid_http_host(host) { return Err("Invalid public server address".into()); }
    let port = inbound.get("port").and_then(|v| v.as_u64()).filter(|p| *p > 0 && *p <= 65535).ok_or("Invalid VLESS port")?;
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
    let token = security_framework::passwords::get_generic_password(SERVICE, &panel.url)
        .map_err(|e| format!("Keychain: {e}"))?;
    let token = std::str::from_utf8(&token).map_err(|_| "Invalid token in Keychain")?;
    let inbounds = list_inbounds_for(&panel, token)?;
    crate::client_plan::prepare(&inbounds, inbound_id, email)?;
    let body = serde_json::json!({"client":{"email":email,"enable":true,"totalGB":0,"expiryTime":0,"limitIp":0},"inboundIds":[inbound_id]});
    let _result = panel_request(&panel, token, "clients/add", Some(body))?;
    cancel_pending_client()?;
    Ok(format!(
        "Client {email} created. Client secrets were not returned."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
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
