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
    match panel.ssh_target.as_deref() {
        None if url.scheme() == "https" && url.host_str().is_some() => {}
        Some(target)
            if url.scheme() == "http"
                && url.host_str() == Some("127.0.0.1")
                && url.port().is_some()
                && valid_ssh_target(target) => {}
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

fn valid_ssh_target(target: &str) -> bool {
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
    let _tunnel = if let Some(target) = panel.ssh_target.as_deref() {
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
    if let Some(target) = panel.ssh_target.as_deref() {
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
}
fn profile_cache_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    Ok(PathBuf::from(home).join("Library/Application Support/VpnClient/client-profiles.json"))
}
fn public_profiles(profiles: &[CachedClientProfile]) -> Result<serde_json::Value, String> {
    let value = profiles.iter().map(|p| serde_json::json!({
        "inbound_id": p.inbound_id, "inbound_name": p.inbound_name, "port": p.port,
        "protocol": p.protocol, "transport": p.transport,
        "inbound_enabled": p.inbound_enabled, "email": p.email, "enabled": p.enabled,
        "has_local_config": p.share_link.is_some()
    })).collect::<Vec<_>>();
    Ok(serde_json::Value::Array(value))
}
pub fn list_client_profiles() -> Result<serde_json::Value, String> {
    let panel = load_panel()?.ok_or("No panel configured")?;
    let path = profile_cache_path()?;
    match std::fs::read(path) {
        Ok(data) => {
            let cache: ProfileCache = serde_json::from_slice(&data).map_err(|_| "Invalid local client profile cache")?;
            if cache.panel_url == panel.url { public_profiles(&cache.profiles) } else { Ok(serde_json::Value::Array(Vec::new())) }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::Value::Array(Vec::new())),
        Err(error) => Err(error.to_string()),
    }
}
pub fn refresh_client_profiles() -> Result<serde_json::Value, String> {
    let panel = load_panel()?.ok_or("No panel configured")?;
    let token = security_framework::passwords::get_generic_password(SERVICE, &panel.url).map_err(|e| format!("Keychain: {e}"))?;
    let token = std::str::from_utf8(&token).map_err(|_| "Invalid token in Keychain")?;
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
                client_share_link_with_token(&panel, token, email, id).ok()
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
    let cache = ProfileCache { panel_url: panel.url.clone(), profiles };
    let path = profile_cache_path()?;
    let parent = path.parent().ok_or("Invalid profile cache path")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&cache).map_err(|e| e.to_string())?).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
    public_profiles(&cache.profiles)
}
pub fn cached_client_share_link(inbound_id: u64, email: &str) -> Result<String, String> {
    let panel = load_panel()?.ok_or("No panel configured")?;
    let data = std::fs::read(profile_cache_path()?).map_err(|_| "No locally saved client profiles. Refresh the list from 3x-ui first.")?;
    let cache: ProfileCache = serde_json::from_slice(&data).map_err(|_| "Invalid local client profile cache")?;
    if cache.panel_url != panel.url { return Err("Local profiles belong to a different panel. Refresh the profile list.".into()); }
    cache.profiles.into_iter().find(|p| p.inbound_id == inbound_id && p.email == email)
        .and_then(|p| p.share_link).ok_or_else(|| "This profile has no locally saved VLESS/TLS/XHTTP configuration. Refresh the list from 3x-ui.".into())
}

pub fn list_inbounds_for(panel: &Panel, token: &str) -> Result<serde_json::Value, String> {
    let value = panel_request(panel, token, "inbounds/list", None)?;
    let list = value
        .get("obj")
        .and_then(|v| v.as_array())
        .ok_or("Panel returned an invalid inbound list")?;
    Ok(serde_json::Value::Array(list.iter().map(|v| serde_json::json!({"id":v.get("id"),"remark":v.get("remark"),"protocol":v.get("protocol"),"port":v.get("port"),"enable":v.get("enable")})).collect()))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PendingClient {
    pub inbound_id: u64,
    pub email: String,
    pub inbound_name: String,
    pub panel_name: String,
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
    if inbound.get("enable").and_then(|v| v.as_bool()) != Some(true) || inbound.get("protocol").and_then(|v| v.as_str()) != Some("vless") { return Err("Selected inbound is not an enabled VLESS service".into()); }
    let settings = inbound.get("streamSettings").cloned().unwrap_or(serde_json::json!({}));
    let settings = if let Some(raw) = settings.as_str() { serde_json::from_str(raw).map_err(|_| "Invalid inbound transport settings")? } else { settings };
    if settings.get("network").and_then(|v| v.as_str()) != Some("xhttp") || settings.get("security").and_then(|v| v.as_str()) != Some("tls") { return Err("Selected inbound is not VLESS/TLS/XHTTP".into()); }
    let tls = settings.get("tlsSettings").ok_or("TLS settings are missing")?;
    let xhttp = settings.get("xhttpSettings").ok_or("XHTTP settings are missing")?;
    let host = inbound.get("shareAddr").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).or(panel.panel_host.as_deref()).or_else(|| panel.ssh_target.as_deref().map(|s| s.rsplit('@').next().unwrap_or(s))).ok_or("Public server address is missing")?;
    if !valid_http_host(host) { return Err("Invalid public server address".into()); }
    let port = inbound.get("port").and_then(|v| v.as_u64()).filter(|p| *p > 0 && *p <= 65535).ok_or("Invalid VLESS port")?;
    let sni = tls.get("serverName").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).ok_or("TLS server name is missing")?;
    let path = xhttp.get("path").and_then(|v| v.as_str()).unwrap_or("/");
    let mut query = vec![("type", "xhttp".to_owned()), ("security", "tls".to_owned()), ("sni", sni.to_owned()), ("path", path.to_owned())];
    if let Some(mode) = xhttp.get("mode").and_then(|v| v.as_str()) { query.push(("mode", mode.to_owned())); }
    if let Some(host) = xhttp.get("host").and_then(|v| v.as_str()).filter(|h| !h.is_empty()) { query.push(("host", host.to_owned())); }
    let query = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(query).finish();
    Ok(format!("vless://{uuid}@{host}:{port}?{query}#{}", url::form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>()))
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
}

pub mod profile;

pub mod xray;

pub mod proxy;

pub mod client_plan;
