//! AmneziaWG servers with Cloudflare WARP as the exit. Installed and managed over SSH (no panel): the userspace
//! `amneziawg-go` binary shipped with the app is uploaded, `awg-quick` comes from Amnezia's PPA.
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::{Command, Stdio};

const BINARY: &[u8] = include_bytes!("../assets/amneziawg-go-linux-amd64");
const BINARY_SHA256: &str = include_str!("../assets/amneziawg-go-linux-amd64.sha256");
const SETUP: &str = include_str!("../scripts/awg/setup.sh");
const ADD_CLIENT: &str = include_str!("../scripts/awg/addclient.sh");
const DEL_CLIENT: &str = include_str!("../scripts/awg/delclient.sh");
const LIST_CLIENTS: &str = include_str!("../scripts/awg/listclients.sh");
const UNINSTALL: &str = include_str!("../scripts/awg/uninstall.sh");

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AwgServer {
    pub id: String,
    pub name: String,
    pub ssh_target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<String>,
    pub port: u16,
    pub server_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct AwgClient { pub name: String, pub address: String }

fn store_path() -> Result<std::path::PathBuf, String> { Ok(crate::compat::data_dir()?.join("awg-servers.json")) }

pub fn list_servers() -> Result<Vec<AwgServer>, String> {
    match std::fs::read(store_path()?) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("awg-servers.json: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.to_string()),
    }
}

fn save_servers(servers: &[AwgServer]) -> Result<(), String> {
    let path = store_path()?;
    if let Some(dir) = path.parent() { std::fs::create_dir_all(dir).map_err(|e| e.to_string())?; }
    let json = serde_json::to_vec_pretty(servers).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())?;
    crate::compat::restrict_path(&path).map_err(|e| e.to_string())
}

pub fn valid_client_name(name: &str) -> bool { !name.is_empty() && name.len() <= 32 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') }

/// Server to act on, by id or by host (the SSH target's host part).
pub fn find_server(id_or_host: &str) -> Result<AwgServer, String> {
    let all = list_servers()?;
    let hits: Vec<_> = all.into_iter().filter(|s| s.id == id_or_host || crate::ssh_host(&s.ssh_target) == id_or_host).collect();
    match hits.len() { 1 => Ok(hits.into_iter().next().unwrap()), 0 => Err("AmneziaWG-сервер не найден".into()), _ => Err("Найдено несколько серверов для этого хоста".into()) }
}

/// Runs `script` as `bash -s` over SSH with `env` assignments, optionally uploading a file first.
fn ssh_run(target: &str, key: Option<&str>, env: &[(&str, &str)], script: &str, args: &[&str], upload: Option<(&[u8], &str)>) -> Result<String, String> {
    if !crate::valid_ssh_target(target) { return Err("Некорректный SSH-адрес".into()); }
    let (dest, port) = crate::split_ssh_target(target);
    let base = |remote: &str| -> Result<Command, String> {
        let mut ssh = Command::new("/usr/bin/ssh");
        crate::apply_ssh_key(&mut ssh, key)?;
        if let Some(p) = port { ssh.args(["-p", &p.to_string()]); }
        ssh.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=25", "-o", "StrictHostKeyChecking=accept-new", "--", dest, remote]);
        Ok(ssh)
    };
    if let Some((bytes, remote_path)) = upload {
        let mut up = base(&format!("cat > {remote_path} && chmod 600 {remote_path}"))?;
        let mut child = up.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
        child.stdin.take().ok_or("нет stdin")?.write_all(bytes).map_err(|e| format!("Загрузка не удалась: {e}"))?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(format!("Загрузка не удалась: {}", String::from_utf8_lossy(&out.stderr).trim())); }
    }
    let assigns: String = env.iter().map(|(k, v)| format!("{k}={v} ")).collect();
    let remote = format!("{assigns}bash -s -- {}", args.join(" "));
    let mut child = base(&remote)?.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    child.stdin.take().ok_or("нет stdin")?.write_all(script.as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() { Ok(stdout) } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!("Команда на сервере завершилась с ошибкой ({}): {}", out.status.code().unwrap_or(-1), err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim()))
    }
}

fn binary_sha256() -> &'static str { BINARY_SHA256.split_whitespace().next().unwrap_or("") }

/// Installs AmneziaWG + WARP on a fresh Ubuntu/Debian server and remembers it. `port`: UDP port (random when `None`).
pub fn install(name: &str, ssh_target: &str, ssh_key: Option<&str>, port: Option<u16>, country: Option<String>) -> Result<AwgServer, String> {
    if name.trim().is_empty() || name.len() > 64 { return Err("Имя сервера: 1–64 символа".into()); }
    let port = match port { Some(p) if p >= 1024 => p, Some(_) => return Err("Порт должен быть не меньше 1024".into()), None => { let mut b = [0u8; 2]; crate::compat::random_bytes(&mut b)?; 20000 + (u16::from_be_bytes(b) % 40000) } };
    let uname = ssh_run(ssh_target, ssh_key, &[], "uname -m", &[], None)?;
    if uname.trim() != "x86_64" { return Err(format!("Поддерживается только x86_64 (на сервере {})", uname.trim())); }
    let port_s = port.to_string();
    let out = ssh_run(ssh_target, ssh_key, &[("AWG_PORT", &port_s), ("AWG_SHA256", binary_sha256())], SETUP, &[], Some((BINARY, "/root/amneziawg-go.upload")))?;
    let public = out.lines().find_map(|l| l.split("SERVER_PUB=").nth(1)).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).ok_or("Установка завершилась без публичного ключа сервера")?;
    let mut id = [0u8; 16]; crate::compat::random_bytes(&mut id)?;
    let server = AwgServer { id: id.iter().map(|b| format!("{b:02x}")).collect(), name: name.trim().to_string(), ssh_target: ssh_target.to_string(), ssh_key: ssh_key.map(str::to_string), port, server_public_key: public, country };
    let mut all = list_servers()?; all.retain(|s| s.ssh_target != server.ssh_target); all.push(server.clone());
    save_servers(&all)?;
    Ok(server)
}

pub fn add_client(server: &AwgServer, name: &str) -> Result<String, String> {
    if !valid_client_name(name) { return Err("Имя клиента: латиница, цифры, - и _ (до 32 символов)".into()); }
    if list_clients(server)?.iter().any(|c| c.name == name) { return Err("Клиент с таким именем уже есть".into()); }
    ssh_run(&server.ssh_target, server.ssh_key.as_deref(), &[], ADD_CLIENT, &[name], None)
}

pub fn list_clients(server: &AwgServer) -> Result<Vec<AwgClient>, String> {
    let out = ssh_run(&server.ssh_target, server.ssh_key.as_deref(), &[], LIST_CLIENTS, &[], None)?;
    Ok(parse_clients(&out))
}

pub fn parse_clients(out: &str) -> Vec<AwgClient> {
    out.lines().filter_map(|l| { let mut p = l.split_whitespace(); Some(AwgClient { name: p.next()?.to_string(), address: p.next()?.trim_end_matches("/32").to_string() }) }).collect()
}

pub fn delete_client(server: &AwgServer, name: &str) -> Result<(), String> {
    if !valid_client_name(name) { return Err("Некорректное имя клиента".into()); }
    ssh_run(&server.ssh_target, server.ssh_key.as_deref(), &[], DEL_CLIENT, &[name], None).map(|_| ())
}

/// WireGuard handshake/transfer of the WARP side and of the client side.
pub fn status(server: &AwgServer) -> Result<String, String> {
    ssh_run(&server.ssh_target, server.ssh_key.as_deref(), &[], "export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go; systemctl is-active awg-quick@awg0 awg-quick@warp0; echo ---; awg show warp0 | grep -E 'handshake|transfer'; echo ---; awg show awg0 | grep -E 'peer|handshake|transfer'", &[], None)
}

pub fn uninstall(server: &AwgServer) -> Result<(), String> {
    ssh_run(&server.ssh_target, server.ssh_key.as_deref(), &[], UNINSTALL, &[], None)?;
    let mut all = list_servers()?; all.retain(|s| s.id != server.id); save_servers(&all)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn client_names_are_restricted() { assert!(valid_client_name("mac-1_a")); assert!(!valid_client_name("")); assert!(!valid_client_name("a b")); assert!(!valid_client_name("a;rm")); assert!(!valid_client_name(&"x".repeat(33))); }
    #[test] fn parses_client_listing() { assert_eq!(parse_clients("mac 10.8.1.2/32\nphone 10.8.1.3/32\n"), vec![AwgClient{name:"mac".into(),address:"10.8.1.2".into()}, AwgClient{name:"phone".into(),address:"10.8.1.3".into()}]); assert!(parse_clients("").is_empty()); }
    #[test] fn embedded_binary_matches_its_checksum() {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(BINARY); let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, binary_sha256());
    }
    #[test] fn scripts_are_embedded() { assert!(SETUP.contains("awg0")); assert!(ADD_CLIENT.contains("# client")); assert!(DEL_CLIENT.contains("remove")); }
}
