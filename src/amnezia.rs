//! AmneziaWG servers with Cloudflare WARP as the exit. Installed and managed over SSH (no panel): the userspace
//! `amneziawg-go` binary shipped with the app is uploaded, `awg-quick` comes from Amnezia's PPA.
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

const BINARY: &[u8] = include_bytes!("../assets/amneziawg-go-linux-amd64");
const BINARY_SHA256: &str = include_str!("../assets/amneziawg-go-linux-amd64.sha256");
const SETUP: &str = include_str!("../scripts/awg/setup.sh");
const ADD_CLIENT: &str = include_str!("../scripts/awg/addclient.sh");
const DEL_CLIENT: &str = include_str!("../scripts/awg/delclient.sh");
const VIEW_CLIENT: &str = include_str!("../scripts/awg/viewclient.sh");
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
/// Single-quotes `s` for the remote POSIX shell.
fn sh_quote(s: &str) -> String { format!("'{}'", s.replace('\'', r"'\''")) }

/// Output of the install run, shown live in the admin window (polled by `install_log`). Capped to the last lines.
static INSTALL_LOG: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
const INSTALL_LOG_LINES: usize = 3000;
fn push_install_log(line: &str) {
    if let Ok(mut log) = INSTALL_LOG.lock() {
        log.push(line.to_owned());
        if log.len() > INSTALL_LOG_LINES { let extra = log.len() - INSTALL_LOG_LINES; log.drain(..extra); }
    }
}
pub fn install_log() -> Vec<String> { INSTALL_LOG.lock().map(|log| log.clone()).unwrap_or_default() }
pub fn clear_install_log() { if let Ok(mut log) = INSTALL_LOG.lock() { log.clear(); } }

/// Calls `f` for every line of `reader`. Splits on `\n` bytes and decodes each line lossily, so bad bytes
/// cannot cut the output short the way `BufRead::lines` would.
fn each_line<R: Read>(reader: R, mut f: impl FnMut(String)) {
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') { buf.pop(); }
                f(String::from_utf8_lossy(&buf).into_owned());
            }
        }
    }
}

fn ssh_run(target: &str, key: Option<&str>, env: &[(&str, &str)], script: &str, args: &[&str], upload: Option<(&[u8], &str)>) -> Result<String, String> {
    ssh_run_with(target, key, env, script, args, upload, &|_| {})
}

/// Like `ssh_run`, but every output line (stdout and stderr, as it arrives) is also passed to `on_line`.
fn ssh_run_with(target: &str, key: Option<&str>, env: &[(&str, &str)], script: &str, args: &[&str], upload: Option<(&[u8], &str)>, on_line: &dyn Fn(&str)) -> Result<String, String> {
    if !crate::valid_ssh_target(target) { return Err("Некорректный SSH-адрес".into()); }
    let (dest, port) = crate::split_ssh_target(target);
    let base = |remote: &str| -> Result<Command, String> {
        let mut ssh = Command::new("/usr/bin/ssh");
        crate::apply_ssh_key(&mut ssh, key)?;
        if let Some(p) = port { ssh.args(["-p", &p.to_string()]); }
        ssh.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=25", "-o", "StrictHostKeyChecking=yes", "--", dest, remote]);
        Ok(ssh)
    };
    if let Some((bytes, remote_path)) = upload {
        let p = sh_quote(remote_path);
        let mut up = base(&format!("cat > {p} && chmod 600 {p}"))?;
        let mut child = up.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
        child.stdin.take().ok_or("нет stdin")?.write_all(bytes).map_err(|e| format!("Загрузка не удалась: {e}"))?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() { return Err(format!("Загрузка не удалась: {}", String::from_utf8_lossy(&out.stderr).trim())); }
    }
    let assigns: String = env.iter().map(|(k, v)| format!("{k}={} ", sh_quote(v))).collect();
    let quoted: Vec<String> = args.iter().map(|a| sh_quote(a)).collect();
    let remote = format!("{assigns}bash -s -- {}", quoted.join(" "));
    let mut child = base(&remote)?.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    let (Some(stdout_pipe), Some(stderr_pipe)) = (child.stdout.take(), child.stderr.take()) else { return Err("нет вывода команды".into()) };
    // Reader threads forward lines as they come; this thread consumes them, so a chatty server cannot block on a full pipe.
    let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
    let tx_err = tx.clone();
    let out_reader = std::thread::spawn(move || each_line(stdout_pipe, |line| { let _ = tx.send((true, line)); }));
    let err_reader = std::thread::spawn(move || each_line(stderr_pipe, |line| { let _ = tx_err.send((false, line)); }));
    let written = child.stdin.take().ok_or("нет stdin")?.write_all(script.as_bytes());
    let (mut stdout, mut stderr) = (String::new(), String::new());
    for (is_stdout, line) in rx {
        on_line(&line);
        let text = if is_stdout { &mut stdout } else { &mut stderr };
        text.push_str(&line); text.push('\n');
    }
    let _ = out_reader.join(); let _ = err_reader.join();
    let status = child.wait().map_err(|e| e.to_string())?;
    written.map_err(|e| e.to_string())?;
    if status.success() { Ok(stdout) } else {
        let code = status.code().unwrap_or(-1);
        let detail = stderr.lines().rev().find(|l| l.trim_start().starts_with("ERROR "))
            .or_else(|| stderr.lines().rev().find(|l| !l.trim().is_empty())).unwrap_or("").trim();
        let hint = match code {
            141 => " Возможен обрыв канала вывода (SIGPIPE); проверьте предыдущие строки журнала.",
            255 => " SSH-соединение прервалось или не установилось; проверьте доступность сервера и журнал.",
            _ => "",
        };
        Err(format!("Команда на сервере завершилась с ошибкой ({code}): {detail}.{hint}"))
    }
}

fn binary_sha256() -> &'static str { BINARY_SHA256.split_whitespace().next().unwrap_or("") }

/// Where the awg/awg-quick tools come from: `github` (built from a pinned tag) or `ppa` (Launchpad packages).
pub fn tools_source(tools: &str) -> Result<&'static str, String> {
    match tools { "github" => Ok("github"), "ppa" => Ok("ppa"), _ => Err("Источник amneziawg-tools: github или ppa".into()) }
}

/// Installs AmneziaWG + WARP on a fresh Ubuntu/Debian server and remembers it. `port`: UDP port (random when `None`).
/// `tools`: `github` or `ppa`, see `tools_source`.
pub fn install(name: &str, ssh_target: &str, ssh_key: Option<&str>, port: Option<u16>, country: Option<String>, tools: &str) -> Result<AwgServer, String> {
    push_install_log(&format!("Устанавливаем на {}…", crate::ssh_host(ssh_target)));
    let result = tools_source(tools).and_then(|tools| install_steps(name, ssh_target, ssh_key, port, country, tools));
    match &result {
        Ok(server) => push_install_log(&format!("Готово: UDP {}.", server.port)),
        Err(e) => push_install_log(&format!("Ошибка: {e}")),
    }
    result
}

fn install_steps(name: &str, ssh_target: &str, ssh_key: Option<&str>, port: Option<u16>, country: Option<String>, tools: &str) -> Result<AwgServer, String> {
    if name.trim().is_empty() || name.len() > 64 { return Err("Имя сервера: 1–64 символа".into()); }
    let port = match port { Some(p) if p >= 1024 => p, Some(_) => return Err("Порт должен быть не меньше 1024".into()), None => { let mut b = [0u8; 2]; crate::compat::random_bytes(&mut b)?; 20000 + (u16::from_be_bytes(b) % 40000) } };
    let uname = ssh_run(ssh_target, ssh_key, &[], "uname -m", &[], None)?;
    if uname.trim() != "x86_64" { return Err(format!("Поддерживается только x86_64 (на сервере {})", uname.trim())); }
    let port_s = port.to_string();
    let out = ssh_run_with(ssh_target, ssh_key, &[("AWG_PORT", &port_s), ("AWG_SHA256", binary_sha256()), ("AWG_TOOLS", tools)], SETUP, &[], Some((BINARY, "/root/amneziawg-go.upload")), &push_install_log)?;
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

/// Saved config of an existing client (only clients created since configs are stored have one).
pub fn client_config(server: &AwgServer, name: &str) -> Result<String, String> {
    if !valid_client_name(name) { return Err("Некорректное имя клиента".into()); }
    ssh_run(&server.ssh_target, server.ssh_key.as_deref(), &[], VIEW_CLIENT, &[name], None).map_err(|e| if e.contains("(5)") { "Конфиг этого клиента не сохранён на сервере (клиент создан старой версией). Удалите клиента и создайте заново.".to_string() } else { e })
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

/// Drops the app's record of the server without touching the machine.
pub fn forget(id: &str) -> Result<(), String> {
    let mut all = list_servers()?; all.retain(|s| s.id != id); save_servers(&all)
}

pub fn uninstall(server: &AwgServer) -> Result<(), String> {
    ssh_run(&server.ssh_target, server.ssh_key.as_deref(), &[], UNINSTALL, &[], None)?;
    let mut all = list_servers()?; all.retain(|s| s.id != server.id); save_servers(&all)
}


fn conf_value<'a>(conf: &'a str, key: &str) -> Option<&'a str> {
    conf.lines().find_map(|l| { let (k, v) = l.split_once('=')?; (k.trim() == key).then(|| v.trim()) })
}

/// `vpn://…` link understood by the Amnezia app: base64url of Qt's `qCompress` (4-byte big-endian length + zlib)
/// of the JSON description of an AmneziaWG container.
pub fn vpn_link(description: &str, conf: &str) -> Result<String, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use flate2::{write::ZlibEncoder, Compression};
    let need = |k: &str| conf_value(conf, k).map(str::to_string).ok_or_else(|| format!("В конфиге нет поля {k}"));
    let (endpoint, address) = (need("Endpoint")?, need("Address")?);
    let (host, port) = endpoint.rsplit_once(':').ok_or("Некорректный Endpoint")?;
    let ip = address.split('/').next().unwrap_or_default();
    let mut details = serde_json::Map::new();
    for k in ["H1", "H2", "H3", "H4", "Jc", "Jmax", "Jmin", "S1", "S2"] { details.insert(k.into(), need(k)?.into()); }
    let dns: Vec<&str> = conf_value(conf, "DNS").unwrap_or("1.1.1.1").split(',').map(str::trim).collect();
    details.insert("client_ip".into(), ip.into());
    details.insert("client_priv_key".into(), need("PrivateKey")?.into());
    details.insert("config".into(), conf.into());
    details.insert("hostName".into(), host.into());
    details.insert("mtu".into(), "1280".into());
    details.insert("persistent_keep_alive".into(), "25".into());
    details.insert("port".into(), port.parse::<u16>().map_err(|_| "Некорректный порт")?.into());
    details.insert("psk_key".into(), need("PresharedKey")?.into());
    details.insert("server_pub_key".into(), need("PublicKey")?.into());
    let mut awg = serde_json::Map::new();
    for k in ["H1", "H2", "H3", "H4", "Jc", "Jmax", "Jmin", "S1", "S2"] { awg.insert(k.into(), need(k)?.into()); }
    awg.insert("last_config".into(), serde_json::Value::Object(details).to_string().into());
    awg.insert("port".into(), port.into());
    awg.insert("transport_proto".into(), "udp".into());
    let doc = serde_json::json!({
        "containers": [{"awg": awg, "container": "amnezia-awg"}],
        "defaultContainer": "amnezia-awg",
        "description": description,
        "dns1": dns.first().copied().unwrap_or("1.1.1.1"),
        "dns2": dns.get(1).copied().unwrap_or("1.0.0.1"),
        "hostName": host,
    });
    let json = serde_json::to_vec(&doc).map_err(|e| e.to_string())?;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    enc.write_all(&json).map_err(|e| e.to_string())?;
    let mut out = (json.len() as u32).to_be_bytes().to_vec();
    out.extend(enc.finish().map_err(|e| e.to_string())?);
    Ok(format!("vpn://{}", URL_SAFE_NO_PAD.encode(out)))
}

/// SVG of a QR code carrying `text` (the plain `.conf`, which AmneziaWG clients scan directly).
pub fn qr_svg(text: &str) -> Result<String, String> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::L).map_err(|e| format!("QR: {e}"))?;
    Ok(code.render::<qrcode::render::svg::Color>().min_dimensions(300, 300).quiet_zone(true).build())
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
    #[test] fn each_line_strips_line_endings_and_survives_invalid_utf8() {
        let mut lines = Vec::new();
        each_line(&b"first\r\nbad \xff byte\nlast"[..], |l| lines.push(l));
        assert_eq!(lines, ["first", "bad \u{fffd} byte", "last"]);
    }
    #[test] fn tools_source_accepts_only_known_values() {
        assert_eq!(tools_source("github"), Ok("github"));
        assert_eq!(tools_source("ppa"), Ok("ppa"));
        assert!(tools_source("apt").is_err());
        assert!(tools_source("").is_err());
    }
    #[test] fn install_log_keeps_recent_lines_only() {
        clear_install_log();
        for i in 0..INSTALL_LOG_LINES + 5 { push_install_log(&i.to_string()); }
        let log = install_log();
        assert_eq!(log.len(), INSTALL_LOG_LINES);
        assert_eq!(log.first().map(String::as_str), Some("5"));
        clear_install_log();
    }
    #[test] fn vpn_link_roundtrips_to_the_container_description() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use std::io::Read;
        let conf = "[Interface]\nPrivateKey = PRIV\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1\nJc = 4\nJmin = 50\nJmax = 1000\nS1 = 94\nS2 = 125\nH1 = 11\nH2 = 22\nH3 = 33\nH4 = 44\n\n[Peer]\nPublicKey = SRVPUB\nPresharedKey = PSK\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.5:47821\nPersistentKeepalive = 25\n";
        let link = vpn_link("test", conf).unwrap();
        let raw = URL_SAFE_NO_PAD.decode(link.strip_prefix("vpn://").unwrap()).unwrap();
        let len = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
        let mut json = String::new(); flate2::read::ZlibDecoder::new(&raw[4..]).read_to_string(&mut json).unwrap();
        assert_eq!(json.len(), len);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["hostName"], "203.0.113.5"); assert_eq!(v["defaultContainer"], "amnezia-awg");
        let awg = &v["containers"][0]["awg"]; assert_eq!(awg["Jc"], "4"); assert_eq!(awg["port"], "47821");
        let last: serde_json::Value = serde_json::from_str(awg["last_config"].as_str().unwrap()).unwrap();
        assert_eq!(last["client_ip"], "10.8.1.2"); assert_eq!(last["server_pub_key"], "SRVPUB"); assert_eq!(last["config"], conf);
        assert!(vpn_link("x", "[Interface]\n").is_err());
    }
    #[test] fn qr_is_an_svg() { assert!(qr_svg("hello").unwrap().contains("<svg")); }
}
