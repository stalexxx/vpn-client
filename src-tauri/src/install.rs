use std::{io::{BufRead, BufReader}, process::{Command, Stdio}, sync::Mutex};

#[derive(Default, Clone, serde::Serialize)]
pub struct Progress {
    running: bool,
    finished: bool,
    success: bool,
    log: Vec<String>,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    /// The panel was bound to 127.0.0.1 after install: it is reachable only through the SSH tunnel.
    local_only: bool,
    /// File name (in ~/.ssh) of the key the server was set up with, to be remembered for its tunnel; `None` = ssh defaults.
    ssh_key: Option<String>,
}
#[derive(Default)]
pub struct InstallState(Mutex<Progress>);

/// Temporary SSH_ASKPASS helper: prints the password from the child's environment, never stores it.
struct Askpass(std::path::PathBuf);
impl Askpass {
    fn create() -> Result<Self, String> {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let dir = std::env::temp_dir().join(format!("vpnclient-askpass-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));
        std::fs::create_dir(&dir).map_err(|_| "Не удалось подготовить вход по паролю")?;
        let _ = std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        let path = dir.join("askpass.sh");
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o700).open(&path).map_err(|_| "Не удалось подготовить вход по паролю")?;
        file.write_all(b"#!/bin/sh\nprintf '%s\\n' \"$VPN_SSH_PASSWORD\"\n").map_err(|_| "Не удалось подготовить вход по паролю")?;
        Ok(Askpass(path))
    }
}
impl Drop for Askpass {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); if let Some(dir) = self.0.parent() { let _ = std::fs::remove_dir(dir); } }
}
fn valid_password(password: &str) -> bool { !password.is_empty() && password.len() <= 256 && !password.chars().any(|c| c == '\0' || c == '\n' || c == '\r') }
/// ssh command for `target`; all authentication modes require a previously verified host key.
/// `key` is the chosen private key name in ~/.ssh; it only applies to key authentication.
fn ssh_command(password: Option<&str>, askpass: Option<&Askpass>, port: Option<u16>, key: Option<&str>) -> Command {
    let mut ssh = Command::new("/usr/bin/ssh");
    ssh.args(["-T", "-o", "ConnectTimeout=10"]);
    if let Some(port) = port { ssh.args(["-p", &port.to_string()]); }
    match (password, askpass) {
        (Some(password), Some(askpass)) => {
            ssh.args(["-o", "BatchMode=no", "-o", "StrictHostKeyChecking=yes", "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=1"])
                .env("SSH_ASKPASS", &askpass.0).env("SSH_ASKPASS_REQUIRE", "force").env("DISPLAY", "vpnclient:0").env("VPN_SSH_PASSWORD", password);
        }
        _ => {
            // The key was validated before the installation started; a failure here would only mean it vanished since.
            let _ = vpn_core::apply_ssh_key(&mut ssh, key);
            ssh.args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]);
        }
    }
    ssh
}
/// Remote script: make 3x-ui listen on 127.0.0.1 only, restart it and confirm the setting.
/// Exit codes: 45 x-ui missing, 46 setting failed, 47 restart failed, 48 not confirmed.
const BIND_LOCAL_SCRIPT: &str = "f=/usr/local/x-ui/x-ui; [ -x \"$f\" ] || exit 45; \"$f\" setting -listenIP 127.0.0.1 >/dev/null 2>&1 || exit 46; (systemctl restart x-ui || rc-service x-ui restart || x-ui restart) >/dev/null 2>&1 || exit 47; sleep 2; \"$f\" setting -getListen true 2>&1 | grep -q 'listenIP: 127.0.0.1' || exit 48";
fn bind_local_message(code: Option<i32>) -> &'static str {
    match code {
        Some(0) => "✓ Панель закрыта от интернета: слушает только 127.0.0.1, приложение управляет ею через SSH-туннель.",
        Some(45) => "Панель осталась открытой: не найден /usr/local/x-ui/x-ui. Закройте её вручную: x-ui setting -listenIP 127.0.0.1.",
        Some(46) => "Панель осталась открытой: не удалось выставить listenIP 127.0.0.1. Закройте её вручную: x-ui setting -listenIP 127.0.0.1.",
        Some(47) => "Адрес прослушивания изменён, но панель не перезапустилась: выполните на сервере systemctl restart x-ui.",
        Some(48) => "Не удалось подтвердить, что панель слушает только 127.0.0.1; проверьте: x-ui setting -getListen true.",
        _ => "Не удалось закрыть панель от интернета (ошибка SSH). Закройте её вручную: x-ui setting -listenIP 127.0.0.1.",
    }
}
/// The same panel URL addressed through the tunnel (`http://127.0.0.1:port/...`); only plain-HTTP panels are tunnelled.
fn tunnel_url(url: &str) -> Option<String> {
    let mut parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "http" { return None; }
    parsed.set_host(Some("127.0.0.1")).ok()?;
    Some(parsed.to_string())
}
/// The key to authorize on the server (file name, public key line): the chosen one, else the app-wide default key,
/// else the first usable default pair.
fn key_to_install(key: Option<&str>) -> Option<(String, String)> {
    if let Some(name) = key { return vpn_core::ssh_public_key_line(name).ok().map(|line| (name.to_owned(), line)); }
    if let Some(name) = vpn_core::default_ssh_key() { if let Ok(line) = vpn_core::ssh_public_key_line(&name) { return Some((name, line)); } }
    let home = std::env::var_os("HOME")?;
    default_key_pair_in(&std::path::PathBuf::from(home).join(".ssh"))
}
/// First default key (app key, ed25519, rsa) that has both halves; a lone `.pub` is skipped because it could not log in later.
fn default_key_pair_in(ssh_dir: &std::path::Path) -> Option<(String, String)> {
    for name in [vpn_core::APP_SSH_KEY, "id_ed25519", "id_rsa"] {
        if !ssh_dir.join(name).is_file() { continue; }
        if let Ok(text) = std::fs::read_to_string(ssh_dir.join(format!("{name}.pub"))) {
            let line = text.lines().next().unwrap_or("").trim().to_owned();
            if (line.starts_with("ssh-ed25519 ") || line.starts_with("ssh-rsa ") || line.starts_with("ecdsa-sha2-")) && line.len() < 2048 && !line.contains(['\'', '"', '\\', '`', '$']) { return Some((name.to_owned(), line)); }
        }
    }
    None
}

fn strip_ansi(s: &str) -> String {
    let mut output = String::new(); let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' { if chars.next() == Some('[') { for c in chars.by_ref() { if ('@'..='~').contains(&c) { break; } } } }
        else if !c.is_control() || c == '\t' { output.push(c); }
    }
    output
}
fn field<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    if key.trim().eq_ignore_ascii_case(label) { Some(value.trim()) } else { None }
}
fn merge_install_result(progress: &mut Progress, contents: &str) {
    let mut port = None;
    let mut base_path = None;
    for line in contents.lines() {
        let Some((key, raw)) = line.split_once('=') else { continue };
        let raw = raw.trim();
        let value = if raw.len() >= 2 && ((raw.starts_with('"') && raw.ends_with('"')) || (raw.starts_with('\'') && raw.ends_with('\''))) {
            &raw[1..raw.len()-1]
        } else { raw };
        if value.is_empty() && key.trim() != "XUI_WEB_BASE_PATH" { continue; }
        match key.trim() {
            "XUI_USERNAME" if progress.username.is_none() => progress.username = Some(value.to_owned()),
            "XUI_PASSWORD" if progress.password.is_none() => progress.password = Some(value.to_owned()),
            "XUI_API_TOKEN" if progress.token.is_none() => progress.token = Some(value.to_owned()),
            "XUI_ACCESS_URL" if progress.url.is_none() => {
                if let Ok(url) = url::Url::parse(value) {
                    if ["http", "https"].contains(&url.scheme()) && url.host_str().is_some() && url.username().is_empty() && url.password().is_none() && url.query().is_none() && url.fragment().is_none() { progress.url = Some(url.to_string()); }
                }
            }
            "XUI_PANEL_PORT" => port = value.parse::<u16>().ok().filter(|p| *p > 0),
            "XUI_WEB_BASE_PATH" => base_path = Some(value.to_owned()),
            _ => {}
        }
    }
    if progress.url.is_none() {
        if let (Some(port), Some(path)) = (port, base_path) {
            let path = path.trim_matches('/');
            if !path.contains(['?', '#', '\r', '\n']) {
                let candidate = if path.is_empty() { format!("http://127.0.0.1:{port}/") } else { format!("http://127.0.0.1:{port}/{path}/") };
                if let Ok(url) = url::Url::parse(&candidate) { progress.url = Some(url.to_string()); }
            }
        }
    }
}
// Preserve the server's output, while keeping credentials out of the visible log.
fn consume(progress: &mut Progress, raw: &str, ssh_password: Option<&str>) {
    let line = strip_ansi(raw);
    let trimmed = line.trim();
    let mut display = line.clone();
    for (label, slot) in [("Username", &mut progress.username), ("Password", &mut progress.password), ("API Token", &mut progress.token)] {
        if let Some(value) = field(trimmed, label) {
            if !value.is_empty() { *slot = Some(value.to_owned()); }
            if label != "Username" && !value.is_empty() { display = display.replace(value, "[скрыто]"); }
        }
    }
    if let Some(value) = field(trimmed, "Access URL") {
        if let Ok(url) = url::Url::parse(value) {
            if ["https", "http"].contains(&url.scheme()) && url.host_str().is_some() && url.username().is_empty() && url.password().is_none() && url.query().is_none() && url.fragment().is_none() { progress.url = Some(url.to_string()); }
        }
    }
    for secret in [ssh_password, progress.password.as_deref(), progress.token.as_deref()].into_iter().flatten().filter(|s| !s.is_empty()) {
        display = display.replace(secret, "[скрыто]");
    }
    progress.log.push(display);
}
fn read_output<R: std::io::Read>(reader: R, state: &InstallState, password: Option<&str>) {
    for line in BufReader::new(reader).split(b'\n') {
        match line { Ok(bytes) => { let text = String::from_utf8_lossy(&bytes); if let Ok(mut p) = state.0.lock() { consume(&mut p, &text, password); } }, Err(_) => break }
    }
}
#[tauri::command]
pub fn install_progress(state: tauri::State<'_, InstallState>) -> Result<Progress, String> {
    state.0.lock().map(|p| p.clone()).map_err(|_| "Состояние установки недоступно".into())
}
#[tauri::command]
pub fn install_panel(app: tauri::AppHandle, target: String, password: Option<String>, install_key: Option<bool>, ssh_key: Option<String>) -> Result<(), String> {
    use tauri::Manager;
    if !target.starts_with("root@") || !vpn_core::valid_ssh_target(&target) { return Err("Укажите SSH-цель в формате root@хост или root@хост:порт".into()); }
    let password = password.filter(|p| !p.is_empty());
    if let Some(p) = &password { if !valid_password(p) { return Err("Пароль не должен быть пустым, длиннее 256 символов или содержать переводы строк".into()); } }
    let ssh_key = ssh_key.filter(|k| !k.is_empty());
    // Fail before anything runs if the chosen key is not a usable pair inside ~/.ssh (the key itself is never read).
    if let Some(name) = ssh_key.as_ref().filter(|n| n.as_str() != vpn_core::SYSTEM_SSH_KEY) { vpn_core::resolve_ssh_key(name)?; }
    let install_key = password.is_some() && install_key.unwrap_or(false);
    {
        let state = app.state::<InstallState>(); let mut p = state.0.lock().map_err(|_| "Состояние установки недоступно")?;
        if p.running { return Err("Установка уже выполняется".into()); }
        *p = Progress { running: true, log: vec!["Подключаемся по SSH и запускаем официальный установщик 3x-ui…".into()], ..Progress::default() };
    }
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<InstallState>();
        let (dest, ssh_port) = vpn_core::split_ssh_target(&target);
        let askpass = match password.as_deref().map(|_| Askpass::create()).transpose() {
            Ok(a) => a,
            Err(e) => { if let Ok(mut p) = state.0.lock() { p.running = false; p.finished = true; p.log.push(e); } return; }
        };
        let child = ssh_command(password.as_deref(), askpass.as_ref(), ssh_port, ssh_key.as_deref()).args(["--", dest,
            "bash -c 'set -o pipefail; curl -fsSL https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh | XUI_NONINTERACTIVE=1 bash' 2>&1"])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
        match child {
            Ok(mut child) => {
                let stderr = child.stderr.take().unwrap();
                std::thread::scope(|scope| { scope.spawn(|| read_output(stderr, &state, password.as_deref())); read_output(child.stdout.take().unwrap(), &state, password.as_deref()); });
                let status = child.wait();
                let needs_result = status.as_ref().is_ok_and(|s| s.success()) && state.0.lock().map(|p| p.username.is_none() || p.password.is_none() || p.token.is_none() || p.url.is_none()).unwrap_or(false);
                if needs_result {
                    let result = ssh_command(password.as_deref(), askpass.as_ref(), ssh_port, ssh_key.as_deref())
                        .args(["--", dest,
                            "if [ -f /etc/x-ui/install-result.env ]; then cat /etc/x-ui/install-result.env; else exit 44; fi"])
                        .stdin(Stdio::null()).stderr(Stdio::null()).output();
                    if let Ok(mut p) = state.0.lock() {
                        match result {
                            Ok(output) if output.status.success() => merge_install_result(&mut p, &String::from_utf8_lossy(&output.stdout)),
                            Ok(output) if output.status.code() == Some(44) => p.log.push("Файл результата установки /etc/x-ui/install-result.env не найден на сервере.".into()),
                            _ => p.log.push("Не удалось прочитать файл результата установки по SSH.".into()),
                        }
                    }
                }
                // The key the panel will later be reached with: the chosen one, or the default pair that was just authorized.
                let mut used_key = ssh_key.clone();
                if install_key && status.as_ref().is_ok_and(|s| s.success()) {
                    let message = match key_to_install(ssh_key.as_deref()) {
                        None => "Подходящий публичный SSH-ключ не найден в ~/.ssh: добавьте ключ на сервер вручную, иначе управление панелью будет недоступно.".to_owned(),
                        Some((key_name, key)) => {
                            let script = "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; IFS= read -r k; grep -qxF \"$k\" ~/.ssh/authorized_keys || printf '%s\\n' \"$k\" >> ~/.ssh/authorized_keys";
                            let spawned = ssh_command(password.as_deref(), askpass.as_ref(), ssh_port, ssh_key.as_deref()).args(["--", dest, script]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
                            match spawned {
                                Ok(mut child) => {
                                    if let Some(mut stdin) = child.stdin.take() { use std::io::Write; let _ = writeln!(stdin, "{key}"); }
                                    if child.wait().is_ok_and(|s| s.success()) { used_key = Some(key_name); if ssh_key.is_some() { "Выбранный публичный SSH-ключ добавлен на сервер." } else { "Ваш публичный SSH-ключ добавлен на сервер." }.to_owned() }
                                    else { "Не удалось добавить SSH-ключ на сервер: управление панелью по SSH-туннелю может не работать.".to_owned() }
                                }
                                Err(_) => "Не удалось запустить системный SSH для добавления ключа.".to_owned(),
                            }
                        }
                    };
                    if let Ok(mut p) = state.0.lock() { p.log.push(message); }
                }
                // Close the panel to the internet, but only if the tunnel will work: it needs key authentication.
                if status.as_ref().is_ok_and(|s| s.success()) {
                    let plain_http = state.0.lock().ok().and_then(|p| p.url.clone()).and_then(|u| tunnel_url(&u)).is_some();
                    if plain_http {
                        let key_works = ssh_command(None, None, ssh_port, ssh_key.as_deref()).args(["--", dest, "true"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
                        if !key_works {
                            if let Ok(mut p) = state.0.lock() { p.log.push("Панель оставлена доступной из интернета: вход по SSH-ключу не настроен, без него приложение не сможет управлять закрытой панелью. Добавьте ключ и закройте панель: x-ui setting -listenIP 127.0.0.1.".into()); }
                        } else {
                            let result = ssh_command(None, None, ssh_port, ssh_key.as_deref()).args(["--", dest, BIND_LOCAL_SCRIPT]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
                            let code = result.as_ref().ok().and_then(|s| s.code());
                            if let Ok(mut p) = state.0.lock() {
                                p.log.push(bind_local_message(code).into());
                                if code == Some(0) { p.local_only = true; if let Some(url) = p.url.as_deref().and_then(tunnel_url) { p.url = Some(url); } }
                            }
                        }
                    }
                }
                if let Ok(mut p) = state.0.lock() { p.running = false; p.finished = true; p.success = status.as_ref().map(|s| s.success()).unwrap_or(false); if p.success { p.ssh_key = used_key; } let message = match status { Ok(s) if s.success() => "Установка завершена.".to_owned(), Ok(s) => format!("Установка завершилась с ошибкой: код {}.", s.code().map(|c| c.to_string()).unwrap_or_else(|| "нет".into())), Err(_) => "Не удалось получить результат установки.".into() }; p.log.push(message); }
            }
            Err(_) => { if let Ok(mut p) = state.0.lock() { p.running = false; p.finished = true; p.log.push("Не удалось запустить системный SSH.".into()); } }
        }
    });
    Ok(())
}
#[tauri::command]
pub async fn check_ssh(target: String, password: Option<String>, ssh_key: Option<String>) -> Result<String, String> {
    if !target.starts_with("root@") || !vpn_core::valid_ssh_target(&target) { return Err("Укажите SSH-цель в формате root@хост или root@хост:порт".into()); }
    let password = password.filter(|p| !p.is_empty());
    if password.as_deref().is_some_and(|p| !valid_password(p)) { return Err("Недопустимый SSH-пароль".into()); }
    let ssh_key = ssh_key.filter(|k| !k.is_empty());
    if let Some(name) = ssh_key.as_ref().filter(|n| n.as_str() != vpn_core::SYSTEM_SSH_KEY) { vpn_core::resolve_ssh_key(name)?; }
    tauri::async_runtime::spawn_blocking(move || {
        let askpass = password.as_deref().map(|_| Askpass::create()).transpose()?;
        let (dest, port) = vpn_core::split_ssh_target(&target);
        let output = ssh_command(password.as_deref(), askpass.as_ref(), port, ssh_key.as_deref()).args(["--", dest, "printf 'VPNCLIENT_SSH_OK\\n'"]).stdin(Stdio::null()).output().map_err(|e| format!("Не удалось запустить SSH: {e}"))?;
        if output.status.success() { return Ok("SSH-подключение успешно: вход на сервер выполнен.".into()); }
        let mut error = strip_ansi(&String::from_utf8_lossy(&output.stderr));
        if let Some(secret) = password.as_deref() { error = error.replace(secret, "[скрыто]"); }
        if error.trim().is_empty() { error = format!("SSH завершился с кодом {}", output.status.code().map(|c| c.to_string()).unwrap_or_else(|| "нет".into())); }
        Err(error.trim().to_owned())
    }).await.map_err(|e| format!("Ошибка проверки SSH: {e}"))?
}
/// Authorize the configured public key using a one-time SSH password, then verify key login.
#[tauri::command]
pub async fn add_ssh_key(target: String, password: String, ssh_key: Option<String>) -> Result<String, String> {
    if !target.starts_with("root@") || !vpn_core::valid_ssh_target(&target) { return Err("Некорректная SSH-цель".into()); }
    if !valid_password(&password) { return Err("Введите SSH-пароль (не более 256 символов, без переносов строки).".into()); }
    let ssh_key = ssh_key.filter(|k| !k.is_empty());
    let (name, public_key) = if ssh_key.as_deref() == Some(vpn_core::SYSTEM_SSH_KEY) {
        let home = std::env::var_os("HOME").ok_or("Домашний каталог не найден")?;
        let dir = std::path::PathBuf::from(home).join(".ssh");
        ["id_ed25519", "id_rsa"].iter().find_map(|name| vpn_core::ssh_public_key_line(name).ok().map(|key| ((*name).to_owned(), key)))
            .ok_or_else(|| format!("Для системного SSH не найдена пара id_ed25519 или id_rsa в {}", dir.display()))?
    } else {
        key_to_install(ssh_key.as_deref()).ok_or("Подходящая пара SSH-ключей не найдена в ~/.ssh. Создайте ключ или выберите существующий в настройках.")?
    };
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Write;
        let askpass = Askpass::create()?;
        let (dest, port) = vpn_core::split_ssh_target(&target);
        let script = "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; IFS= read -r k; grep -qxF \"$k\" ~/.ssh/authorized_keys || printf '%s\\n' \"$k\" >> ~/.ssh/authorized_keys";
        let mut child = ssh_command(Some(&password), Some(&askpass), port, None).args(["--", dest, script]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|e| format!("Не удалось запустить SSH: {e}"))?;
        let write_result = child.stdin.take().ok_or("Не удалось передать публичный ключ")?.write_all(format!("{public_key}\n").as_bytes());
        let output = child.wait_with_output().map_err(|e| format!("Ошибка SSH: {e}"))?;
        if !output.status.success() || write_result.is_err() {
            let error = strip_ansi(&String::from_utf8_lossy(&output.stderr)).replace(&password, "[скрыто]");
            return Err(if error.trim().is_empty() { "Не удалось добавить ключ на сервер.".into() } else { error.trim().to_owned() });
        }
        let verify = ssh_command(None, None, port, ssh_key.as_deref()).args(["--", dest, "true"]).stdin(Stdio::null()).output().map_err(|e| format!("Ключ {name} добавлен, но не удалось проверить вход: {e}"))?;
        if !verify.status.success() { return Err(format!("Ключ {name} добавлен, но вход по настройкам сервера не подтверждён: {}", strip_ansi(&String::from_utf8_lossy(&verify.stderr)).trim())); }
        Ok(format!("Ключ {name} добавлен. Вход по SSH-ключу успешно проверен."))
    }).await.map_err(|e| format!("Ошибка добавления SSH-ключа: {e}"))?
}
#[tauri::command]
pub fn clear_install(state: tauri::State<'_, InstallState>) -> Result<(), String> {
    let mut p = state.0.lock().map_err(|_| "Состояние установки недоступно")?;
    if p.running { return Err("Установка ещё выполняется".into()); }
    *p = Progress::default(); Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_key_pair_skips_a_lone_public_key_and_reports_the_name_that_was_used() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_ed25519_vpn_client.pub"), "ssh-ed25519 AAAA app\n").unwrap(); // no private half
        assert_eq!(default_key_pair_in(dir.path()), None);
        std::fs::write(dir.path().join("id_ed25519"), "PRIVATE").unwrap();
        std::fs::write(dir.path().join("id_ed25519.pub"), "ssh-ed25519 AAAA me\n").unwrap();
        assert_eq!(default_key_pair_in(dir.path()), Some(("id_ed25519".into(), "ssh-ed25519 AAAA me".into())));
        std::fs::write(dir.path().join("id_ed25519_vpn_client"), "PRIVATE").unwrap();
        assert_eq!(default_key_pair_in(dir.path()).unwrap().0, "id_ed25519_vpn_client", "the app key wins once complete");
    }
    #[test]
    fn askpass_prints_password_from_environment_and_cleans_up() {
        use std::os::unix::fs::PermissionsExt;
        let askpass = Askpass::create().unwrap();
        let path = askpass.0.clone();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        let out = Command::new(&path).env("VPN_SSH_PASSWORD", "p@ss $w'rd\"").output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "p@ss $w'rd\"\n");
        assert!(!std::fs::read_to_string(&path).unwrap().contains("p@ss"));
        drop(askpass);
        assert!(!path.exists());
        assert!(valid_password("abc") && !valid_password("") && !valid_password("a\nb"));
    }
    #[test]
    fn preserves_output_and_redacts_known_secrets() {
        let mut p = Progress::default();
        consume(&mut p, "an arbitrary installer message", Some("ssh-secret"));
        consume(&mut p, "Password: panel-secret", Some("ssh-secret"));
        consume(&mut p, "API Token: token-secret", Some("ssh-secret"));
        consume(&mut p, "error: ssh-secret panel-secret token-secret", Some("ssh-secret"));
        consume(&mut p, "Access URL: http://example.com:2053/base/", None);
        assert_eq!(p.log[0], "an arbitrary installer message");
        assert_eq!(p.password.as_deref(), Some("panel-secret"));
        assert_eq!(p.token.as_deref(), Some("token-secret"));
        assert_eq!(p.url.as_deref(), Some("http://example.com:2053/base/"));
        for secret in ["ssh-secret", "panel-secret", "token-secret"] { assert!(!p.log.join(" ").contains(secret)); }
    }
    #[test]
    fn panel_is_bound_to_localhost_with_a_valid_confirmed_script() {
        let status = Command::new("/bin/sh").args(["-n", "-c", BIND_LOCAL_SCRIPT]).status().unwrap();
        assert!(status.success(), "bind script is not valid shell");
        assert!(BIND_LOCAL_SCRIPT.contains("setting -listenIP 127.0.0.1"));
        assert!(BIND_LOCAL_SCRIPT.contains("-getListen") && BIND_LOCAL_SCRIPT.contains("exit 48"));
        assert!(bind_local_message(Some(0)).starts_with('✓'));
        for code in [Some(45), Some(46), Some(47), Some(48), None, Some(255)] { assert!(!bind_local_message(code).starts_with('✓')); }
    }
    #[test]
    fn password_login_never_offers_the_chosen_key_and_key_login_is_batch_only() {
        let askpass = Askpass::create().unwrap();
        let args = |c: &Command| c.get_args().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>();
        let with_password = args(&ssh_command(Some("pw"), Some(&askpass), None, Some("work")));
        assert!(!with_password.iter().any(|a| a == "-i" || a == "IdentitiesOnly=yes"));
        assert!(with_password.iter().any(|a| a == "StrictHostKeyChecking=yes"));
        assert!(!with_password.iter().any(|a| a == "StrictHostKeyChecking=accept-new"));
        assert!(with_password.iter().any(|a| a.starts_with("PreferredAuthentications=password")));
        // An unusable key name adds no identity (it was rejected before the install started) but stays non-interactive.
        let by_key = args(&ssh_command(None, None, Some(2222), Some("../evil")));
        assert!(!by_key.iter().any(|a| a == "-i") && by_key.iter().any(|a| a == "BatchMode=yes") && by_key.windows(2).any(|w| w == ["-p", "2222"]));
    }
    #[test]
    fn only_plain_http_panel_urls_are_rewritten_to_the_tunnel() {
        assert_eq!(tunnel_url("http://203.0.113.5:2053/abc/").as_deref(), Some("http://127.0.0.1:2053/abc/"));
        assert_eq!(tunnel_url("http://127.0.0.1:2053/").as_deref(), Some("http://127.0.0.1:2053/"));
        assert_eq!(tunnel_url("https://panel.example.com:2053/abc/"), None);
        assert_eq!(tunnel_url("not a url"), None);
    }
    #[test]
    fn reads_result_file_without_exposing_secrets_or_overwriting_output() {
        let mut p = Progress { username: Some("existing".into()), ..Progress::default() };
        merge_install_result(&mut p, "XUI_USERNAME='ignored'\nXUI_PASSWORD=\"secretpass\"\nXUI_API_TOKEN='secrettoken'\nXUI_PANEL_PORT='2053'\nXUI_WEB_BASE_PATH=\"panel\"\nOTHER=secretignored\n");
        assert_eq!(p.username.as_deref(), Some("existing"));
        assert_eq!(p.password.as_deref(), Some("secretpass"));
        assert_eq!(p.token.as_deref(), Some("secrettoken"));
        assert_eq!(p.url.as_deref(), Some("http://127.0.0.1:2053/panel/"));
        assert!(!p.log.join(" ").contains("secret"));
        let mut p = Progress::default();
        merge_install_result(&mut p, "XUI_ACCESS_URL='https://example.org:2053/base/'\nXUI_PANEL_PORT=8080\nXUI_WEB_BASE_PATH=other\n");
        assert_eq!(p.url.as_deref(), Some("https://example.org:2053/base/"));
    }
}
