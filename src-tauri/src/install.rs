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
}
#[derive(Default)]
pub struct InstallState(Mutex<Progress>);

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
// Never forward arbitrary installer output: it may contain credentials or tokens.
fn consume(progress: &mut Progress, raw: &str) {
    let line = strip_ansi(raw); let line = line.trim();
    if let Some(v) = field(line, "Username") { if !v.is_empty() { progress.username = Some(v.to_owned()); } return; }
    if let Some(v) = field(line, "Password") { if !v.is_empty() { progress.password = Some(v.to_owned()); } return; }
    if let Some(v) = field(line, "API Token") { if !v.is_empty() { progress.token = Some(v.to_owned()); } return; }
    if let Some(v) = field(line, "Access URL") {
        if let Ok(url) = url::Url::parse(v) {
            if ["https", "http"].contains(&url.scheme()) && url.host_str().is_some() && url.username().is_empty() && url.password().is_none() && url.query().is_none() && url.fragment().is_none() {
                progress.url = Some(url.to_string());
                progress.log.push("Установщик сообщил адрес панели.".into());
            }
        }
        return;
    }
    let lower = line.to_ascii_lowercase();
    let message = if lower.contains("permission denied") { Some("SSH: доступ отклонён; проверьте ключ и права.") }
    else if lower.contains("host key verification failed") { Some("SSH: ключ сервера отсутствует в known_hosts или изменился.") }
    else if lower.contains("connection refused") { Some("SSH: соединение отклонено сервером.") }
    else if lower.contains("could not resolve hostname") { Some("SSH: не удалось определить адрес сервера.") }
    else if lower.contains("connection timed out") { Some("SSH: время соединения истекло.") }
    else if lower.contains("curl: (22)") { Some("Не удалось загрузить установщик: сервер вернул ошибку HTTP.") }
    else if lower.contains("curl: (6)") { Some("Не удалось загрузить установщик: имя сервера загрузки не разрешено.") }
    else if lower.contains("curl: (7)") { Some("Не удалось загрузить установщик: соединение с сервером загрузки не установлено.") }
    else if lower.contains("curl: (60)") { Some("Не удалось загрузить установщик: ошибка проверки TLS-сертификата.") }
    else if lower.contains("unable to locate package") || lower.contains("could not get lock") { Some("Не удалось установить системные пакеты; проверьте менеджер пакетов на сервере.") }
    else if lower.contains("fatal error") || lower.starts_with("error:") { Some("Установщик сообщил об ошибке; подробности скрыты, чтобы не раскрыть секреты.") }
    else if lower.contains("installation complete") || lower.contains("install finished") { Some("Установщик сообщил о завершении установки.") }
    else if lower.contains("downloading") { Some("Загрузка компонентов…") }
    else if lower.contains("installing") { Some("Установка компонентов…") }
    else if lower.contains("the os release is:") { Some("Определена операционная система сервера.") }
    else { None };
    if let Some(m) = message { if progress.log.last().map(String::as_str) != Some(m) { progress.log.push(m.into()); } }
    if progress.log.len() > 200 { progress.log.remove(0); }
}
fn read_output<R: std::io::Read>(reader: R, state: &InstallState) {
    for line in BufReader::new(reader).split(b'\n') {
        match line { Ok(bytes) => { let text = String::from_utf8_lossy(&bytes); if let Ok(mut p) = state.0.lock() { consume(&mut p, &text); } }, Err(_) => break }
    }
}
#[tauri::command]
pub fn install_progress(state: tauri::State<'_, InstallState>) -> Result<Progress, String> {
    state.0.lock().map(|p| p.clone()).map_err(|_| "Состояние установки недоступно".into())
}
#[tauri::command]
pub async fn install_panel(app: tauri::AppHandle, target: String) -> Result<(), String> {
    use tauri::Manager;
    if !target.starts_with("root@") || !vpn_core::valid_ssh_target(&target) { return Err("Укажите SSH-цель в формате root@хост".into()); }
    {
        let state = app.state::<InstallState>(); let mut p = state.0.lock().map_err(|_| "Состояние установки недоступно")?;
        if p.running { return Err("Установка уже выполняется".into()); }
        *p = Progress { running: true, log: vec!["Подключаемся по SSH и запускаем официальный установщик 3x-ui…".into()], ..Progress::default() };
    }
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<InstallState>();
        let child = Command::new("/usr/bin/ssh").args(["-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "--", &target,
            "bash -c 'set -o pipefail; curl -fsSL https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh | XUI_NONINTERACTIVE=1 bash' 2>&1"])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
        match child {
            Ok(mut child) => {
                let stderr = child.stderr.take().unwrap();
                std::thread::scope(|scope| { scope.spawn(|| read_output(stderr, &state)); read_output(child.stdout.take().unwrap(), &state); });
                let status = child.wait();
                let needs_result = status.as_ref().is_ok_and(|s| s.success()) && state.0.lock().map(|p| p.username.is_none() || p.password.is_none() || p.token.is_none() || p.url.is_none()).unwrap_or(false);
                if needs_result {
                    let result = Command::new("/usr/bin/ssh")
                        .args(["-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "--", &target,
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
                if let Ok(mut p) = state.0.lock() { p.running = false; p.finished = true; p.success = status.as_ref().map(|s| s.success()).unwrap_or(false); let message = match status { Ok(s) if s.success() => "Установка завершена.".to_owned(), Ok(s) => format!("Установка завершилась с ошибкой: код {}.", s.code().map(|c| c.to_string()).unwrap_or_else(|| "нет".into())), Err(_) => "Не удалось получить результат установки.".into() }; p.log.push(message); }
            }
            Err(_) => { if let Ok(mut p) = state.0.lock() { p.running = false; p.finished = true; p.log.push("Не удалось запустить системный SSH.".into()); } }
        }
    }).await.map_err(|_| "Не удалось выполнить установку".to_owned())?;
    Ok(())
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
    fn reports_known_errors_without_forwarding_secrets() {
        let mut p = Progress::default();
        consume(&mut p, "curl: (22) HTTP error secretpassword");
        assert_eq!(p.log, ["Не удалось загрузить установщик: сервер вернул ошибку HTTP."]);
        assert!(!p.log.join(" ").contains("secretpassword"));
    }
    #[test]
    fn credentials_and_unknown_lines_never_enter_log() {
        let mut p = Progress::default();
        consume(&mut p, "\x1b[32mUsername: secretuser\x1b[0m");
        consume(&mut p, "Password: secretpass"); consume(&mut p, "API Token: secrettoken");
        consume(&mut p, "Error: secretuser secretpass secrettoken");
        consume(&mut p, "Access URL: http://example.com:2053/base/");
        assert_eq!(p.username.as_deref(), Some("secretuser"));
        assert_eq!(p.password.as_deref(), Some("secretpass"));
        assert_eq!(p.token.as_deref(), Some("secrettoken"));
        assert_eq!(p.url.as_deref(), Some("http://example.com:2053/base/"));
        let log = p.log.join(" "); for secret in ["secretuser", "secretpass", "secrettoken"] { assert!(!log.contains(secret)); }
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
