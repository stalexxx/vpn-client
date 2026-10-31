use serde_json::{json, Value};
use std::{io::{self, BufRead, BufReader, Read, Write}, os::unix::net::UnixStream, process::Command, time::Duration};

fn control(action: &str) -> Result<String, String> {
    let path = vpn_core::mcp_control_socket_path()?;
    control_at(&path, action)
}
fn control_at(path: &std::path::Path, action: &str) -> Result<String, String> {
    control_request_at(path, &json!({"action":action}))
}
fn control_request_at(path: &std::path::Path, request: &Value) -> Result<String, String> {
    let mut stream = UnixStream::connect(path).map_err(|_| "Приложение VPN недоступно. Запустите его и выберите конфигурацию.".to_owned())?;
    stream.set_read_timeout(Some(Duration::from_secs(120))).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    writeln!(stream, "{request}").map_err(|_| "Не удалось отправить команду приложению".to_owned())?;
    let mut line = String::new();
    BufReader::new(stream).take(16 * 1024).read_line(&mut line).map_err(|_| "Не удалось получить ответ приложения".to_owned())?;
    let response: Value = serde_json::from_str(&line).map_err(|_| "Некорректный ответ приложения".to_owned())?;
    let message = response.get("message").and_then(Value::as_str).unwrap_or("Нет ответа от приложения").to_owned();
    if response.get("ok").and_then(Value::as_bool) == Some(true) { Ok(message) } else { Err(message) }
}

fn valid_install_target(host: &str, username: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && !host.starts_with('-')
        && host.chars().all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
        && vpn_core::valid_ssh_target(&format!("{username}@{host}"))
}

fn ssh_panel(host: &str, username: &str, command: &str) -> Result<std::process::Output, String> {
    if !valid_install_target(host, username) {
        return Err("Укажите корректный хост и SSH-пользователя".into());
    }
    let key = std::path::Path::new(&std::env::var_os("HOME").ok_or("Домашний каталог SSH не найден")?)
        .join(".ssh/id_ed25519_vpn_client");
    if !key.is_file() { return Err("SSH-ключ ~/.ssh/id_ed25519_vpn_client не найден".into()); }
    let target = format!("{username}@{host}");
    // Capture all installer output. The official script may print credentials and API tokens.
    Command::new("/usr/bin/ssh")
        .args(["-T", "-i"]).arg(key)
        .args(["-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "--"])
        .arg(target)
        .arg(command)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|_| "Не удалось запустить системный SSH".to_owned())
}

fn ssh_result(result: &std::process::Output) -> Result<(), String> {
    if result.status.success() { Ok(()) } else {
        let stderr = String::from_utf8_lossy(&result.stderr).to_ascii_lowercase();
        let reason = if stderr.contains("permission denied") { "SSH отклонил доступ; проверьте пользователя и ключ." }
            else if stderr.contains("host key verification failed") { "Ключ сервера не подтверждён в known_hosts." }
            else if stderr.contains("connection timed out") { "Время SSH-соединения истекло." }
            else if stderr.contains("could not resolve hostname") { "Не удалось определить адрес сервера." }
            else { "Установка завершилась с ошибкой; подробный вывод скрыт." };
        Err(reason.into())
    }
}

fn parse_install_result(data: &str) -> Result<(String, String), String> {
    let mut access = None; let mut token = None; let mut port = None; let mut path = None;
    for line in data.lines() {
        let Some((key, raw)) = line.split_once('=') else { continue };
        let raw = raw.trim();
        let value = if raw.len() >= 2 && ((raw.starts_with('"') && raw.ends_with('"')) || (raw.starts_with('\'') && raw.ends_with('\''))) { &raw[1..raw.len()-1] } else { raw };
        match key.trim() {
            "XUI_ACCESS_URL" if !value.is_empty() => access = Some(value.to_owned()),
            "XUI_API_TOKEN" if !value.is_empty() => token = Some(value.to_owned()),
            "XUI_PANEL_PORT" => port = value.parse::<u16>().ok().filter(|p| *p != 0),
            "XUI_WEB_BASE_PATH" => path = Some(value.to_owned()),
            _ => (),
        }
    }
    let token = token.ok_or("Панель установлена, но в результате установки нет API-токена; сервер не добавлен в приложение")?;
    let raw_url = match access { Some(url) => url, None => {
        let port = port.ok_or("Панель установлена, но её порт не найден; сервер не добавлен в приложение")?;
        let path = path.ok_or("Панель установлена, но её путь не найден; сервер не добавлен в приложение")?;
        format!("http://127.0.0.1:{port}/{}/", path.trim_matches('/'))
    }};
    let mut url = url::Url::parse(&raw_url).map_err(|_| "Установщик вернул некорректный адрес панели")?;
    if url.scheme() == "http" { url.set_host(Some("127.0.0.1")).map_err(|_| "Некорректный адрес панели")?; }
    Ok((url.to_string(), token))
}

fn install_3x_ui(host: &str, username: &str) -> Result<String, String> {
    let result = ssh_panel(host, username, "bash -c 'set -o pipefail; curl -fsSL https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh | XUI_NONINTERACTIVE=1 bash'")?;
    ssh_result(&result)?;
    let result = ssh_panel(host, username, "cat /etc/x-ui/install-result.env")?;
    if !result.status.success() { return Err("Панель установлена, но не удалось прочитать результат установки; сервер не добавлен в приложение".into()); }
    let (url, token) = parse_install_result(&String::from_utf8_lossy(&result.stdout))?;
    let target = format!("{username}@{host}");
    let matches: Vec<_> = vpn_core::list_servers()?.into_iter().filter(|s| s.panel.ssh_target.as_deref() == Some(target.as_str())).collect();
    if matches.len() > 1 { return Err("Панель установлена, но найдено несколько записей с этой SSH-целью".into()); }
    let previous = matches.first();
    let panel = vpn_core::Panel { name: previous.map(|s| s.panel.name.clone()).unwrap_or_else(|| host.to_owned()), url, ssh_target: Some(target), panel_host: Some(host.to_owned()) };
    let server = vpn_core::save_server(previous.map(|s| s.id.clone()), panel, &token, previous.and_then(|s| s.country.clone()))
        .map_err(|e| format!("Панель установлена, но не добавлена в приложение: {e}"))?;
    match vpn_core::server_inbounds(&server.id) {
        Ok(_) => Ok("3x-ui установлена и добавлена в администрирование; API панели доступен.".into()),
        Err(e) => {
            let reason = if e.contains("HTTP 401") || e.contains("HTTP 403") { "токен отклонён" } else if e.contains("SSH tunnel") { "не удалось открыть SSH-туннель" } else { "ошибка запроса к панели" };
            Err(format!("Панель добавлена в администрирование, но её API недоступен: {reason}."))
        }
    }
}

fn uninstall_3x_ui(host: &str, username: &str) -> Result<String, String> {
    // The upstream uninstaller can purge PostgreSQL. Refuse that configuration.
    let command = "for f in /etc/default/x-ui /etc/conf.d/x-ui /etc/sysconfig/x-ui; do if grep -qs '^XUI_DB_TYPE=postgres' \"$f\"; then exit 43; fi; done; printf 'y\\n' | /usr/bin/x-ui uninstall >/dev/null 2>&1; if systemctl is-active --quiet x-ui || test -e /usr/local/x-ui/x-ui; then exit 44; fi";
    let result = ssh_panel(host, username, command)?;
    if result.status.code() == Some(43) { return Err("Удаление остановлено: панель использует PostgreSQL, который штатный скрипт может удалить".into()); }
    ssh_result(&result)?;
    let target = format!("{username}@{host}");
    for server in vpn_core::list_servers()?.into_iter().filter(|s| s.panel.ssh_target.as_deref() == Some(target.as_str())) {
        vpn_core::delete_server(&server.id).map_err(|e| format!("Панель удалена с сервера, но запись приложения не очищена: {e}"))?;
    }
    Ok("3x-ui удалена с сервера, связанные записи приложения удалены.".into())
}

fn reply<F: Fn(&str) -> Result<String, String>>(request: Value, call: F) -> Option<Value> {
    let id = request.get("id")?.clone();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"vpn-client","version":env!("CARGO_PKG_VERSION")}}),
        "ping" => json!({}),
        "tools/list" => json!({"tools":[
            {"name":"vpn_connect","description":"Включить VPN с выбранной конфигурацией; при необходимости передать server_id, inbound_id и email.","inputSchema":{"type":"object","properties":{"server_id":{"type":"string"},"inbound_id":{"type":"integer","minimum":1},"email":{"type":"string"}},"dependentRequired":{"server_id":["inbound_id","email"],"inbound_id":["server_id","email"],"email":["server_id","inbound_id"]},"additionalProperties":false}},
            {"name":"vpn_disconnect","description":"Отключить VPN","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
            {"name":"install_3x_ui","description":"Установить 3x-ui и добавить панель в приложение через SSH-ключ ~/.ssh/id_ed25519_vpn_client.","inputSchema":{"type":"object","properties":{"host":{"type":"string"},"username":{"type":"string","default":"root"}},"required":["host"],"additionalProperties":false}},
            {"name":"uninstall_3x_ui","description":"Удалить 3x-ui и все её данные с указанного сервера, а также связанные записи приложения.","inputSchema":{"type":"object","properties":{"host":{"type":"string"},"username":{"type":"string","default":"root"}},"required":["host"],"additionalProperties":false}},
            {"name":"create_reality_client","description":"Создать VLESS TCP Reality inbound на порту 443 и клиента в сохранённой панели.","inputSchema":{"type":"object","properties":{"host":{"type":"string"},"email":{"type":"string","default":"client-1"},"sni":{"type":"string","default":"www.microsoft.com"}},"required":["host"],"additionalProperties":false}},
            {"name":"create_hysteria2_client","description":"Создать Hysteria 2 inbound UDP 443 и клиента в сохранённой панели.","inputSchema":{"type":"object","properties":{"host":{"type":"string"},"email":{"type":"string","default":"client-1"},"sni":{"type":"string"}},"required":["host","sni"],"additionalProperties":false}}
        ]}),
        "tools/call" => {
            let args = request.pointer("/params/arguments").cloned().unwrap_or_else(|| json!({}));
            let name = request.pointer("/params/name").and_then(Value::as_str).unwrap_or("");
            let response = match name {
                "vpn_connect" | "vpn_disconnect" => {
                    if args.as_object().is_some_and(|a| a.is_empty()) { call(if name == "vpn_connect" { "connect" } else { "disconnect" }) }
                    else if name == "vpn_connect" && args.as_object().is_some_and(|a| a.len() == 3) && args["server_id"].as_str().is_some() && args["inbound_id"].as_u64().is_some_and(|n| n > 0) && args["email"].as_str().is_some() {
                        vpn_core::mcp_control_socket_path().and_then(|path| control_request_at(&path, &json!({"action":"connect","profile":args})))
                    } else { Err("Укажите server_id, inbound_id и email вместе".into()) }
                }
                "install_3x_ui" | "uninstall_3x_ui" => {
                    let allowed = args.as_object().is_some_and(|o| o.keys().all(|k| k == "host" || k == "username"));
                    let host = args.get("host").and_then(Value::as_str).unwrap_or("");
                    let username = args.get("username").and_then(Value::as_str).unwrap_or("root");
                    if !allowed { Err("Разрешены только параметры host и username".into()) }
                    else if name == "install_3x_ui" { install_3x_ui(host, username) } else { uninstall_3x_ui(host, username) }
                }
                "create_reality_client" => {
                    if !args.as_object().is_some_and(|o| o.keys().all(|k| ["host","email","sni"].contains(&k.as_str())) && o.values().all(Value::is_string)) { Err("Разрешены строковые параметры host, email и sni".into()) }
                    else {
                        let host = args.get("host").and_then(Value::as_str).unwrap_or("");
                        let email = args.get("email").and_then(Value::as_str).unwrap_or("client-1");
                        let sni = args.get("sni").and_then(Value::as_str).unwrap_or("www.microsoft.com");
                        vpn_core::create_reality_client(host, email, sni).map(|(server,id)| format!("Inbound TCP Reality создан: сервер {server}, inbound {id}, клиент {email}.")).map_err(|e| {
                            if e.contains("Panel request failed") { "Не удалось обратиться к панели через SSH-туннель".to_owned() }
                            else if e.contains("Panel returned HTTP") { "Панель отклонила запрос".to_owned() }
                            else { e }
                        })
                    }
                }
                "create_hysteria2_client" => {
                    if !args.as_object().is_some_and(|o| o.keys().all(|k| ["host","email","sni"].contains(&k.as_str())) && o.values().all(Value::is_string)) { Err("Разрешены строковые параметры host, email и sni".into()) }
                    else if let (Some(host), Some(sni)) = (args.get("host").and_then(Value::as_str), args.get("sni").and_then(Value::as_str)) {
                        let email = args.get("email").and_then(Value::as_str).unwrap_or("client-1");
                        vpn_core::create_hysteria2_client(host, email, sni).map(|(server,id)| format!("Hysteria 2 inbound UDP создан: сервер {server}, inbound {id}, клиент {email}."))
                    } else { Err("Требуются параметры host и sni".into()) }
                }
                _ => Err("Неизвестная команда".into()),
            };
            match response { Ok(message) => json!({"content":[{"type":"text","text":message}]}), Err(message) => json!({"isError":true,"content":[{"type":"text","text":message}]}) }
        }
        _ => return Some(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}})),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let response = match serde_json::from_str(&line) { Ok(request) => reply(request, control), Err(_) => Some(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})) };
        if let Some(response) = response { if writeln!(stdout, "{response}").and_then(|_| stdout.flush()).is_err() { break; } }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exposes_vpn_controls_and_panel_installer() {
        let list=reply(json!({"id":1,"method":"tools/list"}), |_| panic!()).unwrap();
        let tools=list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(),6); assert_eq!(tools[0]["name"],"vpn_connect"); assert_eq!(tools[1]["name"],"vpn_disconnect"); assert_eq!(tools[2]["name"],"install_3x_ui"); assert_eq!(tools[3]["name"],"uninstall_3x_ui"); assert_eq!(tools[4]["name"],"create_reality_client"); assert_eq!(tools[5]["name"],"create_hysteria2_client");
        let result=reply(json!({"id":2,"method":"tools/call","params":{"name":"vpn_connect","arguments":{}}}), |action| { assert_eq!(action,"connect"); Ok("connected".into()) }).unwrap();
        assert_eq!(result["result"]["content"][0]["text"],"connected");
        let failure=reply(json!({"id":3,"method":"tools/call","params":{"name":"vpn_disconnect"}}), |action| { assert_eq!(action,"disconnect"); Err("error".into()) }).unwrap();
        assert_eq!(failure["result"]["isError"],true);
        let invalid=reply(json!({"id":4,"method":"tools/call","params":{"name":"vpn_connect","arguments":{"extra":1}}}), |_| panic!()).unwrap();
        assert_eq!(invalid["result"]["isError"],true);
    }
    #[test]
    fn validates_install_host_and_user_without_executing_ssh() {
        assert!(valid_install_target("31.58.181.55", "root"));
        assert!(valid_install_target("panel.example.org", "root"));
        assert!(!valid_install_target("-oProxyCommand=bad", "root"));
        assert!(!valid_install_target("host;id", "root"));
        assert!(!valid_install_target("31.58.181.55", "root;id"));
    }
    #[test]
    fn parses_panel_result_and_never_uses_other_fields() {
        let (url, token) = parse_install_result("XUI_ACCESS_URL='http://203.0.113.5:2053/panel/'\nXUI_API_TOKEN=\"secret\"\nXUI_PASSWORD=ignored\n").unwrap();
        assert_eq!(url, "http://127.0.0.1:2053/panel/"); assert_eq!(token, "secret");
        let (url, _) = parse_install_result("XUI_PANEL_PORT='2053'\nXUI_WEB_BASE_PATH=panel\nXUI_API_TOKEN=secret\n").unwrap();
        assert_eq!(url, "http://127.0.0.1:2053/panel/");
        assert!(parse_install_result("XUI_PANEL_PORT=2053\nXUI_WEB_BASE_PATH=panel").is_err());
    }
    #[test]
    fn stdio_tools_forward_to_local_application_socket() {
        use std::os::unix::net::UnixListener;
        let dir=tempfile::tempdir().unwrap(); let path=dir.path().join("control.sock");
        let listener=UnixListener::bind(&path).unwrap();
        let server=std::thread::spawn(move || {
            for expected in ["connect", "disconnect"] {
                let (mut stream,_)=listener.accept().unwrap();
                let mut line=String::new(); BufReader::new(&mut stream).read_line(&mut line).unwrap();
                let request: Value=serde_json::from_str(&line).unwrap(); assert_eq!(request["action"],expected);
                writeln!(stream,"{}",json!({"ok":true,"message":expected})).unwrap();
            }
        });
        for (name, expected) in [("vpn_connect","connect"), ("vpn_disconnect","disconnect")] {
            let response=reply(json!({"id":1,"method":"tools/call","params":{"name":name,"arguments":{}}}), |action| control_at(&path,action)).unwrap();
            assert_eq!(response["result"]["content"][0]["text"],expected);
        }
        server.join().unwrap();
    }
}
