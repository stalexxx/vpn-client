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
    BufReader::new(stream).take(64 * 1024).read_line(&mut line).map_err(|_| "Не удалось получить ответ приложения".to_owned())?;
    let response: Value = serde_json::from_str(&line).map_err(|_| "Некорректный ответ приложения".to_owned())?;
    let message = response.get("message").and_then(Value::as_str).unwrap_or("Нет ответа от приложения").to_owned();
    if response.get("ok").and_then(Value::as_bool) == Some(true) { Ok(message) } else { Err(message) }
}

fn human_rate(bytes: f64) -> String {
    if bytes >= 1048576.0 { format!("{:.1} МБ/с", bytes / 1048576.0) } else if bytes >= 1024.0 { format!("{:.0} КБ/с", bytes / 1024.0) } else { format!("{bytes:.0} Б/с") }
}
fn human_total(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1073741824.0 { format!("{:.2} ГБ", b / 1073741824.0) } else if b >= 1048576.0 { format!("{:.1} МБ", b / 1048576.0) } else { format!("{:.0} КБ", b / 1024.0) }
}
/// Two counter samples `secs` apart give the current speed; totals are since the tunnel started.
fn sample_stats(path: &std::path::Path, secs: u64) -> Result<String, String> {
    let read = || -> Result<Value, String> { serde_json::from_str(&control_request_at(path, &json!({"action":"stats"}))?).map_err(|_| "Некорректный ответ статистики".to_owned()) };
    let first = read()?;
    std::thread::sleep(Duration::from_secs(secs));
    let second = read()?;
    let dt = (second["ts_ms"].as_f64().unwrap_or(0.0) - first["ts_ms"].as_f64().unwrap_or(0.0)) / 1000.0;
    if dt <= 0.0 { return Err("Не удалось измерить скорость".into()); }
    let num = |v: &Value, route: &str, dir: &str| v[route][dir].as_u64().unwrap_or(0);
    let line = |route: &str, label: &str| {
        let rate = |dir: &str| num(&second, route, dir).saturating_sub(num(&first, route, dir)) as f64 / dt;
        format!("{label}: ↓ {} ↑ {} (всего ↓ {} ↑ {})", human_rate(rate("down")), human_rate(rate("up")), human_total(num(&second, route, "down")), human_total(num(&second, route, "up")))
    };
    Ok(format!("{}\n{}", line("vpn", "Через VPN"), line("direct", "Напрямую")))
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
    let panel = vpn_core::Panel { name: previous.map(|s| s.panel.name.clone()).unwrap_or_else(|| host.to_owned()), url, ssh_target: Some(target), panel_host: Some(host.to_owned()), ssh_key: previous.and_then(|s| s.panel.ssh_key.clone()) };
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
            {"name":"create_reality_client","description":"Создать VLESS TCP Reality inbound и клиента в сохранённой панели.","inputSchema":{"type":"object","properties":{"host":{"type":"string"},"email":{"type":"string","default":"client-1"},"sni":{"type":"string","default":"www.microsoft.com"},"port":{"type":"integer","minimum":1,"maximum":65535,"default":443}},"required":["host"],"additionalProperties":false}},
            {"name":"create_xhttp_relay_client","description":"Создать отдельный XHTTP relay без подмены адреса назначения; использует существующий сертификат.","inputSchema":{"type":"object","properties":{"host":{"type":"string"},"email":{"type":"string"},"sni":{"type":"string"},"port":{"type":"integer","minimum":1,"maximum":65535}},"required":["host","email","sni","port"],"additionalProperties":false}},
            {"name":"list_server_inbounds","description":"Показать inbound-ы сохранённой панели по адресу сервера.","inputSchema":{"type":"object","properties":{"host":{"type":"string"}},"required":["host"],"additionalProperties":false}},
            {"name":"delete_server_inbound","description":"Удалить указанный inbound по ID на сохранённой панели.","inputSchema":{"type":"object","properties":{"host":{"type":"string"},"inbound_id":{"type":"integer","minimum":1}},"required":["host","inbound_id"],"additionalProperties":false}},
            {"name":"delete_reality_inbound","description":"Удалить только VLESS TCP Reality inbound с портом 443 и именем VLESS-REALITY-443 на сохранённой панели.","inputSchema":{"type":"object","properties":{"host":{"type":"string"}},"required":["host"],"additionalProperties":false}},
            {"name":"enable_server_warp","description":"Включить Cloudflare WARP как выход сервера: весь трафик пользователей выходит через WARP, а не с адреса входа (при сбое WARP трафик блокируется). Исходный шаблон Xray сохраняется; если Xray не запустился, шаблон восстанавливается.","inputSchema":{"type":"object","properties":{"host":{"type":"string"}},"required":["host"],"additionalProperties":false}},
            {"name":"disable_server_warp","description":"Отключить WARP на сервере: убрать outbound warp и правила к нему.","inputSchema":{"type":"object","properties":{"host":{"type":"string"}},"required":["host"],"additionalProperties":false}},
            {"name":"vpn_get_stats","description":"Трафик и текущая скорость по маршрутам: direct (мимо VPN, например BitTorrent) и vpn (через туннель). Скорость измеряется за интервал interval_secs.","inputSchema":{"type":"object","properties":{"interval_secs":{"type":"integer","minimum":1,"maximum":10,"default":2}},"additionalProperties":false}},
            {"name":"vpn_get_log","description":"Показать последние строки журнала Xray (маршрутизация direct / vpn-out видна при уровне info); можно отфильтровать по подстроке, например bittorrent.","inputSchema":{"type":"object","properties":{"lines":{"type":"integer","minimum":1,"maximum":300,"default":50},"filter":{"type":"string","maxLength":64}},"additionalProperties":false}},
            {"name":"vpn_set_log_level","description":"Уровень журнала Xray: info (с адресами назначения, только для диагностики) или warning. Применяется при следующем подключении.","inputSchema":{"type":"object","properties":{"level":{"type":"string","enum":["info","warning"]}},"required":["level"],"additionalProperties":false}},
            {"name":"create_hysteria2_client","description":"Создать Hysteria 2 inbound UDP 443 и клиента в сохранённой панели.","inputSchema":{"type":"object","properties":{"host":{"type":"string"},"email":{"type":"string","default":"client-1"},"sni":{"type":"string"}},"required":["host","sni"],"additionalProperties":false}},
            {"name":"install_amneziawg","description":"Установить на сервер AmneziaWG с выходом через Cloudflare WARP (по SSH, Ubuntu/Debian x86_64). Возвращает порт и публичный ключ; клиентов добавляйте через add_awg_client.","inputSchema":{"type":"object","properties":{"name":{"type":"string"},"ssh_target":{"type":"string","description":"user@host[:port]"},"ssh_key":{"type":"string","description":"имя ключа в ~/.ssh"},"port":{"type":"integer","minimum":1024,"maximum":65535}},"required":["name","ssh_target"],"additionalProperties":false}},
            {"name":"add_awg_client","description":"Создать клиента AmneziaWG и вернуть его .conf и ссылку vpn:// (импортируются в официальный клиент Amnezia).","inputSchema":{"type":"object","properties":{"host":{"type":"string"},"client":{"type":"string"}},"required":["host","client"],"additionalProperties":false}},
            {"name":"list_awg_clients","description":"Клиенты AmneziaWG-сервера и состояние WARP (рукопожатие, трафик).","inputSchema":{"type":"object","properties":{"host":{"type":"string"}},"required":["host"],"additionalProperties":false}},
            {"name":"delete_awg_client","description":"Удалить клиента AmneziaWG.","inputSchema":{"type":"object","properties":{"host":{"type":"string"},"client":{"type":"string"}},"required":["host","client"],"additionalProperties":false}},
            {"name":"uninstall_amneziawg","description":"Удалить AmneziaWG и WARP-интерфейс с сервера вместе с ключами и клиентами.","inputSchema":{"type":"object","properties":{"host":{"type":"string"}},"required":["host"],"additionalProperties":false}}
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
                    if !args.as_object().is_some_and(|o| o.iter().all(|(k,v)| match k.as_str() { "host" | "email" | "sni" => v.is_string(), "port" => v.as_u64().is_some_and(|n| (1..=65535).contains(&n)), _ => false })) { Err("Некорректные параметры Reality".into()) }
                    else {
                        let host = args.get("host").and_then(Value::as_str).unwrap_or("");
                        let email = args.get("email").and_then(Value::as_str).unwrap_or("client-1");
                        let sni = args.get("sni").and_then(Value::as_str).unwrap_or("www.microsoft.com");
                        let port = args.get("port").and_then(Value::as_u64).unwrap_or(443) as u16;
                        vpn_core::create_reality_client_on_port(host, email, sni, port).map(|(server,id)| format!("Inbound TCP Reality создан: сервер {server}, inbound {id}, клиент {email}.")).map_err(|e| {
                            if e.contains("Panel request failed") { "Не удалось обратиться к панели через SSH-туннель".to_owned() }
                            else if e.contains("Panel returned HTTP") { "Панель отклонила запрос".to_owned() }
                            else { e }
                        })
                    }
                }
                "create_xhttp_relay_client" => {
                    if !args.as_object().is_some_and(|o| o.len() == 4 && ["host","email","sni"].iter().all(|k| o.get(*k).is_some_and(Value::is_string)) && o.get("port").and_then(Value::as_u64).is_some_and(|n| (1..=65535).contains(&n))) { Err("Требуются host, email, sni и port".into()) }
                    else { vpn_core::create_xhttp_relay_client(args["host"].as_str().unwrap_or_default(), args["email"].as_str().unwrap_or_default(), args["sni"].as_str().unwrap_or_default(), args["port"].as_u64().unwrap_or_default() as u16).map(|(server,id)| format!("XHTTP relay создан: сервер {server}, inbound {id}.")) }
                }
                "delete_reality_inbound" => {
                    if !args.as_object().is_some_and(|o| o.len() == 1 && o.get("host").is_some_and(Value::is_string)) { Err("Требуется строковый параметр host".into()) }
                    else { vpn_core::delete_reality_inbound(args["host"].as_str().unwrap_or_default()).map_err(|e| if e.contains("Panel request failed") { "Не удалось обратиться к панели через SSH-туннель".to_owned() } else { e }) }
                }
                "list_server_inbounds" => {
                    if !args.as_object().is_some_and(|o| o.len() == 1 && o.get("host").is_some_and(Value::is_string)) { Err("Требуется строковый параметр host".into()) }
                    else { vpn_core::list_inbounds_for_host(args["host"].as_str().unwrap_or_default()).map(|v| serde_json::to_string(&v).unwrap_or_default()).map_err(|e| if e.contains("Panel request failed") { "Не удалось обратиться к панели через SSH-туннель".to_owned() } else { e }) }
                }
                "delete_server_inbound" => {
                    if !args.as_object().is_some_and(|o| o.len() == 2 && o.get("host").is_some_and(Value::is_string) && o.get("inbound_id").and_then(Value::as_u64).is_some_and(|n| n > 0)) { Err("Требуются host и положительный inbound_id".into()) }
                    else { vpn_core::delete_inbound_for_host(args["host"].as_str().unwrap_or_default(), args["inbound_id"].as_u64().unwrap_or_default()).map_err(|e| if e.contains("Panel request failed") { "Не удалось обратиться к панели через SSH-туннель".to_owned() } else { e }) }
                }
                "enable_server_warp" | "disable_server_warp" => {
                    if !args.as_object().is_some_and(|o| o.len() == 1 && o.get("host").is_some_and(Value::is_string)) { Err("Требуется строковый параметр host".into()) }
                    else {
                        let host = args["host"].as_str().unwrap_or_default();
                        (if name == "enable_server_warp" { vpn_core::enable_warp_for_host(host) } else { vpn_core::disable_warp_for_host(host) })
                            .map_err(|e| if e.contains("Panel request failed") { "Не удалось обратиться к панели через SSH-туннель".to_owned() } else { e })
                    }
                }
                "install_amneziawg" => {
                    let ok = args.as_object().is_some_and(|o| o.keys().all(|k| ["name","ssh_target","ssh_key","port"].contains(&k.as_str())) && o.get("name").is_some_and(Value::is_string) && o.get("ssh_target").is_some_and(Value::is_string));
                    if !ok { Err("Требуются name и ssh_target".into()) } else {
                        let port = args.get("port").and_then(Value::as_u64).map(|p| p as u16);
                        vpn_core::amnezia::install(args["name"].as_str().unwrap_or_default(), args["ssh_target"].as_str().unwrap_or_default(), args.get("ssh_key").and_then(Value::as_str), port, None)
                            .map(|s| format!("AmneziaWG установлен на {}: UDP-порт {}, публичный ключ {}. WARP — выход для всех клиентов.", vpn_core::ssh_host(&s.ssh_target), s.port, s.server_public_key))
                    }
                }
                "add_awg_client" | "delete_awg_client" => {
                    if !args.as_object().is_some_and(|o| o.len() == 2 && o.get("host").is_some_and(Value::is_string) && o.get("client").is_some_and(Value::is_string)) { Err("Требуются host и client".into()) }
                    else {
                        let client = args["client"].as_str().unwrap_or_default();
                        vpn_core::amnezia::find_server(args["host"].as_str().unwrap_or_default()).and_then(|s| if name == "add_awg_client" { vpn_core::amnezia::add_client(&s, client).and_then(|conf| { let link = vpn_core::amnezia::vpn_link(&format!("{} · {}", s.name, client), &conf)?; Ok(format!("{conf}\n\nСсылка для приложения Amnezia:\n{link}")) }) } else { vpn_core::amnezia::delete_client(&s, client).map(|_| format!("Клиент {client} удалён")) })
                    }
                }
                "list_awg_clients" | "uninstall_amneziawg" => {
                    if !args.as_object().is_some_and(|o| o.len() == 1 && o.get("host").is_some_and(Value::is_string)) { Err("Требуется строковый параметр host".into()) }
                    else {
                        vpn_core::amnezia::find_server(args["host"].as_str().unwrap_or_default()).and_then(|s| if name == "list_awg_clients" {
                            let clients = vpn_core::amnezia::list_clients(&s)?; let status = vpn_core::amnezia::status(&s).unwrap_or_default();
                            Ok(format!("{}\n{}", serde_json::to_string(&clients).unwrap_or_default(), status))
                        } else { vpn_core::amnezia::uninstall(&s).map(|_| "AmneziaWG удалён".to_string()) })
                    }
                }
                "vpn_get_stats" => {
                    let secs = args.get("interval_secs").and_then(Value::as_u64).unwrap_or(2);
                    if !args.as_object().is_some_and(|o| o.keys().all(|k| k == "interval_secs")) || !(1..=10).contains(&secs) { Err("Некорректный интервал".into()) }
                    else { vpn_core::mcp_control_socket_path().and_then(|path| sample_stats(&path, secs)) }
                }
                "vpn_get_log" => {
                    let lines = args.get("lines").and_then(Value::as_u64).unwrap_or(50);
                    let filter = args.get("filter").and_then(Value::as_str);
                    if !args.as_object().is_some_and(|o| o.keys().all(|k| k == "lines" || k == "filter")) || !(1..=300).contains(&lines) || filter.is_some_and(|f| f.len() > 64) { Err("Некорректные параметры журнала".into()) }
                    else { vpn_core::mcp_control_socket_path().and_then(|path| control_request_at(&path, &json!({"action":"log","lines":lines,"filter":filter}))) }
                }
                "vpn_set_log_level" => match (args.as_object().map(|o| o.len()), args.get("level").and_then(Value::as_str)) {
                    (Some(1), Some(level @ ("info" | "warning"))) => vpn_core::mcp_control_socket_path().and_then(|path| control_request_at(&path, &json!({"action":"set_log_level","level":level}))),
                    _ => Err("Укажите level: info или warning".into()),
                },
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
        assert_eq!(tools.len(),20); assert_eq!(tools[0]["name"],"vpn_connect"); assert_eq!(tools[1]["name"],"vpn_disconnect"); assert_eq!(tools[2]["name"],"install_3x_ui"); assert_eq!(tools[3]["name"],"uninstall_3x_ui"); assert_eq!(tools[4]["name"],"create_reality_client"); assert_eq!(tools[5]["name"],"create_xhttp_relay_client"); assert_eq!(tools[6]["name"],"list_server_inbounds"); assert_eq!(tools[7]["name"],"delete_server_inbound"); assert_eq!(tools[8]["name"],"delete_reality_inbound"); assert_eq!(tools[9]["name"],"enable_server_warp"); assert_eq!(tools[10]["name"],"disable_server_warp"); assert_eq!(tools[11]["name"],"vpn_get_stats"); assert_eq!(tools[12]["name"],"vpn_get_log"); assert_eq!(tools[13]["name"],"vpn_set_log_level"); assert_eq!(tools[14]["name"],"create_hysteria2_client");
        let bad=reply(json!({"id":9,"method":"tools/call","params":{"name":"vpn_set_log_level","arguments":{"level":"debug"}}}), |_| panic!()).unwrap();
        assert_eq!(bad["result"]["isError"],true);
        let bad=reply(json!({"id":9,"method":"tools/call","params":{"name":"vpn_get_log","arguments":{"lines":0}}}), |_| panic!()).unwrap();
        assert_eq!(bad["result"]["isError"],true);
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
