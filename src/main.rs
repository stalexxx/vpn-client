use serde_json::{json, Value};
use std::{io::{self, BufRead, BufReader, Read, Write}, os::unix::net::UnixStream, time::Duration};

fn control(action: &str) -> Result<String, String> {
    let path = vpn_core::mcp_control_socket_path()?;
    control_at(&path, action)
}
fn control_at(path: &std::path::Path, action: &str) -> Result<String, String> {
    let mut stream = UnixStream::connect(path).map_err(|_| "Приложение VPN недоступно. Запустите его и выберите конфигурацию.".to_owned())?;
    stream.set_read_timeout(Some(Duration::from_secs(120))).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    writeln!(stream, "{}", json!({"action":action})).map_err(|_| "Не удалось отправить команду приложению".to_owned())?;
    let mut line = String::new();
    BufReader::new(stream).take(16 * 1024).read_line(&mut line).map_err(|_| "Не удалось получить ответ приложения".to_owned())?;
    let response: Value = serde_json::from_str(&line).map_err(|_| "Некорректный ответ приложения".to_owned())?;
    let message = response.get("message").and_then(Value::as_str).unwrap_or("Нет ответа от приложения").to_owned();
    if response.get("ok").and_then(Value::as_bool) == Some(true) { Ok(message) } else { Err(message) }
}

fn reply<F: Fn(&str) -> Result<String, String>>(request: Value, call: F) -> Option<Value> {
    let id = request.get("id")?.clone();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"vpn-client","version":env!("CARGO_PKG_VERSION")}}),
        "ping" => json!({}),
        "tools/list" => json!({"tools":[
            {"name":"vpn_connect","description":"Включить VPN с конфигурацией, выбранной в приложении","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
            {"name":"vpn_disconnect","description":"Отключить VPN","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}
        ]}),
        "tools/call" => {
            let args = request.pointer("/params/arguments").cloned().unwrap_or_else(|| json!({}));
            let name = request.pointer("/params/name").and_then(Value::as_str).unwrap_or("");
            let response = if !args.as_object().is_some_and(|a| a.is_empty()) { Err("Эта команда не принимает параметры".into()) }
                else { match name { "vpn_connect" => call("connect"), "vpn_disconnect" => call("disconnect"), _ => Err("Неизвестная команда".into()) } };
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
    fn exposes_only_two_vpn_commands_and_forwards_results() {
        let list=reply(json!({"id":1,"method":"tools/list"}), |_| panic!()).unwrap();
        let tools=list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(),2); assert_eq!(tools[0]["name"],"vpn_connect"); assert_eq!(tools[1]["name"],"vpn_disconnect");
        let result=reply(json!({"id":2,"method":"tools/call","params":{"name":"vpn_connect","arguments":{}}}), |action| { assert_eq!(action,"connect"); Ok("connected".into()) }).unwrap();
        assert_eq!(result["result"]["content"][0]["text"],"connected");
        let failure=reply(json!({"id":3,"method":"tools/call","params":{"name":"vpn_disconnect"}}), |action| { assert_eq!(action,"disconnect"); Err("error".into()) }).unwrap();
        assert_eq!(failure["result"]["isError"],true);
        let invalid=reply(json!({"id":4,"method":"tools/call","params":{"name":"vpn_connect","arguments":{"extra":1}}}), |_| panic!()).unwrap();
        assert_eq!(invalid["result"]["isError"],true);
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
