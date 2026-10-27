use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn reply(request: Value) -> Option<Value> {
    let id = request.get("id")?.clone();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => {
            json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"vpn-client","version":"0.1.0"}})
        }
        "ping" => json!({}),
        "tools/list" => {
            json!({"tools":[{"name":"get_panel","description":"Show the configured panel without credentials","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},{"name":"list_inbounds","description":"List panel inbounds without client secrets","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},{"name":"prepare_create_client","description":"Prepare a VLESS client creation plan; does not change the server. Queues a proposal for explicit approval in the desktop app; never modifies the panel directly.","inputSchema":{"type":"object","properties":{"inbound_id":{"type":"integer","minimum":1},"email":{"type":"string","minLength":1,"maxLength":128}},"required":["inbound_id","email"],"additionalProperties":false}}]})
        }
        "tools/call" => {
            let name = request
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let response = match name {
                "get_panel" => vpn_core::load_panel()
                    .and_then(|p| serde_json::to_value(p).map_err(|e| e.to_string())),
                "list_inbounds" => vpn_core::list_inbounds(),
                "prepare_create_client" => {
                    let args = request.pointer("/params/arguments");
                    match (
                        args.and_then(|a| a.get("inbound_id"))
                            .and_then(Value::as_u64),
                        args.and_then(|a| a.get("email")).and_then(Value::as_str),
                    ) {
                        (Some(id), Some(email)) => vpn_core::queue_client(id, email)
                            .and_then(|plan| serde_json::to_value(plan).map_err(|e| e.to_string())),
                        _ => Err("inbound_id and email are required".into()),
                    }
                }
                _ => Err("Unknown tool".to_owned()),
            };
            match response {
                Ok(value) => json!({"content":[{"type":"text","text":value.to_string()}]}),
                Err(error) => json!({"isError":true,"content":[{"type":"text","text":error}]}),
            }
        }
        _ => {
            return Some(
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}}),
            )
        }
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let response = match serde_json::from_str(&line) {
            Ok(request) => reply(request),
            Err(_) => Some(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}),
            ),
        };
        if let Some(response) = response {
            if writeln!(stdout, "{response}")
                .and_then(|_| stdout.flush())
                .is_err()
            {
                break;
            }
        }
    }
}
