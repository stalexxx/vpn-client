use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientPlan {
    pub action: String,
    pub inbound_id: u64,
    pub inbound_name: String,
    pub email: String,
    pub requires_confirmation: bool,
}

pub fn prepare(inbounds: &Value, inbound_id: u64, email: &str) -> Result<ClientPlan, String> {
    if inbound_id == 0 {
        return Err("Invalid inbound ID".into());
    }
    if email.is_empty()
        || email.len() > 128
        || !email
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c))
    {
        return Err("Client name must contain only letters, digits, @, ., _, + or -".into());
    }
    let inbound = inbounds
        .as_array()
        .ok_or("Invalid inbound list")?
        .iter()
        .find(|item| item.get("id").and_then(Value::as_u64) == Some(inbound_id))
        .ok_or("Inbound not found")?;
    if inbound.get("protocol").and_then(Value::as_str) != Some("vless") {
        return Err("Only VLESS is supported".into());
    }
    if inbound.get("enable").and_then(Value::as_bool) != Some(true) {
        return Err("Inbound is disabled".into());
    }
    Ok(ClientPlan {
        action: "create_client".into(),
        inbound_id,
        inbound_name: inbound
            .get("remark")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        email: email.into(),
        requires_confirmation: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permits_only_enabled_vless_and_safe_names() {
        let list = serde_json::json!([{"id": 2, "remark": "Main", "protocol": "vless", "enable": true},{"id": 3,"protocol":"trojan","enable":true},{"id":4,"protocol":"vless","enable":false}]);
        assert!(prepare(&list, 2, "alice@example.com").is_ok());
        assert!(prepare(&list, 3, "alice").is_err());
        assert!(prepare(&list, 4, "alice").is_err());
        assert!(prepare(&list, 2, "bad\nname").is_err());
        assert!(prepare(&list, 99, "alice").is_err());
    }
}
