use serde_json::{json, Value};
use url::Url;

pub fn vless_config(link: &str, socks_port: u16) -> Result<Value, String> {
    let url = Url::parse(link).map_err(|_| "Invalid VLESS link")?;
    if url.scheme() == "hysteria2" {
        return hysteria2_config(link, socks_port);
    }
    if url.query_pairs().any(|(k,v)| k == "security" && v == "reality") {
        return vless_reality_config(link, socks_port);
    }
    vless_xhttp_config(link, socks_port)
}

/// Translate a Hysteria 2 share link into an Xray client configuration.
/// The link carries an authentication secret and must be kept private.
pub fn hysteria2_config(link: &str, socks_port: u16) -> Result<Value, String> {
    let url = Url::parse(link).map_err(|_| "Invalid Hysteria 2 link")?;
    if url.scheme() != "hysteria2" || url.password().is_some() || socks_port == 0 {
        return Err("Invalid Hysteria 2 configuration".into());
    }
    let auth = percent_encoding::percent_decode_str(url.username()).decode_utf8().map_err(|_| "Invalid Hysteria 2 authentication")?.into_owned();
    if auth.is_empty() { return Err("Missing Hysteria 2 authentication".into()); }
    let server = url.host_str().ok_or("Missing Hysteria 2 server")?;
    let port = url.port().ok_or("Missing Hysteria 2 port")?;
    let mut sni = None;
    let mut insecure = false;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "sni" => { if sni.replace(value.into_owned()).is_some() { return Err("Duplicate Hysteria 2 SNI".into()); } },
            "insecure" => insecure = match value.as_ref() { "0" | "false" => false, "1" | "true" => true, _ => return Err("Invalid Hysteria 2 TLS option".into()) },
            "obfs" | "obfs-password" => return Err("Hysteria 2 obfuscation is not supported".into()),
            _ => return Err("Unsupported Hysteria 2 parameter".into()),
        }
    }
    let sni = sni.filter(|v| !v.is_empty()).unwrap_or_else(|| server.to_owned());
    Ok(json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":server,"port":port},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":sni,"alpn":["h3"],"allowInsecure":insecure},"hysteriaSettings":{"version":2,"auth":auth}}}]}))
}

fn vless_reality_config(link: &str, socks_port: u16) -> Result<Value, String> {
    let url = Url::parse(link).map_err(|_| "Invalid VLESS link")?;
    let id = url.username();
    if url.scheme() != "vless" || url.password().is_some() || id.len() != 36 || !id.chars().enumerate().all(|(i,c)| if [8,13,18,23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() }) { return Err("Invalid VLESS client UUID".into()); }
    let mut fields = std::collections::HashMap::new();
    for (key,value) in url.query_pairs() {
        if !["type","security","sni","pbk","sid","fp","spx","flow","encryption"].contains(&key.as_ref()) { return Err("Unsupported REALITY parameter".into()); }
        if fields.insert(key.into_owned(), value.into_owned()).is_some() { return Err("Duplicate REALITY parameter".into()); }
    }
    if fields.get("type").map(String::as_str) != Some("tcp") || fields.get("security").map(String::as_str) != Some("reality") || fields.get("encryption").is_some_and(|v| v != "none") || socks_port == 0 { return Err("Invalid VLESS TCP REALITY configuration".into()); }
    let server = url.host_str().ok_or("Missing server")?;
    let port = url.port().ok_or("Missing server port")?;
    let sni = fields.get("sni").filter(|s| !s.is_empty()).ok_or("Missing REALITY SNI")?;
    let pbk = fields.get("pbk").filter(|s| s.len() == 43 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')).ok_or("Invalid REALITY public key")?;
    let sid = fields.get("sid").ok_or("Missing REALITY short ID")?;
    if sid.len() > 16 || sid.len() % 2 != 0 || !sid.bytes().all(|c| c.is_ascii_hexdigit()) { return Err("Invalid REALITY short ID".into()); }
    let flow = fields.get("flow").map(String::as_str).unwrap_or("");
    if !["", "xtls-rprx-vision"].contains(&flow) { return Err("Unsupported VLESS flow".into()); }
    let fingerprint = fields.get("fp").map(String::as_str).unwrap_or("chrome");
    if !["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"].contains(&fingerprint) { return Err("Unsupported REALITY fingerprint".into()); }
    let spider = fields.get("spx").map(String::as_str).unwrap_or("/");
    if !spider.starts_with('/') || spider.chars().any(char::is_control) { return Err("Invalid REALITY spider path".into()); }
    Ok(json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":server,"port":port,"users":[{"id":id,"encryption":"none","flow":flow}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":sni,"fingerprint":fingerprint,"publicKey":pbk,"shortId":sid,"spiderX":spider}}}]}))
}

/// Translate a VLESS TLS XHTTP share URL into an Xray client configuration.
/// The returned configuration contains credentials and must be handled as secret.
pub fn vless_xhttp_config(link: &str, socks_port: u16) -> Result<Value, String> {
    let url = Url::parse(link).map_err(|_| "Invalid VLESS link")?;
    if url.scheme() != "vless" || url.host_str().is_none() || url.password().is_some() {
        return Err("Expected a VLESS link with a host and client UUID".into());
    }
    let id = url.username();
    if id.len() != 36
        || !id.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
    {
        return Err("Invalid client UUID".into());
    }
    let mut network = None;
    let mut security = None;
    let mut sni = None;
    let mut path = None;
    let mut host = None;
    let mut mode = None;
    let mut encryption = None;
    let mut alpn = None;
    let mut fingerprint = None;
    for (key, value) in url.query_pairs() {
        let target = match key.as_ref() {
            "type" => &mut network,
            "security" => &mut security,
            "sni" => &mut sni,
            "path" => &mut path,
            "host" => &mut host,
            "mode" => &mut mode,
            "encryption" => &mut encryption,
            "alpn" => &mut alpn,
            "fp" => &mut fingerprint,
            _ => return Err(format!("Unsupported VLESS parameter: {key}")),
        };
        if target.replace(value.into_owned()).is_some() {
            return Err(format!("Duplicate VLESS parameter: {key}"));
        }
    }
    if network.as_deref() != Some("xhttp") || security.as_deref() != Some("tls") {
        return Err("Only VLESS with TLS and XHTTP is supported".into());
    }
    if encryption.as_deref().unwrap_or("none") != "none" {
        return Err("Unsupported VLESS encryption".into());
    }
    let server = url.host_str().ok_or("Missing server")?;
    let port = url.port().ok_or("Missing server port")?;
    let sni = sni
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| server.to_owned());
    let path = path.unwrap_or_else(|| "/".to_owned());
    if !path.starts_with('/') {
        return Err("XHTTP path must begin with /".into());
    }
    let mut xhttp = json!({"path": path});
    if let Some(host) = host {
        xhttp["host"] = json!(host);
    }
    if let Some(mode) = mode {
        if !["auto", "packet-up", "stream-up", "stream-one"].contains(&mode.as_str()) {
            return Err("Unsupported XHTTP mode".into());
        }
        xhttp["mode"] = json!(mode);
    } else {
        // 3x-ui share links omit the mode; "auto" proved unreliable against this server, stream-one works.
        xhttp["mode"] = json!("stream-one");
    }
    if socks_port == 0 {
        return Err("Invalid local SOCKS port".into());
    }
    Ok(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": true}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": server, "port": port, "users": [{"id": id, "encryption": "none"}]}]}, "streamSettings": {"network": "xhttp", "security": "tls", "tlsSettings": {"serverName": sni, "alpn": alpn.as_deref().map(|v| v.split(',').map(str::to_owned).collect::<Vec<_>>()).unwrap_or_else(|| vec!["h2".into()]), "fingerprint": fingerprint.unwrap_or_else(|| "firefox".into())}, "xhttpSettings": xhttp}}]
    }))
}

/// Convert a VLESS/TLS/XHTTP link into a full-system Xray TUN configuration.
pub fn vless_xhttp_tun_config(link: &str, interface: &str) -> Result<Value, String> {
    vless_tun_config_with_relay(link, interface, None)
}

/// Build a full-system TUN config, optionally dialing a Hysteria 2 outbound
/// through an established VLESS/XHTTP relay for networks that block UDP.
pub fn vless_tun_config_with_relay(link: &str, interface: &str, relay_link: Option<&str>) -> Result<Value, String> {
    if !interface.starts_with("utun") || !interface[4..].chars().all(|c| c.is_ascii_digit()) {
        return Err("Invalid macOS TUN interface name".into());
    }
    let mut config = vless_config(link, 10808)?;
    if let Some(relay_link) = relay_link {
        if !link.starts_with("hysteria2://") { return Err("A relay is supported only for Hysteria 2".into()); }
        let mut relay = vless_config(relay_link, 10808)?["outbounds"][0].clone();
        if relay["protocol"] != "vless" || relay["streamSettings"]["network"] != "xhttp" || relay["streamSettings"]["security"] != "tls" {
            return Err("The Hysteria relay must be VLESS over TLS/XHTTP".into());
        }
        relay["tag"] = json!("hysteria-relay");
        config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] = json!("hysteria-relay");
        config["outbounds"].as_array_mut().ok_or("Invalid outbound config")?.push(relay);
    }
    config["inbounds"] = json!([{
        "tag": "tun-in",
        "port": 0,
        "protocol": "tun",
        "settings": {
            "name": interface,
            "mtu": 1400,
            "gateway": ["169.254.10.1/30"],
            "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
            "autoOutboundsInterface": "auto"
        }
    }]);
    config["outbounds"][0]["tag"] = json!("vpn-out");
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builds_xhttp_client_and_keeps_local_proxy_private() {
        let link = "vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=xhttp&security=tls&sni=example.org&path=%2Fvpn&mode=auto";
        let config = vless_xhttp_config(link, 10808).unwrap();
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"],
            "/vpn"
        );
        assert_eq!(
            config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"],
            "12345678-1234-1234-1234-123456789abc"
        );
    }
    #[test]
    fn applies_tls_and_xhttp_defaults_missing_from_share_links() {
        let link = "vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=xhttp&security=tls&sni=example.org&path=%2F";
        let stream = &vless_xhttp_tun_config(link, "utun10").unwrap()["outbounds"][0]["streamSettings"];
        assert_eq!(stream["tlsSettings"]["alpn"], json!(["h2"]));
        assert_eq!(stream["tlsSettings"]["fingerprint"], "firefox");
        assert_eq!(stream["xhttpSettings"]["mode"], "stream-one");
        let explicit = format!("{link}&mode=packet-up");
        let stream = &vless_xhttp_config(&explicit, 10808).unwrap()["outbounds"][0]["streamSettings"];
        assert_eq!(stream["xhttpSettings"]["mode"], "packet-up");
    }
    #[test]
    fn rejects_unsupported_or_ambiguous_parameters() {
        let base =
            "vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=xhttp&security=tls";
        assert!(vless_xhttp_config(&format!("{base}&security=none"), 10808).is_err());
        assert!(vless_xhttp_config(&format!("{base}&allowInsecure=1"), 10808).is_err());
        assert!(vless_xhttp_config(base, 0).is_err());
    }
    #[test]
    fn builds_reality_tun_and_rejects_invalid_keys() {
        let link="vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=tcp&security=reality&sni=www.microsoft.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01234567&fp=chrome&spx=%2F&flow=xtls-rprx-vision";
        let config=vless_xhttp_tun_config(link,"utun10").unwrap();
        assert_eq!(config["outbounds"][0]["streamSettings"]["security"],"reality");
        assert_eq!(config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],"xtls-rprx-vision");
        assert!(vless_config(&link.replace("sid=01234567","sid=xyz"),10808).is_err());
        assert!(vless_config(&link.replace("pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","pbk=bad"),10808).is_err());
    }
    #[test]
    fn builds_hysteria2_tun_and_rejects_bad_links() {
        let link = "hysteria2://secret%3Aauth@example.org:443/?sni=example.org&insecure=0";
        let config = vless_xhttp_tun_config(link, "utun10").unwrap();
        assert_eq!(config["outbounds"][0]["protocol"], "hysteria");
        assert_eq!(config["outbounds"][0]["settings"]["version"], 2);
        assert_eq!(config["outbounds"][0]["streamSettings"]["hysteriaSettings"]["auth"], "secret:auth");
        assert_eq!(config["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"], "example.org");
        assert_eq!(config["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"], json!(["h3"]));
        assert!(vless_config(&link.replace("insecure=0", "obfs=salamander"), 10808).is_err());
        assert!(vless_config("hysteria2://@example.org:443", 10808).is_err());
    }
    #[test]
    fn chains_hysteria_through_vless_xhttp_relay() {
        let h = "hysteria2://secret@example.org:443/?sni=example.org";
        let relay = "vless://12345678-1234-1234-1234-123456789abc@relay.example:443?type=xhttp&security=tls&sni=relay.example&path=%2Fvpn";
        let config = vless_tun_config_with_relay(h, "utun10", Some(relay)).unwrap();
        assert_eq!(config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"], "hysteria-relay");
        assert_eq!(config["outbounds"][1]["protocol"], "vless");
        assert_eq!(config["outbounds"][1]["streamSettings"]["network"], "xhttp");
        assert!(vless_tun_config_with_relay(h, "utun10", Some("hysteria2://bad@relay:443")).is_err());
    }
}
