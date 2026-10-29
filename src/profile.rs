use serde_json::{json, Value};
use url::Url;

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
    if !interface.starts_with("utun") || !interface[4..].chars().all(|c| c.is_ascii_digit()) {
        return Err("Invalid macOS TUN interface name".into());
    }
    let mut config = vless_xhttp_config(link, 10808)?;
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
}
