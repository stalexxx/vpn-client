use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

pub fn vless_config(link: &str, socks_port: u16) -> Result<Value, String> {
    let url = Url::parse(link).map_err(|_| "Invalid VLESS link")?;
    if url.scheme() == "hysteria2" {
        return hysteria2_config(link, socks_port);
    }
    if url.scheme() == "socks5" { return socks5_config(&url, socks_port); }
    if url.query_pairs().any(|(k,v)| k == "security" && v == "reality") {
        return vless_reality_config(link, socks_port);
    }
    vless_xhttp_config(link, socks_port)
}

/// A loopback SOCKS5 proxy as the VPN outbound. The helper runs the embedded AmneziaWG client (`awgsocks`) on that
/// address and hands Xray this link instead of the `awg://` one. `socks5://user:pass@127.0.0.1:port` adds the
/// per-run credentials of that client (flat `user`/`pass` outbound settings, checked against Xray 26.10.21).
pub fn socks5_config(url: &Url, socks_port: u16) -> Result<Value, String> {
    let host = url.host_str().ok_or("Missing SOCKS address")?;
    let port = url.port().ok_or("Missing SOCKS port")?;
    if host != "127.0.0.1" || port == 0 || socks_port == 0 { return Err("Only a loopback SOCKS proxy is supported".into()); }
    let decode = |v: &str| percent_encoding::percent_decode_str(v).decode_utf8().map(|v| v.into_owned()).map_err(|_| "Invalid SOCKS credentials".to_owned());
    let (user, pass) = (decode(url.username())?, decode(url.password().unwrap_or(""))?);
    let mut settings = json!({"address":host,"port":port});
    if !user.is_empty() || !pass.is_empty() {
        // RFC 1929 needs both fields, 1..=255 bytes each.
        if user.is_empty() || pass.is_empty() || user.len() > 255 || pass.len() > 255 { return Err("Invalid SOCKS credentials".into()); }
        settings["user"] = json!(user);
        settings["pass"] = json!(pass);
    }
    Ok(json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks","settings":{"udp":true}}],"outbounds":[{"protocol":"socks","settings":settings}]}))
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
        match key.as_ref() {
            "type" | "security" | "sni" | "pbk" | "sid" | "fp" | "spx" | "flow" | "encryption" => {}
            // Harmless defaults that share-link generators add: accepted only with their no-op values.
            "headerType" if matches!(value.as_ref(), "" | "none") => continue,
            "allowInsecure" | "insecure" if matches!(value.as_ref(), "" | "0" | "false") => continue,
            "packetEncoding" if matches!(value.as_ref(), "" | "none" | "xudp") => continue,
            other => return Err(format!("Unsupported REALITY parameter: {}", other.chars().take(32).collect::<String>())),
        }
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
const TLS_FINGERPRINTS: &[&str] = &["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"];

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
    // Explicit ranges instead of the core's defaults: fixed values (and defaults that change between Xray versions)
    // give the connection a recognisable pattern. Padding equals the server default, so any server accepts it;
    // xmux is client-only and spreads connection lifetime/reuse and caps parallel streams per connection.
    xhttp["xPaddingBytes"] = json!("100-1000");
    xhttp["xmux"] = json!({"maxConcurrency": "16-32", "maxConnections": 0, "cMaxReuseTimes": 0, "hMaxRequestTimes": "600-900", "hMaxReusableSecs": "1800-3000", "hKeepAlivePeriod": 0});
    if let Some(fp) = fingerprint.as_deref() {
        // A Go-default TLS fingerprint identifies a proxy; only browser (uTLS) profiles are accepted.
        if !TLS_FINGERPRINTS.contains(&fp) { return Err("Unsupported TLS fingerprint".into()); }
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

// Public routes keep local networks and Tailscale reachable outside the tunnel.
const PUBLIC_TUN_ROUTES: &[&str] = &[
    "208.0.0.0/4", "200.0.0.0/5", "196.0.0.0/6", "194.0.0.0/7",
    "193.0.0.0/8", "192.0.0.0/9", "192.192.0.0/10", "192.128.0.0/11",
    "192.176.0.0/12", "192.160.0.0/13", "192.172.0.0/14", "192.170.0.0/15",
    "192.169.0.0/16", "128.0.0.0/3", "176.0.0.0/4", "160.0.0.0/5",
    "174.0.0.0/7", "173.0.0.0/8", "172.128.0.0/9", "172.64.0.0/10",
    "172.32.0.0/11", "172.0.0.0/12", "170.0.0.0/7", "168.0.0.0/8",
    "169.0.0.0/9", "169.128.0.0/10", "169.192.0.0/11", "169.224.0.0/12",
    "169.240.0.0/13", "169.248.0.0/14", "169.252.0.0/15", "169.255.0.0/16",
    "64.0.0.0/3", "112.0.0.0/5", "120.0.0.0/6", "124.0.0.0/7",
    "126.0.0.0/8", "104.0.0.0/5", "96.0.0.0/6", "102.0.0.0/7",
    "101.0.0.0/8", "100.128.0.0/9", "100.0.0.0/10", "32.0.0.0/3",
    "16.0.0.0/4", "12.0.0.0/6", "8.0.0.0/7", "11.0.0.0/8",
    "4.0.0.0/6", "2.0.0.0/7", "1.0.0.0/8", "8000::/2",
    "c000::/3", "e000::/4", "f000::/5", "f800::/6",
    "fe00::/9", "fec0::/10", "4000::/2", "2000::/3",
    "1000::/4", "800::/5", "400::/6", "200::/7",
    "100::/8", "80::/9", "40::/10", "20::/11",
    "10::/12", "8::/13", "4::/14", "2::/15",
    "1::/16", "0:8000::/17", "0:4000::/18", "0:2000::/19",
    "0:1000::/20", "0:800::/21", "0:400::/22", "0:200::/23",
    "0:100::/24", "0:80::/25", "0:40::/26", "0:20::/27",
    "0:10::/28", "0:8::/29", "0:4::/30", "0:2::/31",
    "0:1::/32", "0:0:8000::/33", "0:0:4000::/34", "0:0:2000::/35",
    "0:0:1000::/36", "0:0:800::/37", "0:0:400::/38", "0:0:200::/39",
    "0:0:100::/40", "0:0:80::/41", "0:0:40::/42", "0:0:20::/43",
    "0:0:10::/44", "0:0:8::/45", "0:0:4::/46", "0:0:2::/47",
    "0:0:1::/48", "0:0:0:8000::/49", "0:0:0:4000::/50", "0:0:0:2000::/51",
    "0:0:0:1000::/52", "0:0:0:800::/53", "0:0:0:400::/54", "0:0:0:200::/55",
    "0:0:0:100::/56", "0:0:0:80::/57", "0:0:0:40::/58", "0:0:0:20::/59",
    "0:0:0:10::/60", "0:0:0:8::/61", "0:0:0:4::/62", "0:0:0:2::/63",
    "0:0:0:1::/64", "::8000:0:0:0/65", "::4000:0:0:0/66", "::2000:0:0:0/67",
    "::1000:0:0:0/68", "::800:0:0:0/69", "::400:0:0:0/70", "::200:0:0:0/71",
    "::100:0:0:0/72", "::80:0:0:0/73", "::40:0:0:0/74", "::20:0:0:0/75",
    "::10:0:0:0/76", "::8:0:0:0/77", "::4:0:0:0/78", "::2:0:0:0/79",
    "::1:0:0:0/80", "::8000:0:0/81", "::4000:0:0/82", "::2000:0:0/83",
    "::1000:0:0/84", "::800:0:0/85", "::400:0:0/86", "::200:0:0/87",
    "::100:0:0/88", "::80:0:0/89", "::40:0:0/90", "::20:0:0/91",
    "::10:0:0/92", "::8:0:0/93", "::4:0:0/94", "::2:0:0/95",
    "::1:0:0/96", "::8000:0/97", "::4000:0/98", "::2000:0/99",
    "::1000:0/100", "::800:0/101", "::400:0/102", "::200:0/103",
    "::100:0/104", "::80:0/105", "::40:0/106", "::20:0/107",
    "::10:0/108", "::8:0/109", "::4:0/110", "::2:0/111",
    "::1:0/112", "::8000/113", "::4000/114", "::2000/115",
    "::1000/116", "::800/117", "::400/118", "::200/119",
    "::100/120", "::80/121", "::40/122", "::20/123",
    "::10/124", "::8/125", "::4/126", "::2/127",
    "::/128",
];

/// Convert a VLESS/TLS/XHTTP link into a full-system Xray TUN configuration.
pub fn vless_xhttp_tun_config(link: &str, interface: &str) -> Result<Value, String> {
    vless_tun_config_with_relay(link, interface, None)
}

/// What the tunnel must NOT carry: BitTorrent and user-listed domains / IPs / CIDRs go out directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bypass {
    #[serde(default = "default_true")]
    pub bittorrent: bool,
    #[serde(default)]
    pub entries: Vec<String>,
}
fn default_true() -> bool { true }
impl Default for Bypass { fn default() -> Self { Bypass { bittorrent: true, entries: Vec::new() } } }

fn valid_domain(name: &str) -> bool {
    name.len() <= 253 && name.contains('.') && name.split('.').all(|l| {
        !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}
/// A pattern with `*` standing for any characters, e.g. `video*.example.com` or `*.google.*`.
fn valid_wildcard(entry: &str) -> bool {
    entry.contains('*') && entry.chars().any(|c| c.is_ascii_alphanumeric()) && !entry.contains("**") && entry.len() <= 253 && valid_domain(&entry.replace('*', "x"))
}
fn is_wildcard(entry: &str) -> bool { entry.contains('*') }
/// `geoip:ru` / `geosite:category-ru` — lists from Xray's geoip.dat / geosite.dat (name only; existence is checked against the files).
fn valid_geo(entry: &str) -> bool {
    let name = match entry.strip_prefix("geoip:").or_else(|| entry.strip_prefix("geosite:")) { Some(n) => n, None => return false };
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@!".contains(c))
}
fn is_ip_entry(entry: &str) -> bool { valid_ip_or_cidr(entry) || entry.starts_with("geoip:") }
fn valid_ip_or_cidr(entry: &str) -> bool {
    match entry.split_once('/') {
        None => entry.parse::<std::net::IpAddr>().is_ok(),
        Some((ip, bits)) => match (ip.parse::<std::net::IpAddr>(), bits.parse::<u8>()) {
            (Ok(std::net::IpAddr::V4(_)), Ok(n)) => n <= 32,
            (Ok(std::net::IpAddr::V6(_)), Ok(n)) => n <= 128,
            _ => false,
        },
    }
}
impl Bypass {
    /// Lowercase, de-duplicate and strictly validate every entry (a domain, an IP or a CIDR).
    pub fn validated(self) -> Result<Bypass, String> {
        let mut entries: Vec<String> = Vec::new();
        for raw in &self.entries {
            let entry = raw.trim().to_ascii_lowercase();
            // `*.example.com` is just the domain rule (it already covers subdomains); other `*` stay as patterns.
            let entry = match entry.strip_prefix("*.") { Some(rest) if !rest.contains('*') && rest.contains('.') => rest.to_owned(), _ => entry };
            if entry.is_empty() { continue; }
            if !(valid_ip_or_cidr(&entry) || valid_geo(&entry) || valid_domain(&entry) || valid_wildcard(&entry)) {
                return Err(format!("Не похоже на домен, IP или подсеть: {}", raw.chars().take(40).collect::<String>()));
            }
            if !entries.contains(&entry) { entries.push(entry); }
        }
        if entries.len() > 200 { return Err("Слишком много исключений (максимум 200)".into()); }
        Ok(Bypass { bittorrent: self.bittorrent, entries })
    }
}

/// Build a full-system TUN config, optionally dialing a Hysteria 2 outbound
/// through an established VLESS/XHTTP relay for networks that block UDP.
pub fn vless_tun_config_with_relay(link: &str, interface: &str, relay_link: Option<&str>) -> Result<Value, String> {
    vless_tun_config_with_options(link, interface, relay_link, false, None, &Bypass::default())
}

/// The final routing rule of the TUN config: all remaining traffic goes to the VPN outbound.
pub fn tail_rule() -> Value { json!({"type": "field", "network": "tcp,udp", "outboundTag": "vpn-out", "ruleTag": "tail"}) }
/// Parked behind `tail` during a profile switch; becomes effective once `tail` is removed and drops everything.
pub fn kill_rule() -> Value { json!({"type": "field", "network": "tcp,udp", "outboundTag": "block", "ruleTag": "kill"}) }

/// Same as `vless_tun_config_with_relay`; `verbose` turns on the info level and the
/// access log (it records destination addresses, so it is opt-in and diagnostic only).
pub fn vless_tun_config_with_options(link: &str, interface: &str, relay_link: Option<&str>, verbose: bool, api_port: Option<u16>, bypass: &Bypass) -> Result<Value, String> {
    let macos_name = interface.starts_with("utun") && interface[4..].chars().all(|c| c.is_ascii_digit());
    // Windows (wintun) adapters have a free-form name; accept a short alphanumeric one.
    let named = !interface.is_empty() && interface.len() <= 32 && interface.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !macos_name && !(cfg!(windows) && named) {
        return Err("Invalid TUN interface name".into());
    }
    let mut config = vless_config(link, 10808)?;
    // Helper keeps Xray's stdout in a root-only xray.log; an empty access path sends the access log there.
    // Per-outbound traffic counters, readable only through a loopback StatsService (no handler/control services).
    if let Some(port) = api_port {
        config["stats"] = json!({});
        config["policy"] = json!({"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}});
        // HandlerService/RoutingService let the helper swap the VPN outbound in place (profile switch without restarting Xray).
        config["api"] = json!({"tag": "api", "listen": format!("127.0.0.1:{port}"), "services": ["StatsService", "HandlerService", "RoutingService"]});
    }
    if verbose { config["log"] = json!({"loglevel": "info", "access": ""}); }
    if let Some(relay_link) = relay_link {
        if !link.starts_with("hysteria2://") && config["outbounds"][0]["streamSettings"]["security"] != "reality" { return Err("A relay is supported only for Hysteria 2 or REALITY".into()); }
        let mut relay = vless_config(relay_link, 10808)?["outbounds"][0].clone();
        if relay["protocol"] != "vless" || relay["streamSettings"]["network"] != "xhttp" || relay["streamSettings"]["security"] != "tls" {
            return Err("The Hysteria relay must be VLESS over TLS/XHTTP".into());
        }
        relay["tag"] = json!("vpn-relay");
        config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"] = json!("vpn-relay");
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
            "autoSystemRoutingTable": PUBLIC_TUN_ROUTES,
            "autoOutboundsInterface": "auto"
        },
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}
    }]);
    config["outbounds"][0]["tag"] = json!("vpn-out");
    // BitTorrent goes straight out of the physical interface, not through the VPN.
    config["outbounds"].as_array_mut().ok_or("Invalid outbound config")?
        .push(json!({"tag": "direct", "protocol": "freedom"}));
    let bypass = bypass.clone().validated()?;
    let mut rules: Vec<Value> = Vec::new();
    if bypass.bittorrent { rules.push(json!({"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"})); }
    let domains: Vec<String> = bypass.entries.iter().filter(|e| !is_ip_entry(e)).map(|e| {
        if e.starts_with("geosite:") { e.clone() } else if is_wildcard(e) { format!("regexp:^{}$", e.replace('.', "\\.").replace('*', ".*")) } else { format!("domain:{e}") }
    }).collect();
    if !domains.is_empty() {
        // Excluded domains must be dialed by name over IPv4: many networks have no IPv6, and the TUN accepts the
        // handshake locally, so a direct IPv6 dial that fails would never fall back to IPv4 in the browser.
        config["inbounds"][0]["sniffing"]["routeOnly"] = json!(false);
        let direct = config["outbounds"].as_array_mut().and_then(|o| o.last_mut()).ok_or("Invalid outbound config")?;
        direct["settings"] = json!({"domainStrategy": "UseIPv4"});
        // Resolve those names with our own DNS, sent out of the physical interface. Without it Xray falls back to the
        // system resolver, whose first server can be unreachable (e.g. Tailscale's IPv6 MagicDNS) and stalls ~30 s.
        // TCP, not UDP: a direct UDP socket cannot be bound to the physical interface by Xray's TUN on macOS
        // ("failed to set interface: invalid argument"), so UDP queries (and QUIC) from the direct outbound time out.
        config["dns"] = json!({"servers": ["tcp://1.1.1.1", "tcp://1.0.0.1"], "queryStrategy": "UseIPv4"});
        rules.insert(0, json!({"type": "field", "ip": ["1.1.1.1", "1.0.0.1"], "port": "53", "network": "tcp", "outboundTag": "direct"}));
    }
    let ips: Vec<&String> = bypass.entries.iter().filter(|e| is_ip_entry(e)).collect();
    if !domains.is_empty() { rules.push(json!({"type": "field", "domain": domains, "outboundTag": "direct"})); }
    if !ips.is_empty() { rules.push(json!({"type": "field", "ip": ips, "outboundTag": "direct"})); }
    // Everything else goes to the VPN via an explicit tail rule. A profile switch replaces the VPN outbound in place:
    // the helper first parks a "kill" rule behind it, removes the tail rule (so everything is blackholed), swaps the
    // outbound and restores the tail rule, so no step of the switch can send traffic around the tunnel.
    config["outbounds"].as_array_mut().ok_or("Invalid outbound config")?.push(json!({"tag": "block", "protocol": "blackhole"}));
    rules.push(tail_rule());
    config["routing"] = json!({"domainStrategy": "AsIs", "rules": rules});
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builds_xhttp_client_and_keeps_local_proxy_private() {
        let link = "vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=xhttp&security=tls&sni=example.org&path=%2Fvpn&mode=auto";
        let config = vless_xhttp_config(link, 10808).unwrap();
        assert_eq!(config["log"]["loglevel"], "warning");
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
        assert_eq!(stream["xhttpSettings"]["xPaddingBytes"], "100-1000");
        assert_eq!(stream["xhttpSettings"]["xmux"]["maxConcurrency"], "16-32");
        assert!(vless_xhttp_config(&format!("{link}&fp=golang"), 10808).is_err());
        assert!(vless_xhttp_config(&format!("{link}&fp=chrome"), 10808).is_ok());
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
        assert_eq!(config["log"]["loglevel"], "warning");
        assert!(config["log"].get("access").is_none());
        let verbose=vless_tun_config_with_options(link,"utun10",None,true,Some(18085),&Bypass::default()).unwrap();
        assert_eq!(verbose["log"]["loglevel"], "info");
        assert_eq!(verbose["log"]["access"], "");
        assert_eq!(verbose["api"]["listen"], "127.0.0.1:18085");
        assert_eq!(verbose["api"]["services"], json!(["StatsService", "HandlerService", "RoutingService"]));
        assert_eq!(verbose["policy"]["system"]["statsOutboundDownlink"], true);
        assert!(config.get("api").is_none());
        let custom=Bypass{bittorrent:false,entries:vec!["*.Example.org".into()," 10.1.0.0/16 ".into(),"2001:db8::/32".into(),"example.org".into()]};
        let routed=vless_tun_config_with_options(link,"utun10",None,false,None,&custom).unwrap();
        let rules=routed["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(),4);
        // The last rule sends the rest to the VPN; a blackhole outbound exists for the switch procedure.
        assert_eq!(rules[3]["ruleTag"],"tail");
        assert_eq!(rules[3]["outboundTag"],"vpn-out");
        assert!(routed["routing"].get("balancers").is_none());
        assert_eq!(kill_rule()["outboundTag"],"block");
        assert!(routed["outbounds"].as_array().unwrap().iter().any(|o| o["tag"]=="block" && o["protocol"]=="blackhole"));
        assert_eq!(rules[0]["ip"],json!(["1.1.1.1","1.0.0.1"]));
        assert_eq!(rules[1]["domain"],json!(["domain:example.org"]));
        assert_eq!(rules[2]["ip"],json!(["10.1.0.0/16","2001:db8::/32"]));
        assert!(config["routing"]["rules"][0]["protocol"]==json!(["bittorrent"]));
        // Domain exclusions switch sniffing to destination override and the direct outbound to IPv4.
        assert_eq!(routed["inbounds"][0]["sniffing"]["routeOnly"], false);
        assert_eq!(routed["outbounds"].as_array().unwrap().iter().find(|o| o["tag"]=="direct").unwrap()["settings"]["domainStrategy"], "UseIPv4");
        assert_eq!(config["inbounds"][0]["sniffing"]["routeOnly"], true);
        assert_eq!(routed["dns"]["servers"], json!(["tcp://1.1.1.1","tcp://1.0.0.1"]));
        assert_eq!(routed["routing"]["rules"][0]["network"], "tcp");
        assert_eq!(routed["routing"]["rules"][0]["port"], "53");
        assert_eq!(routed["routing"]["rules"][0]["outboundTag"], "direct");
        assert!(config.get("dns").is_none());
        let ip_only=vless_tun_config_with_options(link,"utun10",None,false,None,&Bypass{bittorrent:true,entries:vec!["10.0.0.0/8".into()]}).unwrap();
        assert_eq!(ip_only["inbounds"][0]["sniffing"]["routeOnly"], true);
        // Wildcards become regexp rules; `*.domain` stays a plain domain rule.
        let wild=Bypass{bittorrent:false,entries:vec!["*.Example.com".into(),"video*.cdn.example.org".into(),"*.google.*".into()]}.validated().unwrap();
        assert_eq!(wild.entries,vec!["example.com","video*.cdn.example.org","*.google.*"]);
        let wr=vless_tun_config_with_options(link,"utun10",None,false,None,&wild).unwrap();
        assert_eq!(wr["routing"]["rules"][1]["domain"],json!(["domain:example.com","regexp:^video.*\\.cdn\\.example\\.org$","regexp:^.*\\.google\\..*$"]));
        // A whole zone: `*.ru` matches every .ru name (a bare `ru` is still rejected).
        let zone=Bypass{bittorrent:false,entries:vec!["*.RU".into()]}.validated().unwrap();
        assert_eq!(zone.entries,vec!["*.ru"]);
        let zr=vless_tun_config_with_options(link,"utun10",None,false,None,&zone).unwrap();
        assert_eq!(zr["routing"]["rules"][1]["domain"],json!(["regexp:^.*\\.ru$"]));
        assert!(Bypass{bittorrent:true,entries:vec!["ru".into()]}.validated().is_err());
        // geoip / geosite lists pass through to Xray untouched.
        let geo=Bypass{bittorrent:false,entries:vec!["GeoSite:TLD-RU".into(),"geosite:category-gov-ru".into(),"geoip:ru".into(),"geoip:private".into(),"10.0.0.0/8".into()]}.validated().unwrap();
        let gr=vless_tun_config_with_options(link,"utun10",None,false,None,&geo).unwrap();
        assert_eq!(gr["routing"]["rules"][1]["domain"],json!(["geosite:tld-ru","geosite:category-gov-ru"]));
        assert_eq!(gr["routing"]["rules"][2]["ip"],json!(["geoip:ru","geoip:private","10.0.0.0/8"]));
        for bad in ["geoip:","geosite:a b","geoip:ru/x","geo:ru"] { assert!(Bypass{bittorrent:true,entries:vec![bad.into()]}.validated().is_err(),"{bad}"); }
        for bad in ["*","**.com","a**b.com","*.*","exa mple.*"] { assert!(Bypass{bittorrent:true,entries:vec![bad.into()]}.validated().is_err(),"{bad}"); }
        for bad in ["bad entry","a..b","-x.com","10.0.0.0/33","localhost","1.2.3.4/x"] {
            assert!(Bypass{bittorrent:true,entries:vec![bad.into()]}.validated().is_err(),"{bad}");
        }
        assert_eq!(config["outbounds"][0]["streamSettings"]["security"],"reality");
        assert_eq!(config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],"xtls-rprx-vision");
        assert!(vless_config(&link.replace("sid=01234567","sid=xyz"),10808).is_err());
        assert!(vless_config(&link.replace("pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","pbk=bad"),10808).is_err());
    }
    #[test]
    fn chains_reality_through_xhttp_relay() {
        let reality = "vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=tcp&security=reality&sni=www.apple.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01234567&fp=chrome";
        let relay = "vless://12345678-1234-1234-1234-123456789abc@relay.example:8443?type=xhttp&security=tls&sni=relay.example&path=%2F";
        let config = vless_tun_config_with_relay(reality, "utun10", Some(relay)).unwrap();
        assert_eq!(config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"], "vpn-relay");
        assert_eq!(config["outbounds"][1]["tag"], "vpn-relay");
        assert_eq!(config["outbounds"][1]["streamSettings"]["network"], "xhttp");
    }
    #[test]
    fn reality_accepts_noop_defaults_and_names_unsupported_parameters() {
        let link="vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=tcp&security=reality&sni=www.microsoft.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01234567&fp=chrome&spx=%2F&flow=xtls-rprx-vision";
        assert!(vless_config(&format!("{link}&headerType=none&packetEncoding=xudp&allowInsecure=0"),10808).is_ok());
        assert!(vless_config(&format!("{link}&headerType=http"),10808).is_err());
        let err=vless_config(&format!("{link}&pqv=secret"),10808).unwrap_err();
        assert!(err.contains("pqv") && !err.contains("secret"));
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
        assert_eq!(config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"], "vpn-relay");
        assert_eq!(config["outbounds"][1]["protocol"], "vless");
        assert_eq!(config["outbounds"][1]["streamSettings"]["network"], "xhttp");
        assert!(vless_tun_config_with_relay(h, "utun10", Some("hysteria2://bad@relay:443")).is_err());
    }
}

#[cfg(test)]
mod socks_tests {
    use super::*;
    #[test]
    fn loopback_socks_link_becomes_the_vpn_outbound_of_the_tun_config() {
        let config = vless_tun_config_with_options("socks5://127.0.0.1:19999", "utun10", None, false, Some(18000), &Bypass::default()).unwrap();
        let out = &config["outbounds"][0];
        assert_eq!((out["tag"].as_str(), out["protocol"].as_str(), out["settings"]["port"].as_u64()), (Some("vpn-out"), Some("socks"), Some(19999)));
        assert!(vless_config("socks5://10.0.0.1:1080", 10808).is_err(), "only loopback is allowed");
        assert!(vless_config("socks5://127.0.0.1", 10808).is_err());
    }
    #[test]
    fn socks_link_without_credentials_has_no_user_in_the_outbound() {
        let config = vless_config("socks5://127.0.0.1:19999", 10808).unwrap();
        assert_eq!(config["outbounds"][0]["settings"], json!({"address":"127.0.0.1","port":19999}));
    }
    #[test]
    fn socks_link_credentials_go_into_the_outbound() {
        let config = vless_config("socks5://0011aabb:ccdd%40eeff@127.0.0.1:19999", 10808).unwrap();
        assert_eq!(config["outbounds"][0]["settings"], json!({"address":"127.0.0.1","port":19999,"user":"0011aabb","pass":"ccdd@eeff"}));
        let tun = vless_tun_config_with_options("socks5://u:p@127.0.0.1:19999", "utun10", None, false, Some(18000), &Bypass::default()).unwrap();
        assert_eq!((tun["outbounds"][0]["tag"].as_str(), tun["outbounds"][0]["settings"]["user"].as_str(), tun["outbounds"][0]["settings"]["pass"].as_str()), (Some("vpn-out"), Some("u"), Some("p")));
        assert!(vless_config("socks5://u:p@10.0.0.1:1080", 10808).is_err(), "credentials do not lift the loopback restriction");
        assert!(vless_config("socks5://u:p@localhost:1080", 10808).is_err());
        assert!(vless_config("socks5://u@127.0.0.1:1080", 10808).is_err(), "user without password");
        assert!(vless_config("socks5://:p@127.0.0.1:1080", 10808).is_err(), "password without user");
    }
}
