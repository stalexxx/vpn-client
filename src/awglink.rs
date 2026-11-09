//! AmneziaWG profiles as share links: `awg://HOST:PORT/?c=<base64url(.conf)>#name`.
//! The link carries the whole client config (including the private key), so it must be kept private like any other link.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::io::Read;

pub const SCHEME: &str = "awg://";

fn conf_values(conf: &str) -> Vec<(String, String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in conf.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') { continue; }
        if line.starts_with('[') { section = line.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase(); continue; }
        if let Some((k, v)) = line.split_once('=') { out.push((section.clone(), k.trim().to_ascii_lowercase(), v.trim().to_owned())); }
    }
    out
}
fn get<'a>(vals: &'a [(String, String, String)], section: &str, key: &str) -> Option<&'a str> {
    vals.iter().find(|(s, k, _)| s == section && k == key).map(|(_, _, v)| v.as_str())
}
fn valid_key(v: &str) -> bool { base64::engine::general_purpose::STANDARD.decode(v).map(|b| b.len() == 32).unwrap_or(false) }

/// Checks the config has what the client needs and returns (host, port).
pub fn validate_conf(conf: &str) -> Result<(String, u16), String> {
    let vals = conf_values(conf);
    if !vals.iter().any(|(s, _, _)| s == "interface") || !vals.iter().any(|(s, _, _)| s == "peer") { return Err("В конфиге нет секций [Interface] и [Peer]".into()); }
    if !get(&vals, "interface", "privatekey").is_some_and(valid_key) { return Err("В конфиге нет корректного PrivateKey".into()); }
    if !get(&vals, "peer", "publickey").is_some_and(valid_key) { return Err("В конфиге нет корректного PublicKey сервера".into()); }
    if let Some(psk) = get(&vals, "peer", "presharedkey") { if !valid_key(psk) { return Err("Некорректный PresharedKey".into()); } }
    let address = get(&vals, "interface", "address").ok_or("В конфиге нет Address")?;
    if !address.split(',').all(|a| a.trim().parse::<ipnet_like::Prefix>().is_ok()) { return Err("Некорректный Address".into()); }
    let endpoint = get(&vals, "peer", "endpoint").ok_or("В конфиге нет Endpoint")?;
    let (host, port) = endpoint.rsplit_once(':').ok_or("Некорректный Endpoint")?;
    let port: u16 = port.parse().map_err(|_| "Некорректный порт Endpoint")?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() || port == 0 || host.contains(|c: char| c.is_whitespace() || c == '/' || c == '#' || c == '?') { return Err("Некорректный Endpoint".into()); }
    Ok((host.to_owned(), port))
}
mod ipnet_like {
    pub struct Prefix;
    impl std::str::FromStr for Prefix {
        type Err = ();
        fn from_str(s: &str) -> Result<Self, ()> {
            let (ip, len) = s.split_once('/').unwrap_or((s, "32"));
            let ip: std::net::IpAddr = ip.parse().map_err(|_| ())?;
            let len: u8 = len.parse().map_err(|_| ())?;
            if len > if ip.is_ipv4() { 32 } else { 128 } { return Err(()); }
            Ok(Prefix)
        }
    }
}

pub fn conf_to_link(conf: &str, name: Option<&str>) -> Result<String, String> {
    let (host, port) = validate_conf(conf)?;
    let host = if host.contains(':') { format!("[{host}]") } else { host };
    let mut link = format!("{SCHEME}{host}:{port}/?c={}", URL_SAFE_NO_PAD.encode(conf.as_bytes()));
    if let Some(name) = name.map(str::trim).filter(|n| !n.is_empty()) { link.push('#'); link.push_str(&percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC).to_string()); }
    Ok(link)
}
pub fn link_to_conf(link: &str) -> Result<String, String> {
    let url = url::Url::parse(link).map_err(|_| "Некорректная ссылка AmneziaWG")?;
    if url.scheme() != "awg" { return Err("Это не ссылка AmneziaWG".into()); }
    let c = url.query_pairs().find(|(k, _)| k == "c").map(|(_, v)| v.into_owned()).ok_or("В ссылке нет конфигурации")?;
    let conf = String::from_utf8(URL_SAFE_NO_PAD.decode(c.trim_end_matches('=')).map_err(|_| "Конфигурация в ссылке повреждена")?).map_err(|_| "Конфигурация в ссылке повреждена")?;
    validate_conf(&conf)?;
    Ok(conf)
}
/// Name stored in the link fragment, if any.
pub fn link_name(link: &str) -> Option<String> {
    let url = url::Url::parse(link).ok()?;
    let name = percent_encoding::percent_decode_str(url.fragment()?).decode_utf8().ok()?.into_owned();
    Some(name).filter(|n| !n.is_empty())
}

/// Reads the `.conf` out of an Amnezia `vpn://` link (base64url of Qt qCompress of the container JSON).
/// Returns (config, description).
pub fn vpn_link_to_conf(link: &str) -> Result<(String, Option<String>), String> {
    let body = link.trim().strip_prefix("vpn://").ok_or("Это не ссылка vpn://")?;
    let raw = URL_SAFE_NO_PAD.decode(body.trim_end_matches('=')).map_err(|_| "Ссылка vpn:// повреждена")?;
    if raw.len() < 5 { return Err("Ссылка vpn:// повреждена".into()); }
    let mut json = Vec::new();
    flate2::read::ZlibDecoder::new(&raw[4..]).take(8 << 20).read_to_end(&mut json).map_err(|_| "Не удалось распаковать ссылку vpn://")?;
    let doc: serde_json::Value = serde_json::from_slice(&json).map_err(|_| "Ссылка vpn:// содержит некорректные данные")?;
    let container = doc["containers"].as_array().and_then(|c| c.iter().find(|c| c["container"] == "amnezia-awg" || c["awg"].is_object()))
        .ok_or("В ссылке нет контейнера AmneziaWG (поддерживается только AmneziaWG)")?;
    let last: serde_json::Value = serde_json::from_str(container["awg"]["last_config"].as_str().ok_or("В ссылке нет конфигурации клиента")?).map_err(|_| "Конфигурация клиента в ссылке повреждена")?;
    let conf = last["config"].as_str().ok_or("В ссылке нет текста конфигурации")?.to_owned();
    validate_conf(&conf)?;
    Ok((conf, doc["description"].as_str().map(str::to_owned).filter(|d| !d.is_empty())))
}

/// Everything importable out of pasted text: `awg://`, `vpn://` links or a whole `.conf`. Returns (link, name).
pub fn extract_awg(text: &str) -> Vec<Result<(String, Option<String>), String>> {
    let mut out = Vec::new();
    if text.contains("[Interface]") && text.contains("[Peer]") {
        out.push(conf_to_link(text, None).map(|l| (l, None)));
        return out;
    }
    for part in text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',') {
        if part.starts_with("vpn://") {
            out.push(vpn_link_to_conf(part).and_then(|(conf, desc)| conf_to_link(&conf, desc.as_deref()).map(|l| (l, desc))));
        } else if part.starts_with(SCHEME) {
            out.push(link_to_conf(part).map(|_| (part.to_owned(), link_name(part))));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    const CONF: &str = "[Interface]\nPrivateKey = cGxlYXNlLWRvLW5vdC11c2UtdGhpcy1rZXktMDAwMDA=\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1\nMTU = 1280\nJc = 4\nJmin = 50\nJmax = 1000\nS1 = 94\nS2 = 125\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n\n[Peer]\nPublicKey = cGxlYXNlLWRvLW5vdC11c2UtdGhpcy1rZXktMDAwMDA=\nPresharedKey = cGxlYXNlLWRvLW5vdC11c2UtdGhpcy1rZXktMDAwMDA=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.5:47821\nPersistentKeepalive = 25\n";
    #[test]
    fn conf_roundtrips_through_link() {
        let link = conf_to_link(CONF, Some("silicon mac")).unwrap();
        assert!(link.starts_with("awg://203.0.113.5:47821/?c="));
        assert_eq!(link_to_conf(&link).unwrap(), CONF);
        assert_eq!(link_name(&link).as_deref(), Some("silicon mac"));
    }
    #[test]
    fn bad_configs_are_rejected() {
        assert!(conf_to_link("[Interface]\n[Peer]\n", None).is_err());
        assert!(conf_to_link(&CONF.replace("203.0.113.5:47821", "nohostport"), None).is_err());
        assert!(conf_to_link(&CONF.replacen("cGxlYXNl", "bad", 1), None).is_err());
    }
    #[test]
    fn vpn_link_made_by_us_is_read_back() {
        use std::io::Write;
        let details = serde_json::json!({"config": CONF}).to_string();
        let doc = serde_json::json!({"containers":[{"awg":{"last_config":details},"container":"amnezia-awg"}],"description":"srv"});
        let json = serde_json::to_vec(&doc).unwrap();
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&json).unwrap();
        let mut raw = (json.len() as u32).to_be_bytes().to_vec();
        raw.extend(enc.finish().unwrap());
        let link = format!("vpn://{}", URL_SAFE_NO_PAD.encode(raw));
        let (conf, desc) = vpn_link_to_conf(&link).unwrap();
        assert_eq!(conf, CONF);
        assert_eq!(desc.as_deref(), Some("srv"));
        assert_eq!(extract_awg(&format!("вот {link} ок")).len(), 1);
    }
    #[test]
    fn whole_conf_text_is_extracted() {
        let found = extract_awg(CONF);
        assert_eq!(found.len(), 1);
        assert!(found[0].as_ref().unwrap().0.starts_with("awg://"));
    }
}
