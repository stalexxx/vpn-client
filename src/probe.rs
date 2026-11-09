//! Liveness probes for the configured servers, made *outside* Xray and outside the tunnel.
//!
//! A probe is a single TCP `connect` to the server's `host:port` (no TLS handshake, so nothing that looks like a
//! proxy client fingerprint) timed in milliseconds. While the VPN is up the socket is bound to the physical
//! interface so the probe measures the server, not the path through the TUN (macOS: `IP_BOUND_IF`; elsewhere the
//! scheduler pauses while the tunnel is up). Rounds run every 3–6 minutes with a random spread and random gaps
//! between servers, so the probes do not form a recognisable pattern. UDP-only profiles (Hysteria 2) are not probed.
use serde::Serialize;
use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ROUND_MIN_SECS: u64 = 180;
const ROUND_MAX_SECS: u64 = 360;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target { pub key: String, pub host: String, pub port: u16, pub udp: bool }

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ProbeResult {
    /// Round-trip of the TCP handshake; `None` when the server did not answer.
    pub ms: Option<u32>,
    pub error: Option<String>,
    /// Unix seconds of the check.
    pub ts: u64,
    /// UDP-only profile: not probed.
    pub udp: bool,
}

#[derive(Default)]
pub struct ProbeStore(Mutex<HashMap<String, ProbeResult>>);
impl ProbeStore {
    pub fn snapshot(&self) -> HashMap<String, ProbeResult> { self.0.lock().map(|m| m.clone()).unwrap_or_default() }
    fn set(&self, key: &str, result: ProbeResult) { if let Ok(mut m) = self.0.lock() { m.insert(key.to_owned(), result); } }
    /// Forget profiles that no longer exist.
    fn retain(&self, keys: &[String]) { if let Ok(mut m) = self.0.lock() { m.retain(|k, _| keys.contains(k)); } }
}

static TUNNEL_UP: AtomicBool = AtomicBool::new(false);
/// Platforms that cannot bind probes to the physical interface pause them while the tunnel is up.
pub fn set_tunnel_up(up: bool) { TUNNEL_UP.store(up, Ordering::SeqCst); }
fn probes_allowed() -> bool { cfg!(target_os = "macos") || !TUNNEL_UP.load(Ordering::SeqCst) }

fn now_secs() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
fn random_between(lo: u64, hi: u64) -> u64 {
    let mut bytes = [0u8; 8];
    if crate::compat::random_bytes(&mut bytes).is_err() { return (lo + hi) / 2; }
    lo + u64::from_le_bytes(bytes) % (hi - lo + 1)
}

/// Host and port a share link connects to. Hysteria 2 (QUIC) and AmneziaWG are UDP and flagged `udp`.
pub fn target_from_link(key: &str, link: &str) -> Option<Target> {
    let url = url::Url::parse(link).ok()?;
    let udp = matches!(url.scheme(), "hysteria2" | "hy2" | "awg");
    let host = url.host_str()?.trim_start_matches('[').trim_end_matches(']').to_owned();
    let port = url.port().or(if udp { Some(443) } else { None })?;
    if host.is_empty() || port == 0 { return None; }
    Some(Target { key: key.to_owned(), host, port, udp })
}

/// Every profile the client can show: imported links and cached server profiles.
pub fn probe_targets() -> Result<Vec<Target>, String> {
    let mut targets = Vec::new();
    for item in crate::list_imported_profiles()? {
        let Some(id) = item["id"].as_str() else { continue };
        if let Some(t) = crate::imported_share_link(id).ok().and_then(|l| target_from_link(&format!("imported:{id}"), &l)) { targets.push(t); }
    }
    for p in crate::list_connectable_profiles().unwrap_or_default() {
        let (Some(server), Some(inbound), Some(email)) = (p["server_id"].as_str(), p["inbound_id"].as_u64(), p["email"].as_str()) else { continue };
        let key = format!("{server}:{inbound}:{email}");
        if let Some(t) = crate::cached_client_share_link(server, inbound, email).ok().and_then(|l| target_from_link(&key, &l)) { targets.push(t); }
    }
    Ok(targets)
}

/// Name of the physical interface the default route uses (never a tunnel).
#[cfg(target_os = "macos")]
fn physical_interface() -> Result<String, String> {
    let output = std::process::Command::new("/sbin/route").args(["-n", "get", "default"]).output().map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&output.stdout);
    let name = text.lines().find_map(|l| l.trim().strip_prefix("interface:")).map(|v| v.trim().to_owned()).ok_or("нет маршрута по умолчанию")?;
    if name.starts_with("utun") { return Err("маршрут по умолчанию ведёт в туннель".into()); }
    Ok(name)
}

fn connect_bound(addr: &SocketAddr, timeout: Duration, interface: Option<&str>) -> Result<(), String> {
    use socket2::{Domain, Socket, Type};
    let socket = Socket::new(Domain::for_address(*addr), Type::STREAM, None).map_err(|e| e.to_string())?;
    #[cfg(target_os = "macos")]
    if let Some(name) = interface {
        let cname = std::ffi::CString::new(name).map_err(|_| "некорректное имя интерфейса")?;
        let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        let index = std::num::NonZeroU32::new(index).ok_or("интерфейс не найден")?;
        if addr.is_ipv4() { socket.bind_device_by_index_v4(Some(index)) } else { socket.bind_device_by_index_v6(Some(index)) }.map_err(|e| e.to_string())?;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = interface;
    socket.connect_timeout(&(*addr).into(), timeout).map_err(|e| match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "таймаут".to_owned(),
        std::io::ErrorKind::ConnectionRefused => "отказ".to_owned(),
        _ => e.to_string(),
    })
}

/// Times a TCP handshake to `host:port` (IPv4 addresses first). `interface` pins the probe to a physical interface.
pub fn probe_tcp_with(host: &str, port: u16, timeout: Duration, interface: Option<&str>) -> Result<u32, String> {
    let mut addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().map_err(|_| "имя не разрешилось".to_owned())?.collect();
    addrs.sort_by_key(|a| !a.is_ipv4());
    let mut last = "нет адресов".to_owned();
    for addr in addrs.iter().take(2) {
        let started = std::time::Instant::now();
        match connect_bound(addr, timeout, interface) {
            Ok(()) => return Ok(started.elapsed().as_millis().clamp(1, u32::MAX as u128) as u32),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn probe_target(target: &Target) -> ProbeResult {
    let ts = now_secs();
    if target.udp { return ProbeResult { ms: None, error: None, ts, udp: true }; }
    #[cfg(target_os = "macos")]
    let interface = physical_interface();
    #[cfg(not(target_os = "macos"))]
    let interface: Result<String, String> = Err(String::new());
    #[cfg(target_os = "macos")]
    let bound = match &interface { Ok(name) => Some(name.as_str()), Err(e) => return ProbeResult { ms: None, error: Some(e.clone()), ts, udp: false } };
    #[cfg(not(target_os = "macos"))]
    let bound = { let _ = &interface; None };
    match probe_tcp_with(&target.host, target.port, CONNECT_TIMEOUT, bound) {
        Ok(ms) => ProbeResult { ms: Some(ms), error: None, ts, udp: false },
        Err(error) => ProbeResult { ms: None, error: Some(error), ts, udp: false },
    }
}

/// One pass over all servers in random order, with a random pause between them.
fn run_round(store: &ProbeStore) {
    let Ok(mut targets) = probe_targets() else { return };
    store.retain(&targets.iter().map(|t| t.key.clone()).collect::<Vec<_>>());
    // Fisher–Yates with OS randomness.
    for i in (1..targets.len()).rev() { targets.swap(i, random_between(0, i as u64) as usize); }
    // One probe per distinct endpoint; the result is shared by profiles pointing at it.
    let mut done: HashMap<(String, u16), ProbeResult> = HashMap::new();
    for (index, target) in targets.iter().enumerate() {
        if !probes_allowed() { return; }
        let id = (target.host.clone(), target.port);
        let result = match done.get(&id) { Some(r) => r.clone(), None => {
            if index > 0 { std::thread::sleep(Duration::from_millis(random_between(800, 3500))); }
            let r = probe_target(target); done.insert(id, r.clone()); r } };
        store.set(&target.key, result);
    }
}

pub struct ProbeHandle { pub store: Arc<ProbeStore>, wake: mpsc::Sender<()> }
impl ProbeHandle {
    /// Ask the scheduler for an immediate round (the "check now" button).
    pub fn probe_now(&self) { let _ = self.wake.send(()); }
}

/// Starts the background scheduler: a first round shortly after start, then every 3–6 minutes.
pub fn start() -> ProbeHandle {
    let store = Arc::new(ProbeStore::default());
    let (wake, wakeup) = mpsc::channel::<()>();
    let worker = store.clone();
    std::thread::spawn(move || {
        let mut wait = Duration::from_secs(3);
        loop {
            // A manual request cuts the wait short; extra queued requests are coalesced into one round.
            match wakeup.recv_timeout(wait) {
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
                _ => while wakeup.try_recv().is_ok() {},
            }
            if probes_allowed() { run_round(&worker); }
            wait = Duration::from_secs(random_between(ROUND_MIN_SECS, ROUND_MAX_SECS));
        }
    });
    ProbeHandle { store, wake }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_comes_from_the_link_host_and_port() {
        let t = target_from_link("k", "vless://12345678-1234-1234-1234-123456789abc@example.org:8443?type=xhttp&security=tls").unwrap();
        assert_eq!((t.host.as_str(), t.port, t.udp), ("example.org", 8443, false));
        let v6 = target_from_link("k", "vless://12345678-1234-1234-1234-123456789abc@[2001:db8::1]:443?type=tcp").unwrap();
        assert_eq!(v6.host, "2001:db8::1");
        // Hysteria 2 is UDP: flagged, and 443 is assumed when the link omits the port.
        let hy = target_from_link("k", "hysteria2://secret@example.org?sni=example.org").unwrap();
        assert_eq!((hy.port, hy.udp), (443, true));
        assert!(target_from_link("k", "vless://id@example.org?type=tcp").is_none());
        assert!(target_from_link("k", "not a link").is_none());
    }
    #[test]
    fn tcp_probe_measures_an_open_port_and_reports_a_closed_one() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(probe_tcp_with("127.0.0.1", port, Duration::from_secs(2), None).unwrap() >= 1);
        drop(listener);
        assert_eq!(probe_tcp_with("127.0.0.1", port, Duration::from_secs(2), None).unwrap_err(), "отказ");
        assert!(probe_tcp_with("no-such-host.invalid", 443, Duration::from_secs(2), None).is_err());
    }
    #[test]
    fn udp_profiles_are_marked_not_probed_and_jitter_stays_in_range() {
        let r = probe_target(&Target { key: "k".into(), host: "example.org".into(), port: 443, udp: true });
        assert!(r.udp && r.ms.is_none() && r.error.is_none());
        for _ in 0..50 { let v = random_between(ROUND_MIN_SECS, ROUND_MAX_SECS); assert!((ROUND_MIN_SECS..=ROUND_MAX_SECS).contains(&v)); }
    }
    #[test]
    fn store_forgets_deleted_profiles() {
        let store = ProbeStore::default();
        store.set("a", ProbeResult { ms: Some(5), error: None, ts: 1, udp: false });
        store.set("b", ProbeResult { ms: None, error: Some("таймаут".into()), ts: 1, udp: false });
        store.retain(&["a".to_owned()]);
        let snap = store.snapshot();
        assert!(snap.contains_key("a") && !snap.contains_key("b"));
    }
}

/// Public address the world sees for this machine (goes through the tunnel when it is up).
pub fn exit_ip() -> Result<String, String> {
    let client = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(8)).build().map_err(|e| e.to_string())?;
    let body: serde_json::Value = client.get("https://api.ipify.org?format=json").send().and_then(|r| r.json()).map_err(|e| e.to_string())?;
    body["ip"].as_str().map(str::to_string).ok_or_else(|| "нет поля ip".to_string())
}
