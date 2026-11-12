//! AmneziaWG + WARP servers (see `vpn_core::amnezia`): install, clients, removal.
use vpn_core::amnezia::{self, AwgClient, AwgServer};

fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> impl std::future::Future<Output = Result<T, String>> {
    async move { tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())? }
}

#[tauri::command]
pub fn awg_list_servers() -> Result<Vec<AwgServer>, String> { amnezia::list_servers() }

#[tauri::command]
pub async fn awg_install(name: String, ssh_target: String, ssh_key: Option<String>, port: Option<u16>, tools: Option<String>, country: Option<String>) -> Result<AwgServer, String> {
    blocking(move || { amnezia::clear_install_log(); amnezia::install(&name, &ssh_target, ssh_key.as_deref(), port, country, tools.as_deref().unwrap_or("github")) }).await
}

/// Lines of the current (or last) install run, polled by the admin window while it runs.
#[tauri::command]
pub fn awg_install_log() -> Vec<String> { amnezia::install_log() }

#[tauri::command]
pub async fn awg_clients(id: String) -> Result<Vec<AwgClient>, String> {
    blocking(move || amnezia::list_clients(&amnezia::find_server(&id)?)).await
}

#[tauri::command]
pub async fn awg_status(id: String) -> Result<String, String> {
    blocking(move || amnezia::status(&amnezia::find_server(&id)?)).await
}

fn deliver(server: &AwgServer, client: &str, conf: String) -> Result<serde_json::Value, String> {
    let dir = std::env::var_os("HOME").map(std::path::PathBuf::from).ok_or("нет HOME")?.join("Downloads");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let safe: String = server.name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
    let path = dir.join(format!("{safe}-{client}.conf"));
    // Create the file 0600 so the private key is never readable, even briefly.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; opts.mode(0o600); }
    std::io::Write::write_all(&mut opts.open(&path).map_err(|e| e.to_string())?, conf.as_bytes()).map_err(|e| e.to_string())?;
    vpn_core::compat::restrict_path(&path).map_err(|e| e.to_string())?;
    let link = amnezia::vpn_link(&format!("{} · {}", server.name, client), &conf)?;
    let qr = amnezia::qr_svg(&conf)?;
    Ok(serde_json::json!({"path": path.to_string_lossy(), "conf": conf, "link": link, "qr_svg": qr}))
}

/// Creates the client and saves its `.conf` into ~/Downloads; returns `{path, conf, link, qr_svg}`.
#[tauri::command]
pub async fn awg_add_client(id: String, client: String) -> Result<serde_json::Value, String> {
    blocking(move || { let server = amnezia::find_server(&id)?; let conf = amnezia::add_client(&server, &client)?; deliver(&server, &client, conf) }).await
}

/// Same result for a client that already exists.
#[tauri::command]
pub async fn awg_client_config(id: String, client: String) -> Result<serde_json::Value, String> {
    blocking(move || { let server = amnezia::find_server(&id)?; let conf = amnezia::client_config(&server, &client)?; deliver(&server, &client, conf) }).await
}

#[tauri::command]
pub async fn awg_delete_client(id: String, client: String) -> Result<(), String> {
    blocking(move || { amnezia::delete_client(&amnezia::find_server(&id)?, &client)?; let _ = vpn_core::unpin_awg(&format!("{id}:{client}")); Ok(()) }).await
}

#[tauri::command]
pub async fn awg_uninstall(id: String) -> Result<(), String> {
    blocking(move || { amnezia::uninstall(&amnezia::find_server(&id)?)?; let _ = vpn_core::unpin_awg(&format!("{id}:")); Ok(()) }).await
}

/// Reveals a saved `.conf` in Finder.
#[tauri::command]
pub fn awg_reveal(path: String) -> Result<(), String> {
    let p = std::path::Path::new(&path);
    if p.extension().and_then(|e| e.to_str()) != Some("conf") || !p.is_file() { return Err("Файл не найден".into()); }
    std::process::Command::new("/usr/bin/open").args(["-R", "--"]).arg(p).status().map(|_| ()).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_hosts() -> Result<Vec<vpn_core::hosts::Host>, String> { vpn_core::hosts::list_hosts() }

#[tauri::command]
pub fn save_host(id: Option<String>, name: String, ssh_target: String, ssh_key: Option<String>, country: Option<String>) -> Result<vpn_core::hosts::Host, String> {
    let ssh_key = ssh_key.filter(|k| !k.is_empty());
    if let Some(key) = &ssh_key { if key != vpn_core::SYSTEM_SSH_KEY { vpn_core::resolve_ssh_key(key)?; } }
    vpn_core::hosts::save_host(id, &name, &ssh_target, ssh_key, country)
}

#[tauri::command]
pub fn delete_host(id: String) -> Result<(), String> { vpn_core::hosts::delete_host(&id) }

/// Clients of this server that are pinned to the main screen.
#[tauri::command]
pub fn awg_pinned(id: String) -> Result<Vec<String>, String> {
    let prefix = format!("{id}:");
    Ok(vpn_core::pinned_awg_sources()?.into_iter().filter_map(|s| s.strip_prefix(&prefix).map(str::to_owned)).collect())
}

/// Pinning imports the client's config as a profile of the main window; unpinning removes that copy.
#[tauri::command]
pub async fn awg_set_pinned(id: String, client: String, pinned: bool) -> Result<(), String> {
    blocking(move || {
        let source = format!("{id}:{client}");
        if !pinned { return vpn_core::unpin_awg(&source); }
        let server = amnezia::find_server(&id)?;
        let conf = amnezia::client_config(&server, &client)?;
        let name = format!("{} · {}", server.name, client);
        vpn_core::pin_awg_client(&source, &vpn_core::awglink::conf_to_link(&conf, Some(&name))?, &name)
    }).await
}
