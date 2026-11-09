//! AmneziaWG + WARP servers (see `vpn_core::amnezia`): install, clients, removal.
use vpn_core::amnezia::{self, AwgClient, AwgServer};

fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> impl std::future::Future<Output = Result<T, String>> {
    async move { tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())? }
}

#[tauri::command]
pub fn awg_list_servers() -> Result<Vec<AwgServer>, String> { amnezia::list_servers() }

#[tauri::command]
pub async fn awg_install(name: String, ssh_target: String, ssh_key: Option<String>, port: Option<u16>) -> Result<AwgServer, String> {
    blocking(move || amnezia::install(&name, &ssh_target, ssh_key.as_deref(), port, None)).await
}

#[tauri::command]
pub async fn awg_clients(id: String) -> Result<Vec<AwgClient>, String> {
    blocking(move || amnezia::list_clients(&amnezia::find_server(&id)?)).await
}

#[tauri::command]
pub async fn awg_status(id: String) -> Result<String, String> {
    blocking(move || amnezia::status(&amnezia::find_server(&id)?)).await
}

/// Creates the client and saves its `.conf` into ~/Downloads; returns `{path, conf}`.
#[tauri::command]
pub async fn awg_add_client(id: String, client: String) -> Result<serde_json::Value, String> {
    blocking(move || {
        let server = amnezia::find_server(&id)?;
        let conf = amnezia::add_client(&server, &client)?;
        let dir = std::env::var_os("HOME").map(std::path::PathBuf::from).ok_or("нет HOME")?.join("Downloads");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let safe: String = server.name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
        let path = dir.join(format!("{safe}-{client}.conf"));
        std::fs::write(&path, &conf).map_err(|e| e.to_string())?;
        vpn_core::compat::restrict_path(&path).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({"path": path.to_string_lossy(), "conf": conf}))
    }).await
}

#[tauri::command]
pub async fn awg_delete_client(id: String, client: String) -> Result<(), String> {
    blocking(move || amnezia::delete_client(&amnezia::find_server(&id)?, &client)).await
}

#[tauri::command]
pub async fn awg_uninstall(id: String) -> Result<(), String> {
    blocking(move || amnezia::uninstall(&amnezia::find_server(&id)?)).await
}

/// Reveals a saved `.conf` in Finder.
#[tauri::command]
pub fn awg_reveal(path: String) -> Result<(), String> {
    let p = std::path::Path::new(&path);
    if p.extension().and_then(|e| e.to_str()) != Some("conf") || !p.is_file() { return Err("Файл не найден".into()); }
    std::process::Command::new("/usr/bin/open").args(["-R", "--"]).arg(p).status().map(|_| ()).map_err(|e| e.to_string())
}
