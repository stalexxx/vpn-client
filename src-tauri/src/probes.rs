//! Commands for the server liveness probes (see `vpn_core::probe`).
use std::collections::HashMap;
use vpn_core::probe::{ProbeHandle, ProbeResult};

/// Latest result per profile key (`imported:<id>` or `<server>:<inbound>:<email>`).
#[tauri::command]
pub fn get_probe_results(probes: tauri::State<'_, ProbeHandle>) -> HashMap<String, ProbeResult> { probes.store.snapshot() }

/// Run a probe round now instead of waiting for the next scheduled one.
#[tauri::command]
pub fn probe_now(probes: tauri::State<'_, ProbeHandle>) { probes.probe_now(); }

/// What api.ipify.org reports (shown under the connected profile).
#[tauri::command]
pub async fn get_exit_ip() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(vpn_core::probe::exit_ip).await.map_err(|e| e.to_string())?
}
