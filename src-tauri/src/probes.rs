//! Commands for the server liveness probes (see `vpn_core::probe`).
use std::collections::HashMap;
use vpn_core::probe::{ProbeHandle, ProbeResult};

/// Latest result per profile key (`imported:<id>` or `<server>:<inbound>:<email>`).
#[tauri::command]
pub fn get_probe_results(probes: tauri::State<'_, ProbeHandle>) -> HashMap<String, ProbeResult> { probes.store.snapshot() }

/// Run a probe round now instead of waiting for the next scheduled one.
#[tauri::command]
pub fn probe_now(probes: tauri::State<'_, ProbeHandle>) { probes.probe_now(); }
