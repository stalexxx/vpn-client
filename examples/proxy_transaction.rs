use vpn_core::{
    proxy::{apply_proxy, restore_proxy, MacNetworkSetup, NetworkSetup},
    xray::{self, XrayState},
};
fn main() -> Result<(), String> {
    let ops = MacNetworkSetup;
    let service = "Wi-Fi";
    let journal = std::path::Path::new("/tmp/vpn-xray-test/proxy-journal-test.json");
    let original = ops.read(service)?;
    let state = XrayState::default();
    let link = "vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=xhttp&security=tls&sni=example.org&path=%2Fvpn&mode=auto";
    xray::start(&state, "/tmp/vpn-xray-test/xray".into(), link.into())?;
    let result = apply_proxy(&ops, journal, service, xray::active_port(&state)?);
    if journal.exists() {
        let restored = restore_proxy(&ops, journal);
        if let Err(error) = restored {
            return Err(format!("RESTORE FAILED; journal retained: {error}"));
        }
    }
    xray::stop(&state)?;
    if ops.read(service)? != original {
        return Err("Settings did not return to original state".into());
    }
    result?;
    println!("Proxy applied and original settings restored");
    Ok(())
}
