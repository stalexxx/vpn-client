fn main() -> Result<(), String> {
    let executable = std::env::args().nth(1).ok_or("missing xray executable")?;
    let link = "vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=xhttp&security=tls&sni=example.org&path=%2Fvpn&mode=auto";
    let state = vpn_core::xray::XrayState::default();
    let started = vpn_core::xray::start(&state, executable, link.to_owned())?;
    println!("{started}");
    if vpn_core::xray::start(&state, "unused".into(), link.into()).is_ok() {
        return Err("duplicate start unexpectedly succeeded".into());
    }
    vpn_core::xray::stop(&state)?;
    vpn_core::xray::stop(&state)?;
    println!("Xray stopped; duplicate start refused");
    Ok(())
}
