fn main() {
    let link = "vless://12345678-1234-1234-1234-123456789abc@example.org:443?type=xhttp&security=tls&sni=example.org&path=%2Fvpn&mode=auto";
    println!(
        "{}",
        vpn_core::profile::vless_xhttp_config(link, 10808).unwrap()
    );
}
