use std::process::Command;

fn main() {
    let stamp = Command::new("date")
        .args(["+%Y%m%d-%H%M"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=VPN_BUILD_STAMP={stamp}");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=../src");
    println!("cargo:rerun-if-changed=../ui");
    tauri_build::build()
}
