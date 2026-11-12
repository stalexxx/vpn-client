use std::process::Command;
fn main() {
    let number = Command::new("date").args(["+%Y%m%d%H%M%S"]).output().ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned()).filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=VPN_BUILD_NUMBER={number}");
    println!("cargo:rerun-if-changed=build.rs");
}
