use std::process::Command;

// Windows: the app starts Xray's TUN itself, which needs administrator rights; ask for them at launch.
const WINDOWS_MANIFEST: &str = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application>
  </compatibility>
</assembly>"#;

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
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let windows = tauri_build::WindowsAttributes::new().app_manifest(WINDOWS_MANIFEST);
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows)).expect("tauri build failed");
    } else {
        tauri_build::build()
    }
}
