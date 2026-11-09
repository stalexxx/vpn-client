use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::{MetadataExt, PermissionsExt}, net::UnixStream},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

const SOCKET: &str = "/var/run/vpnclient-tun.sock";
const LABEL: &str = "local.vpn-client.tun-helper";
const HELPER_DEST: &str = "/Library/PrivilegedHelperTools/local.vpn-client.tun-helper";
const XRAY_DEST: &str = "/Library/PrivilegedHelperTools/local.vpn-client.xray";
const AWG_DEST: &str = "/Library/PrivilegedHelperTools/local.vpn-client.awgsocks";
const ASSET_DIR: &str = "/Library/PrivilegedHelperTools/vpnclient-assets";
const PLIST_DEST: &str = "/Library/LaunchDaemons/local.vpn-client.tun-helper.plist";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

fn bundle_helpers() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let contents = exe.parent().and_then(Path::parent).ok_or("VPN Client app bundle path is invalid")?;
    Ok(contents.join("Helpers"))
}
fn shell_quote(s: &str) -> String { format!("'{}'", s.replace('\'', "'\\''")) }
fn helper_status(timeout: Duration) -> Option<Value> {
    let mut stream = UnixStream::connect(SOCKET).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    stream.write_all(b"{\"action\":\"status\"}\n").ok()?;
    let mut line = String::new();
    BufReader::new(stream).take(64 * 1024).read_line(&mut line).ok()?;
    let response: Value = serde_json::from_str(&line).ok()?;
    (response.get("ok").and_then(Value::as_bool) == Some(true)).then_some(response)
}
fn helper_is_compatible(status: &Value) -> bool {
    status.get("version").and_then(Value::as_str) == Some(APP_VERSION)
        && status.get("connectivity_check").and_then(Value::as_bool) == Some(true)
        && status.get("reality_support").and_then(Value::as_bool) == Some(true)
        && status.get("hysteria2_support").and_then(Value::as_bool) == Some(true)
        && status.get("hysteria_chain_support").and_then(Value::as_bool) == Some(true)
        && status.get("awg_support").and_then(Value::as_bool) == Some(true)
        && status.get("api_socket").and_then(Value::as_bool) == Some(true)
}
fn osascript_admin(command: &str) -> Result<(), String> {
    let script = format!("do shell script \"{}\" with administrator privileges", command.replace('\\', "\\\\").replace('"', "\\\""));
    let output = Command::new("/usr/bin/osascript").args(["-e", &script]).output().map_err(|e| e.to_string())?;
    if output.status.success() { Ok(()) }
    else {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if error.contains("-128") || error.to_lowercase().contains("cancel") { Err("Установка системного компонента отменена.".into()) }
        else { Err(format!("Не удалось установить системный компонент: {error}")) }
    }
}
fn xml_escape(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;") }
fn launchd_plist(uid: u32, xray: &str) -> String {
    let args = [HELPER_DEST, "serve", &uid.to_string(), xray, "--system"];
    let args = args.iter().map(|a| format!("<string>{}</string>", xml_escape(a))).collect::<String>();
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{LABEL}</string><key>ProgramArguments</key><array>{args}</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>StandardOutPath</key><string>/var/log/vpn-client-tun-helper.log</string><key>StandardErrorPath</key><string>/var/log/vpn-client-tun-helper.log</string></dict></plist>\n")
}
const ADMIN_GID: u32 = 80;
// /Applications is root:admin 775; group admin may write there (those users can already sudo), nothing else may be group/other-writable.
fn component_is_trusted(path: &Path, uid: u32, gid: u32, mode: u32) -> bool {
    if uid != 0 || mode & 0o002 != 0 { return false; }
    mode & 0o020 == 0 || (path == Path::new("/Applications") && gid == ADMIN_GID)
}
fn verify_bundle_source(path: &Path) -> Result<(), String> { verify_bundle_path(path, true) }
/// Data files (Xray's geo databases) must be root-owned and non-writable like binaries, but are not executable.
fn verify_bundle_data(path: &Path) -> Result<(), String> { verify_bundle_path(path, false) }
fn exec_bit_ok(mode: u32, executable: bool) -> bool { !executable || mode & 0o111 != 0 }
fn verify_bundle_path(path: &Path, executable: bool) -> Result<(), String> {
    for (index, component) in path.ancestors().enumerate() {
        let meta = std::fs::symlink_metadata(component).map_err(|e| format!("Не удалось проверить {}: {e}", component.display()))?;
        if (index == 0 && !meta.file_type().is_file()) || (index != 0 && !meta.file_type().is_dir()) {
            return Err(format!("{} должен быть обычным файлом или каталогом без символических ссылок", component.display()));
        }
        if !component_is_trusted(component, meta.uid(), meta.gid(), meta.permissions().mode()) {
            return Err(format!("{} должен принадлежать root и не быть доступным для записи группе или другим пользователям", component.display()));
        }
        if index == 0 && !exec_bit_ok(meta.permissions().mode(), executable) { return Err(format!("{} не помечен как исполняемый файл", component.display())); }
    }
    Ok(())
}
fn install_command(helper: &std::path::Path, xray: &std::path::Path, awg: &std::path::Path, geo: &[std::path::PathBuf], plist: &str) -> String {
    let (mut geo_verify, mut geo_stage, mut geo_install) = (String::new(), String::new(), String::new());
    if geo.len() == 2 {
        for (i, path) in geo.iter().enumerate() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let src = shell_quote(&path.to_string_lossy());
            geo_verify.push_str(&format!("verify_source {src}; "));
            geo_stage.push_str(&format!("/usr/bin/install -o root -g wheel -m 644 {src} \"$stage/geo{i}\"; /bin/test \"$(/usr/bin/stat -f %u \"$stage/geo{i}\")\" = 0; "));
            geo_install.push_str(&format!("/usr/bin/install -o root -g wheel -m 644 \"$stage/geo{i}\" {}/{name}; ", shell_quote(ASSET_DIR)));
        }
        geo_install = format!("/usr/bin/install -d -o root -g wheel -m 755 {}; {geo_install}", shell_quote(ASSET_DIR));
    }
    format!(
        "set -e; verify_source() {{ p=\"$1\"; /bin/test -f \"$p\"; while :; do /bin/test ! -L \"$p\"; /bin/test \"$(/usr/bin/stat -f %u \"$p\")\" = 0; mode=$(/usr/bin/stat -f %Lp \"$p\"); if /bin/test \"$p\" = /Applications; then /bin/test $((0$mode & 02)) -eq 0; /bin/test \"$(/usr/bin/stat -f %g \"$p\")\" = 80; else /bin/test $((0$mode & 022)) -eq 0; fi; /bin/test \"$p\" != / || break; p=$(/usr/bin/dirname \"$p\"); done; }}; verify_source {helper}; verify_source {xray}; verify_source {awg}; {geo_verify}/bin/mkdir -p /Library/PrivilegedHelperTools /Library/LaunchDaemons; stage=/Library/PrivilegedHelperTools/.vpnclient-stage-$$; /bin/mkdir -m 700 \"$stage\"; trap '/bin/rm -rf \"$stage\"' EXIT; /usr/bin/install -o root -g wheel -m 755 {helper} \"$stage/helper\"; /usr/bin/install -o root -g wheel -m 755 {xray} \"$stage/xray\"; /usr/bin/install -o root -g wheel -m 755 {awg} \"$stage/awg\"; {geo_stage}/bin/test \"$(/usr/bin/stat -f %u \"$stage/helper\")\" = 0; /bin/test \"$(/usr/bin/stat -f %u \"$stage/xray\")\" = 0; /bin/test \"$(/usr/bin/stat -f %u \"$stage/awg\")\" = 0; /bin/launchctl bootout system/{label} >/dev/null 2>&1 || true; /usr/bin/install -o root -g wheel -m 755 \"$stage/helper\" {helper_dest}; /usr/bin/install -o root -g wheel -m 755 \"$stage/xray\" {xray_dest}; /usr/bin/install -o root -g wheel -m 755 \"$stage/awg\" {awg_dest}; {geo_install}/usr/bin/printf %s {plist} > {plist_dest}; /usr/sbin/chown root:wheel {plist_dest}; /bin/chmod 644 {plist_dest}; /bin/launchctl bootstrap system {plist_dest}; /bin/launchctl enable system/{label}",
        helper = shell_quote(&helper.to_string_lossy()), xray = shell_quote(&xray.to_string_lossy()), awg = shell_quote(&awg.to_string_lossy()), awg_dest = shell_quote(AWG_DEST),
        geo_verify = geo_verify, geo_stage = geo_stage, geo_install = geo_install,
        label = LABEL, helper_dest = shell_quote(HELPER_DEST), xray_dest = shell_quote(XRAY_DEST),
        plist = shell_quote(&plist), plist_dest = shell_quote(PLIST_DEST),
    )
}

pub fn ensure_installed() -> Result<(), String> {
    if let Some(status) = helper_status(Duration::from_secs(15)) {
        if helper_is_compatible(&status) { return Ok(()); }
        if status.get("connected").and_then(Value::as_bool) == Some(true) {
            return Err("Отключите VPN перед обновлением системного компонента, затем повторите подключение.".into());
        }
    }
    let helpers = bundle_helpers()?;
    let helper = helpers.join("vpn-tun-helper");
    let xray = helpers.join("xray");
    let awg = helpers.join("awgsocks");
    for path in [&helper, &xray, &awg] { verify_bundle_source(path)?; }
    // Xray's geoip.dat / geosite.dat travel with it (installed root-owned into ASSET_DIR) when the bundle has them.
    let geo: Vec<std::path::PathBuf> = ["geoip.dat", "geosite.dat"].iter().filter_map(|n| helpers.parent().map(|contents| contents.join("Resources").join(n))).filter(|p| p.exists()).collect();
    for path in &geo { verify_bundle_data(path)?; }
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    let meta = std::fs::metadata(&home).map_err(|e| e.to_string())?;
    let uid = meta.uid();
    let xray_dest = XRAY_DEST.to_owned();
    let plist = launchd_plist(uid, &xray_dest);
    let command = install_command(&helper, &xray, &awg, &geo, &plist);
    osascript_admin(&command)?;
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if helper_status(Duration::from_secs(1)).as_ref().is_some_and(helper_is_compatible) { return Ok(()); }
        thread::sleep(Duration::from_millis(100));
    }
    Err("Системный компонент установлен, но не отвечает с ожидаемой версией. Проверьте журнал /var/log/vpn-client-tun-helper.log.".into())
}
fn request_value(request: Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(SOCKET).map_err(|e| format!("Системный компонент недоступен: {e}"))?;
    let timeout = if matches!(request.get("action").and_then(Value::as_str), Some("start" | "switch")) { 60 } else { 15 };
    stream.set_read_timeout(Some(Duration::from_secs(timeout))).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    stream.write_all(request.to_string().as_bytes()).and_then(|_| stream.write_all(b"\n")).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).map_err(|e| e.to_string())?;
    let response: Value = serde_json::from_str(&line).map_err(|_| "Некорректный ответ системного компонента")?;
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(response.get("message").and_then(Value::as_str).unwrap_or("Ошибка системного компонента").to_owned());
    }
    Ok(response)
}
fn request(action: &str, link: Option<&str>, relay_link: Option<&str>) -> Result<Value, String> { request_value(json!({"action":action,"link":link,"relay_link":relay_link})) }
pub fn log_tail(lines: u64, filter: Option<&str>) -> Result<String, String> {
    Ok(request_value(json!({"action":"log","lines":lines,"filter":filter}))?.get("message").and_then(Value::as_str).unwrap_or("").to_owned())
}
pub fn log_level() -> Result<String, String> {
    Ok(request_value(json!({"action":"get_log_level"}))?.get("message").and_then(Value::as_str).unwrap_or("warning").to_owned())
}
pub fn set_log_level(level: &str) -> Result<String, String> {
    Ok(request_value(json!({"action":"set_log_level","level":level}))?.get("message").and_then(Value::as_str).unwrap_or("").to_owned())
}
/// Cumulative per-outbound byte counters: {direct:{up,down}, vpn:{up,down}, ts_ms}.
pub fn stats() -> Result<Value, String> {
    let response = request_value(json!({"action":"stats"}))?;
    let text = response.get("message").and_then(Value::as_str).unwrap_or("");
    serde_json::from_str(text).map_err(|_| "Некорректный ответ статистики".to_owned())
}
pub fn status() -> Result<bool, String> { Ok(request("status", None, None)?.get("connected").and_then(Value::as_bool).unwrap_or(false)) }
/// Connects, or — when a tunnel is already up — switches to this profile in place (DNS stays pinned; failure rolls back).
pub fn start(link: &str, relay_link: Option<&str>) -> Result<String, String> {
    ensure_installed()?;
    let bypass = vpn_core::read_bypass()?;
    Ok(request_value(json!({"action":"switch","link":link,"relay_link":relay_link,"bypass":bypass}))?.get("message").and_then(Value::as_str).unwrap_or("TUN подключён").to_owned())
}
pub fn stop() -> Result<(), String> {
    if helper_status(Duration::from_secs(15)).is_none() { ensure_installed()?; }
    request("stop", None, None).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_helper_without_reality_capability_requires_upgrade() {
        assert!(!helper_is_compatible(&json!({"version":APP_VERSION,"connectivity_check":true})));
        assert!(!helper_is_compatible(&json!({"version":APP_VERSION,"connectivity_check":true,"reality_support":true})));
        assert!(!helper_is_compatible(&json!({"version":APP_VERSION,"connectivity_check":true,"reality_support":true,"hysteria2_support":true})));
        assert!(!helper_is_compatible(&json!({"version":APP_VERSION,"connectivity_check":true,"reality_support":true,"hysteria2_support":true,"hysteria_chain_support":true})));
        // A helper whose Xray API still listens on a loopback TCP port must be reinstalled.
        assert!(!helper_is_compatible(&json!({"version":APP_VERSION,"connectivity_check":true,"reality_support":true,"hysteria2_support":true,"hysteria_chain_support":true,"awg_support":true})));
        assert!(!helper_is_compatible(&json!({"version":APP_VERSION,"connectivity_check":true,"reality_support":true,"hysteria2_support":true,"hysteria_chain_support":true,"awg_support":true,"api_socket":false})));
        assert!(helper_is_compatible(&json!({"version":APP_VERSION,"connectivity_check":true,"reality_support":true,"hysteria2_support":true,"hysteria_chain_support":true,"awg_support":true,"api_socket":true})));
    }
    #[test]
    fn only_applications_may_be_admin_group_writable() {
        assert!(component_is_trusted(Path::new("/Library/VPNClient"), 0, 0, 0o755));
        assert!(component_is_trusted(Path::new("/Applications"), 0, ADMIN_GID, 0o775));
        assert!(!component_is_trusted(Path::new("/Applications"), 0, 0, 0o775));
        assert!(!component_is_trusted(Path::new("/Applications"), 0, ADMIN_GID, 0o777));
        assert!(!component_is_trusted(Path::new("/Applications/VPNClient.app"), 0, ADMIN_GID, 0o775));
        assert!(!component_is_trusted(Path::new("/Applications"), 501, ADMIN_GID, 0o755));
        assert!(!component_is_trusted(Path::new("/private/tmp"), 0, 0, 0o1777));
    }

    #[test]
    fn install_script_is_valid_shell_and_adds_geo_databases_only_when_bundled() {
        use std::path::PathBuf;
        let helper = PathBuf::from("/Applications/VPNClient.app/Contents/Helpers/vpn-tun-helper");
        let xray = PathBuf::from("/Applications/VPNClient.app/Contents/Helpers/xray");
        let awg = PathBuf::from("/Applications/VPNClient.app/Contents/Helpers/awgsocks");
        let geo: Vec<PathBuf> = ["geoip.dat", "geosite.dat"].iter().map(|n| PathBuf::from("/Applications/VPNClient.app/Contents/Resources").join(n)).collect();
        for (files, expect) in [(&geo[..], true), (&[][..], false)] {
            let script = install_command(&helper, &xray, &awg, files, "<plist/>");
            let status = std::process::Command::new("/bin/sh").args(["-n", "-c", &script]).status().unwrap();
            assert!(status.success(), "generated installer is not valid shell");
            assert_eq!(script.contains("vpnclient-assets"), expect);
            assert_eq!(script.contains("geosite.dat"), expect);
            assert!(script.contains("local.vpn-client.xray"));
            assert!(script.contains("local.vpn-client.awgsocks") && script.contains("verify_source '/Applications/VPNClient.app/Contents/Helpers/awgsocks'"));
        }
        let script = install_command(&helper, &xray, &awg, &geo, "<plist/>");
        // Both databases are verified as root-owned bundle files, staged under the root-only stage dir, then installed 0644.
        assert_eq!(script.matches("verify_source '/Applications/VPNClient.app/Contents/Resources/geo").count(), 2);
        assert!(script.contains("install -d -o root -g wheel -m 755 '/Library/PrivilegedHelperTools/vpnclient-assets'"));
        assert!(script.contains("-m 644 \"$stage/geo0\" '/Library/PrivilegedHelperTools/vpnclient-assets'/geoip.dat"));
    }

    #[test]
    fn data_files_do_not_need_the_executable_bit_but_binaries_do() {
        assert!(exec_bit_ok(0o644, false));
        assert!(!exec_bit_ok(0o644, true));
        assert!(exec_bit_ok(0o755, true));
    }

    /// Run on a machine with the app installed from the .pkg: `cargo test -- --ignored installed_bundle`.
    #[test]
    #[ignore]
    fn installed_bundle_files_pass_source_verification() {
        let contents = Path::new("/Applications/VPNClient.app/Contents");
        verify_bundle_source(&contents.join("Helpers/xray")).unwrap();
        verify_bundle_source(&contents.join("Helpers/vpn-tun-helper")).unwrap();
        verify_bundle_data(&contents.join("Resources/geoip.dat")).unwrap();
        verify_bundle_data(&contents.join("Resources/geosite.dat")).unwrap();
        // The same data file is rejected when treated as a binary: this is the bug the data check fixes.
        assert!(verify_bundle_source(&contents.join("Resources/geoip.dat")).is_err());
    }
}
