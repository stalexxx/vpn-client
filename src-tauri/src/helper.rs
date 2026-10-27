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
fn verify_bundle_source(path: &Path) -> Result<(), String> {
    for (index, component) in path.ancestors().enumerate() {
        let meta = std::fs::symlink_metadata(component).map_err(|e| format!("Не удалось проверить {}: {e}", component.display()))?;
        if (index == 0 && !meta.file_type().is_file()) || (index != 0 && !meta.file_type().is_dir()) {
            return Err(format!("{} должен быть обычным файлом или каталогом без символических ссылок", component.display()));
        }
        if !component_is_trusted(component, meta.uid(), meta.gid(), meta.permissions().mode()) {
            return Err(format!("{} должен принадлежать root и не быть доступным для записи группе или другим пользователям", component.display()));
        }
        if index == 0 && meta.permissions().mode() & 0o111 == 0 { return Err(format!("{} не помечен как исполняемый файл", component.display())); }
    }
    Ok(())
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
    for path in [&helper, &xray] { verify_bundle_source(path)?; }
    let home = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    let meta = std::fs::metadata(&home).map_err(|e| e.to_string())?;
    let uid = meta.uid();
    let xray_dest = XRAY_DEST.to_owned();
    let plist = launchd_plist(uid, &xray_dest);
    let command = format!(
        "set -e; verify_source() {{ p=\"$1\"; /bin/test -f \"$p\"; while :; do /bin/test ! -L \"$p\"; /bin/test \"$(/usr/bin/stat -f %u \"$p\")\" = 0; mode=$(/usr/bin/stat -f %Lp \"$p\"); if /bin/test \"$p\" = /Applications; then /bin/test $((0$mode & 02)) -eq 0; /bin/test \"$(/usr/bin/stat -f %g \"$p\")\" = 80; else /bin/test $((0$mode & 022)) -eq 0; fi; /bin/test \"$p\" != / || break; p=$(/usr/bin/dirname \"$p\"); done; }}; verify_source {helper}; verify_source {xray}; /bin/mkdir -p /Library/PrivilegedHelperTools /Library/LaunchDaemons; stage=/Library/PrivilegedHelperTools/.vpnclient-stage-$$; /bin/mkdir -m 700 \"$stage\"; trap '/bin/rm -rf \"$stage\"' EXIT; /usr/bin/install -o root -g wheel -m 755 {helper} \"$stage/helper\"; /usr/bin/install -o root -g wheel -m 755 {xray} \"$stage/xray\"; /bin/test \"$(/usr/bin/stat -f %u \"$stage/helper\")\" = 0; /bin/test \"$(/usr/bin/stat -f %u \"$stage/xray\")\" = 0; /bin/launchctl bootout system/{label} >/dev/null 2>&1 || true; /usr/bin/install -o root -g wheel -m 755 \"$stage/helper\" {helper_dest}; /usr/bin/install -o root -g wheel -m 755 \"$stage/xray\" {xray_dest}; /usr/bin/printf %s {plist} > {plist_dest}; /usr/sbin/chown root:wheel {plist_dest}; /bin/chmod 644 {plist_dest}; /bin/launchctl bootstrap system {plist_dest}; /bin/launchctl enable system/{label}",
        helper = shell_quote(&helper.to_string_lossy()), xray = shell_quote(&xray.to_string_lossy()),
        label = LABEL, helper_dest = shell_quote(HELPER_DEST), xray_dest = shell_quote(XRAY_DEST),
        plist = shell_quote(&plist), plist_dest = shell_quote(PLIST_DEST),
    );
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
    let timeout = if request.get("action").and_then(Value::as_str) == Some("start") { 40 } else { 15 };
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
fn request(action: &str, link: Option<&str>) -> Result<Value, String> { request_value(json!({"action":action,"link":link})) }
pub fn status() -> Result<bool, String> { Ok(request("status", None)?.get("connected").and_then(Value::as_bool).unwrap_or(false)) }
pub fn start(link: &str) -> Result<String, String> {
    ensure_installed()?;
    Ok(request("start", Some(link))?.get("message").and_then(Value::as_str).unwrap_or("TUN подключён").to_owned())
}
pub fn stop() -> Result<(), String> {
    if helper_status(Duration::from_secs(15)).is_none() { ensure_installed()?; }
    request("stop", None).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
