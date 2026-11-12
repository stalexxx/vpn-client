use std::{fs, io::{BufRead, BufReader, Read, Write}, os::unix::{fs::{FileTypeExt, MetadataExt, PermissionsExt}, net::{UnixListener, UnixStream}}, sync::{Arc, Mutex}, time::Duration};
use vpn_core::PinnedProfile;

#[derive(Default)]
pub struct State { pub selected: Mutex<Option<PinnedProfile>>, pub operation: Mutex<()> }
pub fn start(state: Arc<State>) -> Result<(), String> {
 let path = if cfg!(debug_assertions) { std::env::var_os("VPN_CLIENT_DEV_SOCKET").or_else(|| std::env::var_os("VPN_CLIENT_TEST_SOCKET")).map(std::path::PathBuf::from).unwrap_or(vpn_core::mcp_control_socket_path()?) } else { vpn_core::mcp_control_socket_path()? }; let dir=path.parent().ok_or("Некорректный путь MCP")?;
 fs::create_dir_all(dir).map_err(|e| e.to_string())?;
 let meta=fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
 if !meta.file_type().is_dir() || meta.uid()!=unsafe { libc::geteuid() } { return Err("Каталог MCP должен принадлежать текущему пользователю".into()); }
 fs::set_permissions(dir,fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
 if let Ok(meta)=fs::symlink_metadata(&path) { if !meta.file_type().is_socket() || meta.uid()!=unsafe { libc::geteuid() } { return Err("Путь MCP занят посторонним файлом".into()); } if UnixStream::connect(&path).is_ok() { return Err("Приложение VPN уже запущено".into()); } fs::remove_file(&path).map_err(|e| e.to_string())?; }
 let listener=UnixListener::bind(&path).map_err(|e| e.to_string())?; fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
 std::thread::spawn(move || for stream in listener.incoming().flatten() { let state=state.clone(); std::thread::spawn(move || handle(stream,state)); }); Ok(())
}
fn handle(mut stream: UnixStream, state: Arc<State>) {
 let _=stream.set_read_timeout(Some(Duration::from_secs(5))); let _=stream.set_write_timeout(Some(Duration::from_secs(5)));
 let mut line=String::new(); let result=BufReader::new(&mut stream).take(4096).read_line(&mut line).map_err(|_| "Не удалось прочитать запрос".to_owned()).and_then(|_| {
  let req: serde_json::Value=serde_json::from_str(&line).map_err(|_| "Некорректный запрос".to_owned())?; let _guard=state.operation.lock().map_err(|_| "Управление VPN недоступно")?;
  match req["action"].as_str() {
   Some("connect") => { let requested=req.get("profile").map(|v| serde_json::from_value::<PinnedProfile>(v.clone()).map_err(|_| "Некорректная конфигурация".to_owned())).transpose()?; let profile=requested.clone().or(state.selected.lock().map_err(|_| "Выбор недоступен")?.clone()).ok_or("Выберите конфигурацию в приложении")?;
    if !vpn_core::list_connectable_profiles()?.iter().any(|p| p["server_id"]==profile.server_id && p["inbound_id"]==profile.inbound_id && p["email"]==profile.email) { return Err("Конфигурация недоступна".into()); }
    if requested.is_some() { *state.selected.lock().map_err(|_| "Выбор недоступен")?=Some(profile.clone()); }
    vpn_core::vpn_control::connect_profile_inner(&Default::default(),&profile.server_id,profile.inbound_id,&profile.email)
   },
   Some("disconnect") => vpn_core::vpn_control::stop_vpn_inner(&Default::default()).map(|_| "VPN отключён.".to_owned()),
   Some("stats") => vpn_core::helper::stats().map(|v| v.to_string()),
   Some("log") => vpn_core::helper::log_tail(req["lines"].as_u64().unwrap_or(50), req["filter"].as_str()),
   Some("set_log_level") => match req["level"].as_str() { Some(level @ ("info" | "warning")) => vpn_core::helper::set_log_level(level), _ => Err("Допустимые уровни: info, warning".into()) },
   _ => Err("Неизвестная команда".into())
  }
 }); let response=match result { Ok(message)=>serde_json::json!({"ok":true,"message":message}), Err(message)=>serde_json::json!({"ok":false,"message":message}) }; let _=writeln!(stream,"{response}");
}
