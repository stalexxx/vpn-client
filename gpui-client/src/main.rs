mod control;
mod stats;
mod tray;
use gpui::{div, img, ObjectFit, BoxShadow, linear_gradient, linear_color_stop, hsla, point, prelude::*, px, rgb, size, App, Application, Bounds, Context, Window, WindowBounds, WindowOptions};
use std::{collections::BTreeSet, sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}}, time::Duration};

#[derive(Clone)]
enum Profile { Server(serde_json::Value), Imported(serde_json::Value) }
impl Profile {
 fn label(&self) -> String { match self { Self::Server(p) => format!("{} · {}",p["server_name"].as_str().unwrap_or("Сервер"),p["email"].as_str().unwrap_or("")), Self::Imported(p) => format!("{} · {}",p["host"].as_str().unwrap_or("Импорт"),p["name"].as_str().unwrap_or("")) } }
 fn key(&self) -> String { match self { Self::Server(p) => format!("{}:{}:{}",p["server_id"].as_str().unwrap_or(""),p["inbound_id"].as_u64().unwrap_or(0),p["email"].as_str().unwrap_or("")), Self::Imported(p) => format!("imported:{}",p["id"].as_str().unwrap_or("")) } }
 fn connect(&self) -> Result<String,String> { match self { Self::Server(p) => vpn_core::vpn_control::connect_profile_inner(&Default::default(),p["server_id"].as_str().unwrap_or(""),p["inbound_id"].as_u64().unwrap_or(0),p["email"].as_str().unwrap_or("")), Self::Imported(p) => vpn_core::vpn_control::connect_imported_inner(&Default::default(),p["id"].as_str().unwrap_or("")) } }
}
fn profiles() -> Result<Vec<Profile>,String> {
 let mut p: Vec<_>=vpn_core::list_connectable_profiles()?.into_iter().map(Profile::Server).collect();
 let host_countries: std::collections::HashMap<String, Option<String>> = vpn_core::hosts::list_hosts()?.into_iter().map(|host|(host.ssh_target,host.country)).collect();
 let awg_countries: std::collections::HashMap<String, Option<String>> = vpn_core::amnezia::list_servers()?.into_iter().map(|server| { let country=server.country.or_else(||host_countries.get(&server.ssh_target).cloned().flatten()); (server.id,country) }).collect();
 p.extend(vpn_core::list_imported_profiles()?.into_iter().map(|mut item| { if let Some(source)=item["awg_source"].as_str() { if let Some((server_id,_))=source.split_once(':') { if let Some(country)=awg_countries.get(server_id).and_then(Option::as_ref) { item["country"]=serde_json::json!(country); } } } Profile::Imported(item) })); Ok(p)
}
struct Client { profiles: Vec<Profile>, selected: Option<String>, message: Arc<Mutex<String>>, busy: Arc<Mutex<Option<&'static str>>>, control: Arc<control::State>, status: Arc<Mutex<Option<bool>>>, probes: vpn_core::probe::ProbeHandle, stats: Arc<Mutex<stats::Display>>, generation: Arc<AtomicU64>, parked: BTreeSet<String>, armed_delete: Option<String>, vpn_failed: Arc<AtomicBool> }
impl Client {
 fn new(control: Arc<control::State>, cx: &mut Context<Self>) -> Self {
  cx.spawn(async move |view, cx| { loop { cx.background_executor().timer(Duration::from_secs(1)).await; if view.update(cx, |this, cx| { if let Ok(p)=profiles() { this.profiles=p; } cx.notify(); }).is_err() { break; } } }).detach();
  let status=Arc::new(Mutex::new(None)); let status_worker=status.clone();
  std::thread::spawn(move || loop { *status_worker.lock().unwrap()=vpn_core::helper::status().ok(); std::thread::sleep(Duration::from_secs(5)); });
  let parked=load_parked(); let profiles=profiles().unwrap_or_default(); let first=profiles.iter().find(|p|!parked.contains(&p.key())); let selected=first.map(Profile::key);
  if let Some(Profile::Server(p))=first { *control.selected.lock().unwrap()=serde_json::from_value(p.clone()).ok(); }
  let generation=Arc::new(AtomicU64::new(0)); let stats=stats::start(status.clone(),generation.clone());
  Self { profiles, selected, parked, message:Arc::new(Mutex::new(String::new())), busy:Arc::new(Mutex::new(None)), control, status, probes:vpn_core::probe::start(), stats, generation, armed_delete:None, vpn_failed:Arc::new(AtomicBool::new(false)) }
 }
 fn import_from_clipboard(&mut self) {
  let message=self.message.clone(); *message.lock().unwrap()="Импортируем из буфера…".into();
  std::thread::spawn(move || {
   let result=(|| -> Result<String,String> {
    let output=std::process::Command::new("/usr/bin/pbpaste").output().map_err(|e|format!("Не удалось прочитать буфер: {e}"))?;
    if !output.status.success() { return Err("Не удалось прочитать буфер обмена".into()); }
    let text=String::from_utf8(output.stdout).map_err(|_|"В буфере нет текстовой конфигурации".to_string())?;
    if text.trim().is_empty() { return Err("Буфер пуст: скопируйте ссылку или конфиг".into()); }
    let added=vpn_core::import_profiles(&text,None)?; Ok(format!("Импортировано конфигураций: {}",added.len()))
   })();
   *message.lock().unwrap()=result.unwrap_or_else(|error|format!("Ошибка: {error}"));
  });
 }
 fn run(&mut self, profile: Option<Profile>) {
  let mut busy=self.busy.lock().unwrap(); if busy.is_some() { return; } let action=if profile.is_none() { "Отключение…" } else if *self.status.lock().unwrap()==Some(true) { "Переподключение…" } else { "Подключение…" }; *busy=Some(action); drop(busy);
  let busy=self.busy.clone(); let message=self.message.clone(); let control=self.control.clone(); let status=self.status.clone(); let generation=self.generation.clone(); let vpn_failed=self.vpn_failed.clone(); vpn_failed.store(false,Ordering::Relaxed);
  *message.lock().unwrap()=action.into();
  std::thread::spawn(move || { let result=match control.operation.lock() { Ok(_guard) => match profile { Some(p)=>p.connect(), None=>vpn_core::vpn_control::stop_vpn_inner(&Default::default()).map(|_|"VPN отключён".into()) }, Err(_)=>Err("Управление VPN недоступно".into()) }; vpn_failed.store(result.is_err(),Ordering::Relaxed); if result.is_ok() { generation.fetch_add(1,Ordering::Relaxed); } *message.lock().unwrap()=match result { Ok(message)=>format!("Готово: {message}"), Err(error)=>format!("Ошибка: {error}") }; *status.lock().unwrap()=vpn_core::helper::status().ok(); *busy.lock().unwrap()=None; });
 }
}
// Отложенные конфигурации — настройка только этого окна, поэтому хранится отдельным файлом рядом с данными приложения.
fn parked_path() -> Result<std::path::PathBuf,String> { Ok(vpn_core::mcp_control_socket_path()?.parent().and_then(|p|p.parent()).ok_or("Некорректный путь настроек")?.join("gpui-parked-profiles.json")) }
fn load_parked() -> BTreeSet<String> { parked_path().ok().and_then(|p|std::fs::read(p).ok()).and_then(|b|serde_json::from_slice(&b).ok()).unwrap_or_default() }
fn save_parked(parked: &BTreeSet<String>) -> Result<(),String> { let path=parked_path()?; let tmp=path.with_extension("json.tmp"); std::fs::write(&tmp,serde_json::to_vec(parked).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?; std::fs::rename(tmp,path).map_err(|e|e.to_string()) }
impl Client {
 fn choose(&mut self, profile: Option<Profile>) { self.selected=profile.as_ref().map(Profile::key); *self.control.selected.lock().unwrap()=match profile { Some(Profile::Server(p))=>serde_json::from_value(p).ok(), _=>None }; }
 fn delete_imported(&mut self, id: String) {
  if self.armed_delete.as_deref()!=Some(id.as_str()) { self.armed_delete=Some(id); *self.message.lock().unwrap()="Нажмите ещё раз, чтобы удалить конфигурацию".into(); return; }
  self.armed_delete=None;
  if self.busy.lock().unwrap().is_some() { return; }
  match vpn_core::delete_imported_profile(&id) { Ok(())=> { self.profiles.retain(|profile| !matches!(profile,Profile::Imported(item) if item["id"].as_str()==Some(id.as_str()))); if self.selected.as_ref().is_some_and(|key|key==&format!("imported:{id}")) { let next=self.profiles.iter().find(|p|!self.parked.contains(&p.key())).cloned(); self.choose(next); } *self.message.lock().unwrap()="Конфигурация удалена".into(); }, Err(error)=>*self.message.lock().unwrap()=format!("Ошибка: {error}") }
 }
 fn park(&mut self, key: String, parked: bool) {
  if self.busy.lock().unwrap().is_some() { return; }
  if parked && self.selected.as_ref()==Some(&key) {
   // Активное подключение не рвём и не оставляем выбранной отложенную конфигурацию.
   if *self.status.lock().unwrap()==Some(true) { *self.message.lock().unwrap()="Сначала отключитесь или выберите другой сервер".into(); return; }
   let next=self.profiles.iter().find(|p| { let k=p.key(); k!=key && !self.parked.contains(&k) }).cloned(); self.choose(next);
  }
  if parked { self.parked.insert(key); } else { self.parked.remove(&key); if self.selected.is_none() { let back=self.profiles.iter().find(|p|p.key()==key).cloned(); self.choose(back); } }
  if let Err(error)=save_parked(&self.parked) { *self.message.lock().unwrap()=format!("Ошибка: {error}"); }
 }
}

// Палитра окна: один акцент и три цвета состояния, всё остальное — оттенки фона.
const BG: u32 = 0x11151d;
const SURFACE: u32 = 0x1a2030;
const SURFACE_HOVER: u32 = 0x222a3c;
const LINE: u32 = 0x4a566e;
const TEXT: u32 = 0xf1f4f9;
const MUTED: u32 = 0x93a0b5;
const ACCENT: u32 = 0x5b9bff;
const OK: u32 = 0x62d6a0;
const WARN: u32 = 0xf4b860;
const ERR: u32 = 0xff8080;

impl Profile {
 fn title(&self) -> String { match self { Self::Server(p) => p["server_name"].as_str().unwrap_or("Сервер"), Self::Imported(p) => p["host"].as_str().unwrap_or("Импорт") }.to_string() }
 fn subtitle(&self) -> String { match self { Self::Server(p) => p["email"].as_str().unwrap_or(""), Self::Imported(p) => p["name"].as_str().unwrap_or("") }.to_string() }
 fn flag(&self) -> Option<String> { let code=match self { Self::Server(p)=>p["country"].as_str(), Self::Imported(p)=>p["country"].as_str() }?; let mut chars=code.chars(); let a=chars.next()?; let b=chars.next()?; if chars.next().is_some() || !a.is_ascii_alphabetic() || !b.is_ascii_alphabetic() { return None; } Some(char::from_u32(127397+a.to_ascii_uppercase() as u32)?.to_string()+&char::from_u32(127397+b.to_ascii_uppercase() as u32)?.to_string()) }
}

/// Значок питания из примитивов: глиф «⏻» есть не во всех системных шрифтах.
fn power_icon(color: u32, backdrop: u32) -> gpui::Div {
 div().relative().size(px(34.))
  .child(div().absolute().top_0().left_0().size_full().rounded_full().border_3().border_color(rgb(color)))
  .child(div().absolute().top(px(-3.)).left(px(11.)).w(px(12.)).h(px(15.)).bg(rgb(backdrop)))
  .child(div().absolute().top(px(-4.)).left(px(15.5)).w(px(3.)).h(px(18.)).rounded_full().bg(rgb(color)))
}

/// Ячейка трафика: скорость крупно, итог за сессию — второй строкой.
fn traffic(label: &'static str, value: &str, live: bool, history: &[(f64,f64)]) -> gpui::Div {
 let (main, sub) = if live { value.split_once('\n').unwrap_or((value, "")) } else { ("—", "") };
 let peak=history.iter().fold(1.0_f64,|peak,(down,up)|peak.max(*down).max(*up));
 let mut chart=div().flex().items_end().gap(px(1.)).h(px(42.)).w(px(132.)).flex_shrink_0();
 for (down,up) in history { chart=chart.child(div().flex().items_end().gap(px(1.)).flex_1().h_full().child(div().flex_1().rounded_sm().h(px((down/peak*40.0).max(1.0) as f32)).bg(rgb(0x10cde9))).child(div().flex_1().rounded_sm().h(px((up/peak*40.0).max(1.0) as f32)).bg(rgb(0x9b65f7)))); }
 div().flex().items_center().gap_3().flex_1().min_w_0().px_3().py_2().rounded_lg().border_1().border_color(rgb(0x244565)).bg(linear_gradient(145.,linear_color_stop(rgb(0x122945),0.),linear_color_stop(rgb(0x0b152c),1.)))
  .child(div().flex().flex_col().gap_1().flex_1().min_w_0().child(div().text_xs().text_color(rgb(MUTED)).child(label)).child(div().font_family("Menlo").text_sm().text_color(rgb(if live { TEXT } else { MUTED })).truncate().child(main.to_string())).child(div().h(px(16.)).font_family("Menlo").text_xs().text_color(rgb(MUTED)).truncate().child(sub.to_string())))
  .child(chart)
}

/// Второстепенное действие: текст без рамки, фон появляется только при наведении.
fn ghost(id: impl Into<gpui::ElementId>, label: &'static str) -> gpui::Stateful<gpui::Div> {
 div().id(id).px_2().py_1().rounded_md().text_xs().text_color(rgb(MUTED)).cursor_pointer().hover(|s| s.bg(rgb(SURFACE_HOVER)).text_color(rgb(TEXT))).child(label)
}

impl Render for Client {
 fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
  let status=*self.status.lock().unwrap(); let connected=status==Some(true); let busy=*self.busy.lock().unwrap(); let message=self.message.lock().unwrap().clone(); let failed=message.starts_with("Ошибка:"); let vpn_failed=self.vpn_failed.load(Ordering::Relaxed); tray::update(status, busy.is_some(), vpn_failed);
  let selected=self.selected.as_ref().and_then(|k|self.profiles.iter().find(|p|p.key()==*k)).cloned();
  let results=self.probes.store.snapshot(); let stats=self.stats.lock().unwrap().clone();

  // Состояние показывается один раз: цветом кнопки и крупной подписью рядом с ней.
  let (_tone, _fill, state)=match (busy, status) { (Some(action), _) => (WARN, 0x33290f, action), (None, Some(true)) => (OK, 0x12332a, "Подключено"), (None, Some(false)) => (ACCENT, 0x1a2740, "Отключено"), (None, None) => (ACCENT, 0x1a2740, "Нет статуса") };
  // «Готово: …» дублирует статус, поэтому под ним остаются только ошибки и подсказки.
  let note=if busy.is_some() || message.is_empty() || message.starts_with("Готово:") { None } else { Some(message) };
  let server=selected.as_ref().map(Profile::label).unwrap_or_else(|| "Сервер не выбран".into());
  let ip=if !connected { None } else if stats.ip.is_empty() { Some("Проверяем…".to_string()) } else { Some(stats.ip.clone()) };

  let mut list=div().id("profile-list").flex().flex_col().gap_1p5().flex_1().min_h_0().w_full().overflow_y_scroll();
  if self.profiles.is_empty() { list=list.child(div().py_8().text_sm().text_center().text_color(rgb(MUTED)).child("Конфигураций пока нет. Добавьте сервер в «Администрировании».")); }
  let parked_count=self.profiles.iter().filter(|p|self.parked.contains(&p.key())).count(); let active_count=self.profiles.len()-parked_count;
  if active_count==0 && parked_count>0 { list=list.child(div().py_4().text_sm().text_center().text_color(rgb(MUTED)).child("Все конфигурации отложены. Верните нужную из списка ниже.")); }
  // Два прохода: сначала конфигурации в работе, затем отложенные под своим заголовком.
  for pass in [false, true] {
   if pass && parked_count>0 { list=list.child(div().flex().items_center().gap_2().pt_3().pb_1().text_sm().font_weight(gpui::FontWeight::SEMIBOLD).text_color(rgb(MUTED)).child("Временно не используются").child(div().text_xs().font_weight(gpui::FontWeight::NORMAL).child(parked_count.to_string()))); }
   for (i,p) in self.profiles.iter().enumerate() { let key=p.key(); let parked=self.parked.contains(&key); if parked!=pass { continue; }
    let chosen=!parked && self.selected.as_ref()==Some(&key); let profile=p.clone(); let subtitle=p.subtitle(); let flag=p.flag(); let park_key=key.clone(); let imported_id=if let Profile::Imported(item)=p { item["id"].as_str().map(str::to_owned) } else { None }; let armed=self.armed_delete.as_deref().is_some_and(|id|Some(id)==imported_id.as_deref());
    let (ping, ping_tone)=match results.get(&key) { Some(r) if r.udp => ("UDP".to_string(), MUTED), Some(r) if r.ms.is_some() => { let ms=r.ms.unwrap(); (format!("{ms} мс"), if ms<150 { OK } else if ms<400 { WARN } else { ERR }) }, Some(_) => ("Недоступен".to_string(), ERR), None => ("Проверка…".to_string(), MUTED) };
    let mut row=div().id(i).flex().items_center().gap_3().pl_3().pr_1p5().py_2().rounded_lg().border_1().border_color(rgb(if chosen { ACCENT } else if parked { BG } else { SURFACE })).bg(linear_gradient(115., linear_color_stop(rgb(if chosen {0x174b78} else if parked {0x0a1425} else {0x14243d}),0.), linear_color_stop(rgb(if chosen {0x20204c} else {0x0a1529}),1.)))
     .when(!chosen && !parked, |row| row.hover(|s| s.bg(rgb(SURFACE_HOVER)).border_color(rgb(SURFACE_HOVER))))
     .when(parked, |row| row.border_color(rgb(SURFACE)))
     .when(!parked, |row| row.child(div().flex().items_center().justify_center().flex_shrink_0().size(px(16.)).rounded_full().border_2().border_color(rgb(if chosen { ACCENT } else { LINE })).when(chosen, |radio| radio.child(div().size(px(6.)).rounded_full().bg(rgb(ACCENT))))))
     .child(div().flex().flex_col().flex_1().min_w_0()
      .child(div().flex().items_center().gap_2().child(if let Some(flag)=flag { div().text_sm().flex_shrink_0().child(flag) } else { div() }).child(div().text_sm().text_color(rgb(if parked { MUTED } else { TEXT })).truncate().child(p.title())))
      .when(!subtitle.is_empty(), |text| text.child(div().text_xs().text_color(rgb(MUTED)).truncate().child(subtitle))))
     .child(div().flex().items_center().gap_1p5().flex_shrink_0()
      .child(div().size(px(6.)).rounded_full().bg(rgb(ping_tone)))
      .child(div().font_family("Menlo").text_xs().text_color(rgb(if parked || ping_tone==MUTED { MUTED } else { TEXT })).child(ping)))
     .child(ghost(("park", i), if parked { "↑" } else { "↓" }).flex_shrink_0().on_click(cx.listener(move |this,_,_,cx| { cx.stop_propagation(); this.park(park_key.clone(), !parked); cx.notify(); })))
     .when_some(imported_id, |row,id| row.child(ghost(("delete", i), if armed { "Точно?" } else { "×" }).text_color(rgb(ERR)).on_click(cx.listener(move |this,_,_,cx| { cx.stop_propagation(); this.delete_imported(id.clone()); cx.notify(); }))));
    if !parked { row=row.cursor_pointer().on_click(cx.listener(move |this,_,_,cx| { if this.busy.lock().unwrap().is_some() { return; } let changed=this.selected.as_ref()!=Some(&key); this.selected=Some(key.clone()); *this.control.selected.lock().unwrap()=match &profile { Profile::Server(p)=>serde_json::from_value(p.clone()).ok(), Profile::Imported(_)=>None }; let connected_now=*this.status.lock().unwrap()==Some(true); if changed && connected_now { this.run(Some(profile.clone())); } cx.notify(); })); }
    list=list.child(row);
   }
  }

  let image_path=std::env::current_exe().ok().and_then(|p|p.parent()?.parent().map(|p|p.join("Resources/globe.png"))).filter(|p|p.exists()).unwrap_or_else(||std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/globe.png"));
  let button_tone=if busy.is_some(){WARN}else if vpn_failed {ERR}else if connected {0xdba4ff}else{0x8070a8};
  let (glow_hue,glow_alpha)=if busy.is_some(){(0.10,0.60)}else if vpn_failed {(0.0,0.55)}else if connected {(0.77,0.90)}else{(0.74,0.20)};
  let button_state=if busy.is_some(){state}else if connected {"ПОДКЛЮЧЕНО"}else if status==Some(false){"ОТКЛЮЧЕНО"}else{"НЕТ СТАТУСА"};
  div().flex().flex_col().gap_3().p_4().size_full().font_family("Avenir Next").bg(linear_gradient(135.,linear_color_stop(rgb(0x101b3b),0.),linear_color_stop(rgb(0x030b1a),1.))).text_color(rgb(TEXT))
   .child(div().h(px(26.)).w_full().flex().items_center().justify_end().gap_2().pr_1()
    .child(div().flex().items_center().justify_center().size(px(20.)).rounded_full().border_1().border_color(rgb(0x21dcef)).bg(linear_gradient(135.,linear_color_stop(rgb(0x184d72),0.),linear_color_stop(rgb(0x15163e),1.))).shadow(vec![BoxShadow { color:hsla(0.52,1.,0.5,0.42),offset:point(px(0.),px(0.)),blur_radius:px(10.),spread_radius:px(0.) }]).child(div().text_xs().font_weight(gpui::FontWeight::BOLD).text_color(rgb(0x72f5ff)).child("V")))
    .child(div().flex().items_center().gap_1().text_xs().child(div().font_weight(gpui::FontWeight::BOLD).text_color(rgb(0xeaf7ff)).child("VPN")).child(div().text_color(rgb(0x81a0c0)).child("CLIENT")))
    .on_mouse_down(gpui::MouseButton::Left, |_,window,_| window.start_window_move()))
   .child(div().flex().gap_3().flex_1().min_h_0().w_full()
    .child(div().flex().flex_col().gap_3().flex_1().min_w_0()
     .child(div().relative().flex().flex_col().justify_end().items_center().overflow_hidden().flex_1().min_h_0().w_full().rounded_xl().border_1().border_color(rgb(0x265c80)).bg(rgb(0x061327)).shadow(vec![BoxShadow { color:hsla(0.55,0.9,0.5,0.16),offset:point(px(0.),px(2.)),blur_radius:px(22.),spread_radius:px(0.) }])
      .child(img(image_path).absolute().top_0().left_0().size_full().object_fit(ObjectFit::Cover))
      .child(div().relative().flex().flex_col().items_center().gap_2().pb_5()
       .child(div().id("toggle").flex().flex_col().items_center().justify_center().gap_2().size(px(128.)).rounded_full().border_3().border_color(rgb(button_tone)).bg(linear_gradient(135.,linear_color_stop(rgb(if connected {0x3c1c60}else{0x19152e}),0.),linear_color_stop(rgb(0x090b1e),1.))).shadow(vec![BoxShadow { color:hsla(glow_hue,1.,0.60,glow_alpha),offset:point(px(0.),px(0.)),blur_radius:px(40.),spread_radius:px(8.) }, BoxShadow { color:hsla(glow_hue,0.95,0.52,glow_alpha*0.6),offset:point(px(0.),px(0.)),blur_radius:px(65.),spread_radius:px(12.) }]).cursor_pointer()
        .child(power_icon(button_tone,0x071928)).child(div().text_sm().child(if busy.is_some(){"Подождите…"}else if connected{"Отключить"}else{"Подключить"}))
        .on_click(cx.listener(move |this,_,_,cx| { if connected { this.run(None); } else if let Some(p)=selected.clone() { this.run(Some(p)); } else { *this.message.lock().unwrap()="Выберите конфигурацию".into(); } cx.notify(); })))
       .child(div().px_4().py_1().rounded_md().bg(rgb(0x0a1930)).text_color(rgb(button_tone)).font_family("Avenir Next Condensed").text_lg().font_weight(gpui::FontWeight::BOLD).child(button_state))
       .child(div().px_4().py_2().rounded_md().bg(rgb(0x0a1930)).text_sm().child(server))
       .when_some(ip,|el,ip|el.child(div().px_3().py_1().rounded_md().bg(rgb(0x0a1930)).text_xs().child(format!("IP  {ip}"))))
       .when_some(note,|el,note|el.child(div().px_3().py_1().rounded_md().bg(rgb(0x0a1930)).text_color(rgb(if failed{ERR}else{WARN})).text_xs().child(note)))))
     .child(div().flex().gap_3().w_full().child(traffic("Через VPN", &stats.vpn, connected && !stats.vpn.is_empty(), &stats.vpn_history)).child(traffic("Напрямую", &stats.direct, connected && !stats.direct.is_empty(), &stats.direct_history))))
    .child(div().flex().flex_col().gap_3().w(px(345.)).flex_shrink_0().p_3().rounded_xl().border_1().border_color(rgb(0x345076)).bg(linear_gradient(145.,linear_color_stop(rgb(0x10243f),0.),linear_color_stop(rgb(0x091327),1.))).shadow(vec![BoxShadow { color:hsla(0.58,0.8,0.5,0.18),offset:point(px(0.),px(0.)),blur_radius:px(18.),spread_radius:px(0.) }])
     .child(div().flex().items_center().justify_between().child(div().font_family("Avenir Next Condensed").text_xl().font_weight(gpui::FontWeight::BOLD).child(format!("Серверы  {active_count}"))).child(ghost("probe-now", "Обновить пинги").on_click(cx.listener(|this,_,_,_|this.probes.probe_now()))))
     .child(list)))
   .child(div().flex().justify_between().items_center().w_full().text_xs().text_color(rgb(MUTED)).child(concat!("v", env!("CARGO_PKG_VERSION"), " · ", env!("VPN_BUILD_NUMBER"))).child(div().flex().items_center().gap_3()
    .child(ghost("import", "Импорт из буфера").on_click(cx.listener(|this,_,_,cx| { this.import_from_clipboard(); cx.notify(); })))
    .child(ghost("admin", "Администрирование").on_click(|_,_,_| { let _=std::process::Command::new("open").arg("/Applications/VPNAdmin.app").spawn(); }))))

 }
}

fn main() { let control=Arc::new(control::State::default()); control::start(control.clone()).expect("Не удалось запустить MCP-сокет"); Application::new().run(move |cx: &mut App| { tray::install(); let bounds=Bounds::centered(None,size(px(1180.),px(720.)),cx); cx.open_window(WindowOptions { window_bounds:Some(WindowBounds::Windowed(bounds)), window_min_size:Some(size(px(820.),px(560.))), titlebar:Some(gpui::TitlebarOptions { title:Some("VPN Client".into()), appears_transparent:true, traffic_light_position:Some(point(px(12.),px(12.))) }), ..Default::default() }, |_,cx| cx.new(|cx|Client::new(control.clone(),cx))).unwrap(); cx.activate(true); }); }
