mod control;
mod stats;
mod tray;
use gpui::{div, prelude::*, px, rgb, size, App, Application, Bounds, Context, Window, WindowBounds, WindowOptions};
use std::{collections::BTreeSet, sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}}, time::Duration};

#[derive(Clone)]
enum Profile { Server(serde_json::Value), Imported(serde_json::Value) }
impl Profile {
 fn label(&self) -> String { match self { Self::Server(p) => format!("{} · {}",p["server_name"].as_str().unwrap_or("Сервер"),p["email"].as_str().unwrap_or("")), Self::Imported(p) => format!("{} · {}",p["host"].as_str().unwrap_or("Импорт"),p["name"].as_str().unwrap_or("")) } }
 fn key(&self) -> String { match self { Self::Server(p) => format!("{}:{}:{}",p["server_id"].as_str().unwrap_or(""),p["inbound_id"].as_u64().unwrap_or(0),p["email"].as_str().unwrap_or("")), Self::Imported(p) => format!("imported:{}",p["id"].as_str().unwrap_or("")) } }
 fn connect(&self) -> Result<String,String> { match self { Self::Server(p) => vpn_core::vpn_control::connect_profile_inner(&Default::default(),p["server_id"].as_str().unwrap_or(""),p["inbound_id"].as_u64().unwrap_or(0),p["email"].as_str().unwrap_or("")), Self::Imported(p) => vpn_core::vpn_control::connect_imported_inner(&Default::default(),p["id"].as_str().unwrap_or("")) } }
}
fn profiles() -> Result<Vec<Profile>,String> { let mut p: Vec<_>=vpn_core::list_connectable_profiles()?.into_iter().map(Profile::Server).collect(); p.extend(vpn_core::list_imported_profiles()?.into_iter().map(Profile::Imported)); Ok(p) }
struct Client { profiles: Vec<Profile>, selected: Option<String>, message: Arc<Mutex<String>>, busy: Arc<Mutex<Option<&'static str>>>, control: Arc<control::State>, status: Arc<Mutex<Option<bool>>>, probes: vpn_core::probe::ProbeHandle, stats: Arc<Mutex<stats::Display>>, generation: Arc<AtomicU64>, parked: BTreeSet<String> }
impl Client {
 fn new(control: Arc<control::State>, cx: &mut Context<Self>) -> Self {
  cx.spawn(async move |view, cx| { loop { cx.background_executor().timer(Duration::from_secs(1)).await; if view.update(cx, |this, cx| { if let Ok(p)=profiles() { this.profiles=p; } cx.notify(); }).is_err() { break; } } }).detach();
  let status=Arc::new(Mutex::new(None)); let status_worker=status.clone();
  std::thread::spawn(move || loop { *status_worker.lock().unwrap()=vpn_core::helper::status().ok(); std::thread::sleep(Duration::from_secs(5)); });
  let parked=load_parked(); let profiles=profiles().unwrap_or_default(); let first=profiles.iter().find(|p|!parked.contains(&p.key())); let selected=first.map(Profile::key);
  if let Some(Profile::Server(p))=first { *control.selected.lock().unwrap()=serde_json::from_value(p.clone()).ok(); }
  let generation=Arc::new(AtomicU64::new(0)); let stats=stats::start(status.clone(),generation.clone());
  Self { profiles, selected, parked, message:Arc::new(Mutex::new(String::new())), busy:Arc::new(Mutex::new(None)), control, status, probes:vpn_core::probe::start(), stats, generation }
 }
 fn run(&mut self, profile: Option<Profile>) {
  let mut busy=self.busy.lock().unwrap(); if busy.is_some() { return; } let action=if profile.is_none() { "Отключение…" } else if *self.status.lock().unwrap()==Some(true) { "Переподключение…" } else { "Подключение…" }; *busy=Some(action); drop(busy);
  let busy=self.busy.clone(); let message=self.message.clone(); let control=self.control.clone(); let status=self.status.clone(); let generation=self.generation.clone();
  *message.lock().unwrap()=action.into();
  std::thread::spawn(move || { let result=match control.operation.lock() { Ok(_guard) => match profile { Some(p)=>p.connect(), None=>vpn_core::vpn_control::stop_vpn_inner(&Default::default()).map(|_|"VPN отключён".into()) }, Err(_)=>Err("Управление VPN недоступно".into()) }; if result.is_ok() { generation.fetch_add(1,Ordering::Relaxed); } *message.lock().unwrap()=match result { Ok(message)=>format!("Готово: {message}"), Err(error)=>format!("Ошибка: {error}") }; *status.lock().unwrap()=vpn_core::helper::status().ok(); *busy.lock().unwrap()=None; });
 }
}
// Отложенные конфигурации — настройка только этого окна, поэтому хранится отдельным файлом рядом с данными приложения.
fn parked_path() -> Result<std::path::PathBuf,String> { Ok(vpn_core::mcp_control_socket_path()?.parent().and_then(|p|p.parent()).ok_or("Некорректный путь настроек")?.join("gpui-parked-profiles.json")) }
fn load_parked() -> BTreeSet<String> { parked_path().ok().and_then(|p|std::fs::read(p).ok()).and_then(|b|serde_json::from_slice(&b).ok()).unwrap_or_default() }
fn save_parked(parked: &BTreeSet<String>) -> Result<(),String> { let path=parked_path()?; let tmp=path.with_extension("json.tmp"); std::fs::write(&tmp,serde_json::to_vec(parked).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?; std::fs::rename(tmp,path).map_err(|e|e.to_string()) }
impl Client {
 fn choose(&mut self, profile: Option<Profile>) { self.selected=profile.as_ref().map(Profile::key); *self.control.selected.lock().unwrap()=match profile { Some(Profile::Server(p))=>serde_json::from_value(p).ok(), _=>None }; }
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
const SELECTED: u32 = 0x1b2a45;
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
}

/// Значок питания из примитивов: глиф «⏻» есть не во всех системных шрифтах.
fn power_icon(color: u32, backdrop: u32) -> gpui::Div {
 div().relative().size(px(34.))
  .child(div().absolute().top_0().left_0().size_full().rounded_full().border_3().border_color(rgb(color)))
  .child(div().absolute().top(px(-3.)).left(px(11.)).w(px(12.)).h(px(15.)).bg(rgb(backdrop)))
  .child(div().absolute().top(px(-4.)).left(px(15.5)).w(px(3.)).h(px(18.)).rounded_full().bg(rgb(color)))
}

/// Ячейка трафика: скорость крупно, итог за сессию — второй строкой.
fn traffic(label: &'static str, value: &str, live: bool) -> gpui::Div {
 let (main, sub) = if live { value.split_once('\n').unwrap_or((value, "")) } else { ("—", "") };
 div().flex().flex_col().gap_1().flex_1().min_w_0().px_3().py_2().rounded_lg().bg(rgb(SURFACE))
  .child(div().text_xs().text_color(rgb(MUTED)).child(label))
  .child(div().text_sm().text_color(rgb(if live { TEXT } else { MUTED })).truncate().child(main.to_string()))
  .child(div().h(px(16.)).text_xs().text_color(rgb(MUTED)).truncate().child(sub.to_string()))
}

/// Второстепенное действие: текст без рамки, фон появляется только при наведении.
fn ghost(id: impl Into<gpui::ElementId>, label: &'static str) -> gpui::Stateful<gpui::Div> {
 div().id(id).px_2().py_1().rounded_md().text_xs().text_color(rgb(MUTED)).cursor_pointer().hover(|s| s.bg(rgb(SURFACE_HOVER)).text_color(rgb(TEXT))).child(label)
}

impl Render for Client {
 fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
  let status=*self.status.lock().unwrap(); let connected=status==Some(true); let busy=*self.busy.lock().unwrap(); let message=self.message.lock().unwrap().clone(); let failed=message.starts_with("Ошибка:"); tray::update(status, busy.is_some(), failed);
  let selected=self.selected.as_ref().and_then(|k|self.profiles.iter().find(|p|p.key()==*k)).cloned();
  let results=self.probes.store.snapshot(); let stats=self.stats.lock().unwrap().clone();

  // Состояние показывается один раз: цветом кнопки и крупной подписью рядом с ней.
  let (tone, fill, state)=match (busy, status) { (Some(action), _) => (WARN, 0x33290f, action), (None, Some(true)) => (OK, 0x12332a, "Подключено"), (None, Some(false)) => (ACCENT, 0x1a2740, "Отключено"), (None, None) => (ACCENT, 0x1a2740, "Нет статуса") };
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
    let chosen=!parked && self.selected.as_ref()==Some(&key); let profile=p.clone(); let subtitle=p.subtitle(); let park_key=key.clone();
    let (ping, ping_tone)=match results.get(&key) { Some(r) if r.udp => ("UDP".to_string(), MUTED), Some(r) if r.ms.is_some() => { let ms=r.ms.unwrap(); (format!("{ms} мс"), if ms<150 { OK } else if ms<400 { WARN } else { ERR }) }, Some(_) => ("Недоступен".to_string(), ERR), None => ("Проверка…".to_string(), MUTED) };
    let mut row=div().id(i).flex().items_center().gap_3().pl_3().pr_1p5().py_2().rounded_lg().border_1().border_color(rgb(if chosen { ACCENT } else if parked { BG } else { SURFACE })).bg(rgb(if chosen { SELECTED } else if parked { BG } else { SURFACE }))
     .when(!chosen && !parked, |row| row.hover(|s| s.bg(rgb(SURFACE_HOVER)).border_color(rgb(SURFACE_HOVER))))
     .when(parked, |row| row.border_color(rgb(SURFACE)))
     .when(!parked, |row| row.child(div().flex().items_center().justify_center().flex_shrink_0().size(px(16.)).rounded_full().border_2().border_color(rgb(if chosen { ACCENT } else { LINE })).when(chosen, |radio| radio.child(div().size(px(6.)).rounded_full().bg(rgb(ACCENT))))))
     .child(div().flex().flex_col().flex_1().min_w_0()
      .child(div().text_sm().text_color(rgb(if parked { MUTED } else { TEXT })).truncate().child(p.title()))
      .when(!subtitle.is_empty(), |text| text.child(div().text_xs().text_color(rgb(MUTED)).truncate().child(subtitle))))
     .child(div().flex().items_center().gap_1p5().flex_shrink_0()
      .child(div().size(px(6.)).rounded_full().bg(rgb(ping_tone)))
      .child(div().text_xs().text_color(rgb(if parked || ping_tone==MUTED { MUTED } else { TEXT })).child(ping)))
     .child(ghost(("park", i), if parked { "Вернуть" } else { "Отложить" }).flex_shrink_0().on_click(cx.listener(move |this,_,_,cx| { cx.stop_propagation(); this.park(park_key.clone(), !parked); cx.notify(); })));
    if !parked { row=row.cursor_pointer().on_click(cx.listener(move |this,_,_,cx| { if this.busy.lock().unwrap().is_some() { return; } let changed=this.selected.as_ref()!=Some(&key); this.selected=Some(key.clone()); *this.control.selected.lock().unwrap()=match &profile { Profile::Server(p)=>serde_json::from_value(p.clone()).ok(), Profile::Imported(_)=>None }; let connected_now=*this.status.lock().unwrap()==Some(true); if changed && connected_now { this.run(Some(profile.clone())); } cx.notify(); })); }
    list=list.child(row);
   }
  }

  div().flex().flex_col().gap_3().p_4().size_full().bg(rgb(BG)).text_color(rgb(TEXT))
   // Главный блок: кнопка — единственный яркий элемент окна.
   .child(div().flex().items_center().gap_4().w_full().p_4().rounded_xl().bg(rgb(SURFACE))
    .child(div().id("toggle").flex().flex_col().items_center().justify_center().gap_2().flex_shrink_0().size(px(108.)).rounded_full().border_2().border_color(rgb(tone)).bg(rgb(fill)).cursor_pointer()
     .child(power_icon(tone, fill))
     .child(div().text_xs().child(if busy.is_some() {"Подождите…"} else if connected {"Отключить"} else {"Подключить"}))
     .on_click(cx.listener(move |this,_,_,cx| { if connected { this.run(None); } else if let Some(p)=selected.clone() { this.run(Some(p)); } else { *this.message.lock().unwrap()="Выберите конфигурацию".into(); } cx.notify(); })))
    .child(div().flex().flex_col().gap_1().flex_1().min_w_0()
     .child(div().text_xl().font_weight(gpui::FontWeight::SEMIBOLD).text_color(rgb(if busy.is_some() || connected { tone } else { TEXT })).child(state))
     .child(div().text_sm().text_color(rgb(MUTED)).truncate().child(server))
     .when_some(ip, |info, ip| info.child(div().flex().gap_2().text_sm().child(div().text_color(rgb(MUTED)).child("IP")).child(div().truncate().child(ip))))
     .when_some(note, |info, note| info.child(div().pt_1().text_xs().text_color(rgb(if failed { ERR } else { WARN })).line_clamp(4).child(note)))))
   .child(div().flex().gap_2().w_full()
    .child(traffic("Через VPN", &stats.vpn, connected && !stats.vpn.is_empty()))
    .child(traffic("Напрямую", &stats.direct, connected && !stats.direct.is_empty())))
   .child(div().flex().justify_between().items_center().w_full().pt_1()
    .child(div().flex().items_center().gap_2().text_sm().font_weight(gpui::FontWeight::SEMIBOLD).child("В работе").child(div().text_xs().font_weight(gpui::FontWeight::NORMAL).text_color(rgb(MUTED)).child(active_count.to_string())))
    .child(ghost("probe-now", "Обновить пинги").on_click(cx.listener(|this,_,_,_|this.probes.probe_now()))))
   .child(list)
   .child(div().flex().justify_end().w_full().child(ghost("admin", "Администрирование").on_click(|_,_,_| { let _=std::process::Command::new("open").arg("/Applications/VPNAdmin.app").spawn(); })))
 }
}

fn main() { let control=Arc::new(control::State::default()); control::start(control.clone()).expect("Не удалось запустить MCP-сокет"); Application::new().run(move |cx: &mut App| { tray::install(); let bounds=Bounds::centered(None,size(px(420.),px(600.)),cx); cx.open_window(WindowOptions { window_bounds:Some(WindowBounds::Windowed(bounds)), window_min_size:Some(size(px(380.),px(480.))), titlebar:Some(gpui::TitlebarOptions { title:Some("VPN Client".into()), ..Default::default() }), ..Default::default() }, |_,cx| cx.new(|cx|Client::new(control.clone(),cx))).unwrap(); cx.activate(true); }); }
