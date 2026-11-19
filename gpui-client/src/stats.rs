use std::{sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}}, time::Duration};
use serde_json::Value;

#[derive(Clone, Default)]
pub struct Display { pub ip: String, pub vpn: String, pub direct: String, pub vpn_history: Vec<(f64,f64)>, pub direct_history: Vec<(f64,f64)> }
fn total(n: f64) -> String { if n >= 1_073_741_824.0 { format!("{:.2} ГБ",n / 1_073_741_824.0) } else if n >= 1_048_576.0 { format!("{:.1} МБ",n / 1_048_576.0) } else { format!("{:.0} КБ",n / 1024.0) } }
fn rate(n: f64) -> String { if n >= 1_048_576.0 { format!("{:.1} МБ/с",n / 1_048_576.0) } else if n >= 1024.0 { format!("{:.0} КБ/с",n / 1024.0) } else { format!("{:.0} Б/с",n) } }
fn row(now: &Value, prev: Option<&Value>, route: &str) -> Option<String> {
 let up=now[route]["up"].as_u64()?; let down=now[route]["down"].as_u64()?; let ts=now["ts_ms"].as_u64()?;
 let speeds=prev.and_then(|p| { let dt=ts.checked_sub(p["ts_ms"].as_u64()?)?; if dt==0 { return None; } let prev_up=p[route]["up"].as_u64()?; let prev_down=p[route]["down"].as_u64()?; Some((up.saturating_sub(prev_up) as f64*1000.0/dt as f64,down.saturating_sub(prev_down) as f64*1000.0/dt as f64)) });
 let (upload,download)=speeds.unwrap_or((0.0,0.0));
 Some(format!("↓ {}  ↑ {}\nВсего ↓ {}  ↑ {}",rate(download),rate(upload),total(down as f64),total(up as f64)))
}
fn sample(now: &Value, previous: Option<&Value>, route: &str) -> Option<(f64,f64)> {
 let prev=previous?; let dt=now["ts_ms"].as_u64()?.checked_sub(prev["ts_ms"].as_u64()?)?; if dt==0 { return None; }
 let down=now[route]["down"].as_u64()?.checked_sub(prev[route]["down"].as_u64()?)?;
 let up=now[route]["up"].as_u64()?.checked_sub(prev[route]["up"].as_u64()?)?;
 Some((down as f64*1000.0/dt as f64,up as f64*1000.0/dt as f64))
}
fn push_sample(history: &mut Vec<(f64,f64)>, sample: Option<(f64,f64)>) { if let Some(sample)=sample { if history.len()>=36 { history.remove(0); } history.push(sample); } }
pub fn start(status: Arc<Mutex<Option<bool>>>, generation: Arc<AtomicU64>) -> Arc<Mutex<Display>> {
 let display=Arc::new(Mutex::new(Display::default())); let output=display.clone();
 std::thread::spawn(move || { let mut previous: Option<Value>=None; let mut last_generation=None;
  loop { if *status.lock().unwrap()!=Some(true) { previous=None; last_generation=None; *output.lock().unwrap()=Display::default(); std::thread::sleep(Duration::from_millis(1500)); continue; }
   let current_generation=generation.load(Ordering::Relaxed);
   if last_generation!=Some(current_generation) { previous=None; last_generation=Some(current_generation); { let mut display=output.lock().unwrap(); display.ip="Проверяем…".into(); display.vpn_history.clear(); display.direct_history.clear(); } let output=output.clone(); let generation=generation.clone(); std::thread::spawn(move || { let ip=vpn_core::probe::exit_ip().unwrap_or_else(|_|"Не удалось получить".into()); if generation.load(Ordering::Relaxed)==current_generation { output.lock().unwrap().ip=ip; } }); }
   match vpn_core::helper::stats() { Ok(now) => { let vpn=row(&now,previous.as_ref(),"vpn"); let direct=row(&now,previous.as_ref(),"direct"); let mut display=output.lock().unwrap(); display.vpn=vpn.unwrap_or_else(||"Нет данных".into()); display.direct=direct.unwrap_or_else(||"Нет данных".into()); push_sample(&mut display.vpn_history,sample(&now,previous.as_ref(),"vpn")); push_sample(&mut display.direct_history,sample(&now,previous.as_ref(),"direct")); drop(display); previous=Some(now); }, Err(_) => { previous=None; let mut display=output.lock().unwrap(); display.vpn="Нет данных".into(); display.direct="Нет данных".into(); display.vpn_history.clear(); display.direct_history.clear(); } }
   std::thread::sleep(Duration::from_millis(1500));
  }
 }); display
}
#[cfg(test)] mod tests { use super::*; use serde_json::json;
 #[test] fn history_uses_real_rates_and_discards_counter_resets() { let before=json!({"ts_ms":1000,"vpn":{"up":100,"down":200}}); let after=json!({"ts_ms":3000,"vpn":{"up":1100,"down":4200}}); assert_eq!(sample(&after,Some(&before),"vpn"),Some((2000.0,500.0))); assert_eq!(sample(&before,Some(&after),"vpn"),None); assert_eq!(sample(&after,None,"vpn"),None); }
 #[test] fn calculates_and_clamps_rates() { let prev=json!({"ts_ms":1000,"vpn":{"up":100,"down":400}}); let now=json!({"ts_ms":3000,"vpn":{"up":2148,"down":200}}); let text=row(&now,Some(&prev),"vpn").unwrap(); assert!(text.contains("↑ 1 КБ/с")); assert!(text.contains("↓ 0 Б/с")); assert!(row(&json!({}),None,"vpn").is_none()); } }
