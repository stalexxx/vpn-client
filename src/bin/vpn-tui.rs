//! TUI-монитор VPN: подключение, скорость и журнал.
//!
//! Опрашивает helper-сокет `/var/run/vpnclient-tun.sock` напрямую
//! (GUI-приложение не требуется):
//! - `status` каждую секунду — подключён ли туннель;
//! - `stats` каждую секунду — счётчики Xray `{direct,vpn}x{up,down}` + `ts_ms`,
//!   скорость считается по дельте двух соседних замеров;
//! - `log` каждые 5 секунд — хвост журнала Xray.
//!
//! Запуск: `cargo run --bin vpn-tui [-- --once] [--interval-ms 1000] [--log-lines 12]`
//! Выход: `q` или `Esc`. Без TTY (пайп) автоматически печатает один снимок.

use std::collections::VecDeque;
use std::io::{self, IsTerminal};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Sparkline, Table, Wrap};

const HISTORY: usize = 120;

fn human_rate(bytes: f64) -> String {
    if bytes >= 1048576.0 {
        format!("{:.1} МБ/с", bytes / 1048576.0)
    } else if bytes >= 1024.0 {
        format!("{:.0} КБ/с", bytes / 1024.0)
    } else {
        format!("{bytes:.0} Б/с")
    }
}

fn human_total(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1073741824.0 {
        format!("{:.2} ГБ", b / 1073741824.0)
    } else if b >= 1048576.0 {
        format!("{:.1} МБ", b / 1048576.0)
    } else {
        format!("{:.0} КБ", b / 1024.0)
    }
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Counters {
    vpn_up: u64,
    vpn_down: u64,
    direct_up: u64,
    direct_down: u64,
    ts_ms: u64,
}

fn counters_of(v: &serde_json::Value) -> Counters {
    let num = |route: &str, dir: &str| v[route][dir].as_u64().unwrap_or(0);
    Counters {
        vpn_up: num("vpn", "up"),
        vpn_down: num("vpn", "down"),
        direct_up: num("direct", "up"),
        direct_down: num("direct", "down"),
        ts_ms: v["ts_ms"].as_u64().unwrap_or(0),
    }
}

/// Скорость (Б/с) по двум соседним замерам. `None`, если дельта времени неположительна.
fn rates_from(prev: &Counters, cur: &Counters) -> Option<(f64, f64, f64, f64)> {
    let dt = (cur.ts_ms.saturating_sub(prev.ts_ms) as f64) / 1000.0;
    if dt <= 0.0 {
        return None;
    }
    let rate = |a: u64, b: u64| b.saturating_sub(a) as f64 / dt;
    Some((
        rate(prev.vpn_down, cur.vpn_down),
        rate(prev.vpn_up, cur.vpn_up),
        rate(prev.direct_down, cur.direct_down),
        rate(prev.direct_up, cur.direct_up),
    ))
}

#[derive(Debug, Default)]
struct Snapshot {
    connected: Option<bool>,
    error: Option<String>,
    counters: Option<Counters>,
    /// (vpn_down, vpn_up, direct_down, direct_up), Б/с.
    rates: (f64, f64, f64, f64),
    log: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum ProfileTarget {
    Server { server_id: String, inbound_id: u64, email: String },
    Imported { id: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Profile {
    /// `srv:<server_id>:<inbound_id>:<email>` or `imported:<id>`.
    key: String,
    title: String,
    detail: String,
    target: ProfileTarget,
}

/// Server profiles first, then imported ones (awg://, vless://, hysteria2://).
/// Pure mapping over the core listings, so it is unit-testable.
fn summarize_profiles(
    servers: &[serde_json::Value],
    imported: &[serde_json::Value],
) -> Vec<Profile> {
    let mut out = Vec::new();
    for p in servers {
        let (Some(server_id), Some(inbound_id), Some(email)) = (
            p["server_id"].as_str(),
            p["inbound_id"].as_u64(),
            p["email"].as_str(),
        ) else { continue };
        out.push(Profile {
            key: format!("srv:{server_id}:{inbound_id}:{email}"),
            title: format!(
                "{} · {} ({})",
                email,
                p["inbound_name"].as_str().unwrap_or("Подключение"),
                p["server_name"].as_str().unwrap_or(""),
            ),
            detail: format!(
                "{} · {} · порт {}",
                p["protocol"].as_str().unwrap_or("?"),
                p["transport"].as_str().unwrap_or("?"),
                p["port"].as_u64().unwrap_or(0),
            ),
            target: ProfileTarget::Server {
                server_id: server_id.to_owned(),
                inbound_id,
                email: email.to_owned(),
            },
        });
    }
    for p in imported {
        let Some(id) = p["id"].as_str() else { continue };
        out.push(Profile {
            key: format!("imported:{id}"),
            title: p["name"].as_str().unwrap_or(id).to_owned(),
            detail: format!(
                "{} · {}:{}",
                p["transport"].as_str().unwrap_or("?"),
                p["host"].as_str().unwrap_or("?"),
                p["port"].as_u64().unwrap_or(0),
            ),
            target: ProfileTarget::Imported { id: id.to_owned() },
        });
    }
    out
}

/// Core listings as TUI rows; `Err` is a display string, never a fatal error.
fn load_profiles() -> (Vec<Profile>, Option<String>) {
    let mut err = None;
    let servers = match vpn_core::list_connectable_profiles() {
        Ok(v) => v,
        Err(e) => {
            err = Some(e);
            Vec::new()
        }
    };
    let imported = match vpn_core::list_imported_profiles() {
        Ok(v) => v,
        Err(e) => {
            err = Some(e);
            Vec::new()
        }
    };
    (summarize_profiles(&servers, &imported), err)
}

fn connect_profile(state: &vpn_core::xray::XrayState, profile: &Profile) -> Result<String, String> {
    match &profile.target {
        ProfileTarget::Server { server_id, inbound_id, email } => {
            vpn_core::vpn_control::connect_profile_inner(state, server_id, *inbound_id, email)
        }
        ProfileTarget::Imported { id } => {
            vpn_core::vpn_control::connect_imported_inner(state, id)
        }
    }
}

/// Trims an ipify answer; `None` rejects garbage before it reaches the screen.
fn clean_ip(raw: &str) -> Option<String> {
    let ip = raw.trim().to_owned();
    if ip.is_empty() || ip.len() > 64 || ip.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    Some(ip)
}

/// External egress IP as the internet sees it, fetched off-thread so the
/// 60s helper switch never blocks on it. Sends `None` on any failure.
fn spawn_ip_lookup(tx: std::sync::mpsc::Sender<Option<String>>) {
    std::thread::spawn(move || {
        let ip = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .ok()
            .and_then(|client| client.get("https://api.ipify.org").send().ok())
            .and_then(|response| response.text().ok())
            .and_then(|text| clean_ip(&text));
        let _ = tx.send(ip);
    });
}

fn poll_once(log_lines: u64) -> Snapshot {
    let mut snap = Snapshot::default();
    match vpn_core::helper::status() {
        Ok(up) => snap.connected = Some(up),
        Err(e) => {
            snap.error = Some(e);
            return snap;
        }
    }
    if snap.connected != Some(true) {
        return snap;
    }
    match vpn_core::helper::stats() {
        Ok(v) => snap.counters = Some(counters_of(&v)),
        Err(e) => snap.error = Some(e),
    }
    match vpn_core::helper::log_tail(log_lines, None) {
        Ok(text) => {
            snap.log = text.lines().map(str::to_owned).collect();
        }
        Err(e) => {
            let msg = format!("журнал недоступен: {e}");
            snap.log = vec![msg];
        }
    }
    snap
}

fn print_once(interval: Duration, log_lines: u64) {
    let status = vpn_core::helper::status();
    let connected = status.as_ref().is_ok_and(|up| *up);
    if !connected {
        match &status {
            Err(e) => println!("VPN: недоступен ({e})"),
            Ok(_) => println!("VPN: отключён"),
        }
        return;
    }
    let first = vpn_core::helper::stats().ok().map(|v| counters_of(&v));
    std::thread::sleep(interval);
    let second = vpn_core::helper::stats().ok().map(|v| counters_of(&v));
    match (first, second) {
        (Some(a), Some(b)) => match rates_from(&a, &b) {
            Some((vd, vu, dd, du)) => {
                println!("VPN: подключён");
                println!(
                    "Через VPN: ↓ {} ↑ {} (всего ↓ {} ↑ {})",
                    human_rate(vd),
                    human_rate(vu),
                    human_total(b.vpn_down),
                    human_total(b.vpn_up)
                );
                println!(
                    "Напрямую:  ↓ {} ↑ {} (всего ↓ {} ↑ {})",
                    human_rate(dd),
                    human_rate(du),
                    human_total(b.direct_down),
                    human_total(b.direct_up)
                );
            }
            None => println!("VPN: подключён (не удалось измерить скорость)"),
        },
        _ => println!("VPN: подключён (статистика недоступна)"),
    }
    match vpn_core::helper::log_tail(log_lines, None) {
        Ok(text) if !text.is_empty() => println!("--- журнал ---\n{text}"),
        _ => {}
    }
}

struct Args {
    once: bool,
    interval: Duration,
    log_lines: u64,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut once = false;
    let mut interval = Duration::from_secs(1);
    let mut log_lines = 12u64;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--once" => once = true,
            "--interval-ms" => {
                i += 1;
                let ms: u64 = argv
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .filter(|ms| (250..=10_000).contains(ms))
                    .ok_or("Некорректный --interval-ms (250–10000)")?;
                interval = Duration::from_millis(ms);
            }
            "--log-lines" => {
                i += 1;
                log_lines = argv
                    .get(i)
                    .and_then(|s| s.parse::<u64>().ok())
                    .filter(|n| (0..=50u64).contains(n))
                    .ok_or("Некорректный --log-lines (0–50)")?;
            }
            other => return Err(format!("Неизвестный аргумент: {other}")),
        }
        i += 1;
    }
    Ok(Args {
        once,
        interval,
        log_lines,
    })
}

fn status_line(snap: &Snapshot) -> (String, Color) {
    match snap.connected {
        Some(true) => ("● ПОДКЛЮЧЁН".to_owned(), Color::Green),
        Some(false) => ("○ ОТКЛЮЧЁН".to_owned(), Color::Red),
        None => ("? НЕТ СВЯЗИ С HELPER".to_owned(), Color::Yellow),
    }
}

fn run_tui(args: Args) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut prev: Option<Counters> = None;
    let mut hist_down: VecDeque<u64> = VecDeque::with_capacity(HISTORY);
    let mut hist_up: VecDeque<u64> = VecDeque::with_capacity(HISTORY);
    let mut snap = Snapshot::default();
    let mut tick = 0u64;
    // Switching reuses the same core logic as the GUI clients.
    let xray_state = vpn_core::xray::XrayState::default();
    let (mut profiles, err) = load_profiles();
    let mut selected = 0usize;
    let mut offset = 0usize;
    let mut message: Option<String> = err;
    // Key of the profile this session connected last; cleared when the tunnel drops.
    let mut active_key: Option<String> = None;
    let (ip_tx, ip_rx) = std::sync::mpsc::channel::<Option<String>>();
    spawn_ip_lookup(ip_tx.clone());
    // Egress IP as the internet sees it via ipify; "…" until the first answer.
    let mut visible_ip = "…".to_owned();

    let result = loop {
        // Опрос helper: status+stats каждый тик, журнал — каждый 5-й.
        let mut fresh = poll_once(args.log_lines);
        if let (Some(p), Some(c)) = (prev, fresh.counters) {
            if let Some((vd, vu, dd, du)) = rates_from(&p, &c) {
                fresh.rates = (vd, vu, dd, du);
                if hist_down.len() == HISTORY {
                    hist_down.pop_front();
                    hist_up.pop_front();
                }
                hist_down.push_back(vd as u64);
                hist_up.push_back(vu as u64);
            } else {
                fresh.rates = snap.rates;
            }
        } else if fresh.connected != Some(true) {
            fresh.rates = (0.0, 0.0, 0.0, 0.0);
        } else {
            fresh.rates = snap.rates;
        }
        if tick % 5 != 0 {
            fresh.log = std::mem::take(&mut snap.log);
        }
        if let Some(c) = fresh.counters {
            prev = Some(c);
        } else if fresh.connected != Some(true) {
            prev = None;
            hist_down.clear();
            hist_up.clear();
        }
        snap = fresh;
        if snap.connected == Some(false) {
            active_key = None;
        }
        for ip in ip_rx.try_iter() {
            visible_ip = ip.unwrap_or_else(|| "?".to_owned());
        }
        tick += 1;
        if tick % 30 == 0 {
            spawn_ip_lookup(ip_tx.clone());
        }

        terminal.draw(|f| {
            let area = f.area();
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(4),
                    Constraint::Length(9),
                    Constraint::Length(6),
                    Constraint::Min(3),
                    Constraint::Length(2),
                ])
                .split(area);

            let (text, color) = status_line(&snap);
            let mut first = vec![Span::styled(
                format!("VPN {text} · IP {visible_ip}"),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            )];
            if let Some(e) = &snap.error {
                first.push(Span::raw(format!("  — {e}")));
            }
            let second = Line::from(Span::styled(
                message.as_deref().unwrap_or("—"),
                Style::default().fg(Color::DarkGray),
            ));
            f.render_widget(
                Paragraph::new(vec![Line::from(first), second])
                    .block(Block::default().borders(Borders::ALL).title(" Подключение "))
                    .wrap(Wrap { trim: true }),
                rows[0],
            );

            // Profiles: a scroll window of 7 rows around the selection.
            const VISIBLE: usize = 7;
            if selected >= profiles.len() {
                selected = profiles.len().saturating_sub(1);
            }
            if selected < offset {
                offset = selected;
            }
            if selected >= offset + VISIBLE {
                offset = selected + 1 - VISIBLE;
            }
            let items: Vec<ListItem> = if profiles.is_empty() {
                vec![ListItem::new("Нет профилей — импортируйте ссылку в приложении")]
            } else {
                profiles
                    .iter()
                    .enumerate()
                    .skip(offset)
                    .take(VISIBLE)
                    .map(|(i, p)| {
                        let cursor = if i == selected { "▸ " } else { "  " };
                        let mut spans = vec![Span::raw(cursor.to_owned())];
                        if active_key.as_deref() == Some(p.key.as_str())
                            && snap.connected == Some(true)
                        {
                            spans.push(Span::styled(
                                "● ",
                                Style::default()
                                    .fg(Color::Green)
                                    .add_modifier(Modifier::BOLD),
                            ));
                        }
                        spans.push(Span::styled(
                            p.title.clone(),
                            if i == selected {
                                Style::default().add_modifier(Modifier::BOLD)
                            } else {
                                Style::default()
                            },
                        ));
                        spans.push(Span::styled(
                            format!("  {}", p.detail),
                            Style::default().fg(Color::DarkGray),
                        ));
                        ListItem::new(Line::from(spans))
                    })
                    .collect()
            };
            f.render_widget(
                List::new(items).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Профили (Enter — подключить) "),
                ),
                rows[1],
            );

            let (vd, vu, dd, du) = snap.rates;
            let totals: (u64, u64, u64, u64) = snap.counters.map_or((0, 0, 0, 0), |c| {
                (c.vpn_down, c.vpn_up, c.direct_down, c.direct_up)
            });
            let traffic = Table::new(
                vec![
                    Row::new(vec![
                        Cell::from("VPN ↓"),
                        Cell::from(human_rate(vd)),
                        Cell::from(format!("всего {}", human_total(totals.0))),
                    ]),
                    Row::new(vec![
                        Cell::from("VPN ↑"),
                        Cell::from(human_rate(vu)),
                        Cell::from(format!("всего {}", human_total(totals.1))),
                    ]),
                    Row::new(vec![
                        Cell::from("мимо ↓"),
                        Cell::from(human_rate(dd)),
                        Cell::from(format!("всего {}", human_total(totals.2))),
                    ]),
                    Row::new(vec![
                        Cell::from("мимо ↑"),
                        Cell::from(human_rate(du)),
                        Cell::from(format!("всего {}", human_total(totals.3))),
                    ]),
                ],
                [
                    Constraint::Length(10),
                    Constraint::Length(14),
                    Constraint::Min(10),
                ],
            )
            .block(Block::default().borders(Borders::ALL).title(" Трафик "))
            .column_spacing(2);
            f.render_widget(traffic, rows[2]);

            let down: Vec<u64> = hist_down.iter().copied().collect();
            let up: Vec<u64> = hist_up.iter().copied().collect();
            let peak = down.iter().chain(up.iter()).copied().max().unwrap_or(1).max(1);
            let chart_rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(rows[3]);
            f.render_widget(
                Sparkline::default()
                    .block(
                        Block::default().borders(Borders::ALL).title(format!(
                            " ↓ входящая (пик {}) ",
                            human_rate(peak as f64)
                        )),
                    )
                    .data(&down)
                    .max(peak)
                    .style(Style::default().fg(Color::Green)),
                chart_rows[0],
            );
            if args.log_lines > 0 {
                let log_text = if snap.log.is_empty() {
                    "—".to_owned()
                } else {
                    snap.log.join("\n")
                };
                f.render_widget(
                    Paragraph::new(log_text)
                        .block(Block::default().borders(Borders::ALL).title(" Журнал Xray "))
                        .wrap(Wrap { trim: false }),
                    chart_rows[1],
                );
            } else {
                f.render_widget(
                    Sparkline::default()
                        .block(Block::default().borders(Borders::ALL).title(" ↑ исходящая "))
                        .data(&up)
                        .max(peak)
                        .style(Style::default().fg(Color::Cyan)),
                    chart_rows[1],
                );
            }

            f.render_widget(
                Paragraph::new("↑/↓ выбор · Enter ВКЛ · d ВЫКЛ · r обновить · q/Esc выход")
                    .style(Style::default().fg(Color::DarkGray)),
                rows[4],
            );
        })?;

        if event::poll(args.interval)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                    KeyCode::Up | KeyCode::Char('k') => {
                        selected = selected.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if !profiles.is_empty() {
                            selected = (selected + 1).min(profiles.len() - 1);
                        }
                    }
                    // Helper switches the tunnel in place; on failure it keeps
                    // the previous profile and reports why. Blocks up to ~60s.
                    KeyCode::Enter => {
                        if let Some(p) = profiles.get(selected).cloned() {
                            match connect_profile(&xray_state, &p) {
                                Ok(ok) => {
                                    active_key = Some(p.key);
                                    message = Some(ok);
                                }
                                Err(e) => message = Some(format!("Ошибка: {e}")),
                            }
                            spawn_ip_lookup(ip_tx.clone());
                        }
                    }
                    KeyCode::Char('d') | KeyCode::Char('x') | KeyCode::Backspace => {
                        match vpn_core::vpn_control::stop_vpn_inner(&xray_state) {
                            Ok(()) => {
                                active_key = None;
                                message = Some("VPN отключён".to_owned());
                            }
                            Err(e) => message = Some(format!("Ошибка: {e}")),
                        }
                        spawn_ip_lookup(ip_tx.clone());
                    }
                    KeyCode::Char('r') => {
                        let (fresh, err) = load_profiles();
                        profiles = fresh;
                        message = err.or(Some(format!("Профилей: {}", profiles.len())));
                    }
                    _ => {}
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            eprintln!("usage: vpn-tui [--once] [--interval-ms 250–10000] [--log-lines 0–50]");
            std::process::exit(2);
        }
    };
    if args.once || !io::stdout().is_terminal() {
        print_once(args.interval.min(Duration::from_secs(10)), args.log_lines);
        return;
    }
    if let Err(e) = run_tui(args) {
        eprintln!("TUI: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_use_wall_clock_delta() {
        let a = Counters {
            vpn_down: 1000,
            vpn_up: 500,
            direct_down: 0,
            direct_up: 0,
            ts_ms: 1000,
        };
        let b = Counters {
            vpn_down: 3000,
            vpn_up: 1500,
            direct_down: 4000,
            direct_up: 2000,
            ts_ms: 3000,
        };
        assert_eq!(rates_from(&a, &b), Some((1000.0, 500.0, 2000.0, 1000.0)));
    }

    #[test]
    fn rates_reject_non_positive_delta() {
        let a = Counters { ts_ms: 5, ..Counters::default() };
        let b = Counters { ts_ms: 5, ..Counters::default() };
        assert_eq!(rates_from(&a, &b), None);
    }

    #[test]
    fn counters_tolerate_missing_fields() {
        let v: serde_json::Value = serde_json::json!({"vpn": {"up": 7}, "ts_ms": 9});
        assert_eq!(
            counters_of(&v),
            Counters {
                vpn_up: 7,
                vpn_down: 0,
                direct_up: 0,
                direct_down: 0,
                ts_ms: 9,
            }
        );
    }

    #[test]
    fn human_formats_match_core_cli() {
        assert_eq!(human_rate(512.0), "512 Б/с");
        assert_eq!(human_rate(2048.0), "2 КБ/с");
        assert_eq!(human_rate(3.0 * 1048576.0), "3.0 МБ/с");
        assert_eq!(human_total(512), "0 КБ");
        assert_eq!(human_total(3 * 1048576), "3.0 МБ");
    }

    #[test]
    fn args_reject_garbage() {
        let argv = vec!["vpn-tui".to_owned(), "--bogus".to_owned()];
        assert!(parse_args(&argv).is_err());
        let argv = vec![
            "vpn-tui".to_owned(),
            "--interval-ms".to_owned(),
            "10".to_owned(),
        ];
        assert!(parse_args(&argv).is_err());
    }
    #[test]
    fn profiles_list_servers_then_imported() {
        let servers = vec![
            serde_json::json!({"server_id":"s1","inbound_id":3,"email":"me@example.com","inbound_name":"XHTTP","server_name":"de","protocol":"vless","transport":"xhttp","port":443}),
            serde_json::json!({"server_id":"s1","email":"broken"}),
        ];
        let imported = vec![
            serde_json::json!({"id":"abc","name":"amnezia","host":"82.38.66.80","port":43506,"transport":"awg"}),
        ];
        let got = summarize_profiles(&servers, &imported);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].key, "srv:s1:3:me@example.com");
        assert_eq!(got[0].title, "me@example.com · XHTTP (de)");
        assert!(matches!(got[0].target, ProfileTarget::Server { inbound_id: 3, .. }));
        assert_eq!(got[1].key, "imported:abc");
        assert_eq!(got[1].title, "amnezia");
        assert_eq!(got[1].detail, "awg · 82.38.66.80:43506");
    }

    #[test]
    fn profiles_empty_without_listings() {
        assert!(summarize_profiles(&[], &[]).is_empty());
    }

    #[test]
    fn ipify_answer_is_sanitized() {
        assert_eq!(clean_ip("  203.0.113.7\n"), Some("203.0.113.7".to_owned()));
        assert_eq!(clean_ip("2a09:bac5:4e25:2719::3e5:9"), Some("2a09:bac5:4e25:2719::3e5:9".to_owned()));
        assert_eq!(clean_ip(""), None);
        assert_eq!(clean_ip("1.2.3.4 5.6.7.8"), None);
        assert_eq!(clean_ip(&"9".repeat(65)), None);
    }
}
