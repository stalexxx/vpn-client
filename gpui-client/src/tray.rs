#[cfg(target_os = "macos")]
use objc2::{rc::Retained, MainThreadMarker};
#[cfg(target_os = "macos")]
use objc2_app_kit::{NSStatusBar, NSStatusItem};
#[cfg(target_os = "macos")]
use objc2_foundation::NSString;
#[cfg(target_os = "macos")]
use std::cell::RefCell;

#[cfg(target_os = "macos")]
thread_local! { static STATUS_ITEM: RefCell<Option<Retained<NSStatusItem>>> = const { RefCell::new(None) }; }

#[cfg(target_os = "macos")]
pub fn install() {
    assert!(MainThreadMarker::new().is_some());
    let item = NSStatusBar::systemStatusBar().statusItemWithLength(18.0);
    STATUS_ITEM.with(|slot| *slot.borrow_mut() = Some(item));
    update(None, false, false);
}

#[cfg(target_os = "linux")]
use std::{cell::RefCell, mem::ManuallyDrop};
#[cfg(target_os = "linux")]
thread_local! {
    // ManuallyDrop: teardown ksni-трея при выходе процесса падает (join/shutdown
    // на фоне остановки рантайма), а паника в деструкторе thread-local = abort.
    // Иконку не нужно аккуратно снимать: соединение D-Bus рвётся вместе с процессом.
    static TRAY: RefCell<Option<ManuallyDrop<tray_icon::TrayIcon>>> = const { RefCell::new(None) };
    static LAST: RefCell<(u32, &'static str)> = const { RefCell::new((0, "")) };
}
/// 32x32 filled circle for the indicator (ayatana shows no emoji, so color carries the state).
#[cfg(target_os = "linux")]
fn circle_rgba(rgb: u32) -> Vec<u8> {
    let (r, g, b) = ((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8);
    let mut out = Vec::with_capacity(32 * 32 * 4);
    for y in 0..32 { for x in 0..32 {
        let d = (x as f32 - 15.5).hypot(y as f32 - 15.5);
        let a = if d <= 12.5 { 255 } else if d <= 13.5 { 128 } else { 0 };
        out.extend_from_slice(&[r, g, b, a]);
    } }
    out
}
/// Best-effort indicator: without a host (headless X) there is simply no icon, never a crash.
#[cfg(target_os = "linux")]
fn build_tray(color: u32, tooltip: &'static str) -> Option<tray_icon::TrayIcon> {
    tray_icon::Icon::from_rgba(circle_rgba(color), 32, 32).ok().and_then(|icon| {
        tray_icon::TrayIconBuilder::new().with_icon(icon).with_tooltip(tooltip).build().ok()
    })
}

#[cfg(target_os = "linux")]
pub fn install() {
    TRAY.with(|slot| *slot.borrow_mut() = build_tray(0x93a0b5, "VPN: состояние недоступно").map(ManuallyDrop::new));
    update(None, false, false);
}
#[cfg(all(not(target_os = "macos"), not(target_os = "linux")))]
pub fn install() {}

#[cfg(target_os = "macos")]
pub fn update(connected: Option<bool>, busy: bool, failed: bool) {
    let Some(mtm) = MainThreadMarker::new() else { return };
    // Plain text glyphs render monochrome in the macOS menu bar.
    let (icon, tooltip) = if busy { ("◌", "VPN: подключение или переключение") }
        else if failed { ("!", "VPN: ошибка последней операции") }
        else { match connected { Some(true) => ("●", "VPN подключён"), Some(false) => ("○", "VPN отключён"), None => ("○", "VPN: состояние недоступно") } };
    STATUS_ITEM.with(|slot| { if let Some(button) = slot.borrow().as_ref().and_then(|item| item.button(mtm)) {
        button.setTitle(&NSString::from_str(icon));
        button.setToolTip(Some(&NSString::from_str(tooltip)));
    }});
}

#[cfg(target_os = "linux")]
pub fn update(connected: Option<bool>, busy: bool, failed: bool) {
    let (color, tooltip): (u32, &'static str) = if busy { (0xf4b860, "VPN: подключение или переключение") }
        else if failed { (0xff8080, "VPN: ошибка последней операции") }
        else { match connected { Some(true) => (0x62d6a0, "VPN подключён"), Some(false) => (0x93a0b5, "VPN отключён"), None => (0x93a0b5, "VPN: состояние недоступно") } };
    TRAY.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            // Шина или хост трея могли появиться позже старта — пробуем создать заново.
            *slot = build_tray(color, tooltip).map(ManuallyDrop::new);
            if slot.is_some() { LAST.with(|last| *last.borrow_mut() = (color, tooltip)); }
            return;
        }
        let changed = LAST.with(|last| { let mut last = last.borrow_mut(); if *last == (color, tooltip) { false } else { *last = (color, tooltip); true } });
        if !changed { return; }
        if let Some(tray) = slot.as_mut() {
            if let Ok(icon) = tray_icon::Icon::from_rgba(circle_rgba(color), 32, 32) { let _ = tray.set_icon(Some(icon)); }
            let _ = tray.set_tooltip(Some(tooltip));
        }
    });
}
#[cfg(all(not(target_os = "macos"), not(target_os = "linux")))]
pub fn update(_connected: Option<bool>, _busy: bool, _failed: bool) {}
