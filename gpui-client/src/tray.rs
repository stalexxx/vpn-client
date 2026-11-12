use objc2::{rc::Retained, MainThreadMarker};
use objc2_app_kit::{NSStatusBar, NSStatusItem};
use objc2_foundation::NSString;
use std::cell::RefCell;

thread_local! { static STATUS_ITEM: RefCell<Option<Retained<NSStatusItem>>> = const { RefCell::new(None) }; }

pub fn install() {
    assert!(MainThreadMarker::new().is_some());
    let item = NSStatusBar::systemStatusBar().statusItemWithLength(18.0);
    STATUS_ITEM.with(|slot| *slot.borrow_mut() = Some(item));
    update(None, false, false);
}

pub fn update(connected: Option<bool>, busy: bool, failed: bool) {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let (icon, tooltip) = if busy { ("🟠", "VPN: подключение или переключение") }
        else if failed { ("🔴", "VPN: ошибка последней операции") }
        else { match connected { Some(true) => ("🟢", "VPN подключён"), Some(false) => ("⚪", "VPN отключён"), None => ("⚪", "VPN: состояние недоступно") } };
    STATUS_ITEM.with(|slot| { if let Some(button) = slot.borrow().as_ref().and_then(|item| item.button(mtm)) {
        button.setTitle(&NSString::from_str(icon));
        button.setToolTip(Some(&NSString::from_str(tooltip)));
    }});
}
