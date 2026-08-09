use std::mem::{offset_of, size_of};
use std::sync::{Mutex, OnceLock, mpsc::Sender};

use anyhow::{Context, Result};
use windows::Win32::Foundation::{HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, RegisterEventSourceW,
    ReportEventW,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DBT_DEVICEARRIVAL, DBT_DEVICEREMOVECOMPLETE, DBT_DEVNODES_CHANGED,
    DBT_DEVTYP_DEVICEINTERFACE, DEV_BROADCAST_DEVICEINTERFACE_W, DEV_BROADCAST_HDR,
    DEVICE_NOTIFY_ALL_INTERFACE_CLASSES, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW,
    DestroyWindow, DispatchMessageW, GetMessageW, HWND_MESSAGE, MSG, PostThreadMessageW,
    RegisterClassW, RegisterDeviceNotificationW, TranslateMessage, UnregisterDeviceNotification,
    WM_DEVICECHANGE, WM_QUIT, WNDCLASSW,
};
use windows::core::{GUID, PCWSTR, w};

use crate::{DeviceEvent, EventKind, RiskLevel};

static EVENT_SENDER: OnceLock<Mutex<Option<Sender<DeviceEvent>>>> = OnceLock::new();

pub fn run_notification_loop(sender: Sender<DeviceEvent>) -> Result<u32> {
    let channel = EVENT_SENDER.get_or_init(|| Mutex::new(None));
    *channel.lock().expect("notification sender mutex") = Some(sender);
    let thread_id = unsafe { GetCurrentThreadId() };
    let instance = unsafe { GetModuleHandleW(None) }.context("get module handle")?;
    let instance = HINSTANCE(instance.0);
    let class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: w!("PeripheralLedgerMessageWindow"),
        ..Default::default()
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        return Err(std::io::Error::last_os_error()).context("register message-window class");
    }
    let window = unsafe {
        CreateWindowExW(
            Default::default(),
            w!("PeripheralLedgerMessageWindow"),
            w!(""),
            Default::default(),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance),
            None,
        )
    }
    .context("create message-only window")?;
    let filter = DEV_BROADCAST_DEVICEINTERFACE_W {
        dbcc_size: size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>() as u32,
        dbcc_devicetype: DBT_DEVTYP_DEVICEINTERFACE.0,
        dbcc_classguid: GUID::zeroed(),
        ..Default::default()
    };
    let notification = unsafe {
        RegisterDeviceNotificationW(
            HANDLE(window.0),
            &filter as *const _ as *const _,
            DEVICE_NOTIFY_WINDOW_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES,
        )
    }
    .context("register device notifications")?;
    let mut message = MSG::default();
    loop {
        let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
        if result.0 == -1 {
            unsafe { UnregisterDeviceNotification(notification) }.ok();
            unsafe { DestroyWindow(window) }.ok();
            return Err(std::io::Error::last_os_error()).context("read device message");
        }
        if result.0 == 0 {
            break;
        }
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    unsafe { UnregisterDeviceNotification(notification) }.ok();
    unsafe { DestroyWindow(window) }.ok();
    *channel.lock().expect("notification sender mutex") = None;
    Ok(thread_id)
}

pub fn request_notification_stop(thread_id: u32) {
    unsafe { PostThreadMessageW(thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) }.ok();
}

pub fn report_event(event: &DeviceEvent) {
    let source = unsafe { RegisterEventSourceW(None, w!("PeripheralLedger")) };
    let Ok(source) = source else { return };
    let text = format!(
        "{} {} {} ({})",
        event.kind.as_str(),
        event.device_path,
        event.risk.as_str(),
        event.reason
    );
    let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let strings = [PCWSTR(wide.as_ptr())];
    let event_type = if event.risk >= RiskLevel::Notice {
        EVENTLOG_WARNING_TYPE
    } else {
        EVENTLOG_INFORMATION_TYPE
    };
    unsafe { ReportEventW(source, event_type, 0, 1000, None, 0, Some(&strings), None) }.ok();
    unsafe { DeregisterEventSource(source) }.ok();
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    parameter: WPARAM,
    data: LPARAM,
) -> LRESULT {
    if message == WM_DEVICECHANGE {
        if let Some(event) = unsafe { parse_device_message(parameter.0 as u32, data) }
            && let Some(channel) = EVENT_SENDER.get()
            && let Some(sender) = channel.lock().expect("notification sender mutex").as_ref()
        {
            sender.send(event).ok();
        }
        return LRESULT(1);
    }
    unsafe { DefWindowProcW(window, message, parameter, data) }
}

unsafe fn parse_device_message(event_type: u32, data: LPARAM) -> Option<DeviceEvent> {
    let kind = match event_type {
        DBT_DEVICEARRIVAL => EventKind::Arrived,
        DBT_DEVICEREMOVECOMPLETE => EventKind::Removed,
        DBT_DEVNODES_CHANGED => EventKind::TopologyChanged,
        _ => return None,
    };
    if kind == EventKind::TopologyChanged || data.0 == 0 {
        return Some(DeviceEvent::from_native(now_ms(), kind, "", ""));
    }
    let header = unsafe { &*(data.0 as *const DEV_BROADCAST_HDR) };
    if header.dbch_devicetype != DBT_DEVTYP_DEVICEINTERFACE {
        return None;
    }
    let interface = unsafe { &*(data.0 as *const DEV_BROADCAST_DEVICEINTERFACE_W) };
    let name_offset = offset_of!(DEV_BROADCAST_DEVICEINTERFACE_W, dbcc_name);
    let name_bytes = interface.dbcc_size as usize;
    if name_bytes <= name_offset {
        return None;
    }
    let name_len = (name_bytes - name_offset) / size_of::<u16>();
    let name = unsafe { std::slice::from_raw_parts(interface.dbcc_name.as_ptr(), name_len) };
    let terminator = name
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(name.len());
    let path = String::from_utf16_lossy(&name[..terminator]);
    Some(DeviceEvent::from_native(
        now_ms(),
        kind,
        path,
        format!("{:?}", interface.dbcc_classguid),
    ))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
