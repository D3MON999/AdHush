// AdHush tray: notification-area icon coloured by protection state, a context menu for the
// common switches, the settings UI in a WebView2 window, and Windows toasts for service events.
// It talks only to the local API (http://127.0.0.1:<api.port>) with the per-install token.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::{Icon as WindowIcon, Window, WindowBuilder};
use tauri_winrt_notification::Toast;
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use wry::{WebContext, WebView, WebViewBuilder};

const POLL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    Active,
    Paused,
    Disabled,
    Offline,
}

#[derive(Debug)]
enum UserEvent {
    Tray(TrayIconEvent),
    Menu(MenuEvent),
    Status(Option<Value>),
    Notify(Vec<Value>),
    Ipc(String),
    IpcReply(Value),
    DnsState(Option<Value>),
    /// The service is installing an update: get out of the way and come back afterwards.
    Updating,
    /// Another launch (Start menu, autostart, setup) asked this instance to show its window.
    Show,
}

// --- single instance ----------------------------------------------------------------

/// Named event in this sign-in session (`Local\`), so each Windows user gets one tray.
/// Returns the event if this is the first instance; otherwise wakes the first one and returns None.
fn claim_single_instance() -> Option<usize> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};
    let name: Vec<u16> = "Local\\AdHushTray.Show".encode_utf16().chain(Some(0)).collect();
    unsafe {
        let h = CreateEventW(std::ptr::null(), 0, 0, name.as_ptr());
        if h.is_null() {
            return Some(0); // cannot coordinate; better to run than to show nothing
        }
        if GetLastError() == ERROR_ALREADY_EXISTS {
            SetEvent(h);
            return None;
        }
        Some(h as usize)
    }
}

fn watch_show_requests(event: usize, proxy: EventLoopProxy<UserEvent>) {
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};
    if event == 0 {
        return;
    }
    std::thread::spawn(move || loop {
        if unsafe { WaitForSingleObject(event as _, INFINITE) } != WAIT_OBJECT_0 || proxy.send_event(UserEvent::Show).is_err() {
            return;
        }
    });
}

enum Cmd {
    Protection(bool),
    Pause(u32),
}

// --- locating the service -------------------------------------------------------------

fn data_dir() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--data" {
            if let Some(d) = args.next() {
                return PathBuf::from(d);
            }
        }
    }
    if let Some(d) = std::env::var_os("ADHUSH_DATA") {
        return PathBuf::from(d);
    }
    // Development layout: <repo>\tray\target\release\adhush-tray.exe next to <repo>\data.
    if let Ok(exe) = std::env::current_exe() {
        for dir in exe.ancestors().skip(1) {
            if dir.join("data").join("api-token").is_file() {
                return dir.join("data");
            }
        }
    }
    let pd = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    pd.join("AdHush")
}

fn api_port(dir: &Path) -> u16 {
    std::fs::read_to_string(dir.join("settings.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v["api"]["port"].as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(8899)
}

struct Api {
    dir: PathBuf,
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
}

impl Api {
    fn new(dir: PathBuf) -> Self {
        let base = format!("http://127.0.0.1:{}", api_port(&dir));
        let agent = ureq::Agent::config_builder()
            .proxy(None)
            .timeout_global(Some(Duration::from_secs(5)))
            .http_status_as_error(false)
            .build()
            .new_agent();
        Api { dir, base, token: None, agent }
    }

    fn token(&mut self) -> Option<String> {
        if self.token.is_none() {
            self.token = std::fs::read_to_string(self.dir.join("api-token")).ok().map(|t| t.trim().to_string());
        }
        self.token.clone()
    }

    /// Returns (status code, parsed body). Network failures are `None`.
    fn call(&mut self, method: &str, path: &str, body: Option<Value>) -> Option<(u16, Value)> {
        let token = self.token()?;
        let url = format!("{}{}", self.base, path);
        let res = match body {
            Some(b) => self.agent.post(&url).header("x-adhush-token", &token).content_type("application/json").send(b.to_string()),
            None if method == "GET" => self.agent.get(&url).header("x-adhush-token", &token).call(),
            None => self.agent.post(&url).header("x-adhush-token", &token).send_empty(),
        };
        let mut res = res.ok()?;
        let status = res.status().as_u16();
        if status == 401 {
            self.token = None; // token rotated (data dir reset): re-read next time
        }
        let text = res.body_mut().read_to_string().unwrap_or_default();
        Some((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn state_of(status: &Option<Value>) -> State {
    let Some(s) = status else { return State::Offline };
    let p = &s["protection"];
    if !p["enabled"].as_bool().unwrap_or(false) {
        State::Disabled
    } else if p["pausedUntil"].as_u64().unwrap_or(0) > now_ms() {
        State::Paused
    } else {
        State::Active
    }
}

/// Background thread: executes menu commands and polls status + notifications.
fn poller(dir: PathBuf, rx: mpsc::Receiver<Cmd>, proxy: EventLoopProxy<UserEvent>) {
    let mut api = Api::new(dir);
    let mut since: Option<u64> = None;
    loop {
        match rx.recv_timeout(POLL) {
            Ok(cmd) => {
                let (path, body) = match cmd {
                    Cmd::Protection(on) => ("/api/protection", json!({ "enabled": on })),
                    Cmd::Pause(min) => ("/api/protection/pause", json!({ "minutes": min })),
                };
                api.call("POST", path, Some(body));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let status = match api.call("GET", "/api/status", None) {
            Some((200, v)) => Some(v),
            _ => None,
        };
        let online = status.is_some();
        if proxy.send_event(UserEvent::Status(status)).is_err() {
            return;
        }
        // Written by the service's DNS guard; readable even when AdHush itself is down.
        let dns = std::fs::read_to_string(api.dir.join("dns-state.json")).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok());
        let _ = proxy.send_event(UserEvent::DnsState(dns));
        if api.dir.join("update-installing.json").is_file() {
            let _ = proxy.send_event(UserEvent::Updating);
            return;
        }
        if !online {
            continue;
        }
        let q = format!("/api/notifications?since={}", since.unwrap_or(0));
        if let Some((200, v)) = api.call("GET", &q, None) {
            let last = v["last"].as_u64().unwrap_or(0);
            // First successful poll only syncs the cursor: never replay old events on start.
            if since.is_some() {
                let items = v["items"].as_array().cloned().unwrap_or_default();
                if !items.is_empty() {
                    let _ = proxy.send_event(UserEvent::Notify(items));
                }
            }
            since = Some(last);
        }
    }
}

// --- icon ---------------------------------------------------------------------------

/// 32x32 shield drawn procedurally so the tray needs no image assets.
fn shield_rgba(state: State) -> Vec<u8> {
    const N: usize = 32;
    let (r, g, b) = match state {
        // Brand emerald / amber / slate / red, matching the app's design tokens.
        State::Active => (0x10, 0xb9, 0x81),
        State::Paused => (0xd9, 0x77, 0x06),
        State::Disabled => (0x64, 0x74, 0x8b),
        State::Offline => (0xdc, 0x26, 0x26),
    };
    let mut px = vec![0u8; N * N * 4];
    let cx = (N as f32 - 1.0) / 2.0;
    for y in 0..N {
        for x in 0..N {
            let fy = y as f32;
            let half = if fy < 2.0 {
                -1.0
            } else if fy < 15.0 {
                13.0
            } else {
                13.0 * (1.0 - (fy - 15.0) / 15.5).max(0.0).powf(0.75)
            };
            let d = (x as f32 - cx).abs();
            // One pixel of soft edge for a cleaner outline at small sizes.
            let cover = (half + 0.5 - d).clamp(0.0, 1.0);
            if cover <= 0.0 {
                continue;
            }
            let mut c = (r, g, b);
            let (ix, iy) = (x as i32, y as i32);
            let glyph = match state {
                State::Active => {
                    // check mark
                    let on_short = (8..=13).contains(&ix) && (iy - (ix + 7)).abs() <= 1;
                    let on_long = (13..=23).contains(&ix) && (iy - (33 - ix)).abs() <= 1;
                    on_short || on_long
                }
                State::Paused => (9..=19).contains(&iy) && ((10..=13).contains(&ix) || (18..=21).contains(&ix)),
                State::Disabled => (13..=16).contains(&iy) && (9..=22).contains(&ix),
                State::Offline => (9..=21).contains(&iy) && ((ix - iy).abs() <= 1 || (ix + iy - 31).abs() <= 1) && (9..=22).contains(&ix),
            };
            if glyph {
                c = (0xff, 0xff, 0xff);
            }
            let i = (y * N + x) * 4;
            px[i..i + 4].copy_from_slice(&[c.0, c.1, c.2, (cover * 255.0) as u8]);
        }
    }
    px
}

fn tray_icon(state: State) -> Icon {
    Icon::from_rgba(shield_rgba(state), 32, 32).expect("valid icon")
}

fn tooltip(state: State, status: &Option<Value>) -> String {
    let rules = status.as_ref().and_then(|s| s["engine"]["rules"].as_u64()).unwrap_or(0);
    match state {
        State::Active => format!("AdHush — protection on ({rules} DNS rules)"),
        State::Paused => {
            let until = status.as_ref().and_then(|s| s["protection"]["pausedUntil"].as_u64()).unwrap_or(0);
            let mins = until.saturating_sub(now_ms()).div_ceil(60_000);
            format!("AdHush — paused, resumes in {mins} min")
        }
        State::Disabled => "AdHush — protection off".into(),
        State::Offline => "AdHush — service not running".into(),
    }
}

// --- window -------------------------------------------------------------------------

struct UiWindow {
    window: Window,
    webview: WebView,
}

fn open_external(url: &str) {
    if url.starts_with("http://") || url.starts_with("https://") {
        let _ = std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).spawn();
    }
}

// --- browser extension setup (requests from the UI over window.ipc) --------------------

/// Chromium browsers that can load the AdHush Assistant: (id, name, extensions page, exe paths to try).
const BROWSERS: [(&str, &str, &str, &[&str]); 3] = [
    ("chrome", "Google Chrome", "chrome://extensions/", &[r"%ProgramFiles%\Google\Chrome\Application\chrome.exe", r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe", r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"]),
    ("edge", "Microsoft Edge", "edge://extensions/", &[r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe", r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"]),
    ("brave", "Brave", "brave://extensions/", &[r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe", r"%ProgramFiles(x86)%\BraveSoftware\Brave-Browser\Application\brave.exe", r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"]),
];

fn expand_env(path: &str) -> PathBuf {
    let mut out = String::new();
    let mut rest = path;
    while let Some(start) = rest.find('%') {
        let Some(len) = rest[start + 1..].find('%') else { break };
        out.push_str(&rest[..start]);
        let name = &rest[start + 1..start + 1 + len];
        out.push_str(&std::env::var(name).unwrap_or_default());
        rest = &rest[start + 2 + len..];
    }
    out.push_str(rest);
    PathBuf::from(out)
}

fn browser_exe(id: &str) -> Option<PathBuf> {
    let (_, _, _, paths) = BROWSERS.iter().find(|b| b.0 == id)?;
    paths.iter().map(|p| expand_env(p)).find(|p| p.is_file())
}

/// The unpacked extension folder: `<install dir>\extension`, or `<repo>\extension` in a dev checkout.
fn extension_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    exe.ancestors().skip(1).map(|d| d.join("extension")).find(|d| d.join("manifest.json").is_file())
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// The user's Desktop folder (follows OneDrive/redirected Desktops).
fn desktop_dir() -> PathBuf {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_Desktop, SHGetKnownFolderPath};
    unsafe {
        let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
        if SHGetKnownFolderPath(&FOLDERID_Desktop, 0, std::ptr::null_mut(), &mut p) == 0 && !p.is_null() {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            let path = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            CoTaskMemFree(p as _);
            return PathBuf::from(path);
        }
    }
    PathBuf::from(std::env::var_os("USERPROFILE").unwrap_or_default()).join("Desktop")
}

/// Downloads the diagnostics zip from the service and saves it on the Desktop.
fn save_diagnostics(dir: &Path) -> Result<PathBuf, String> {
    let mut api = Api::new(dir.to_path_buf());
    let token = api.token().ok_or("AdHush is not installed (no API token)")?;
    let mut res = api
        .agent
        .get(&format!("{}/api/diagnostics", api.base))
        .header("x-adhush-token", &token)
        .call()
        .map_err(|_| "AdHush is not running".to_string())?;
    if res.status().as_u16() != 200 {
        return Err(format!("AdHush answered HTTP {}", res.status().as_u16()));
    }
    let name = res
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split("filename=\"").nth(1))
        .map(|v| v.trim_end_matches('"').to_string())
        .unwrap_or_else(|| "AdHush-logs.zip".into());
    let bytes = res.body_mut().with_config().limit(200 * 1024 * 1024).read_to_vec().map_err(|e| e.to_string())?;
    let path = desktop_dir().join(name);
    std::fs::write(&path, bytes).map_err(|e| format!("could not write {}: {e}", path.display()))?;
    let _ = std::process::Command::new("explorer.exe").arg(format!("/select,{}", path.display())).spawn();
    Ok(path)
}

/// The installer replaces this exe, so it must not be running. A hidden PowerShell waits until the
/// service's update marker is gone (at most 10 minutes) and starts the new tray.
fn relaunch_after_update(data: &Path) {
    use std::os::windows::process::CommandExt;
    let Ok(exe) = std::env::current_exe() else { return };
    let quote = |p: &Path| p.display().to_string().replace('\'', "''");
    let script = format!(
        "$m='{}'; $end=(Get-Date).AddMinutes(10); Start-Sleep 5; while ((Test-Path $m) -and (Get-Date) -lt $end) {{ Start-Sleep 2 }}; Start-Sleep 3; Start-Process '{}'",
        quote(&data.join("update-installing.json")),
        quote(&exe)
    );
    let _ = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script])
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .spawn();
}

/// Asks for administrator rights and puts Windows' previous DNS back (scripts\restore-internet.cmd).
fn restore_internet() {
    let Ok(exe) = std::env::current_exe() else { return };
    if let Some(script) = exe.ancestors().skip(1).map(|d| d.join("scripts").join("restore-internet.cmd")).find(|p| p.is_file()) {
        let _ = std::process::Command::new("cmd.exe").arg("/c").arg(script).spawn();
    }
}

/// Replies right away, or returns None when the work runs on a thread and replies via IpcReply.
fn handle_ipc(msg: &str, base: &str, dir: &Path, proxy: &EventLoopProxy<UserEvent>) -> Option<Value> {
    let req: Value = serde_json::from_str(msg).unwrap_or(Value::Null);
    let id = req["id"].clone();
    if req["cmd"] == "saveDiagnostics" {
        let (dir, proxy) = (dir.to_path_buf(), proxy.clone());
        std::thread::spawn(move || {
            let reply = match save_diagnostics(&dir) {
                Ok(p) => json!({ "ok": true, "file": p.display().to_string() }),
                Err(e) => json!({ "ok": false, "error": e }),
            };
            let _ = proxy.send_event(UserEvent::IpcReply(json!({ "id": id, "reply": reply })));
        });
        return None;
    }
    let reply = match req["cmd"].as_str() {
        Some("browsers") => json!({
            "ok": true,
            "extensionDir": extension_dir().map(|d| d.display().to_string()),
            "browsers": BROWSERS.iter().filter(|b| browser_exe(b.0).is_some()).map(|b| json!({ "id": b.0, "name": b.1 })).collect::<Vec<_>>(),
        }),
        Some("openExtensions") => {
            let browser = req["browser"].as_str().unwrap_or("");
            match (BROWSERS.iter().find(|b| b.0 == browser), browser_exe(browser)) {
                // Browsers refuse to open chrome:// / edge:// pages passed on the command line, so open
                // AdHush's guide page instead; the UI has already copied the extensions-page address.
                (Some((id, name, _, _)), Some(exe)) => {
                    let dir = extension_dir().map(|d| d.display().to_string()).unwrap_or_default();
                    let guide = format!("{base}/extension-setup.html#b={id}&dir={}", url_encode(&dir));
                    match std::process::Command::new(exe).arg(guide).spawn() {
                        Ok(_) => json!({ "ok": true }),
                        Err(e) => json!({ "ok": false, "error": format!("could not start {name}: {e}") }),
                    }
                }
                _ => json!({ "ok": false, "error": "that browser is not installed" }),
            }
        }
        _ => json!({ "ok": false, "error": "unknown command" }),
    };
    Some(json!({ "id": id, "reply": reply }))
}

fn build_window(
    target: &tao::event_loop::EventLoopWindowTarget<UserEvent>,
    ctx: &mut WebContext,
    base: &str,
    route: &str,
    proxy: EventLoopProxy<UserEvent>,
) -> Option<UiWindow> {
    let window = WindowBuilder::new()
        .with_title("AdHush")
        .with_inner_size(LogicalSize::new(1180.0, 780.0))
        .with_min_inner_size(LogicalSize::new(720.0, 480.0))
        .with_window_icon(WindowIcon::from_rgba(shield_rgba(State::Active), 32, 32).ok())
        .build(target)
        .ok()?;
    let origin = format!("{base}/");
    let nav_origin = origin.clone();
    let ipc_origin = origin.clone();
    let webview = WebViewBuilder::new_with_web_context(ctx)
        .with_url(format!("{origin}{route}"))
        // Only the local UI may ask the tray to do things on the desktop.
        .with_ipc_handler(move |req| {
            if req.uri().to_string().starts_with(&ipc_origin) {
                let _ = proxy.send_event(UserEvent::Ipc(req.body().clone()));
            }
        })
        // Keep the window on the local UI; anything else (docs, filter homepages) opens in the browser.
        .with_navigation_handler(move |url| {
            if url.starts_with(&nav_origin) {
                true
            } else {
                open_external(&url);
                false
            }
        })
        .with_new_window_req_handler(|url, _| {
            open_external(&url);
            wry::NewWindowResponse::Deny
        })
        .build(&window)
        .ok()?;
    Some(UiWindow { window, webview })
}

fn notify(item: &Value) {
    let title = item["title"].as_str().unwrap_or("AdHush");
    let body = item["body"].as_str().unwrap_or("");
    // Unpackaged apps have no registered AppUserModelID; borrowing PowerShell's avoids a registry write.
    let _ = Toast::new(Toast::POWERSHELL_APP_ID).title(title).text1(body).show();
}

fn main() {
    let Some(instance) = claim_single_instance() else { return };
    let dir = data_dir();
    let base = format!("http://127.0.0.1:{}", api_port(&dir));

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    {
        let p = proxy.clone();
        TrayIconEvent::set_event_handler(Some(move |e| {
            let _ = p.send_event(UserEvent::Tray(e));
        }));
        let p = proxy.clone();
        MenuEvent::set_event_handler(Some(move |e| {
            let _ = p.send_event(UserEvent::Menu(e));
        }));
    }

    watch_show_requests(instance, proxy.clone());

    let (tx, rx) = mpsc::channel::<Cmd>();
    {
        let p = proxy.clone();
        let d = dir.clone();
        std::thread::spawn(move || poller(d, rx, p));
    }

    let status_item = MenuItem::with_id("status", "Starting…", false, None);
    let open_item = MenuItem::with_id("open", "Open AdHush", true, None);
    let protect_item = CheckMenuItem::with_id("protect", "Protection", false, true, None);
    let pause_item = MenuItem::with_id("pause", "Pause for 30 minutes", false, None);
    let log_item = MenuItem::with_id("log", "Filtering log", true, None);
    let stats_item = MenuItem::with_id("stats", "Statistics", true, None);
    let broken_item = MenuItem::with_id("broken", "A website isn't working…", true, None);
    let restore_item = MenuItem::with_id("restore", "Restore normal internet…", true, None);
    let quit_item = MenuItem::with_id("quit", "Quit tray", true, None);
    let menu = Menu::new();
    menu.append_items(&[
        &status_item,
        &PredefinedMenuItem::separator(),
        &open_item,
        &protect_item,
        &pause_item,
        &PredefinedMenuItem::separator(),
        &log_item,
        &stats_item,
        &PredefinedMenuItem::separator(),
        &broken_item,
        &restore_item,
        &quit_item,
    ])
    .expect("menu");

    let mut tray: Option<TrayIcon> = None;
    let mut state = State::Offline;
    let mut ui: Option<UiWindow> = None;
    let mut wizard_shown = false;
    let mut dns_mode: Option<String> = None;
    let ipc_proxy = proxy.clone();
    let data = dir.clone();
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let mut web_ctx = WebContext::new(Some(local.join("AdHush").join("webview")));

    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;
        let mut open = |route: &str, ui: &mut Option<UiWindow>| {
            match ui {
                Some(w) => {
                    if !route.is_empty() {
                        let _ = w.webview.evaluate_script(&format!("location.hash = {}", json!(route)));
                    }
                    w.window.set_minimized(false);
                    w.window.set_visible(true);
                    w.window.set_focus();
                }
                None => *ui = build_window(target, &mut web_ctx, &base, route, ipc_proxy.clone()),
            }
        };
        match event {
            Event::NewEvents(tao::event::StartCause::Init) => {
                // Created after the loop starts so the icon registers with the shell's message window.
                tray = TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_menu_on_left_click(false)
                    .with_tooltip("AdHush")
                    .with_icon(tray_icon(State::Offline))
                    .build()
                    .ok();
            }
            Event::UserEvent(UserEvent::Tray(TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. })) => {
                open("", &mut ui);
            }
            Event::UserEvent(UserEvent::Menu(e)) => match e.id().as_ref() {
                "open" => open("", &mut ui),
                "log" => open("#/log", &mut ui),
                "stats" => open("#/stats", &mut ui),
                "broken" => open("#/home?fix", &mut ui),
                "protect" => {
                    // muda has already toggled the check mark; send the new state.
                    let _ = tx.send(Cmd::Protection(protect_item.is_checked()));
                }
                "pause" => {
                    let cmd = if state == State::Paused { Cmd::Protection(true) } else { Cmd::Pause(30) };
                    let _ = tx.send(cmd);
                }
                "restore" => restore_internet(),
                "quit" => {
                    tray = None;
                    ui = None;
                    *control_flow = ControlFlow::Exit;
                }
                _ => {}
            },
            Event::UserEvent(UserEvent::Status(status)) => {
                // First run after setup: show the welcome wizard once.
                if !wizard_shown && status.as_ref().is_some_and(|s| s["onboarded"] == Value::Bool(false)) {
                    wizard_shown = true;
                    open("#/welcome", &mut ui);
                }
                let next = state_of(&status);
                if next != state {
                    state = next;
                    if let Some(t) = &tray {
                        let _ = t.set_icon(Some(tray_icon(state)));
                    }
                }
                if let Some(t) = &tray {
                    let _ = t.set_tooltip(Some(tooltip(state, &status)));
                }
                let online = state != State::Offline;
                status_item.set_text(tooltip(state, &status).trim_start_matches("AdHush — "));
                protect_item.set_enabled(online);
                protect_item.set_checked(matches!(state, State::Active | State::Paused));
                pause_item.set_enabled(matches!(state, State::Active | State::Paused));
                pause_item.set_text(if state == State::Paused { "Resume protection" } else { "Pause for 30 minutes" });
            }
            Event::UserEvent(UserEvent::Notify(items)) => {
                for item in items.iter().take(5) {
                    notify(item);
                }
            }
            Event::UserEvent(UserEvent::Show) => open("", &mut ui),
            Event::UserEvent(UserEvent::Updating) => {
                notify(&json!({ "title": "Updating AdHush", "body": "A new version is being installed. AdHush will be back in a minute." }));
                relaunch_after_update(&data);
                tray = None;
                ui = None;
                *control_flow = ControlFlow::Exit;
            }
            Event::UserEvent(UserEvent::Ipc(msg)) => {
                if let (Some(out), Some(w)) = (handle_ipc(&msg, &base, &data, &ipc_proxy), &ui) {
                    let _ = w.webview.evaluate_script(&format!("window.adhushNative && window.adhushNative({out})"));
                }
            }
            Event::UserEvent(UserEvent::IpcReply(out)) => {
                if let Some(w) = &ui {
                    let _ = w.webview.evaluate_script(&format!("window.adhushNative && window.adhushNative({out})"));
                }
            }
            Event::UserEvent(UserEvent::DnsState(dns)) => {
                let mode = dns.as_ref().and_then(|d| d["mode"].as_str()).unwrap_or("").to_string();
                // Tell the person when the safety net kicks in or ends; not on the first reading.
                if let Some(prev) = &dns_mode {
                    if *prev != mode && mode == "fallback" {
                        notify(&json!({ "title": "AdHush paused itself", "body": "AdHush stopped answering, so your normal internet settings were restored. Filtering resumes automatically." }));
                    } else if *prev == "fallback" && mode == "filtering" {
                        notify(&json!({ "title": "AdHush is filtering again", "body": "Every app on this PC is protected again." }));
                    }
                }
                dns_mode = Some(mode);
            }
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                // Closing the window frees the WebView2 process; the tray keeps running.
                ui = None;
            }
            _ => {}
        }
    });
}
