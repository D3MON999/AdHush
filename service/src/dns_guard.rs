// Keeps "whole-PC protection" safe. When settings.json has system.manageDns = true:
//   * while AdHush answers, every active network adapter (including ones connected later)
//     points its DNS at 127.0.0.1 / ::1 (scripts\set-system-dns.ps1, which backs up the old servers);
//   * if AdHush stops answering for FALLBACK_AFTER, the previous DNS servers are restored so the PC
//     keeps working (scripts\restore-system-dns.ps1), and pointed back once AdHush is healthy again;
//   * when the service stops (including Windows shutdown) DNS is restored, so a stopped or broken
//     AdHush can never leave a PC without internet.
// The current mode is written to <data>\dns-state.json for the app and the tray.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const CHECK_EVERY: Duration = Duration::from_secs(15);
const FALLBACK_AFTER: Duration = Duration::from_secs(60);
const REAPPLY_EVERY: Duration = Duration::from_secs(120); // picks up newly connected adapters
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Starting,
    Filtering,
    Fallback,
    Off,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Starting => "starting",
            Mode::Filtering => "filtering",
            Mode::Fallback => "fallback",
            Mode::Off => "off",
        }
    }
}

pub struct DnsGuard {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    app: PathBuf,
    data: PathBuf,
}

impl DnsGuard {
    pub fn start(app: PathBuf, data: PathBuf) -> DnsGuard {
        let stop = Arc::new(AtomicBool::new(false));
        let (s, a, d) = (stop.clone(), app.clone(), data.clone());
        let thread = std::thread::spawn(move || run(&s, &a, &d));
        DnsGuard { stop, thread: Some(thread), app, data }
    }

    /// Stops the guard and, if Windows is pointed at AdHush, puts the previous DNS back.
    pub fn finish(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if pointed(&self.data) {
            let ok = script(&self.app, &self.data, "restore-system-dns.ps1");
            write_state(&self.data, Mode::Off, if ok { "AdHush stopped; normal DNS restored" } else { "AdHush stopped; restoring DNS failed" });
        }
    }
}

fn run(stop: &AtomicBool, app: &Path, data: &Path) {
    let mut mode = Mode::Starting;
    let mut unhealthy_since: Option<Instant> = None;
    let mut last_apply: Option<Instant> = None;
    write_state(data, mode, "waiting for AdHush to start");
    while !stop.load(Ordering::SeqCst) {
        let manage = manage_dns(data);
        let healthy = healthy(data);
        if healthy {
            unhealthy_since = None;
        } else if unhealthy_since.is_none() {
            unhealthy_since = Some(Instant::now());
        }

        if !manage {
            // Whole-PC protection switched off: undo our change once.
            if pointed(data) {
                let ok = script(app, data, "restore-system-dns.ps1");
                crate::log(&format!("dns guard: protection off, restore {}", if ok { "ok" } else { "FAILED" }));
            }
            if mode != Mode::Off {
                mode = Mode::Off;
                write_state(data, mode, "whole-PC protection is off");
            }
        } else if healthy {
            let due = mode != Mode::Filtering || last_apply.is_none_or(|t| t.elapsed() >= REAPPLY_EVERY);
            if due {
                let ok = script(app, data, "set-system-dns.ps1");
                last_apply = Some(Instant::now());
                if ok && mode != Mode::Filtering {
                    crate::log(&format!("dns guard: {} -> filtering", mode.name()));
                    mode = Mode::Filtering;
                    write_state(data, mode, "Windows DNS points at AdHush");
                } else if !ok {
                    crate::log("dns guard: applying DNS failed");
                }
            }
        } else if unhealthy_since.is_some_and(|t| t.elapsed() >= FALLBACK_AFTER) && (pointed(data) || mode == Mode::Filtering) {
            let ok = script(app, data, "restore-system-dns.ps1");
            crate::log(&format!("dns guard: AdHush not answering, fallback restore {}", if ok { "ok" } else { "FAILED" }));
            mode = Mode::Fallback;
            write_state(data, mode, "AdHush was not answering, so normal DNS was restored. Filtering resumes automatically when it recovers.");
        }

        let wake = Instant::now() + CHECK_EVERY;
        while Instant::now() < wake && !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

fn settings(data: &Path) -> Value {
    std::fs::read_to_string(data.join("settings.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)
}

fn manage_dns(data: &Path) -> bool {
    settings(data)["system"]["manageDns"].as_bool().unwrap_or(false)
}

/// set-system-dns.ps1 keeps this backup for as long as Windows points at AdHush.
fn pointed(data: &Path) -> bool {
    data.join("dns-backup.json").is_file()
}

/// AdHush is healthy when its API answers and reports at least one DNS listener.
fn healthy(data: &Path) -> bool {
    let Ok(token) = std::fs::read_to_string(data.join("api-token")) else { return false };
    let port = settings(data)["api"]["port"].as_u64().unwrap_or(8899) as u16;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let req = format!("GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nx-adhush-token: {}\r\nConnection: close\r\n\r\n", token.trim());
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let _ = s.take(256 * 1024).read_to_end(&mut buf);
    // Node answers with chunked transfer encoding, so look for the field in the raw text rather than
    // parsing the body: healthy = 200 and at least one DNS listener ("listening":["udp://…", …]).
    let text = String::from_utf8_lossy(&buf);
    text.starts_with("HTTP/1.1 200") && text.contains("\"listening\":[\"")
}

fn script(app: &Path, data: &Path, name: &str) -> bool {
    use std::os::windows::process::CommandExt;
    let path = app.join("scripts").join(name);
    let child = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&path)
        .arg("-DataDir")
        .arg(data)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .spawn();
    let Ok(mut child) = child else {
        crate::log(&format!("dns guard: cannot run {name}"));
        return false;
    };
    let deadline = Instant::now() + SCRIPT_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            _ => {
                let _ = child.kill();
                crate::log(&format!("dns guard: {name} timed out"));
                return false;
            }
        }
    }
}

fn write_state(data: &Path, mode: Mode, detail: &str) {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let body = json!({ "mode": mode.name(), "since": since, "detail": detail }).to_string();
    let tmp = data.join("dns-state.json.tmp");
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, data.join("dns-state.json"));
    }
}
