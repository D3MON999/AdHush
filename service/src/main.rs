// Windows service wrapper for AdHush. The service control manager starts this exe as
// LocalSystem; it runs the bundled Node runtime on app\src\index.js, restarts it if it dies,
// and on stop closes Node's stdin so it can shut down cleanly (Windows has no SIGTERM).
// Every child is placed in a kill-on-close job object, so nothing (Node, adhush-core) can
// outlive the service.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

mod dns_guard;
mod updater;

const SERVICE_NAME: &str = "AdHush";
const STOP_GRACE: Duration = Duration::from_secs(10);

define_windows_service!(ffi_service_main, service_main);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--verify") {
        // adhush-service.exe --verify <latest.json>: checks latest.json.sig with the built-in key.
        let Some(path) = args.get(2) else {
            eprintln!("usage: adhush-service --verify <latest.json>");
            std::process::exit(2);
        };
        let manifest = std::fs::read(path).unwrap_or_default();
        let sig = std::fs::read_to_string(format!("{path}.sig")).unwrap_or_default();
        match updater::verify(&manifest, &sig) {
            Ok(m) => println!("OK: signed AdHush {}", m["version"].as_str().unwrap_or("?")),
            Err(e) => {
                println!("REJECTED: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("--check-feed") {
        // adhush-service.exe --check-feed <feed url>: a real update check that installs nothing.
        match updater::dry_run(args.get(2).map(String::as_str).unwrap_or_default()) {
            Ok(msg) => println!("OK: {msg}"),
            Err(e) => {
                println!("FAILED: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if std::env::args().any(|a| a == "--console") {
        // Debug mode: run the supervisor in the foreground until Enter is pressed.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = std::io::stdin().read_line(&mut String::new());
            let _ = tx.send(());
        });
        supervise(&rx);
        return;
    }
    if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        eprintln!("adhush-service must be started by the Windows service manager ({e}). Use --console to run it directly.");
        std::process::exit(1);
    }
}

fn install_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_default()
}

fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("AdHush")
}

fn log(msg: &str) {
    let dir = data_dir().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(dir.join("service.log")) {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let _ = writeln!(f, "[{secs}] {msg}");
    }
}

struct Job(HANDLE);

impl Job {
    fn new() -> Option<Job> {
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            (ok != 0).then_some(Job(h))
        }
    }

    fn assign(&self, child: &Child) {
        unsafe {
            AssignProcessToJobObject(self.0, child.as_raw_handle() as HANDLE);
        }
    }
}

fn spawn_node(dir: &Path, data: &Path) -> std::io::Result<Child> {
    use std::os::windows::process::CommandExt;
    let _ = std::fs::create_dir_all(data.join("logs"));
    let stderr = File::options().create(true).append(true).open(data.join("logs").join("node-stderr.log"))?;
    Command::new(dir.join("node").join("node.exe"))
        .arg(dir.join("app").join("src").join("index.js"))
        .arg("--data")
        .arg(data)
        .env("ADHUSH_SERVICE", "1")
        .current_dir(dir.join("app"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
}

/// Runs Node until `stop` fires, restarting it with backoff when it exits on its own.
fn supervise(stop: &mpsc::Receiver<()>) {
    let dir = install_dir();
    let data = data_dir();
    let job = Job::new();
    let mut failures = 0u32;
    loop {
        let started = Instant::now();
        let mut child = match spawn_node(&dir, &data) {
            Ok(c) => c,
            Err(e) => {
                log(&format!("cannot start node: {e}"));
                if stop.recv_timeout(Duration::from_secs(30)).is_ok() {
                    return;
                }
                continue;
            }
        };
        if let Some(j) = &job {
            j.assign(&child);
        }
        log(&format!("started node (pid {})", child.id()));
        let exited = loop {
            match stop.recv_timeout(Duration::from_millis(500)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break None,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if let Ok(Some(status)) = child.try_wait() {
                break Some(status);
            }
        };
        let Some(status) = exited else {
            // Stop requested: close stdin, give Node time to save state, then force it.
            drop(child.stdin.take());
            let deadline = Instant::now() + STOP_GRACE;
            while Instant::now() < deadline {
                if let Ok(Some(_)) = child.try_wait() {
                    log("node stopped");
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            log("node did not stop in time; terminating");
            let _ = child.kill();
            let _ = child.wait();
            return;
        };
        if started.elapsed() > Duration::from_secs(120) {
            failures = 0;
        }
        failures += 1;
        let delay = Duration::from_secs((2u64 << failures.min(5)).min(60));
        log(&format!("node exited ({status}); restarting in {} s", delay.as_secs()));
        if stop.recv_timeout(delay).is_ok() {
            return;
        }
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept, wait: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    let (tx, rx) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(SERVICE_NAME, handler) else {
        log("cannot register service control handler");
        return;
    };
    let _ = handle.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, Duration::ZERO));
    log("service started");
    let guard = dns_guard::DnsGuard::start(install_dir(), data_dir());
    // Not joined on stop: a download in progress must not hold up the service manager.
    let stop_updater = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    updater::start(install_dir(), data_dir(), stop_updater.clone());
    let (node_tx, node_rx) = mpsc::channel();
    let node = std::thread::spawn(move || supervise(&node_rx));
    let _ = rx.recv();
    stop_updater.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = handle.set_service_status(status(ServiceState::StopPending, ServiceControlAccept::empty(), Duration::from_secs(30)));
    // Restore Windows DNS while AdHush still answers, then stop it: no gap without name resolution.
    guard.finish();
    let _ = node_tx.send(());
    let _ = node.join();
    let _ = handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), Duration::ZERO));
}
