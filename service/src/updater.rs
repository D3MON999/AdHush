// Automatic updates. Every 6 hours (and when the app asks via <data>\update-check), fetch the
// feed in settings.updates.feedUrl:
//   latest.json      {"app":"adhush","version","url","sha256","size","notes","published"}
//   latest.json.sig  base64 Ed25519 signature of latest.json's exact bytes
// The signature must verify against the public key compiled into this program
// (update-key.pub, made by scripts/release.mjs keygen), and the downloaded installer must
// match the signed SHA-256. Only then is it run, silently, from a folder only SYSTEM and
// administrators can write. Anything else is refused, so a compromised download host cannot
// push code to these PCs. State for the app: <data>\update-state.json.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PUBLIC_KEY: &str = include_str!("../update-key.pub");
const FIRST_CHECK: Duration = Duration::from_secs(120);
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
const MAX_SETUP_BYTES: u64 = 500 * 1024 * 1024;
const TRAY_GRACE: Duration = Duration::from_secs(12);

pub fn start(app: PathBuf, data: PathBuf, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || run(&app, &data, &stop));
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn run(app: &Path, data: &Path, stop: &AtomicBool) {
    finish_previous(app, data);
    let mut next = Instant::now() + FIRST_CHECK;
    while !stop.load(Ordering::SeqCst) {
        let asked = take_trigger(data, "update-check");
        let install_now = take_trigger(data, "update-install");
        if asked || install_now || Instant::now() >= next {
            next = Instant::now() + CHECK_EVERY;
            if let Err(e) = check(app, data, install_now) {
                crate::log(&format!("updater: {e}"));
                set_state(data, json!({ "status": "error", "error": e, "checkedAt": now_ms() }));
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn take_trigger(data: &Path, name: &str) -> bool {
    std::fs::remove_file(data.join(name)).is_ok()
}

fn settings(data: &Path) -> Value {
    std::fs::read_to_string(data.join("settings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(s.trim_start_matches('\u{feff}')).ok())
        .unwrap_or(Value::Null)
}

fn current_version(app: &Path) -> String {
    std::fs::read_to_string(app.join("app").join("package.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v["version"].as_str().map(str::to_string))
        .unwrap_or_else(|| "0.0.0".into())
}

/// Numeric dotted-version comparison ("0.10.0" > "0.9.3").
pub fn newer(candidate: &str, current: &str) -> bool {
    let parse = |v: &str| v.split(['.', '-', '+']).take(3).map(|p| p.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    let (a, b) = (parse(candidate), parse(current));
    (0..3).map(|i| (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0))).find(|(x, y)| x != y).is_some_and(|(x, y)| x > y)
}

/// Updates are only fetched over HTTPS (plain HTTP only from this PC itself, for testing).
fn allowed_url(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost")
}

fn resolve(feed: &str, url: &str) -> String {
    if url.contains("://") {
        url.to_string()
    } else {
        let base = feed.rsplit_once('/').map(|(b, _)| b).unwrap_or(feed);
        format!("{base}/{}", url.trim_start_matches('/'))
    }
}

pub fn verify(manifest: &[u8], sig_b64: &str) -> Result<Value, String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let key: [u8; 32] = b64.decode(PUBLIC_KEY.trim()).ok().and_then(|k| k.try_into().ok()).ok_or("bad built-in public key")?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| "bad built-in public key")?;
    let sig: [u8; 64] = b64.decode(sig_b64.trim()).ok().and_then(|s| s.try_into().ok()).ok_or("malformed signature")?;
    key.verify_strict(manifest, &Signature::from_bytes(&sig)).map_err(|_| "update signature does not match: refusing this update")?;
    let v: Value = serde_json::from_slice(manifest).map_err(|e| format!("bad manifest: {e}"))?;
    if v["app"] != "adhush" || v["version"].as_str().is_none() || v["sha256"].as_str().map(|s| s.len()) != Some(64) {
        return Err("manifest is missing app/version/sha256".into());
    }
    Ok(v)
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(timeout)).build().new_agent()
}

fn fetch(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let mut res = agent.get(url).call().map_err(|e| format!("{url}: {e}"))?;
    res.body_mut().with_config().limit(limit).read_to_vec().map_err(|e| format!("{url}: {e}"))
}

fn check(app: &Path, data: &Path, install_now: bool) -> Result<(), String> {
    let s = settings(data);
    let feed = s["updates"]["feedUrl"].as_str().unwrap_or("").trim().to_string();
    let current = current_version(app);
    let previous = read_state(data);
    let keep = |mut v: Value| {
        v["current"] = json!(current);
        v["lastUpdate"] = previous["lastUpdate"].clone();
        v
    };
    if feed.is_empty() {
        set_state(data, keep(json!({ "status": "disabled", "checkedAt": now_ms() })));
        return Ok(());
    }
    if !allowed_url(&feed) {
        return Err(format!("update feed must use https: {feed}"));
    }
    let a = agent(Duration::from_secs(30));
    let manifest = fetch(&a, &feed, 64 * 1024)?;
    let sig = String::from_utf8(fetch(&a, &format!("{feed}.sig"), 4096)?).map_err(|_| "signature is not text")?;
    let m = verify(&manifest, &sig)?;
    let latest = m["version"].as_str().unwrap_or_default().to_string();
    let notes = m["notes"].clone();
    if !newer(&latest, &current) {
        set_state(data, keep(json!({ "status": "up-to-date", "latest": latest, "checkedAt": now_ms() })));
        return Ok(());
    }
    let auto = s["updates"]["auto"].as_bool().unwrap_or(true);
    set_state(data, keep(json!({ "status": "available", "latest": latest, "notes": notes, "checkedAt": now_ms() })));
    if !(auto || install_now) {
        return Ok(());
    }
    install(app, data, &feed, &m, &current, &keep)
}

fn install(_app: &Path, data: &Path, feed: &str, m: &Value, current: &str, keep: &dyn Fn(Value) -> Value) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let latest = m["version"].as_str().unwrap_or_default();
    let url = resolve(feed, m["url"].as_str().unwrap_or_default());
    if !allowed_url(&url) {
        return Err(format!("installer URL must use https: {url}"));
    }
    set_state(data, keep(json!({ "status": "downloading", "latest": latest, "checkedAt": now_ms() })));
    let dir = data.join("updates");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // Only SYSTEM and administrators may write here: nobody can swap the file after it is verified.
    let _ = std::process::Command::new("icacls")
        .arg(&dir)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .output();
    let limit = m["size"].as_u64().unwrap_or(MAX_SETUP_BYTES).min(MAX_SETUP_BYTES) + 1;
    let bytes = fetch(&agent(Duration::from_secs(30 * 60)), &url, limit)?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if Some(digest.as_str()) != m["sha256"].as_str() {
        return Err("downloaded installer does not match the signed checksum: refusing to install".into());
    }
    let setup = dir.join(format!("AdHushSetup-{latest}.exe"));
    std::fs::write(&setup, &bytes).map_err(|e| e.to_string())?;
    // Re-hash what is on disk, right before running it.
    let mut on_disk = Vec::new();
    std::fs::File::open(&setup).and_then(|mut f| f.read_to_end(&mut on_disk)).map_err(|e| e.to_string())?;
    if format!("{:x}", Sha256::digest(&on_disk)) != digest {
        return Err("installer changed on disk: refusing to install".into());
    }
    let marker = json!({ "from": current, "to": latest, "at": now_ms() });
    std::fs::write(data.join("update-installing.json"), marker.to_string()).map_err(|e| e.to_string())?;
    set_state(data, keep(json!({ "status": "installing", "latest": latest, "checkedAt": now_ms() })));
    // Trays check for the marker every 5 s; give them time to schedule their relaunch and exit
    // before the installer closes them.
    std::thread::sleep(TRAY_GRACE);
    crate::log(&format!("updater: installing {latest} (from {current})"));
    // Detached: the installer stops this service, then starts the new version.
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    std::process::Command::new(&setup)
        .args(["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/UPDATE"])
        .creation_flags(DETACHED_PROCESS | windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| {
            let _ = std::fs::remove_file(data.join("update-installing.json"));
            format!("could not start the installer: {e}")
        })?;
    Ok(())
}

/// After an update the new service starts here: record the result and clean up.
fn finish_previous(app: &Path, data: &Path) {
    let marker = data.join("update-installing.json");
    let Some(m) = std::fs::read_to_string(&marker).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) else { return };
    let _ = std::fs::remove_file(&marker);
    let _ = std::fs::remove_dir_all(data.join("updates"));
    let current = current_version(app);
    let ok = m["to"].as_str() == Some(current.as_str());
    crate::log(&format!("updater: update to {} {}", m["to"], if ok { "succeeded" } else { "did not complete" }));
    let state = if ok {
        json!({ "status": "up-to-date", "current": current, "latest": current, "checkedAt": now_ms(),
                "lastUpdate": { "from": m["from"], "to": m["to"], "at": now_ms() } })
    } else {
        json!({ "status": "error", "current": current, "checkedAt": now_ms(), "error": format!("update to {} did not complete", m["to"].as_str().unwrap_or("?")) })
    };
    set_state(data, state);
}

fn read_state(data: &Path) -> Value {
    std::fs::read_to_string(data.join("update-state.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)
}

fn set_state(data: &Path, v: Value) {
    let tmp = data.join("update-state.json.tmp");
    if std::fs::write(&tmp, v.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, data.join("update-state.json"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(newer("0.1.1", "0.1.0"));
        assert!(newer("0.10.0", "0.9.9"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.0.9", "0.1.0"));
    }

    #[test]
    fn urls() {
        assert_eq!(resolve("https://h/o/r/releases/latest/download/latest.json", "AdHushSetup-1.exe"), "https://h/o/r/releases/latest/download/AdHushSetup-1.exe");
        assert_eq!(resolve("https://h/latest.json", "https://cdn/x.exe"), "https://cdn/x.exe");
        assert!(allowed_url("https://x") && allowed_url("http://127.0.0.1:9/x") && !allowed_url("http://evil.example/x"));
    }

    #[test]
    fn rejects_bad_signatures() {
        assert!(verify(br#"{"app":"adhush","version":"9.9.9","sha256":"00"}"#, &"A".repeat(88)).is_err());
        assert!(verify(b"{}", "not base64").is_err());
    }
}
