//! Reads AdHush's shared data directory (written by the Node service): settings.json and
//! filters/index.json + filters/<id>.txt for lists whose scope is "content".
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::Value;

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub protection_enabled: bool,
    pub paused_until: i64,
    pub https_enabled: bool,
    pub cosmetic: bool,
    pub auto_exclude: bool,
    pub skip_ev: bool,
    pub exclusions: Vec<String>,
    pub driver_enabled: bool,
    pub driver_all_apps: bool,
    /// Lower-case executable file names, e.g. "chrome.exe".
    pub driver_apps: Vec<String>,
    pub driver_excluded: Vec<String>,
    pub block_quic: bool,
    pub driver_port: u16,
    pub driver_http_port: u16,
    /// Apps whose traffic is never filtered (lower-case exe names).
    pub bypass_apps: Vec<String>,
    /// Apps whose HTTPS is never decrypted.
    pub no_https_apps: Vec<String>,
    /// Tracking protection; None when turned off.
    pub privacy: Option<crate::privacy::Privacy>,
    pub anti_dpi: bool,
    pub anti_dpi_tls_fragment: usize,
    pub anti_dpi_http: bool,
}

fn cookie_minutes(v: &Value) -> Option<u64> {
    if !flag(&v["enabled"], false) {
        return None;
    }
    Some(v["minutes"].as_u64().unwrap_or(0))
}

fn load_privacy(p: &Value) -> Option<crate::privacy::Privacy> {
    if !flag(&p["enabled"], false) {
        return None;
    }
    let s = |k: &str| p[k].as_str().unwrap_or("").to_string();
    Some(crate::privacy::Privacy {
        hide_search_queries: flag(&p["hideSearchQueries"], false),
        send_dnt: flag(&p["sendDnt"], false),
        remove_x_client_data: flag(&p["removeXClientData"], false),
        strip_tracking_params: flag(&p["stripTrackingParams"], false),
        third_party_cookie_minutes: cookie_minutes(&p["thirdPartyCookies"]),
        first_party_cookie_minutes: cookie_minutes(&p["firstPartyCookies"]),
        hide_referrer: flag(&p["hideReferrer"], false),
        custom_referrer: s("customReferrer"),
        hide_user_agent: flag(&p["hideUserAgent"], false),
        custom_user_agent: s("customUserAgent"),
        mask_ip: flag(&p["maskIp"], false),
        custom_ip: s("customIp"),
        block_webrtc: flag(&p["blockWebRtc"], false),
        block_push_api: flag(&p["blockPushApi"], false),
        block_location_api: flag(&p["blockLocationApi"], false),
        block_third_party_auth: flag(&p["blockThirdPartyAuth"], false),
        disable_third_party_cache: flag(&p["disableThirdPartyCache"], false),
    })
}

impl Config {
    pub fn filtering_active(&self) -> bool {
        self.protection_enabled && now_ms() >= self.paused_until
    }

    pub fn is_excluded(&self, host: &str) -> bool {
        self.exclusions.iter().any(|d| host == d || host.ends_with(&format!(".{d}")))
    }
}

pub struct Loaded {
    pub config: Config,
    /// (filter id, list text). Built-in lists (id < 1000) are trusted with privileged scriptlets.
    pub lists: Vec<(i64, String)>,
    pub user_rules: Option<String>,
    pub allowlist: Vec<String>,
    /// Scriptlet and $redirect resources.
    pub resources: Vec<adblock::resources::Resource>,
}

/// `<data>/resources.json` overrides the copy shipped next to the executable.
fn load_resources(data_dir: &Path) -> Vec<adblock::resources::Resource> {
    let shipped = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.join("resources.json")));
    for path in [Some(data_dir.join("resources.json")), shipped].into_iter().flatten() {
        if let Ok(text) = fs::read_to_string(&path) {
            match serde_json::from_str(&text) {
                Ok(r) => return r,
                Err(e) => log::warn!("invalid resources file {}: {e}", path.display()),
            }
        }
    }
    log::warn!("no scriptlet/redirect resources found; ##+js and $redirect rules will be inactive");
    Vec::new()
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn domains(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|d| match d {
                    Value::String(s) => Some(s.clone()),
                    Value::Object(o) if o.get("enabled").and_then(Value::as_bool) != Some(false) => {
                        o.get("name").and_then(Value::as_str).map(str::to_string)
                    }
                    _ => None,
                })
                .map(|d| d.trim().trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn flag(v: &Value, default: bool) -> bool {
    v.as_bool().unwrap_or(default)
}

pub fn load_config(data_dir: &Path) -> Result<Config> {
    let s: Value = serde_json::from_str(&fs::read_to_string(data_dir.join("settings.json")).context("reading settings.json")?)?;
    let h = &s["https"];
    let d = &h["driver"];
    let exe_list = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| a.iter().filter_map(Value::as_str).map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    };
    let port = |v: &Value, default: u16| v.as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0).unwrap_or(default);
    let dpi = &s["privacy"]["antiDpi"];
    Ok(Config {
        bypass_apps: exe_list(&s["apps"]["bypass"]),
        no_https_apps: exe_list(&s["apps"]["noHttps"]),
        privacy: load_privacy(&s["privacy"]),
        anti_dpi: flag(&s["privacy"]["enabled"], false) && flag(&dpi["enabled"], false),
        anti_dpi_tls_fragment: dpi["tlsFragment"].as_u64().unwrap_or(1) as usize,
        anti_dpi_http: flag(&dpi["http"], true),
        driver_enabled: flag(&d["enabled"], false),
        driver_all_apps: d["mode"].as_str() == Some("all"),
        driver_apps: exe_list(&d["apps"]),
        driver_excluded: exe_list(&d["excluded"]),
        block_quic: flag(&d["blockQuic"], true),
        driver_port: port(&d["port"], 18443),
        driver_http_port: port(&d["httpPort"], 18480),
        protection_enabled: flag(&s["protection"]["enabled"], true),
        paused_until: s["protection"]["pausedUntil"].as_i64().unwrap_or(0),
        https_enabled: flag(&h["enabled"], false),
        cosmetic: flag(&h["cosmetic"], true),
        auto_exclude: flag(&h["autoExclude"], true),
        skip_ev: flag(&h["skipEv"], true),
        exclusions: domains(&h["exclusions"]),
    })
}

pub fn load(data_dir: &Path) -> Result<Loaded> {
    let config = load_config(data_dir)?;
    let s: Value = serde_json::from_str(&fs::read_to_string(data_dir.join("settings.json"))?)?;
    let index: Value = fs::read_to_string(data_dir.join("filters").join("index.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);

    let security = flag(&s["security"]["enabled"], true);
    let parental = flag(&s["parental"]["enabled"], false);
    let mut lists = Vec::new();
    for f in index["filters"].as_array().into_iter().flatten() {
        if f["scope"].as_str() != Some("content") || !flag(&f["enabled"], false) {
            continue;
        }
        match f["group"].as_str() {
            Some("security") if !security => continue,
            Some("parental") if !parental => continue,
            _ => {}
        }
        let Some(id) = f["id"].as_i64() else { continue };
        if let Ok(text) = fs::read_to_string(data_dir.join("filters").join(format!("{id}.txt"))) {
            lists.push((id, text));
        }
    }
    let filtering = &s["filtering"];
    let user_rules = if flag(&filtering["userRulesEnabled"], true) {
        filtering["userRules"].as_str().map(str::to_string)
    } else {
        None
    };
    let allowlist = if flag(&filtering["allowlist"]["enabled"], true) { domains(&filtering["allowlist"]["domains"]) } else { Vec::new() };
    Ok(Loaded { config, lists, user_rules, allowlist, resources: load_resources(data_dir) })
}
