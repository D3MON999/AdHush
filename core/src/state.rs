//! Shared runtime state: current config + rule engine (hot-swappable), CA, HTTP client,
//! counters, request log and auto-exclusion caches.
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use anyhow::Result;
use serde::Serialize;

use crate::ca::CertAuthority;
use crate::config::{self, Config, now_ms};
use crate::filter::ContentFilter;
use crate::proxy::{HttpClient, Probe};

const LOG_SIZE: usize = 2000;

#[derive(Default)]
pub struct Stats {
    pub requests: AtomicU64,
    pub blocked: AtomicU64,
    pub rewritten: AtomicU64,
    pub injected: AtomicU64,
    pub mitm: AtomicU64,
    pub tunneled: AtomicU64,
    pub mitm_failed: AtomicU64,
}

impl Stats {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> serde_json::Value {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        serde_json::json!({
            "requests": g(&self.requests), "blocked": g(&self.blocked), "rewritten": g(&self.rewritten),
            "injected": g(&self.injected), "mitm": g(&self.mitm), "tunneled": g(&self.tunneled), "mitmFailed": g(&self.mitm_failed),
        })
    }
}

#[derive(Serialize, Clone, Default)]
pub struct AppStats {
    pub requests: u64,
    pub blocked: u64,
    pub last_seen: i64,
}

#[derive(Serialize, Clone)]
pub struct LogEntry {
    pub id: u64,
    pub time: i64,
    pub app: Option<String>,
    pub method: String,
    pub url: String,
    pub host: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub action: String,
    pub rule: Option<String>,
    pub status: u16,
}

pub struct EngineInfo {
    pub built_at: i64,
    pub build_ms: u128,
    pub rules: usize,
    pub lists: usize,
    pub extended: usize,
}

pub struct State {
    pub data_dir: PathBuf,
    pub token: String,
    pub proxy_port: u16,
    pub ca: CertAuthority,
    pub client: HttpClient,
    pub tls_client: Arc<rustls::ClientConfig>,
    pub config: RwLock<Arc<Config>>,
    pub filter: RwLock<Arc<ContentFilter>>,
    pub engine_info: Mutex<EngineInfo>,
    pub stats: Stats,
    pub log: Mutex<VecDeque<LogEntry>>,
    pub log_seq: AtomicU64,
    pub probes: Mutex<HashMap<String, (Instant, Probe)>>,
    pub failed: Mutex<HashMap<String, Instant>>,
    pub app_stats: Mutex<HashMap<String, AppStats>>,
    pub userscripts: RwLock<Arc<crate::userscripts::UserScripts>>,
    pub driver: std::sync::OnceLock<Arc<crate::divert::Shared>>,
    pub driver_error: Mutex<Option<String>>,
}

impl State {
    pub fn config(&self) -> Arc<Config> {
        self.config.read().unwrap().clone()
    }

    pub fn filter(&self) -> Arc<ContentFilter> {
        self.filter.read().unwrap().clone()
    }

    pub fn userscripts(&self) -> Arc<crate::userscripts::UserScripts> {
        self.userscripts.read().unwrap().clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(&self, app: Option<&str>, method: &str, url: &str, host: &str, rtype: &str, action: &str, rule: Option<String>, status: u16) {
        if let Some(a) = app {
            let mut stats = self.app_stats.lock().unwrap();
            let s = stats.entry(a.to_string()).or_default();
            if rtype != "tunnel" {
                s.requests += 1;
            }
            if action == "blocked" || action == "redirected" {
                s.blocked += 1;
            }
            s.last_seen = now_ms();
        }
        let mut url = url.to_string();
        if url.len() > 400 {
            let mut cut = 400;
            while !url.is_char_boundary(cut) {
                cut -= 1;
            }
            url.truncate(cut);
            url.push('…');
        }
        let entry = LogEntry {
            id: self.log_seq.fetch_add(1, Ordering::Relaxed) + 1,
            time: now_ms(),
            app: app.map(str::to_string),
            method: method.to_string(),
            url,
            host: host.to_string(),
            rtype: rtype.to_string(),
            action: action.to_string(),
            rule,
            status,
        };
        let mut log = self.log.lock().unwrap();
        log.push_back(entry);
        while log.len() > LOG_SIZE {
            log.pop_front();
        }
    }

    pub fn reload_config(&self) {
        match config::load_config(&self.data_dir) {
            Ok(c) => {
                crate::split::configure(c.anti_dpi, c.anti_dpi_tls_fragment, c.anti_dpi_http);
                *self.config.write().unwrap() = Arc::new(c);
            }
            Err(e) => log::warn!("config reload failed: {e:#}"),
        }
    }
}

/// Re-reads settings and filter lists and swaps in a freshly compiled engine.
pub async fn reload(state: Arc<State>) -> Result<()> {
    let dir = state.data_dir.clone();
    let started = Instant::now();
    let (filter, cfg, scripts) = tokio::task::spawn_blocking(move || -> Result<(ContentFilter, Config, crate::userscripts::UserScripts)> {
        let loaded = config::load(&dir)?;
        Ok((ContentFilter::build(&loaded), loaded.config, crate::userscripts::UserScripts::load(&dir)))
    })
    .await??;
    log::info!("{} userscripts/userstyles active", scripts.count());
    *state.userscripts.write().unwrap() = Arc::new(scripts);
    let ms = started.elapsed().as_millis();
    let extended = filter.extended.rule_count();
    log::info!(
        "content engine built: {} rules from {} lists ({extended} extended-syntax), {} resources, in {ms} ms",
        filter.rules, filter.lists, filter.resources
    );
    *state.engine_info.lock().unwrap() = EngineInfo { built_at: now_ms(), build_ms: ms, rules: filter.rules, lists: filter.lists, extended };
    *state.filter.write().unwrap() = Arc::new(filter);
    crate::split::configure(cfg.anti_dpi, cfg.anti_dpi_tls_fragment, cfg.anti_dpi_http);
    *state.config.write().unwrap() = Arc::new(cfg);
    state.probes.lock().unwrap().clear();
    Ok(())
}
