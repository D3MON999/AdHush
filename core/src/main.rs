//! adhush-core: HTTP/HTTPS content filtering proxy for AdHush.
//!
//! Usage: adhush-core --data <DIR> [--port 8080] [--control-port 8901]
mod ca;
mod config;
mod control;
mod divert;
mod extended;
mod privacy;
mod proc;
mod split;
mod filter;
mod html;
mod proxy;
mod sni;
mod state;
mod userscripts;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::state::{EngineInfo, State, Stats};

struct Args {
    data: PathBuf,
    port: u16,
    control_port: u16,
    exclude_pids: Vec<u32>,
    init_ca: bool,
}

fn parse_args() -> Result<Args> {
    let mut data = None;
    let mut port = 8080;
    let mut control_port = 8901;
    let mut exclude_pids = Vec::new();
    let mut init_ca = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--data" => data = it.next().map(PathBuf::from),
            "--port" => port = it.next().context("--port needs a value")?.parse()?,
            "--control-port" => control_port = it.next().context("--control-port needs a value")?.parse()?,
            "--exclude-pid" => exclude_pids.push(it.next().context("--exclude-pid needs a value")?.parse()?),
            "--init-ca" => init_ca = true,
            "-h" | "--help" => {
                println!("adhush-core --data <DIR> [--port 8080] [--control-port 8901] [--exclude-pid PID]...");
                println!("adhush-core --data <DIR> --init-ca   create this PC's root certificate and exit (used by setup)");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(Args { data: data.context("--data is required")?, port, control_port, exclude_pids, init_ca })
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = parse_args()?;
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("could not install the rustls crypto provider"))?;
    if args.init_ca {
        // Every install gets its own key pair; a shared CA key would let anyone intercept every AdHush user.
        ca::CertAuthority::load_or_create(&args.data.join("ca"))?;
        println!("{}", args.data.join("ca").join("adhush-ca.pem").display());
        return Ok(());
    }

    let token = std::fs::read_to_string(args.data.join("api-token"))
        .context("reading api-token (start the AdHush service once first)")?
        .trim()
        .to_string();
    let ca = ca::CertAuthority::load_or_create(&args.data.join("ca"))?;
    let tls_client = proxy::client_tls();
    let state = Arc::new(State {
        data_dir: args.data.clone(),
        token,
        proxy_port: args.port,
        ca,
        client: proxy::build_client(tls_client.clone()),
        tls_client: Arc::new(tls_client),
        config: RwLock::new(Arc::new(config::load_config(&args.data).unwrap_or_default())),
        filter: RwLock::new(Arc::new(filter::ContentFilter::empty())),
        engine_info: Mutex::new(EngineInfo { built_at: 0, build_ms: 0, rules: 0, lists: 0, extended: 0 }),
        stats: Stats::default(),
        log: Mutex::new(VecDeque::new()),
        log_seq: AtomicU64::new(0),
        probes: Mutex::new(HashMap::new()),
        failed: Mutex::new(HashMap::new()),
        app_stats: Mutex::new(HashMap::new()),
        userscripts: RwLock::new(Arc::new(Default::default())),
        driver: std::sync::OnceLock::new(),
        driver_error: Mutex::new(None),
    });

    let control = tokio::spawn(control::run(state.clone(), SocketAddr::from(([127, 0, 0, 1], args.control_port))));
    let proxy = tokio::spawn(proxy::run(state.clone(), SocketAddr::from(([127, 0, 0, 1], args.port))));
    if let Err(e) = state::reload(state.clone()).await {
        log::error!("initial rule load failed: {e:#}");
    }

    // Driver mode: listeners first, then start reflecting packets to them.
    let cfg = state.config();
    if cfg.driver_enabled {
        let started = async {
            proxy::run_transparent(state.clone(), cfg.driver_port, cfg.driver_http_port).await.map_err(|e| e.to_string())?;
            divert::ensure_firewall_rule();
            divert::start(state.clone(), cfg.driver_port, cfg.driver_http_port, args.exclude_pids.clone())
        }
        .await;
        match started {
            Ok(shared) => {
                let _ = state.driver.set(shared);
            }
            Err(e) => {
                log::error!("driver mode unavailable: {e}");
                *state.driver_error.lock().unwrap() = Some(e);
            }
        }
    }

    // Settings such as "paused until" change over time; re-read them periodically.
    let refresher = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            refresher.reload_config();
        }
    });

    tokio::select! {
        r = control => r??,
        r = proxy => r??,
        _ = tokio::signal::ctrl_c() => log::info!("shutting down"),
    }
    Ok(())
}
