//! Loopback control API used by the Node service (token protected).
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::header;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::proxy::{Body, full};
use crate::state::{self, State};

fn json(status: StatusCode, v: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(v.to_string()))
        .unwrap()
}

fn status_json(st: &State) -> serde_json::Value {
    let cfg = st.config();
    let info = st.engine_info.lock().unwrap();
    let excluded: Vec<String> = st.failed.lock().unwrap().keys().cloned().collect();
    let driver = match st.driver.get() {
        Some(d) => {
            use std::sync::atomic::Ordering::Relaxed;
            serde_json::json!({
                "running": true, "error": null, "httpsPort": d.https_port, "httpPort": d.http_port,
                "activeConnections": d.active_connections(), "redirected": d.stats.redirected.load(Relaxed),
                "passed": d.stats.passed.load(Relaxed), "quicDropped": d.stats.quic_dropped.load(Relaxed),
            })
        }
        None => serde_json::json!({ "running": false, "enabled": cfg.driver_enabled, "error": *st.driver_error.lock().unwrap() }),
    };
    serde_json::json!({
        "driver": driver,
        "running": true,
        "version": env!("CARGO_PKG_VERSION"),
        "proxyPort": st.proxy_port,
        "httpsEnabled": cfg.https_enabled,
        "active": cfg.filtering_active(),
        "cosmetic": cfg.cosmetic,
        "engine": { "rules": info.rules, "lists": info.lists, "extended": info.extended, "builtAt": info.built_at, "ms": info.build_ms },
        "privacy": cfg.privacy.is_some(),
        "antiDpi": cfg.anti_dpi,
        "stats": st.stats.snapshot(),
        "autoExcluded": excluded,
        "caPath": st.ca.ca_path.display().to_string(),
    })
}

async fn handle(st: Arc<State>, req: Request<Incoming>) -> Response<Body> {
    let authorized = req.headers().get("x-adhush-token").and_then(|v| v.to_str().ok()) == Some(st.token.as_str());
    if !authorized {
        return json(StatusCode::UNAUTHORIZED, serde_json::json!({ "error": "invalid token" }));
    }
    let query = req.uri().query().unwrap_or("").to_string();
    match (req.method().clone(), req.uri().path()) {
        (Method::GET, "/status") => json(StatusCode::OK, status_json(&st)),
        (Method::GET, "/log") => {
            let limit = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("limit="))
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(200)
                .min(2000);
            let items: Vec<_> = st.log.lock().unwrap().iter().rev().take(limit).cloned().collect();
            json(StatusCode::OK, serde_json::json!({ "items": items }))
        }
        (Method::POST, "/reload") => match state::reload(st.clone()).await {
            Ok(()) => json(StatusCode::OK, status_json(&st)),
            Err(e) => json(StatusCode::INTERNAL_SERVER_ERROR, serde_json::json!({ "error": format!("{e:#}") })),
        },
        (Method::GET, "/apps") => {
            let apps = st.app_stats.lock().unwrap().clone();
            json(StatusCode::OK, serde_json::json!({ "apps": apps }))
        }
        (Method::POST, "/clear-exclusions") => {
            st.failed.lock().unwrap().clear();
            st.probes.lock().unwrap().clear();
            json(StatusCode::OK, serde_json::json!({ "ok": true }))
        }
        (Method::GET, "/ca") => Response::builder()
            .header(header::CONTENT_TYPE, "application/x-pem-file")
            .body(full(st.ca.ca_pem.clone()))
            .unwrap(),
        _ => json(StatusCode::NOT_FOUND, serde_json::json!({ "error": "not found" })),
    }
}

pub async fn run(state: Arc<State>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    log::info!("control API on http://{addr}");
    loop {
        let (stream, _) = listener.accept().await?;
        let st = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let st = st.clone();
                async move { Ok::<_, Infallible>(handle(st, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
        });
    }
}
