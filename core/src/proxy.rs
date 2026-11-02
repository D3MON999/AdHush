//! HTTP proxy with selective HTTPS interception.
//!
//! CONNECT host:port → peek the TLS ClientHello (SNI) → decide:
//!   * tunnel  : not TLS, HTTPS filtering off, excluded host, EV certificate, invalid upstream
//!               certificate, or host auto-excluded after the client rejected our certificate
//!   * intercept: terminate TLS with a leaf cert from our CA, then filter each request
//!               (network rules, removeparam, redirects) and inject cosmetic CSS into HTML.
use std::collections::hash_map::RandomState;
use std::convert::Infallible;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::http::uri::Authority;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::filter::{Verdict, url_host};
use crate::html;
use crate::privacy::{is_third_party, strip_tracking_params};
use crate::split::{SplitConnector, SplitStream};
use crate::sni::{Peek, peek_client_hello};
use crate::state::{State, Stats};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, BoxError>;
pub type HttpClient = hyper_util::client::legacy::Client<hyper_rustls::HttpsConnector<SplitConnector>, Body>;

/// Same-origin path the in-page runtime calls for generic selectors of late-added elements.
const COSMETIC_ENDPOINT: &str = "/__adhush__/cosmetic";
const PROBE_TTL: Duration = Duration::from_secs(3600);
const AUTO_EXCLUDE_TTL: Duration = Duration::from_secs(3600);
const MAX_HTML: usize = 32 * 1024 * 1024;
/// DER encoding of the CA/Browser Forum EV policy OID 2.23.140.1.1.
const EV_OID: &[u8] = &[0x06, 0x05, 0x67, 0x81, 0x0c, 0x01, 0x01];

#[derive(Clone, Copy, Debug)]
pub enum Probe {
    Valid { ev: bool },
    Invalid,
    Unreachable,
}

pub fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

pub fn empty() -> Body {
    full(Bytes::new())
}

fn boxed(body: Incoming) -> Body {
    body.map_err(|e| -> BoxError { Box::new(e) }).boxed()
}

pub fn client_tls() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for e in &native.errors {
        log::warn!("native root store: {e}");
    }
    let (added, _) = roots.add_parsable_certificates(native.certs);
    // Windows fetches roots on demand, so its local store is often incomplete: add Mozilla's set too.
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    log::info!("trusting {added} Windows root certificates + {} bundled Mozilla roots", webpki_roots::TLS_SERVER_ROOTS.len());
    rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
}

/// Largest header block accepted in either direction (matches Chromium).
const MAX_HEADER_LIST: u32 = 256 * 1024;

pub fn build_client(tls: rustls::ClientConfig) -> HttpClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(SplitConnector::new());
    hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        // hyper's 16 KB default is below what real sites send (gemini.google.com: ~27 KB of
        // response headers, mostly CSP); going over it resets the stream with PROTOCOL_ERROR.
        // Browsers accept 256 KB.
        .http2_max_header_list_size(MAX_HEADER_LIST)
        .build(https)
}

fn text_response(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(msg.to_string()))
        .unwrap()
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn block_page(url: &str, rule: Option<&str>) -> Response<Body> {
    let body = format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>Blocked by AdHush</title>\
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:640px;margin:12vh auto;padding:0 20px;color:#17201c}}h1{{font-size:22px}}code{{background:#f0f3f1;padding:2px 6px;border-radius:4px;word-break:break-all}}@media(prefers-color-scheme:dark){{body{{background:#111614;color:#e6ece9}}code{{background:#202825}}}}</style>\
<h1>This page was blocked</h1><p>AdHush blocked <code>{}</code></p>{}<p>To allow it, add the site to the allowlist or create an <code>@@</code> rule in AdHush.</p>",
        escape(url),
        rule.map(|r| format!("<p>Rule: <code>{}</code></p>", escape(r))).unwrap_or_default()
    );
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header("x-adhush", "blocked")
        .body(full(body))
        .unwrap()
}

/// `$redirect` resources arrive as `data:<mime>;base64,<payload>` URLs.
fn redirect_response(data_url: &str) -> Option<Response<Body>> {
    let rest = data_url.strip_prefix("data:")?;
    let (meta, payload) = rest.split_once(',')?;
    let mime = meta.trim_end_matches(";base64");
    let body = if meta.ends_with(";base64") { crate::ca::base64_decode(payload)? } else { payload.as_bytes().to_vec() };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, if mime.is_empty() { "text/plain" } else { mime })
        .header("x-adhush", "redirected")
        .body(full(body))
        .ok()
}

fn blocked_response(rtype: &str, url: &str, rule: Option<&str>, redirect: Option<&str>) -> Response<Body> {
    if let Some(r) = redirect.and_then(redirect_response) {
        return r;
    }
    if rtype == "document" || rtype == "subdocument" {
        return block_page(url, rule);
    }
    Response::builder().status(StatusCode::FORBIDDEN).header("x-adhush", "blocked").body(empty()).unwrap()
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> &'a str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

fn is_upgrade(h: &HeaderMap) -> bool {
    header_str(h, "upgrade").eq_ignore_ascii_case("websocket")
}

/// Maps browser request metadata to adblock request types.
pub fn request_type(h: &HeaderMap, path: &str) -> &'static str {
    if is_upgrade(h) {
        return "websocket";
    }
    match header_str(h, "sec-fetch-dest") {
        "document" => return "document",
        "iframe" | "frame" | "embed" => return "subdocument",
        "object" => return "object",
        "script" | "worker" | "sharedworker" | "serviceworker" => return "script",
        "style" => return "stylesheet",
        "image" => return "image",
        "font" => return "font",
        "audio" | "video" | "track" => return "media",
        "empty" => {
            return if header_str(h, "sec-fetch-mode") == "navigate" { "document" } else { "xmlhttprequest" };
        }
        _ => {}
    }
    if header_str(h, "accept").contains("text/html") {
        return "document";
    }
    let p = path.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
    let ext = p.rsplit('.').next().unwrap_or("");
    match ext {
        "js" | "mjs" => "script",
        "css" => "stylesheet",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "ico" | "avif" | "bmp" => "image",
        "woff" | "woff2" | "ttf" | "otf" | "eot" => "font",
        "mp4" | "webm" | "mp3" | "ogg" | "m3u8" | "ts" | "m4s" => "media",
        _ => "other",
    }
}

fn strip_hop_headers(h: &mut HeaderMap, keep_upgrade: bool) {
    for name in ["connection", "proxy-connection", "keep-alive", "proxy-authorization", "proxy-authenticate", "te", "trailer", "transfer-encoding"] {
        h.remove(name);
    }
    if !keep_upgrade {
        h.remove("upgrade");
    }
}

fn pass(resp: Response<Incoming>) -> Response<Body> {
    let (mut parts, body) = resp.into_parts();
    strip_hop_headers(&mut parts.headers, false);
    Response::from_parts(parts, boxed(body))
}

fn random_nonce() -> String {
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    let a = h.finish();
    let mut h2 = RandomState::new().build_hasher();
    h2.write_u64(a);
    format!("{:016x}{:016x}", a, h2.finish())
}

/// Decodes `application/x-www-form-urlencoded` values.
fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn json_response(status: StatusCode, v: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(full(v.to_string()))
        .unwrap()
}

async fn read_json(req: Request<Incoming>, limit: usize) -> Option<serde_json::Value> {
    let bytes = Limited::new(req.into_body(), limit).collect().await.ok()?.to_bytes();
    serde_json::from_slice(&bytes).ok()
}

fn endpoint_id(path_q: &str) -> &str {
    path_q.rsplit('/').next().unwrap_or("").split('?').next().unwrap_or("")
}

/// GM_setValue / GM_deleteValue persistence.
async fn gm_endpoint(st: &State, path_q: &str, req: Request<Incoming>) -> Response<Body> {
    let id = endpoint_id(path_q).to_string();
    let Some(body) = read_json(req, 4 * 1024 * 1024).await else {
        return json_response(StatusCode::BAD_REQUEST, serde_json::json!({ "error": "invalid body" }));
    };
    let ok = st.userscripts().set_value(&id, body["op"].as_str().unwrap_or(""), body["key"].as_str().unwrap_or(""), body["value"].clone());
    json_response(if ok { StatusCode::OK } else { StatusCode::NOT_FOUND }, serde_json::json!({ "ok": ok }))
}

/// GM_xmlhttpRequest: cross-origin requests on behalf of a userscript, limited to its @connect hosts.
async fn xhr_endpoint(st: &State, path_q: &str, req: Request<Incoming>) -> Response<Body> {
    let id = endpoint_id(path_q).to_string();
    let Some(body) = read_json(req, 16 * 1024 * 1024).await else {
        return json_response(StatusCode::BAD_REQUEST, serde_json::json!({ "error": "invalid body" }));
    };
    let target = body["url"].as_str().unwrap_or("").to_string();
    let page = body["page"].as_str().unwrap_or("");
    if let Err(e) = st.userscripts().check_xhr(&id, page, &target) {
        return json_response(StatusCode::OK, serde_json::json!({ "error": e }));
    }
    let Ok(uri) = target.parse::<Uri>() else {
        return json_response(StatusCode::OK, serde_json::json!({ "error": "invalid URL" }));
    };
    let method = Method::from_bytes(body["method"].as_str().unwrap_or("GET").to_ascii_uppercase().as_bytes()).unwrap_or(Method::GET);
    let mut builder = Request::builder().method(method).uri(uri).version(Version::HTTP_11);
    for (k, v) in body["headers"].as_object().into_iter().flatten() {
        let name = k.to_ascii_lowercase();
        if let (Some(v), false) = (v.as_str(), matches!(name.as_str(), "host" | "connection" | "content-length" | "transfer-encoding")) {
            builder = builder.header(name, v);
        }
    }
    let data = body["data"].as_str().map(|s| s.to_string()).unwrap_or_default();
    let Ok(out) = builder.body(full(data)) else {
        return json_response(StatusCode::OK, serde_json::json!({ "error": "invalid request" }));
    };
    let resp = match timeout(Duration::from_secs(60), st.client.request(out)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return json_response(StatusCode::OK, serde_json::json!({ "error": error_chain(&e) })),
        Err(_) => return json_response(StatusCode::OK, serde_json::json!({ "error": "timed out" })),
    };
    let status = resp.status();
    let headers: String = resp.headers().iter().map(|(k, v)| format!("{}: {}\r\n", k, v.to_str().unwrap_or(""))).collect();
    let encoding = header_str(resp.headers(), "content-encoding").to_string();
    let raw = match Limited::new(resp.into_body(), 10 * 1024 * 1024).collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => return json_response(StatusCode::OK, serde_json::json!({ "error": format!("response read failed: {e}") })),
    };
    let decoded = html::decode(&encoding, &raw).unwrap_or_else(|| raw.to_vec());
    json_response(StatusCode::OK, serde_json::json!({
        "status": status.as_u16(),
        "statusText": status.canonical_reason().unwrap_or(""),
        "finalUrl": target,
        "responseHeaders": headers,
        "responseText": String::from_utf8_lossy(&decoded),
    }))
}

/// Shown instead of a raw .user.js / .user.css file: offers to install it in AdHush.
fn install_page(url: &str, ui_port: u16) -> Response<Body> {
    let enc: String = url.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
    let raw = if url.contains('?') { format!("{url}&adhush-raw=1") } else { format!("{url}?adhush-raw=1") };
    let body = format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>Install extension</title>\
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:640px;margin:12vh auto;padding:0 20px;color:#17201c}}a.b{{display:inline-block;background:#2f9e6e;color:#fff;padding:8px 16px;border-radius:8px;text-decoration:none;font-weight:600}}code{{word-break:break-all;background:#f0f3f1;padding:2px 6px;border-radius:4px}}@media(prefers-color-scheme:dark){{body{{background:#111614;color:#e6ece9}}code{{background:#202825}}}}</style>\
<h1>Install this extension in AdHush?</h1><p><code>{}</code></p><p><a class=b href=\"http://127.0.0.1:{ui_port}/#/extensions?install={enc}\">Review and install</a> &nbsp; <a href=\"{}\">View the file instead</a></p>",
        escape(url), escape(&raw)
    );
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header("x-adhush", "install-offer")
        .body(full(body))
        .unwrap()
}

/// Serves generic hiding selectors to the in-page runtime: `?u=<page>&c=<classes>&i=<ids>`.
fn cosmetic_endpoint(st: &State, path_q: &str) -> Response<Body> {
    let query = path_q.split_once('?').map(|(_, q)| q).unwrap_or("");
    let (mut page, mut classes, mut ids) = (String::new(), String::new(), String::new());
    for kv in query.split('&') {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k {
            "u" => page = form_decode(v),
            "c" => classes = form_decode(v),
            "i" => ids = form_decode(v),
            _ => {}
        }
    }
    let classes: Vec<&str> = classes.split_whitespace().take(500).collect();
    let ids: Vec<&str> = ids.split_whitespace().take(500).collect();
    let selectors = if st.config().filtering_active() && st.config().cosmetic {
        st.filter().generic_selectors(&page, &classes, &ids)
    } else {
        Vec::new()
    };
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(full(serde_json::to_string(&selectors).unwrap_or_else(|_| "[]".into())))
        .unwrap()
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut src = e.source();
    while let Some(s) = src {
        parts.push(s.to_string());
        src = s.source();
    }
    parts.join(": ")
}

fn is_html(h: &HeaderMap) -> bool {
    let ct = header_str(h, "content-type").to_ascii_lowercase();
    ct.starts_with("text/html") || ct.starts_with("application/xhtml")
}

/// Wraps a stream so bytes already read (the ClientHello) are replayed first.
pub struct Rewind<T> {
    prefix: Bytes,
    inner: T,
}

impl<T: AsyncRead + Unpin> AsyncRead for Rewind<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Rewind<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn run(state: Arc<State>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    log::info!("proxy listening on http://{addr}");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                log::warn!("accept failed: {e}");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let st = state.clone();
        tokio::spawn(async move {
            // Which app connected to the proxy (Windows TCP table lookup, off the async threads).
            let port = st.proxy_port;
            let app = tokio::task::spawn_blocking(move || crate::proc::app_for_client(peer, port)).await.ok().flatten();
            let svc = service_fn(move |req| {
                let st = st.clone();
                let app = app.clone();
                async move { Ok::<_, Infallible>(entry(st, req, app).await) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(TokioIo::new(stream), svc)
                .with_upgrades()
                .await
            {
                log::debug!("client connection ended: {e}");
            }
        });
    }
}

/// Listeners for connections reflected by the driver. The peer address is the original server;
/// connections that did not come through the driver (e.g. from the LAN) are refused.
pub async fn run_transparent(state: Arc<State>, https_port: u16, http_port: u16) -> anyhow::Result<()> {
    let mut listeners = Vec::new();
    for (port, tls) in [(https_port, true), (http_port, false)] {
        listeners.push((TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?, tls));
        match TcpListener::bind(SocketAddr::from(([0u16; 8], port))).await {
            Ok(l) => listeners.push((l, tls)),
            Err(e) => log::warn!("IPv6 listener on port {port} unavailable: {e}"),
        }
    }
    log::info!("transparent listeners on ports {https_port} (TLS) and {http_port} (HTTP)");
    for (listener, tls) in listeners {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else { continue };
                let from_driver = st.driver.get().is_some_and(|d| d.is_redirected(peer.is_ipv6(), peer.port()));
                if !from_driver {
                    log::debug!("refusing direct connection from {peer}");
                    continue;
                }
                let _ = stream.set_nodelay(true);
                let st = st.clone();
                let app = st.driver.get().and_then(|d| d.app_for_port(peer.port()));
                tokio::spawn(async move {
                    let ip = peer.ip().to_string();
                    if tls {
                        let orig = SocketAddr::new(peer.ip(), 443);
                        if let Err(e) = handle_connect(st, stream, ip, 443, Some(orig), app).await {
                            log::debug!("transparent TLS {orig} ended: {e:#}");
                        }
                    } else {
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let st = st.clone();
                            let ip = ip.clone();
                            let app = app.clone();
                            async move {
                                let authority = req
                                    .headers()
                                    .get(header::HOST)
                                    .and_then(|h| h.to_str().ok())
                                    .map(str::to_string)
                                    .unwrap_or_else(|| if ip.contains(':') { format!("[{ip}]") } else { ip });
                                Ok::<_, Infallible>(handle(st, req, "http", authority, app).await)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .with_upgrades()
                            .await;
                    }
                });
            }
        });
    }
    Ok(())
}

async fn entry(st: Arc<State>, req: Request<Incoming>, app: Option<Arc<str>>) -> Response<Body> {
    if req.method() == Method::CONNECT {
        let Some(auth) = req.uri().authority().cloned() else {
            return text_response(StatusCode::BAD_REQUEST, "CONNECT needs host:port");
        };
        let host = auth.host().trim_matches(['[', ']']).to_ascii_lowercase();
        let port = auth.port_u16().unwrap_or(443);
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(up) => {
                    if let Err(e) = handle_connect(st, TokioIo::new(up), host.clone(), port, None, app).await {
                        log::debug!("CONNECT {host}:{port} ended: {e:#}");
                    }
                }
                Err(e) => log::debug!("CONNECT upgrade failed: {e}"),
            }
        });
        return Response::new(empty());
    }
    if req.uri().scheme_str() == Some("http") {
        let authority = req.uri().authority().map(|a| a.to_string()).unwrap_or_default();
        return handle(st, req, "http", authority, app).await;
    }
    text_response(StatusCode::BAD_REQUEST, "This is the AdHush filtering proxy. Configure it as your HTTP/HTTPS proxy.")
}

async fn decide(st: &State, host: &str, port: u16, tls: bool, app: Option<&str>) -> (bool, &'static str) {
    let cfg = st.config();
    if !tls {
        return (false, "not-tls");
    }
    if let Some(a) = app {
        if cfg.bypass_apps.iter().any(|b| b == a) {
            return (false, "app-bypassed");
        }
        if cfg.no_https_apps.iter().any(|b| b == a) {
            return (false, "app-https-off");
        }
    }
    if !cfg.https_enabled {
        return (false, "https-filtering-off");
    }
    if !cfg.filtering_active() {
        return (false, "protection-off");
    }
    if cfg.is_excluded(host) {
        return (false, "excluded");
    }
    let auto_excluded = st.failed.lock().unwrap().get(host).is_some_and(|t| t.elapsed() < AUTO_EXCLUDE_TTL);
    if auto_excluded {
        return (false, "auto-excluded");
    }
    match probe(st, host, port).await {
        Probe::Invalid => (false, "upstream-certificate-invalid"),
        Probe::Unreachable => (false, "upstream-unreachable"),
        Probe::Valid { ev: true } if cfg.skip_ev => (false, "ev-certificate"),
        Probe::Valid { .. } => (true, "intercepted"),
    }
}

/// Connects to the real server once per host (cached) to validate its certificate and detect EV.
async fn probe(st: &State, host: &str, port: u16) -> Probe {
    let key = format!("{host}:{port}");
    let cached = st.probes.lock().unwrap().get(&key).filter(|(t, _)| t.elapsed() < PROBE_TTL).map(|(_, p)| *p);
    if let Some(p) = cached {
        return p;
    }
    let result = async {
        let Ok(Ok(tcp)) = timeout(Duration::from_secs(5), TcpStream::connect((host, port))).await else {
            return Probe::Unreachable;
        };
        let Ok(name) = ServerName::try_from(host.to_string()) else { return Probe::Unreachable };
        match timeout(Duration::from_secs(6), TlsConnector::from(st.tls_client.clone()).connect(name, SplitStream::new(tcp))).await {
            Ok(Ok(tls)) => {
                let ev = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).is_some_and(|c| {
                    c.as_ref().windows(EV_OID.len()).any(|w| w == EV_OID)
                });
                Probe::Valid { ev }
            }
            Ok(Err(e)) => {
                let invalid = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()).is_some_and(|r| {
                    matches!(r, rustls::Error::InvalidCertificate(_))
                });
                if invalid { Probe::Invalid } else { Probe::Unreachable }
            }
            Err(_) => Probe::Unreachable,
        }
    }
    .await;
    if !matches!(result, Probe::Unreachable) {
        st.probes.lock().unwrap().insert(key, (Instant::now(), result));
    }
    result
}

/// `upstream`: the original destination when the connection was redirected by the driver.
/// `app`: executable that opened the connection, when known.
async fn handle_connect<T>(
    st: Arc<State>,
    mut io: T,
    host: String,
    port: u16,
    upstream: Option<SocketAddr>,
    app: Option<Arc<str>>,
) -> anyhow::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let peek = loop {
        let n = timeout(Duration::from_secs(15), io.read(&mut tmp)).await??;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        match peek_client_hello(&buf) {
            Peek::NeedMore if buf.len() < 64 * 1024 => continue,
            p => break p,
        }
    };
    let (tls, sni) = match peek {
        Peek::Hello(s) => (true, s),
        _ => (false, None),
    };
    let name = sni.unwrap_or_else(|| host.clone());
    let (intercept, reason) = decide(&st, &name, port, tls, app.as_deref()).await;
    let mut stream = Rewind { prefix: Bytes::from(buf), inner: io };

    if !intercept {
        Stats::inc(&st.stats.tunneled);
        if reason != "not-tls" && reason != "https-filtering-off" {
            st.record(app.as_deref(), "CONNECT", &format!("{name}:{port}"), &name, "tunnel", reason, None, 0);
        }
        let mut remote = SplitStream::new(match upstream {
            Some(addr) => TcpStream::connect(addr).await?,
            None => TcpStream::connect((host.as_str(), port)).await?,
        });
        tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
        return Ok(());
    }

    let server_cfg = st.ca.server_config(&name)?;
    match TlsAcceptor::from(server_cfg).accept(stream).await {
        Ok(tls_stream) => {
            Stats::inc(&st.stats.mitm);
            let svc_state = st.clone();
            let svc_host = name.clone();
            let svc_app = app.clone();
            let svc = service_fn(move |req: Request<Incoming>| {
                let st = svc_state.clone();
                let host = svc_host.clone();
                let app = svc_app.clone();
                async move {
                    let authority = req
                        .uri()
                        .authority()
                        .map(|a| a.to_string())
                        .or_else(|| req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).map(str::to_string))
                        .unwrap_or_else(|| if port == 443 { host.clone() } else { format!("{host}:{port}") });
                    Ok::<_, Infallible>(handle(st, req, "https", authority, app).await)
                }
            });
            let mut server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            server.http2().max_header_list_size(MAX_HEADER_LIST);
            server
                .serve_connection_with_upgrades(TokioIo::new(tls_stream), svc)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        Err(e) => {
            // Typically the client does not trust our CA or pins certificates: stop intercepting this host.
            Stats::inc(&st.stats.mitm_failed);
            if st.config().auto_exclude {
                st.failed.lock().unwrap().insert(name.clone(), Instant::now());
            }
            st.record(app.as_deref(), "CONNECT", &format!("{name}:{port}"), &name, "tunnel", "interception-failed", Some(e.to_string()), 0);
        }
    }
    Ok(())
}

async fn handle(st: Arc<State>, req: Request<Incoming>, scheme: &str, authority: String, app: Option<Arc<str>>) -> Response<Body> {
    Stats::inc(&st.stats.requests);
    let Ok(auth) = authority.parse::<Authority>() else {
        return text_response(StatusCode::BAD_REQUEST, "bad authority");
    };
    let host = auth.host().trim_matches(['[', ']']).to_ascii_lowercase();
    let port = auth.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
    let path_q = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let default_port = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
    let host_port = if default_port { auth.host().to_string() } else { format!("{}:{port}", auth.host()) };
    let mut url = format!("{scheme}://{host_port}{path_q}");
    let method = req.method().clone();
    if method == Method::GET && path_q.starts_with(COSMETIC_ENDPOINT) {
        return cosmetic_endpoint(&st, &path_q);
    }
    if method == Method::POST && path_q.starts_with("/__adhush__/gm/") {
        return gm_endpoint(&st, &path_q, req).await;
    }
    if method == Method::POST && path_q.starts_with("/__adhush__/xhr/") {
        return xhr_endpoint(&st, &path_q, req).await;
    }
    let rtype = request_type(req.headers(), &path_q);
    let cfg = st.config();
    let bypassed = app.as_deref().is_some_and(|a| cfg.bypass_apps.iter().any(|b| b == a));
    let active = cfg.filtering_active() && !bypassed;
    let filter = st.filter();
    let privacy = if active { cfg.privacy.as_ref() } else { None };
    let is_frame = rtype == "document" || rtype == "subdocument";
    let mut action = "allowed";
    let mut rule = None;
    // The page that caused this request (used for third-party decisions and $domain= rules).
    let source = if rtype == "document" {
        url.clone()
    } else {
        let r = header_str(req.headers(), "referer");
        let o = header_str(req.headers(), "origin");
        if !r.is_empty() { r.to_string() } else if !o.is_empty() && o != "null" { o.to_string() } else { url.clone() }
    };
    let page_host = url_host(&source).to_ascii_lowercase();
    let third_party = rtype != "document" && is_third_party(&host, &page_host);

    if let Some(clean) = privacy.filter(|p| p.strip_tracking_params).and_then(|_| strip_tracking_params(&url)) {
        Stats::inc(&st.stats.rewritten);
        if rtype == "document" && method == Method::GET {
            st.record(app.as_deref(), method.as_str(), &url, &host, rtype, "rewritten", Some("tracking parameters".into()), 302);
            return Response::builder().status(StatusCode::FOUND).header(header::LOCATION, clean).body(empty()).unwrap();
        }
        url = clean;
        action = "rewritten";
        rule = Some("tracking parameters".into());
    }

    if active {
        match filter.check(&url, &source, rtype, method.as_str()) {
            Verdict::Block { rule, redirect } => {
                Stats::inc(&st.stats.blocked);
                let action = if redirect.is_some() { "redirected" } else { "blocked" };
                st.record(app.as_deref(), method.as_str(), &url, &host, rtype, action, rule.clone(), 403);
                return blocked_response(rtype, &url, rule.as_deref(), redirect.as_deref());
            }
            Verdict::Rewrite { url: new_url, rule: r } => {
                Stats::inc(&st.stats.rewritten);
                if rtype == "document" && method == Method::GET {
                    st.record(app.as_deref(), method.as_str(), &url, &host, rtype, "rewritten", r, 302);
                    return Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, new_url)
                        .body(empty())
                        .unwrap();
                }
                url = new_url;
                action = "rewritten";
                rule = r;
            }
            Verdict::Allow => {}
        }
    }

    // Opening a .user.js / .user.css link offers to install it in AdHush.
    if active && method == Method::GET && rtype == "document" && !path_q.contains("adhush-raw") {
        let path_only = path_q.split(['?', '#']).next().unwrap_or("");
        let us = st.userscripts();
        if us.detect_install && (path_only.ends_with(".user.js") || path_only.ends_with(".user.css")) {
            st.record(app.as_deref(), method.as_str(), &url, &host, rtype, "install-offer", None, 200);
            return install_page(&url, us.ui_port);
        }
    }

    if is_upgrade(req.headers()) {
        st.record(app.as_deref(), method.as_str(), &url, &host, rtype, "websocket", None, 101);
        return forward_upgrade(st, req, scheme, &host, port, &url).await;
    }

    let want_inject = active && is_frame && method == Method::GET && (cfg.cosmetic || privacy.is_some() || st.userscripts().count() > 0);
    let Ok(uri) = url.parse::<Uri>() else {
        return text_response(StatusCode::BAD_REQUEST, "invalid URL");
    };
    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    parts.version = Version::HTTP_11;
    strip_hop_headers(&mut parts.headers, false);
    // The absolute URI carries the authority: the client derives `Host` for HTTP/1.1 and
    // `:authority` for HTTP/2. Forwarding `host` as well makes strict HTTP/2 servers (Google)
    // reset the stream with PROTOCOL_ERROR.
    parts.headers.remove(header::HOST);
    if active && !filter.is_allowlisted(&source) {
        if let Some(p) = privacy {
            p.apply_request(&mut parts.headers, &host, third_party);
        }
        filter.extended.apply_request(&mut parts.headers, &host, &page_host);
    }
    // Body-less requests can be retried once if the upstream connection fails to establish.
    let retry = matches!(method, Method::GET | Method::HEAD).then(|| (parts.uri.clone(), parts.headers.clone()));
    let out = Request::from_parts(parts, boxed(body));

    let result = match st.client.request(out).await {
        Err(e) if e.is_connect() && retry.is_some() => {
            let (uri, headers) = retry.unwrap();
            let mut again = Request::builder().method(method.clone()).uri(uri).version(Version::HTTP_11).body(empty()).unwrap();
            *again.headers_mut() = headers;
            st.client.request(again).await
        }
        other => other,
    };
    let resp = match result {
        Ok(r) => r,
        Err(e) => {
            let detail = error_chain(&e);
            st.record(app.as_deref(), method.as_str(), &url, &host, rtype, "error", Some(detail.clone()), 502);
            return text_response(StatusCode::BAD_GATEWAY, &format!("AdHush could not reach {host}: {detail}"));
        }
    };
    let status = resp.status().as_u16();
    // Bot-protection services fingerprint our TLS handshake; let the next connection go direct.
    if rtype == "document" && cfg.auto_exclude && header_str(resp.headers(), "cf-mitigated") == "challenge" {
        st.failed.lock().unwrap().insert(host.clone(), Instant::now());
        action = "challenge-bypass";
    }
    let resp = if active && !filter.is_allowlisted(&source) {
        let (mut rp, rb) = resp.into_parts();
        if let Some(p) = privacy {
            p.apply_response(&mut rp.headers, third_party);
        }
        filter.extended.apply_response(&mut rp.headers, &host, &page_host);
        if is_frame {
            if let Some(csp) = filter.csp(&url, &source, rtype).and_then(|c| HeaderValue::from_str(&c).ok()) {
                rp.headers.append(header::CONTENT_SECURITY_POLICY, csp);
            }
        }
        Response::from_parts(rp, rb)
    } else {
        resp
    };
    let resp = if want_inject && resp.status() == StatusCode::OK && is_html(resp.headers()) {
        let (r, injected) = inject_response(&st, resp, &url, rtype == "document", cfg.cosmetic, privacy).await;
        if injected {
            action = "cosmetic";
        }
        r
    } else {
        pass(resp)
    };
    st.record(app.as_deref(), method.as_str(), &url, &host, rtype, action, rule, status);
    resp
}

/// Buffers an HTML response, injects cosmetic CSS/scriptlets/privacy scripts and patches CSP
/// for our nonce.
async fn inject_response(
    st: &State,
    resp: Response<Incoming>,
    url: &str,
    top_frame: bool,
    cosmetic: bool,
    privacy: Option<&crate::privacy::Privacy>,
) -> (Response<Body>, bool) {
    let declared = resp.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > MAX_HTML) {
        return (pass(resp), false);
    }
    let (mut parts, body) = resp.into_parts();
    strip_hop_headers(&mut parts.headers, false);
    let raw = match Limited::new(body, MAX_HTML).collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => return (text_response(StatusCode::BAD_GATEWAY, &format!("response read failed: {e}")), false),
    };
    let original = |parts| (Response::from_parts(parts, full(raw.clone())), false);
    let encoding = header_str(&parts.headers, "content-encoding").to_string();
    let Some(mut doc) = html::decode(&encoding, &raw) else { return original(parts) };
    let filter = st.filter();
    let c = if cosmetic {
        let (classes, ids) = html::harvest_classes_ids(&doc);
        filter.cosmetics(url, &classes, &ids)
    } else {
        crate::filter::Cosmetics { generichide: true, ..Default::default() }
    };
    let ext = if cosmetic && !filter.is_allowlisted(url) { filter.extended.page(url) } else { Default::default() };
    let nonce = random_nonce();
    let mut early_js: Vec<String> = Vec::new();
    if let Some(js) = privacy.map(|p| p.page_script()).filter(|js| !js.is_empty()) {
        early_js.push(js);
    }
    early_js.extend(ext.js);
    let mut css = ext.css;
    if !filter.is_allowlisted(url) {
        let us = st.userscripts();
        css.extend(us.styles_for(url));
        early_js.extend(us.scripts_for(url, top_frame, &nonce));
    }
    let snippet = html::Snippet {
        selectors: &c.selectors,
        css: &css,
        early_js: &early_js,
        scriptlets: &c.scriptlets,
        procedural: &c.procedural,
        endpoint: (!c.generichide).then_some(COSMETIC_ENDPOINT),
        nonce: &nonce,
    };
    if (c.is_empty() && snippet.endpoint.is_none() && css.is_empty() && early_js.is_empty())
        || !html::inject(&mut doc, &html::build_snippet(&snippet))
    {
        return original(parts);
    }
    let with_script = snippet.has_script();
    let csp: Vec<String> = parts
        .headers
        .get_all(header::CONTENT_SECURITY_POLICY)
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| html::patch_csp(s, &nonce, with_script)))
        .collect();
    parts.headers.remove(header::CONTENT_SECURITY_POLICY);
    for v in csp {
        if let Ok(v) = HeaderValue::from_str(&v) {
            parts.headers.append(header::CONTENT_SECURITY_POLICY, v);
        }
    }
    parts.headers.remove(header::CONTENT_ENCODING);
    parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(doc.len()));
    Stats::inc(&st.stats.injected);
    (Response::from_parts(parts, full(doc)), true)
}

async fn h1_send<I>(io: I, req: Request<Body>) -> anyhow::Result<Response<Incoming>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(sender.send_request(req).await?)
}

/// WebSocket (HTTP/1.1 Upgrade) pass-through on a dedicated upstream connection.
async fn forward_upgrade(st: Arc<State>, mut req: Request<Incoming>, scheme: &str, host: &str, port: u16, url: &str) -> Response<Body> {
    let client_upgrade = hyper::upgrade::on(&mut req);
    let path_q = url.parse::<Uri>().ok().and_then(|u| u.path_and_query().map(|p| p.to_string())).unwrap_or_else(|| "/".into());
    let mut builder = Request::builder().method(req.method().clone()).uri(path_q).version(Version::HTTP_11);
    for (k, v) in req.headers() {
        if !matches!(k.as_str(), "proxy-connection" | "proxy-authorization") {
            builder = builder.header(k, v);
        }
    }
    if !req.headers().contains_key(header::HOST) {
        builder = builder.header(header::HOST, host);
    }
    let Ok(out) = builder.body(empty()) else {
        return text_response(StatusCode::BAD_REQUEST, "bad upgrade request");
    };
    let result = async {
        let tcp = SplitStream::new(TcpStream::connect((host, port)).await?);
        if scheme == "https" {
            let mut cfg = (*st.tls_client).clone();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            let tls = TlsConnector::from(Arc::new(cfg)).connect(ServerName::try_from(host.to_string())?, tcp).await?;
            h1_send(TokioIo::new(tls), out).await
        } else {
            h1_send(TokioIo::new(tcp), out).await
        }
    }
    .await;
    match result {
        Ok(mut resp) if resp.status() == StatusCode::SWITCHING_PROTOCOLS => {
            let server_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(a), Ok(b)) = (client_upgrade.await, server_upgrade.await) {
                    let (mut a, mut b) = (TokioIo::new(a), TokioIo::new(b));
                    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                }
            });
            let mut r = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
            for (k, v) in resp.headers() {
                r = r.header(k, v);
            }
            r.body(empty()).unwrap()
        }
        Ok(resp) => pass(resp),
        Err(e) => text_response(StatusCode::BAD_GATEWAY, &format!("WebSocket upstream failed: {e:#}")),
    }
}
