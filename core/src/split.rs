//! Anti-DPI: splits the first write on an outbound connection (the TLS ClientHello or the HTTP
//! request line + Host header) into two TCP segments, so middleboxes that look for the server
//! name in a single packet do not see it. Settings are process-wide and hot-reloadable.
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Size of the first TLS fragment in bytes; 0 disables splitting.
static TLS_SPLIT: AtomicUsize = AtomicUsize::new(0);
static HTTP_SPLIT: AtomicBool = AtomicBool::new(false);

pub fn configure(enabled: bool, tls_fragment: usize, http: bool) {
    TLS_SPLIT.store(if enabled { tls_fragment.max(1) } else { 0 }, Ordering::Relaxed);
    HTTP_SPLIT.store(enabled && http, Ordering::Relaxed);
}

/// Where to cut the first write, if anywhere.
fn split_point(first: &[u8]) -> Option<usize> {
    if first.first() == Some(&0x16) {
        let n = TLS_SPLIT.load(Ordering::Relaxed);
        return (n > 0 && first.len() > n).then_some(n);
    }
    if HTTP_SPLIT.load(Ordering::Relaxed) {
        // Cut inside the "Host" header name so the hostname is never in the first segment.
        let pos = first.windows(6).position(|w| w.eq_ignore_ascii_case(b"\nhost:"));
        return Some(pos.map(|p| p + 3).unwrap_or(4)).filter(|n| *n < first.len());
    }
    None
}

pub struct SplitStream {
    inner: TcpStream,
    first_done: bool,
}

impl SplitStream {
    pub fn new(inner: TcpStream) -> Self {
        let _ = inner.set_nodelay(true); // each write leaves as its own segment
        Self { inner, first_done: false }
    }
}

impl AsyncRead for SplitStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SplitStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if !self.first_done {
            self.first_done = true;
            if let Some(n) = split_point(buf) {
                // Write only the head now; the caller writes the rest in a following call.
                return Pin::new(&mut self.inner).poll_write(cx, &buf[..n]);
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connection for SplitStream {
    fn connected(&self) -> Connected {
        self.inner.connected()
    }
}

/// HTTP connector for the upstream client that wraps every socket in a [`SplitStream`].
#[derive(Clone)]
pub struct SplitConnector {
    inner: HttpConnector,
}

impl SplitConnector {
    pub fn new() -> Self {
        let mut inner = HttpConnector::new();
        inner.enforce_http(false); // TLS is layered on top by hyper-rustls
        inner.set_nodelay(true);
        Self { inner }
    }
}

impl tower_service::Service<Uri> for SplitConnector {
    type Response = TokioIo<SplitStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let fut = self.inner.call(uri);
        Box::pin(async move {
            let io = fut.await?;
            Ok(TokioIo::new(SplitStream::new(io.into_inner())))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_points() {
        configure(true, 2, true);
        assert_eq!(split_point(&[0x16, 3, 1, 0, 200, 1]), Some(2));
        let req = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
        let n = split_point(req).unwrap();
        assert!(!String::from_utf8_lossy(&req[..n]).contains("blocked"));
        configure(false, 2, true);
        assert_eq!(split_point(&[0x16, 3, 1, 0, 200, 1]), None);
        assert_eq!(split_point(req), None);
    }
}
