//! Driver mode: transparent per-application interception with WinDivert.
//!
//! Outbound TCP to ports 80/443 from selected applications is *reflected* to AdHush's local
//! listeners: source and destination addresses are swapped and the destination port becomes the
//! listener port, and the packet is re-injected as inbound. The listener therefore sees the
//! original server as the peer address (so no NAT table is needed). Replies leaving the listener
//! are reflected back with the original port. Which application owns a connection is learned
//! from WinDivert's socket layer (connect events carry the process ID).
//!
//! UDP 443 (QUIC / HTTP/3) from selected applications is dropped so browsers fall back to TCP.
use std::collections::HashMap;
use std::ffi::{CString, c_void};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::state::State;

const LAYER_NETWORK: i32 = 0;
const LAYER_SOCKET: i32 = 3;
const FLAG_SNIFF: u64 = 0x1;
const FLAG_RECV_ONLY: u64 = 0x4;
const EVENT_SOCKET_CONNECT: u32 = 4;
const OUTBOUND_BIT: u32 = 1 << 17;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// WINDIVERT_ADDRESS (80 bytes): timestamp, packed flag bits, reserved, 64-byte layer data union.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    timestamp: i64,
    flags: u32,
    reserved2: u32,
    data: [u8; 64],
}

impl Address {
    fn zeroed() -> Self {
        Self { timestamp: 0, flags: 0, reserved2: 0, data: [0; 64] }
    }
    fn event(&self) -> u32 {
        (self.flags >> 8) & 0xff
    }
    fn set_outbound(&mut self, outbound: bool) {
        if outbound { self.flags |= OUTBOUND_BIT } else { self.flags &= !OUTBOUND_BIT }
    }
    // WINDIVERT_DATA_SOCKET: EndpointId u64, ParentEndpointId u64, ProcessId u32,
    // LocalAddr u32[4], RemoteAddr u32[4], LocalPort u16, RemotePort u16, Protocol u8.
    fn socket_pid(&self) -> u32 {
        u32::from_le_bytes(self.data[16..20].try_into().unwrap())
    }
    fn socket_local_port(&self) -> u16 {
        u16::from_le_bytes(self.data[52..54].try_into().unwrap())
    }
    fn socket_protocol(&self) -> u8 {
        self.data[56]
    }
}

#[link(name = "WinDivert")]
unsafe extern "C" {
    fn WinDivertOpen(filter: *const i8, layer: i32, priority: i16, flags: u64) -> *mut c_void;
    fn WinDivertRecv(h: *mut c_void, packet: *mut c_void, len: u32, recv_len: *mut u32, addr: *mut Address) -> i32;
    fn WinDivertSend(h: *mut c_void, packet: *const c_void, len: u32, send_len: *mut u32, addr: *const Address) -> i32;
    fn WinDivertClose(h: *mut c_void) -> i32;
    fn WinDivertHelperCalcChecksums(packet: *mut c_void, len: u32, addr: *mut Address, flags: u64) -> i32;
}

struct Handle(*mut c_void);
// WinDivert handles may be used from several threads concurrently.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    fn open(filter: &str, layer: i32, priority: i16, flags: u64) -> io::Result<Self> {
        let c = CString::new(filter).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let h = unsafe { WinDivertOpen(c.as_ptr(), layer, priority, flags) };
        if h.is_null() || h as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(h))
    }

    fn recv(&self, buf: &mut [u8], addr: &mut Address) -> io::Result<usize> {
        let mut n = 0u32;
        let ok = unsafe { WinDivertRecv(self.0, buf.as_mut_ptr().cast(), buf.len() as u32, &mut n, addr) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
    }

    fn send(&self, pkt: &[u8], addr: &Address) -> io::Result<()> {
        let ok = unsafe { WinDivertSend(self.0, pkt.as_ptr().cast(), pkt.len() as u32, std::ptr::null_mut(), addr) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { WinDivertClose(self.0) };
    }
}

fn checksums(pkt: &mut [u8], addr: &mut Address) {
    unsafe { WinDivertHelperCalcChecksums(pkt.as_mut_ptr().cast(), pkt.len() as u32, addr, 0) };
}

/// Explains common WinDivertOpen failures.
pub fn describe_open_error(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(5) => "driver mode needs administrator rights (run AdHush as a service / elevated)".into(),
        Some(2) => "WinDivert64.sys was not found next to WinDivert.dll".into(),
        Some(577) => "Windows refused to load the WinDivert driver (signature check failed; Secure Boot policy or antivirus)".into(),
        Some(1275) => "the WinDivert driver was blocked from loading (check Windows Security / antivirus)".into(),
        Some(1753) => "the WinDivert driver service is unavailable (another incompatible WinDivert version may be loaded)".into(),
        _ => format!("WinDivert could not start: {e}"),
    }
}

// ---------- packet parsing / rewriting (pure, unit-tested) ----------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pkt {
    pub v6: bool,
    pub proto: u8,
    pub l4: usize,
    pub src_port: u16,
    pub dst_port: u16,
    pub syn: bool,
    pub ack: bool,
}

pub fn parse(p: &[u8]) -> Option<Pkt> {
    let version = p.first()? >> 4;
    let (v6, proto, l4) = match version {
        4 => {
            let ihl = ((p[0] & 0x0f) as usize) * 4;
            (false, *p.get(9)?, ihl)
        }
        6 => (true, *p.get(6)?, 40), // extension headers are not used on these flows
        _ => return None,
    };
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return None;
    }
    let ports = p.get(l4..l4 + 4)?;
    let src_port = u16::from_be_bytes([ports[0], ports[1]]);
    let dst_port = u16::from_be_bytes([ports[2], ports[3]]);
    let (syn, ack) = if proto == PROTO_TCP {
        let flags = *p.get(l4 + 13)?;
        (flags & 0x02 != 0, flags & 0x10 != 0)
    } else {
        (false, false)
    };
    Some(Pkt { v6, proto, l4, src_port, dst_port, syn, ack })
}

/// Swaps source and destination addresses and optionally replaces the ports.
pub fn reflect(p: &mut [u8], k: &Pkt, src_port: Option<u16>, dst_port: Option<u16>) {
    let (src, dst, len) = if k.v6 { (8, 24, 16) } else { (12, 16, 4) };
    for i in 0..len {
        p.swap(src + i, dst + i);
    }
    if let Some(sp) = src_port {
        p[k.l4..k.l4 + 2].copy_from_slice(&sp.to_be_bytes());
    }
    if let Some(dp) = dst_port {
        p[k.l4 + 2..k.l4 + 4].copy_from_slice(&dp.to_be_bytes());
    }
}

#[derive(Default)]
pub struct DriverStats {
    pub redirected: AtomicU64,
    pub quic_dropped: AtomicU64,
    pub passed: AtomicU64,
}

pub struct Shared {
    pub https_port: u16,
    pub http_port: u16,
    exclude_pids: Vec<u32>,
    /// (protocol, local port) → (pid, seen)
    owners: Mutex<HashMap<(u8, u16), (u32, Instant)>>,
    /// (ipv6, client port) → last activity, for connections being reflected to us
    redirected: Mutex<HashMap<(bool, u16), Instant>>,
    pub stats: DriverStats,
}

impl Shared {
    fn owner(&self, proto: u8, port: u16) -> Option<u32> {
        self.owners.lock().unwrap().get(&(proto, port)).map(|(pid, _)| *pid)
    }

    /// Executable that owns a redirected TCP connection (by its client port).
    pub fn app_for_port(&self, port: u16) -> Option<std::sync::Arc<str>> {
        self.owner(PROTO_TCP, port).and_then(crate::proc::exe_name)
    }

    fn app_selected(&self, st: &State, pid: u32) -> bool {
        if pid == 0 || pid == 4 || pid == std::process::id() || self.exclude_pids.contains(&pid) {
            return false;
        }
        let Some(name) = crate::proc::exe_name(pid) else { return false };
        let cfg = st.config();
        if cfg.driver_excluded.iter().any(|e| **e == *name) || cfg.bypass_apps.iter().any(|e| **e == *name) {
            return false;
        }
        cfg.driver_all_apps || cfg.driver_apps.iter().any(|a| **a == *name)
    }

    /// True when a connection from this client port is being reflected to our listeners
    /// (used by the listeners to refuse anything that did not come through the driver).
    pub fn is_redirected(&self, v6: bool, client_port: u16) -> bool {
        self.redirected.lock().unwrap().contains_key(&(v6, client_port))
    }

    pub fn active_connections(&self) -> usize {
        self.redirected.lock().unwrap().len()
    }

    fn cleanup(&self) {
        self.owners.lock().unwrap().retain(|_, (_, t)| t.elapsed() < Duration::from_secs(120));
        self.redirected.lock().unwrap().retain(|_, t| t.elapsed() < Duration::from_secs(600));
    }
}

struct Pending {
    pkt: Vec<u8>,
    addr: Address,
    k: Pkt,
    since: Instant,
}

/// Opens both WinDivert handles and starts the worker threads.
pub fn start(state: Arc<State>, https_port: u16, http_port: u16, exclude_pids: Vec<u32>) -> Result<Arc<Shared>, String> {
    let net_filter = format!(
        "outbound and !loopback and ((tcp and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == {https_port} or tcp.SrcPort == {http_port})) or (udp and udp.DstPort == 443))"
    );
    let sock_filter = "!loopback and event == CONNECT and (tcp or udp) and (remotePort == 80 or remotePort == 443)";
    let sock = Handle::open(sock_filter, LAYER_SOCKET, 1, FLAG_SNIFF | FLAG_RECV_ONLY).map_err(|e| describe_open_error(&e))?;
    let net = Arc::new(Handle::open(&net_filter, LAYER_NETWORK, 0, 0).map_err(|e| describe_open_error(&e))?);

    let shared = Arc::new(Shared {
        https_port,
        http_port,
        exclude_pids,
        owners: Mutex::new(HashMap::new()),
        redirected: Mutex::new(HashMap::new()),
        stats: DriverStats::default(),
    });

    // Socket monitor: learns which process owns each outgoing connection.
    let sh = shared.clone();
    std::thread::Builder::new().name("divert-socket".into()).spawn(move || {
        let mut addr = Address::zeroed();
        let mut last_cleanup = Instant::now();
        loop {
            match sock.recv(&mut [], &mut addr) {
                Ok(_) if addr.event() == EVENT_SOCKET_CONNECT => {
                    sh.owners.lock().unwrap().insert((addr.socket_protocol(), addr.socket_local_port()), (addr.socket_pid(), Instant::now()));
                }
                Ok(_) => {}
                Err(e) => {
                    log::error!("socket monitor stopped: {e}");
                    return;
                }
            }
            if last_cleanup.elapsed() > Duration::from_secs(30) {
                sh.cleanup();
                last_cleanup = Instant::now();
            }
        }
    }).map_err(|e| e.to_string())?;

    // New connections whose owner is not known yet wait briefly for the socket event.
    let (pending_tx, pending_rx) = mpsc::channel::<Pending>();
    let (sh, net_d, st_d) = (shared.clone(), net.clone(), state.clone());
    std::thread::Builder::new().name("divert-pending".into()).spawn(move || {
        let mut queue: Vec<Pending> = Vec::new();
        loop {
            if queue.is_empty() {
                match pending_rx.recv() {
                    Ok(p) => queue.push(p),
                    Err(_) => return,
                }
            }
            while let Ok(p) = pending_rx.try_recv() {
                queue.push(p);
            }
            queue.retain_mut(|p| {
                let owner = sh.owner(PROTO_TCP, p.k.src_port);
                if owner.is_none() && p.since.elapsed() < Duration::from_millis(80) {
                    return true; // keep waiting
                }
                let redirect = owner.is_some_and(|pid| sh.app_selected(&st_d, pid));
                forward_new_connection(&sh, &net_d, &mut p.pkt, &mut p.addr, &p.k, redirect);
                false
            });
            if !queue.is_empty() {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }).map_err(|e| e.to_string())?;

    // Packet loop.
    let sh = shared.clone();
    std::thread::Builder::new().name("divert-network".into()).spawn(move || {
        let mut buf = vec![0u8; 0xFFFF + 64];
        let mut addr = Address::zeroed();
        loop {
            let n = match net.recv(&mut buf, &mut addr) {
                Ok(n) => n,
                Err(e) => {
                    log::error!("packet loop stopped: {e}");
                    return;
                }
            };
            let pkt = &mut buf[..n];
            let Some(k) = parse(pkt) else {
                let _ = net.send(pkt, &addr);
                continue;
            };
            if k.proto == PROTO_UDP {
                let cfg = state.config();
                if cfg.block_quic && sh.owner(PROTO_UDP, k.src_port).is_some_and(|pid| sh.app_selected(&state, pid)) {
                    sh.stats.quic_dropped.fetch_add(1, Ordering::Relaxed);
                    continue; // drop: the browser falls back to TCP
                }
                let _ = net.send(pkt, &addr);
                continue;
            }
            if k.src_port == sh.https_port || k.src_port == sh.http_port {
                // Reply from our listener → back to the application, as if from the server.
                let orig = if k.src_port == sh.https_port { 443 } else { 80 };
                reflect(pkt, &k, Some(orig), None);
                addr.set_outbound(false);
                checksums(pkt, &mut addr);
                let _ = net.send(pkt, &addr);
                continue;
            }
            if k.syn && !k.ack {
                match sh.owner(PROTO_TCP, k.src_port) {
                    Some(pid) => {
                        let redirect = sh.app_selected(&state, pid);
                        forward_new_connection(&sh, &net, pkt, &mut addr, &k, redirect);
                    }
                    None => {
                        let _ = pending_tx.send(Pending { pkt: pkt.to_vec(), addr, k, since: Instant::now() });
                    }
                }
                continue;
            }
            let key = (k.v6, k.src_port);
            let redirected = {
                let mut r = sh.redirected.lock().unwrap();
                match r.get_mut(&key) {
                    Some(t) => {
                        *t = Instant::now();
                        true
                    }
                    None => false,
                }
            };
            if redirected {
                let port = if k.dst_port == 443 { sh.https_port } else { sh.http_port };
                reflect(pkt, &k, None, Some(port));
                addr.set_outbound(false);
                checksums(pkt, &mut addr);
            }
            let _ = net.send(pkt, &addr);
        }
    }).map_err(|e| e.to_string())?;

    log::info!("driver mode active: reflecting selected apps' TCP 80/443 to ports {http_port}/{https_port}");
    Ok(shared)
}

fn forward_new_connection(sh: &Shared, net: &Handle, pkt: &mut [u8], addr: &mut Address, k: &Pkt, redirect: bool) {
    let key = (k.v6, k.src_port);
    if redirect {
        sh.redirected.lock().unwrap().insert(key, Instant::now());
        sh.stats.redirected.fetch_add(1, Ordering::Relaxed);
        let port = if k.dst_port == 443 { sh.https_port } else { sh.http_port };
        reflect(pkt, k, None, Some(port));
        addr.set_outbound(false);
        checksums(pkt, addr);
    } else {
        sh.redirected.lock().unwrap().remove(&key);
        sh.stats.passed.fetch_add(1, Ordering::Relaxed);
    }
    let _ = net.send(pkt, addr);
}

/// Allows reflected (inbound-looking) connections to reach adhush-core through Windows Firewall.
pub fn ensure_firewall_rule() {
    const NAME: &str = "AdHush transparent proxy";
    let exists = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", &format!("name={NAME}")])
        .output()
        .is_ok_and(|o| o.status.success());
    if exists {
        return;
    }
    let Ok(exe) = std::env::current_exe() else { return };
    let out = std::process::Command::new("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule", &format!("name={NAME}"), "dir=in", "action=allow",
            &format!("program={}", exe.display()), "protocol=TCP", "enable=yes", "profile=any",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => log::info!("added Windows Firewall rule '{NAME}'"),
        Ok(o) => log::warn!("could not add firewall rule: {}", String::from_utf8_lossy(&o.stdout).trim()),
        Err(e) => log::warn!("could not run netsh: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 128;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 0x50;
        p[33] = flags;
        p
    }

    #[test]
    fn address_layout_matches_windivert() {
        assert_eq!(std::mem::size_of::<Address>(), 80);
    }

    #[test]
    fn parse_tcp_syn() {
        let p = ipv4_tcp([192, 168, 1, 5], [93, 184, 216, 34], 50000, 443, 0x02);
        let k = parse(&p).unwrap();
        assert_eq!((k.v6, k.proto, k.l4, k.src_port, k.dst_port, k.syn, k.ack), (false, 6, 20, 50000, 443, true, false));
    }

    #[test]
    fn reflect_to_listener_and_back() {
        // app → server:443 becomes server → app:18443 (inbound to our listener)
        let mut p = ipv4_tcp([192, 168, 1, 5], [93, 184, 216, 34], 50000, 443, 0x02);
        let k = parse(&p).unwrap();
        reflect(&mut p, &k, None, Some(18443));
        let r = parse(&p).unwrap();
        assert_eq!(&p[12..16], &[93, 184, 216, 34]);
        assert_eq!(&p[16..20], &[192, 168, 1, 5]);
        assert_eq!((r.src_port, r.dst_port), (50000, 18443));

        // listener reply (app-ip:18443 → server-ip:50000) becomes server:443 → app:50000
        let mut reply = ipv4_tcp([192, 168, 1, 5], [93, 184, 216, 34], 18443, 50000, 0x12);
        let k = parse(&reply).unwrap();
        reflect(&mut reply, &k, Some(443), None);
        let r = parse(&reply).unwrap();
        assert_eq!(&reply[12..16], &[93, 184, 216, 34]);
        assert_eq!(&reply[16..20], &[192, 168, 1, 5]);
        assert_eq!((r.src_port, r.dst_port, r.syn, r.ack), (443, 50000, true, true));
    }

    #[test]
    fn ipv6_reflect_swaps_addresses() {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[6] = PROTO_TCP;
        p[8..24].copy_from_slice(&[1; 16]);
        p[24..40].copy_from_slice(&[2; 16]);
        p[40..42].copy_from_slice(&40000u16.to_be_bytes());
        p[42..44].copy_from_slice(&80u16.to_be_bytes());
        let k = parse(&p).unwrap();
        assert!(k.v6);
        reflect(&mut p, &k, None, Some(18480));
        assert_eq!(&p[8..24], &[2; 16]);
        assert_eq!(&p[24..40], &[1; 16]);
        assert_eq!(parse(&p).unwrap().dst_port, 18480);
    }
}
