//! Process attribution: which application owns a TCP connection (via the Windows TCP table) and
//! its executable name.
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetExtendedTcpTable(table: *mut c_void, size: *mut u32, order: i32, af: u32, class: i32, reserved: u32) -> u32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn QueryFullProcessImageNameW(h: *mut c_void, flags: u32, buf: *mut u16, size: *mut u32) -> i32;
    fn CloseHandle(h: *mut c_void) -> i32;
}

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const TCP_TABLE_OWNER_PID_CONNECTIONS: i32 = 4;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

fn tcp_table(af: u32) -> Option<Vec<u8>> {
    let mut size = 0u32;
    unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, af, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) };
    for _ in 0..3 {
        let mut buf = vec![0u8; size as usize + 4096];
        size = buf.len() as u32;
        match unsafe { GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut size, 0, af, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) } {
            0 => return Some(buf),
            ERROR_INSUFFICIENT_BUFFER => continue,
            _ => return None,
        }
    }
    None
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// Ports are stored in network byte order in the low 16 bits.
fn port_at(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

/// PID of the process whose connection uses local port `client_port` towards `server_port`.
pub fn pid_for_connection(client: SocketAddr, server_port: u16) -> Option<u32> {
    let (af, row_size, local_port_off, remote_port_off, pid_off) =
        if client.is_ipv6() { (AF_INET6, 56, 20, 44, 52) } else { (AF_INET, 24, 8, 16, 20) };
    let t = tcp_table(af)?;
    let n = u32_at(&t, 0) as usize;
    (0..n).map(|i| 4 + i * row_size).filter(|o| o + row_size <= t.len()).find_map(|o| {
        let row = &t[o..o + row_size];
        (port_at(row, local_port_off) == client.port() && port_at(row, remote_port_off) == server_port).then(|| u32_at(row, pid_off))
    })
}

fn query_exe(pid: u32) -> Option<String> {
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..size as usize]);
        Some(path.rsplit('\\').next().unwrap_or(&path).to_ascii_lowercase())
    }
}

/// Lower-case executable file name for a PID, cached for a minute (PIDs get reused).
pub fn exe_name(pid: u32) -> Option<Arc<str>> {
    static CACHE: OnceLock<Mutex<HashMap<u32, (Option<Arc<str>>, Instant)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some((name, t)) = cache.lock().unwrap().get(&pid) {
        if t.elapsed() < Duration::from_secs(60) {
            return name.clone();
        }
    }
    let name: Option<Arc<str>> = query_exe(pid).map(Into::into);
    let mut c = cache.lock().unwrap();
    if c.len() > 4096 {
        c.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(60));
    }
    c.insert(pid, (name.clone(), Instant::now()));
    name
}

/// The application behind a connection made to our proxy listener.
pub fn app_for_client(client: SocketAddr, server_port: u16) -> Option<Arc<str>> {
    if !client.ip().is_loopback() {
        return None;
    }
    pid_for_connection(client, server_port).and_then(exe_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_own_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let client = std::net::TcpStream::connect(("127.0.0.1", server_port)).unwrap();
        let (_server_side, peer) = listener.accept().unwrap();
        assert_eq!(peer, client.local_addr().unwrap());
        assert_eq!(pid_for_connection(peer, server_port), Some(std::process::id()));
        let me = app_for_client(peer, server_port).unwrap();
        assert!(me.ends_with(".exe"), "{me}");
    }
}
