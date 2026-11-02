//! Minimal TLS ClientHello parser: tells whether a stream starts with TLS and extracts SNI.

#[derive(Debug, PartialEq)]
pub enum Peek {
    NeedMore,
    NotTls,
    Hello(Option<String>),
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|b| b[0] as usize)
    }
    fn u16(&mut self) -> Option<usize> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
    }
}

fn server_name(hello: &[u8]) -> Option<String> {
    let mut c = Cursor { buf: hello, pos: 0 };
    if c.u8()? != 1 {
        return None; // not a ClientHello
    }
    c.take(3)?; // handshake length
    c.take(2 + 32)?; // version + random
    let sid = c.u8()?;
    c.take(sid)?;
    let suites = c.u16()?;
    c.take(suites)?;
    let comp = c.u8()?;
    c.take(comp)?;
    let ext_total = c.u16()?;
    let end = (c.pos + ext_total).min(hello.len());
    while c.pos + 4 <= end {
        let ty = c.u16()?;
        let len = c.u16()?;
        let data = c.take(len)?;
        if ty == 0 {
            let mut e = Cursor { buf: data, pos: 0 };
            e.u16()?; // list length
            if e.u8()? != 0 {
                return None;
            }
            let n = e.u16()?;
            let name = std::str::from_utf8(e.take(n)?).ok()?;
            return Some(name.trim_end_matches('.').to_ascii_lowercase());
        }
    }
    None
}

pub fn peek_client_hello(buf: &[u8]) -> Peek {
    if buf.is_empty() {
        return Peek::NeedMore;
    }
    if buf[0] != 0x16 {
        return Peek::NotTls;
    }
    if buf.len() < 5 {
        return Peek::NeedMore;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + rec_len {
        return Peek::NeedMore;
    }
    Peek::Hello(server_name(&buf[5..5 + rec_len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_with_sni(name: &str) -> Vec<u8> {
        let mut sni = vec![0u8];
        sni.extend((name.len() as u16).to_be_bytes());
        sni.extend(name.as_bytes());
        let mut sni_ext = ((sni.len()) as u16).to_be_bytes().to_vec();
        sni_ext.extend(sni);
        let mut exts = vec![0, 0];
        exts.extend((sni_ext.len() as u16).to_be_bytes());
        exts.extend(sni_ext);
        let mut body = vec![3, 3];
        body.extend([0u8; 32]);
        body.push(0); // session id
        body.extend([0, 2, 0x13, 0x01]); // one cipher suite
        body.extend([1, 0]); // compression
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let mut hs = vec![1];
        hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend(body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    #[test]
    fn extracts_sni() {
        let rec = hello_with_sni("Example.COM");
        assert_eq!(peek_client_hello(&rec), Peek::Hello(Some("example.com".into())));
        assert_eq!(peek_client_hello(&rec[..10]), Peek::NeedMore);
        assert_eq!(peek_client_hello(b"GET / HTTP/1.1"), Peek::NotTls);
    }
}
