// DNS stamps (sdns://), https://dnscrypt.info/stamps-specifications
// Supported protocols: plain DNS (0x00), DoH (0x02), DoT (0x03). DNSCrypt (0x01) and DoQ (0x04) are not.

function readLp(buf, pos) {
  const len = buf[pos];
  return { value: buf.subarray(pos + 1, pos + 1 + len), next: pos + 1 + len };
}

// Variable-length set of hashes: high bit of the length byte means "more follow".
function skipVlp(buf, pos) {
  for (;;) {
    const len = buf[pos];
    pos += 1 + (len & 0x7f);
    if (!(len & 0x80)) return pos;
  }
}

function splitHostPort(s, defaultPort) {
  if (!s) return { host: '', port: defaultPort };
  const m = s.match(/^\[([^\]]+)\](?::(\d+))?$/) || s.match(/^([^:]+)(?::(\d+))?$/);
  if (!m) return { host: s, port: defaultPort };
  return { host: m[1], port: m[2] ? Number(m[2]) : defaultPort };
}

export function decodeStamp(stamp) {
  if (!stamp.startsWith('sdns://')) throw new Error('not a DNS stamp');
  const buf = Buffer.from(stamp.slice(7), 'base64url');
  const proto = buf[0];
  let pos = 9; // protocol byte + 8 bytes of properties
  const addr = readLp(buf, pos);
  pos = addr.next;
  const addrStr = addr.value.toString();
  if (proto === 0x00) {
    const { host, port } = splitHostPort(addrStr, 53);
    return { url: `udp://${host.includes(':') ? `[${host}]` : host}:${port}`, ip: null };
  }
  if (proto === 0x02 || proto === 0x03) {
    pos = skipVlp(buf, pos);
    const hostname = readLp(buf, pos);
    pos = hostname.next;
    const { host, port } = splitHostPort(hostname.value.toString(), proto === 0x02 ? 443 : 853);
    const ip = splitHostPort(addrStr, port).host;
    if (proto === 0x02) {
      const path = readLp(buf, pos).value.toString() || '/dns-query';
      return { url: `https://${host}:${port}${path}`, ip: ip || null };
    }
    return { url: `tls://${host}:${port}`, ip: ip || null };
  }
  throw new Error(`unsupported stamp protocol 0x${proto.toString(16)}`);
}
