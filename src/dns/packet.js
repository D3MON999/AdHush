// Minimal DNS wire-format codec (RFC 1035): enough to inspect queries/responses,
// rewrite IDs and TTLs, and synthesize blocked or rewritten answers.
import net from 'node:net';

export const TYPE = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, OPT: 41, SVCB: 64, HTTPS: 65 };
export const RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };
export const RCODE_NAMES = Object.fromEntries(Object.entries(RCODE).map(([k, v]) => [v, k]));

function readName(buf, offset) {
  const labels = [];
  let pos = offset;
  let end = -1;
  for (let jumps = 0; ;) {
    if (pos >= buf.length) throw new Error('name out of bounds');
    const len = buf[pos];
    if (len === 0) { pos += 1; break; }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw new Error('bad pointer');
      if (end < 0) end = pos + 2;
      pos = ((len & 0x3f) << 8) | buf[pos + 1];
      if (++jumps > 64) throw new Error('compression loop');
      continue;
    }
    if (len > 63) throw new Error('bad label');
    labels.push(buf.toString('latin1', pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  return { name: labels.join('.').toLowerCase(), next: end >= 0 ? end : pos };
}

export function encodeName(name) {
  const parts = name.replace(/\.$/, '').split('.').filter(Boolean);
  const bufs = parts.map((p) => Buffer.concat([Buffer.from([p.length]), Buffer.from(p, 'latin1')]));
  return Buffer.concat([...bufs, Buffer.from([0])]);
}

function readRecords(buf, pos, count, out) {
  for (let i = 0; i < count; i++) {
    const { name, next } = readName(buf, pos);
    if (next + 10 > buf.length) throw new Error('record header out of bounds');
    const type = buf.readUInt16BE(next);
    const klass = buf.readUInt16BE(next + 2);
    const ttlOffset = next + 4;
    const ttl = buf.readUInt32BE(ttlOffset);
    const rdLength = buf.readUInt16BE(next + 8);
    const rdOffset = next + 10;
    if (rdOffset + rdLength > buf.length) throw new Error('rdata out of bounds');
    const rec = { name, type, class: klass, ttl, ttlOffset, rdOffset, rdLength };
    if (type === TYPE.A && rdLength === 4) rec.data = Array.from(buf.subarray(rdOffset, rdOffset + 4)).join('.');
    else if (type === TYPE.AAAA && rdLength === 16) rec.data = ipv6ToString(buf.subarray(rdOffset, rdOffset + 16));
    else if (type === TYPE.CNAME) rec.data = readName(buf, rdOffset).name;
    out.push(rec);
    pos = rdOffset + rdLength;
  }
  return pos;
}

function ipv6ToString(b) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(b.readUInt16BE(i));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (bestLen < 2) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

function ipv6ToBuffer(ip) {
  const [head, tail] = ip.includes('::') ? ip.split('::') : [ip, null];
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const fill = tail === null ? [] : new Array(8 - h.length - t.length).fill('0');
  const groups = [...h, ...fill, ...t];
  const buf = Buffer.alloc(16);
  groups.forEach((g, i) => buf.writeUInt16BE(parseInt(g || '0', 16), i * 2));
  return buf;
}

export function parse(buf) {
  if (buf.length < 12) throw new Error('packet too short');
  const flags = buf.readUInt16BE(2);
  const msg = {
    id: buf.readUInt16BE(0),
    flags,
    qr: !!(flags & 0x8000),
    opcode: (flags >> 11) & 0xf,
    tc: !!(flags & 0x0200),
    rd: !!(flags & 0x0100),
    rcode: flags & 0xf,
    qdcount: buf.readUInt16BE(4),
    questions: [],
    answers: [],
    authority: [],
    additional: [],
  };
  let pos = 12;
  for (let i = 0; i < msg.qdcount; i++) {
    const { name, next } = readName(buf, pos);
    if (next + 4 > buf.length) throw new Error('question out of bounds');
    msg.questions.push({ name, type: buf.readUInt16BE(next), class: buf.readUInt16BE(next + 2) });
    pos = next + 4;
  }
  msg.questionEnd = pos;
  pos = readRecords(buf, pos, buf.readUInt16BE(6), msg.answers);
  pos = readRecords(buf, pos, buf.readUInt16BE(8), msg.authority);
  readRecords(buf, pos, buf.readUInt16BE(10), msg.additional);
  const opt = msg.additional.find((r) => r.type === TYPE.OPT);
  msg.edns = opt ? { udpSize: Math.max(512, opt.class), do: !!(opt.ttl & 0x8000) } : null;
  return msg;
}

// Offsets of every TTL in the message (OPT pseudo-records excluded).
export function ttlOffsets(msg) {
  return [...msg.answers, ...msg.authority, ...msg.additional].filter((r) => r.type !== TYPE.OPT).map((r) => r.ttlOffset);
}

export function withId(buf, id) {
  const copy = Buffer.from(buf);
  copy.writeUInt16BE(id, 0);
  return copy;
}

function rdataFor(rec) {
  if (rec.type === 'A') return { type: TYPE.A, data: Buffer.from(rec.value.split('.').map(Number)) };
  if (rec.type === 'AAAA') return { type: TYPE.AAAA, data: ipv6ToBuffer(rec.value) };
  if (rec.type === 'CNAME') return { type: TYPE.CNAME, data: encodeName(rec.value) };
  throw new Error(`unsupported record type ${rec.type}`);
}

// Builds a response to `queryBuf`. records: [{ type: 'A'|'AAAA'|'CNAME', value, name? , ttl }]
// Records without a name answer the question name (compressed pointer to offset 12).
export function buildResponse(queryBuf, query, { rcode = RCODE.NOERROR, records = [], ttl = 10 } = {}) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(query.id, 0);
  const flags = 0x8000 | (query.opcode << 11) | (query.rd ? 0x0100 : 0) | 0x0080 | (rcode & 0xf);
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(records.length, 6);
  const question = queryBuf.subarray(12, query.questionEnd);
  const answers = records.map((rec) => {
    const { type, data } = rdataFor(rec);
    const name = rec.name ? encodeName(rec.name) : Buffer.from([0xc0, 0x0c]);
    const fixed = Buffer.alloc(10);
    fixed.writeUInt16BE(type, 0);
    fixed.writeUInt16BE(1, 2);
    fixed.writeUInt32BE(rec.ttl ?? ttl, 4);
    fixed.writeUInt16BE(data.length, 8);
    return Buffer.concat([name, fixed, data]);
  });
  return Buffer.concat([header, question, ...answers]);
}

// Header + question only, TC bit set: tells a UDP client to retry over TCP.
export function truncate(responseBuf, msg) {
  const out = Buffer.from(responseBuf.subarray(0, msg.questionEnd));
  out.writeUInt16BE(out.readUInt16BE(2) | 0x0200, 2);
  out.writeUInt16BE(0, 6);
  out.writeUInt16BE(0, 8);
  out.writeUInt16BE(0, 10);
  return out;
}

export function buildQuery(name, type, id = Math.floor(Math.random() * 0xffff)) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2); // RD
  header.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(type, 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([header, encodeName(name), tail]);
}

export function summarizeAnswers(msg) {
  return msg.answers
    .filter((r) => r.data !== undefined)
    .map((r) => (r.type === TYPE.CNAME ? `CNAME ${r.data}` : r.data));
}

export function isIp(s) {
  return net.isIP(s) !== 0;
}
