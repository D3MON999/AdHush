// LRU response cache keyed by (name, type, DO bit). Served copies get the
// client's message ID and TTLs reduced by the time spent in the cache.
import { parse, ttlOffsets, RCODE } from './packet.js';

export class DnsCache {
  constructor({ size = 10000, minTtl = 0, maxTtl = 86400 } = {}) {
    this.size = size;
    this.minTtl = minTtl;
    this.maxTtl = maxTtl;
    this.map = new Map();
    this.hits = 0;
    this.misses = 0;
  }

  static key(q, dnssecOk) {
    return `${q.name}|${q.type}|${dnssecOk ? 1 : 0}`;
  }

  get(key, id) {
    const e = this.map.get(key);
    if (!e) { this.misses++; return null; }
    const now = Date.now();
    if (now >= e.expires) { this.map.delete(key); this.misses++; return null; }
    this.map.delete(key); // refresh LRU position
    this.map.set(key, e);
    this.hits++;
    const out = Buffer.from(e.buf);
    out.writeUInt16BE(id, 0);
    const elapsed = Math.floor((now - e.stored) / 1000);
    for (const off of e.offsets) out.writeUInt32BE(Math.max(0, out.readUInt32BE(off) - elapsed), off);
    return out;
  }

  set(key, buf) {
    let msg;
    try {
      msg = parse(buf);
    } catch {
      return;
    }
    if (msg.tc || (msg.rcode !== RCODE.NOERROR && msg.rcode !== RCODE.NXDOMAIN)) return;
    const offsets = ttlOffsets(msg);
    const ttls = offsets.map((o) => buf.readUInt32BE(o));
    let ttl = ttls.length ? Math.min(...ttls) : 60;
    ttl = Math.min(this.maxTtl, Math.max(this.minTtl, ttl));
    if (ttl <= 0) return;
    // Clamp stored TTLs to the cache lifetime so served answers never exceed it.
    const copy = Buffer.from(buf);
    for (const o of offsets) copy.writeUInt32BE(Math.min(copy.readUInt32BE(o), Math.max(ttl, this.minTtl)), o);
    this.map.set(key, { buf: copy, offsets, stored: Date.now(), expires: Date.now() + ttl * 1000 });
    while (this.map.size > this.size) this.map.delete(this.map.keys().next().value);
  }

  clear() {
    this.map.clear();
  }

  info() {
    return { entries: this.map.size, hits: this.hits, misses: this.misses };
  }
}
