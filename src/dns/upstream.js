// Upstream DNS transports: plain UDP/TCP, DNS-over-TLS (RFC 7858), DNS-over-HTTPS (RFC 8484).
// Encrypted upstreams given by hostname are resolved through plain "bootstrap" servers so
// the resolver never depends on the system resolver (which may point back at us).
import dgram from 'node:dgram';
import net from 'node:net';
import tls from 'node:tls';
import http2 from 'node:http2';
import { parse, buildQuery, withId, TYPE } from './packet.js';
import { decodeStamp } from './stamp.js';
import { logger } from '../log.js';

const log = logger('upstream');

export function parseUpstream(spec) {
  let s = String(spec).trim();
  let ip = null;
  if (s.startsWith('sdns://')) ({ url: s, ip } = decodeStamp(s));
  if (/^quic:\/\//i.test(s)) throw new Error('DNS-over-QUIC upstreams are not supported yet');
  if (/^h3:\/\//i.test(s)) throw new Error('DNS-over-HTTP/3 upstreams are not supported yet');
  if (/^https:\/\//i.test(s)) {
    const u = new URL(s);
    return { proto: 'https', host: u.hostname.replace(/^\[|\]$/g, ''), port: Number(u.port) || 443, path: (u.pathname || '/dns-query') + u.search, ip, spec };
  }
  let proto = 'udp';
  let rest = s;
  const m = s.match(/^(udp|tcp|tls):\/\/(.+)$/i);
  if (m) { proto = m[1].toLowerCase(); rest = m[2].replace(/\/$/, ''); }
  let host;
  let port;
  if (net.isIPv6(rest)) host = rest;
  else {
    const hp = rest.match(/^\[([^\]]+)\](?::(\d+))?$/) || rest.match(/^([^:/[\]]+)(?::(\d+))?$/);
    if (!hp) throw new Error(`invalid upstream "${spec}"`);
    host = hp[1];
    port = hp[2] ? Number(hp[2]) : undefined;
  }
  return { proto, host, port: port ?? (proto === 'tls' ? 853 : 53), path: null, ip, spec };
}

function timeoutError(what, ms) {
  const e = new Error(`${what} timed out after ${ms} ms`);
  e.code = 'ETIMEDOUT';
  return e;
}

export function udpExchange(ip, port, query, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket(net.isIPv6(ip) ? 'udp6' : 'udp4');
    const id = query.readUInt16BE(0);
    const timer = setTimeout(() => { sock.close(); reject(timeoutError(`udp ${ip}`, timeoutMs)); }, timeoutMs);
    sock.on('error', (e) => { clearTimeout(timer); sock.close(); reject(e); });
    sock.on('message', (msg) => {
      if (msg.length < 12 || msg.readUInt16BE(0) !== id) return; // ignore stray packets
      clearTimeout(timer);
      sock.close();
      resolve(msg);
    });
    sock.send(query, port, ip);
  });
}

function frame(query) {
  const len = Buffer.alloc(2);
  len.writeUInt16BE(query.length);
  return Buffer.concat([len, query]);
}

export function tcpExchange(ip, port, query, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const sock = net.connect({ host: ip, port });
    const done = (err, res) => { clearTimeout(timer); sock.destroy(); err ? reject(err) : resolve(res); };
    const timer = setTimeout(() => done(timeoutError(`tcp ${ip}`, timeoutMs)), timeoutMs);
    sock.on('error', (e) => done(e));
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) done(null, buf.subarray(2, 2 + buf.readUInt16BE(0)));
    });
    sock.on('end', () => done(new Error('tcp connection closed before response')));
    sock.write(frame(query));
  });
}

// One long-lived TLS connection, queries multiplexed by message ID.
class DotConnection {
  constructor(ip, port, servername) {
    Object.assign(this, { ip, port, servername });
    this.socket = null;
    this.pending = new Map();
    this.nextId = Math.floor(Math.random() * 0xffff);
    this.buf = Buffer.alloc(0);
    this.idleTimer = null;
  }

  ensure() {
    if (this.socket) return this.socket;
    const s = tls.connect({ host: this.ip, port: this.port, servername: net.isIP(this.servername) ? undefined : this.servername });
    this.buf = Buffer.alloc(0);
    s.on('data', (d) => {
      this.buf = Buffer.concat([this.buf, d]);
      while (this.buf.length >= 2 && this.buf.length >= 2 + this.buf.readUInt16BE(0)) {
        const len = this.buf.readUInt16BE(0);
        const msg = this.buf.subarray(2, 2 + len);
        this.buf = this.buf.subarray(2 + len);
        const p = this.pending.get(msg.readUInt16BE(0));
        if (p) p.resolve(msg);
      }
    });
    const fail = (err) => {
      if (this.socket !== s) return;
      this.socket = null;
      for (const p of this.pending.values()) p.reject(err);
    };
    s.on('error', fail);
    s.on('close', () => fail(Object.assign(new Error('DoT connection closed'), { code: 'ECONNCLOSED' })));
    this.socket = s;
    return s;
  }

  exchange(query, timeoutMs) {
    const sock = this.ensure();
    clearTimeout(this.idleTimer);
    let id;
    do { id = this.nextId = (this.nextId + 1) & 0xffff; } while (this.pending.has(id));
    const originalId = query.readUInt16BE(0);
    return new Promise((resolve, reject) => {
      const finish = () => {
        clearTimeout(timer);
        this.pending.delete(id);
        if (!this.pending.size) this.idleTimer = setTimeout(() => this.close(), 20000);
      };
      const timer = setTimeout(() => { finish(); reject(timeoutError(`tls ${this.servername}`, timeoutMs)); }, timeoutMs);
      this.pending.set(id, {
        resolve: (msg) => { finish(); resolve(withId(msg, originalId)); },
        reject: (e) => { finish(); reject(e); },
      });
      sock.write(frame(withId(query, id)));
    });
  }

  close() {
    clearTimeout(this.idleTimer);
    const s = this.socket;
    this.socket = null;
    s?.destroy();
  }
}

// HTTP/2 session reused across queries (RFC 8484 POST, message ID 0).
class DohConnection {
  constructor(ip, host, port, path) {
    Object.assign(this, { ip, host, port, path });
    this.session = null;
  }

  ensure() {
    if (this.session && !this.session.closed && !this.session.destroyed) return this.session;
    const authority = `https://${net.isIPv6(this.host) ? `[${this.host}]` : this.host}:${this.port}`;
    const session = http2.connect(authority, {
      createConnection: () => tls.connect({
        host: this.ip, port: this.port, ALPNProtocols: ['h2'],
        servername: net.isIP(this.host) ? undefined : this.host,
      }),
    });
    session.on('error', (e) => log.debug(`DoH session ${this.host} error: ${e.message}`));
    session.on('close', () => { if (this.session === session) this.session = null; });
    session.setTimeout(60000, () => session.close());
    this.session = session;
    return session;
  }

  exchange(query, timeoutMs) {
    const originalId = query.readUInt16BE(0);
    const body = withId(query, 0);
    return new Promise((resolve, reject) => {
      let req;
      try {
        req = this.ensure().request({
          ':method': 'POST', ':path': this.path,
          'content-type': 'application/dns-message', accept: 'application/dns-message',
          'content-length': body.length,
        });
      } catch (e) {
        this.session = null;
        return reject(e);
      }
      const chunks = [];
      let status = 0;
      const timer = setTimeout(() => { req.close(http2.constants.NGHTTP2_CANCEL); reject(timeoutError(`https ${this.host}`, timeoutMs)); }, timeoutMs);
      req.on('response', (h) => { status = h[':status']; });
      req.on('data', (d) => chunks.push(d));
      req.on('error', (e) => { clearTimeout(timer); reject(e); });
      req.on('end', () => {
        clearTimeout(timer);
        if (status !== 200) return reject(new Error(`DoH ${this.host} returned HTTP ${status}`));
        const msg = Buffer.concat(chunks);
        if (msg.length < 12) return reject(new Error(`DoH ${this.host} returned a short message`));
        resolve(withId(msg, originalId));
      });
      req.end(body);
    });
  }

  close() {
    this.session?.close();
    this.session = null;
  }
}

const bootstrapCache = new Map();

export async function resolveWithBootstrap(host, bootstrap, timeoutMs) {
  if (net.isIP(host)) return host;
  const cached = bootstrapCache.get(host);
  if (cached && cached.expires > Date.now()) return cached.ip;
  const errors = [];
  for (const type of [TYPE.A, TYPE.AAAA]) {
    for (const server of bootstrap) {
      try {
        const { host: bip, port } = parseUpstream(server);
        if (!net.isIP(bip)) continue;
        const msg = parse(await udpExchange(bip, port, buildQuery(host, type), Math.min(timeoutMs, 3000)));
        const rec = msg.answers.find((r) => r.type === type);
        if (rec) {
          bootstrapCache.set(host, { ip: rec.data, expires: Date.now() + Math.max(300, rec.ttl) * 1000 });
          return rec.data;
        }
      } catch (e) {
        errors.push(`${server}: ${e.message}`);
      }
    }
  }
  throw new Error(`cannot resolve ${host} via bootstrap servers (${errors.join('; ') || 'no answer'})`);
}

export class Upstream {
  constructor(spec, { bootstrap = [], timeoutMs = 5000 } = {}) {
    this.cfg = parseUpstream(spec);
    this.label = spec;
    this.bootstrap = bootstrap;
    this.timeoutMs = timeoutMs;
    this.conn = null;
    this.connIp = null;
    this.stats = { ok: 0, errors: 0, totalMs: 0, lastError: null };
  }

  async connection() {
    const ip = this.cfg.ip || await resolveWithBootstrap(this.cfg.host, this.bootstrap, this.timeoutMs);
    if (this.conn && this.connIp === ip) return { ip, conn: this.conn };
    this.conn?.close();
    this.connIp = ip;
    if (this.cfg.proto === 'tls') this.conn = new DotConnection(ip, this.cfg.port, this.cfg.host);
    else if (this.cfg.proto === 'https') this.conn = new DohConnection(ip, this.cfg.host, this.cfg.port, this.cfg.path);
    else this.conn = null;
    return { ip, conn: this.conn };
  }

  async exchangeOnce(query) {
    const { ip, conn } = await this.connection();
    if (conn) return conn.exchange(query, this.timeoutMs);
    if (this.cfg.proto === 'tcp') return tcpExchange(ip, this.cfg.port, query, this.timeoutMs);
    const res = await udpExchange(ip, this.cfg.port, query, this.timeoutMs);
    if (res.readUInt16BE(2) & 0x0200) return tcpExchange(ip, this.cfg.port, query, this.timeoutMs); // truncated
    return res;
  }

  async exchange(query) {
    const started = Date.now();
    try {
      let res;
      try {
        res = await this.exchangeOnce(query);
      } catch (e) {
        if (!this.conn || e.code === 'ETIMEDOUT') throw e;
        this.conn.close(); // stale persistent connection: retry once on a fresh one
        this.conn = null;
        res = await this.exchangeOnce(query);
      }
      this.stats.ok++;
      this.stats.totalMs += Date.now() - started;
      return res;
    } catch (e) {
      this.stats.errors++;
      this.stats.lastError = e.message;
      throw e;
    }
  }

  close() {
    this.conn?.close();
    this.conn = null;
  }

  info() {
    const { ok, errors, totalMs, lastError } = this.stats;
    return { upstream: this.label, ok, errors, avgMs: ok ? Math.round(totalMs / ok) : null, lastError };
  }
}

export class Resolver {
  constructor(dns) {
    const opts = { bootstrap: dns.bootstrap, timeoutMs: dns.timeoutMs };
    const build = (list) => list.flatMap((spec) => {
      try {
        return [new Upstream(spec, opts)];
      } catch (e) {
        log.warn(`skipping upstream ${spec}: ${e.message}`);
        return [];
      }
    });
    this.mode = dns.upstreamMode;
    this.upstreams = build(dns.upstreams);
    this.fallbacks = build(dns.fallback);
  }

  static async race(list, query) {
    return Promise.any(list.map((u) => u.exchange(query).then((response) => ({ response, upstream: u.label }))));
  }

  async resolve(query) {
    const errors = [];
    if (this.upstreams.length) {
      try {
        if (this.mode === 'parallel') return await Resolver.race(this.upstreams, query);
        for (const u of this.upstreams) {
          try {
            return { response: await u.exchange(query), upstream: u.label };
          } catch (e) {
            errors.push(e);
          }
        }
      } catch (e) {
        errors.push(...(e.errors || [e]));
      }
    }
    if (this.fallbacks.length) {
      try {
        return await Resolver.race(this.fallbacks, query);
      } catch (e) {
        errors.push(...(e.errors || [e]));
      }
    }
    throw new AggregateError(errors, `all upstreams failed: ${errors.map((e) => e.message).join('; ')}`);
  }

  info() {
    return { upstreams: this.upstreams.map((u) => u.info()), fallbacks: this.fallbacks.map((u) => u.info()) };
  }

  close() {
    for (const u of [...this.upstreams, ...this.fallbacks]) u.close();
  }
}
