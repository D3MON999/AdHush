// Local filtering DNS server (UDP + TCP). Pipeline per query:
//   rules → block / rewrite / forward (cache → upstreams) → CNAME-cloaking check → log + stats
import dgram from 'node:dgram';
import net from 'node:net';
import { parse, buildResponse, buildQuery, truncate, summarizeAnswers, TYPE, RCODE, RCODE_NAMES } from './packet.js';
import { DnsCache } from './cache.js';
import { RR_NAMES } from '../rules/parser.js';
import { logger } from '../log.js';

const log = logger('dns');

function headerOnly(buf, rcode) {
  const out = Buffer.from(buf.subarray(0, 12));
  out.writeUInt16BE(0x8000 | (buf.readUInt16BE(2) & 0x7900) | 0x0080 | rcode, 2);
  out.writeUInt16BE(0, 4); out.writeUInt16BE(0, 6); out.writeUInt16BE(0, 8); out.writeUInt16BE(0, 10);
  return out;
}

export class DnsServer {
  // deps: { settings, getEngine(), getResolver(), cache, queryLog, stats }
  constructor(deps) {
    Object.assign(this, deps);
    this.udp = [];
    this.tcp = [];
    this.listening = [];
    this.errors = [];
  }

  async start(listen) {
    this.errors = [];
    for (const { host, port } of listen) {
      await this.listenUdp(host, port).catch((e) => this.errors.push(`udp ${host}:${port}: ${e.message}`));
      await this.listenTcp(host, port).catch((e) => this.errors.push(`tcp ${host}:${port}: ${e.message}`));
    }
    for (const e of this.errors) log.error(`listen failed: ${e}`);
    if (this.listening.length) log.info(`DNS listening on ${this.listening.join(', ')}`);
  }

  listenUdp(host, port) {
    return new Promise((resolve, reject) => {
      const sock = dgram.createSocket(net.isIPv6(host) ? 'udp6' : 'udp4');
      sock.once('error', reject);
      sock.on('message', (msg, rinfo) => {
        log.debug(`udp packet ${msg.length} B from ${rinfo.address}:${rinfo.port}`);
        this.handle(msg, rinfo.address, 'udp')
          .then((res) => res && sock.send(res, rinfo.port, rinfo.address))
          .catch((e) => log.error('udp handler failed', e));
      });
      sock.bind(port, host, () => {
        sock.removeListener('error', reject);
        sock.on('error', (e) => log.error(`udp socket error: ${e.message}`));
        this.udp.push(sock);
        this.listening.push(`udp://${net.isIPv6(host) ? `[${host}]` : host}:${port}`);
        resolve();
      });
    });
  }

  listenTcp(host, port) {
    return new Promise((resolve, reject) => {
      const server = net.createServer((conn) => {
        let buf = Buffer.alloc(0);
        conn.setTimeout(10000, () => conn.destroy());
        conn.on('error', () => {});
        conn.on('data', (d) => {
          buf = Buffer.concat([buf, d]);
          while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
            const q = buf.subarray(2, 2 + buf.readUInt16BE(0));
            buf = buf.subarray(2 + q.length);
            this.handle(q, conn.remoteAddress, 'tcp').then((res) => {
              if (!res || conn.destroyed) return;
              const len = Buffer.alloc(2);
              len.writeUInt16BE(res.length);
              conn.write(Buffer.concat([len, res]));
            }).catch((e) => log.error('tcp handler failed', e));
          }
        });
      });
      server.once('error', reject);
      server.listen(port, host, () => {
        server.removeListener('error', reject);
        this.tcp.push(server);
        this.listening.push(`tcp://${net.isIPv6(host) ? `[${host}]` : host}:${port}`);
        resolve();
      });
    });
  }

  async stop() {
    for (const s of this.udp) s.close();
    for (const s of this.tcp) s.close();
    this.udp = [];
    this.tcp = [];
    this.listening = [];
  }

  blockedResponse(buf, msg, q, rule) {
    const dns = this.settings.get().dns;
    const ttl = dns.blockedTtl;
    let mode = dns.blockingMode;
    let v4 = '0.0.0.0';
    let v6 = '::';
    if (mode === 'refused') return buildResponse(buf, msg, { rcode: RCODE.REFUSED });
    if (mode === 'nxdomain') return buildResponse(buf, msg, { rcode: RCODE.NXDOMAIN });
    if (mode === 'custom') {
      v4 = net.isIPv4(dns.customIpv4) ? dns.customIpv4 : v4;
      v6 = net.isIPv6(dns.customIpv6) ? dns.customIpv6 : v6;
    } else if (mode === 'default' && rule?.hostsStyle) {
      const ip = rule.text.split(' ')[0];
      if (ip === '127.0.0.1') v4 = ip;
      if (ip === '::1') v6 = ip;
    }
    const records = q.type === TYPE.A ? [{ type: 'A', value: v4 }] : q.type === TYPE.AAAA ? [{ type: 'AAAA', value: v6 }] : [];
    return buildResponse(buf, msg, { records, ttl });
  }

  async rewriteResponse(buf, msg, q, rewrite, client) {
    const ttl = this.settings.get().dns.blockedTtl;
    if (rewrite.rcode !== 0) return buildResponse(buf, msg, { rcode: rewrite.rcode });
    const wanted = q.type === TYPE.A ? 'A' : q.type === TYPE.AAAA ? 'AAAA' : null;
    const cname = rewrite.records.find((r) => r.type === 'CNAME');
    if (cname) {
      const records = [{ type: 'CNAME', value: cname.value, ttl }];
      if (wanted) {
        // Resolve the CNAME target ourselves so stub resolvers get usable addresses.
        const sub = buildQuery(cname.value, q.type);
        const subMsg = parse(sub);
        const { response } = await this.forward(sub, subMsg, subMsg.questions[0], client);
        for (const r of parse(response).answers) {
          if (r.type === TYPE.CNAME) records.push({ type: 'CNAME', value: r.data, name: r.name, ttl: r.ttl });
          else if ((r.type === TYPE.A || r.type === TYPE.AAAA) && RR_NAMES[r.type] === wanted) records.push({ type: wanted, value: r.data, name: r.name, ttl: r.ttl });
        }
      }
      return buildResponse(buf, msg, { records, ttl });
    }
    const records = rewrite.records.filter((r) => r.type === wanted).map((r) => ({ ...r, ttl }));
    return buildResponse(buf, msg, { records, ttl });
  }

  async forward(buf, msg, q) {
    const s = this.settings.get().dns;
    const key = DnsCache.key(q, msg.edns?.do);
    if (s.cache.enabled) {
      const hit = this.cache.get(key, msg.id);
      if (hit) return { response: hit, upstream: 'cache', cached: true };
    }
    const { response, upstream } = await this.getResolver().resolve(buf);
    if (s.cache.enabled) this.cache.set(key, response);
    return { response, upstream, cached: false };
  }

  async handle(buf, client, proto) {
    let msg;
    try {
      msg = parse(buf);
    } catch {
      return buf.length >= 12 ? headerOnly(buf, RCODE.FORMERR) : null;
    }
    if (msg.qr) return null;
    if (msg.opcode !== 0) return headerOnly(buf, RCODE.NOTIMP);
    if (msg.questions.length !== 1) return headerOnly(buf, RCODE.FORMERR);

    const q = msg.questions[0];
    const started = Date.now();
    const settings = this.settings.get();
    const active = this.settings.isProtectionActive(started);
    const engine = this.getEngine();
    const entry = {
      time: started, client, proto, name: q.name, type: RR_NAMES[q.type] || String(q.type),
      status: 'processed', rule: null, filterId: null, cname: null, upstream: null, cached: false, answers: [], rcode: '', ms: 0,
    };

    let response;
    try {
      let result = active ? engine.match(q.name, { qtype: q.type, client }) : { action: 'none', rule: null };
      if (result.action === 'block') {
        response = this.blockedResponse(buf, msg, q, result.rule);
        entry.status = 'blocked';
      } else if (result.action === 'rewrite') {
        response = await this.rewriteResponse(buf, msg, q, result.rewrite, client);
        entry.status = 'rewritten';
      } else {
        const fw = await this.forward(buf, msg, q);
        response = fw.response;
        entry.upstream = fw.upstream;
        entry.cached = fw.cached;
        if (result.action === 'allow') entry.status = 'allowed';
        else if (active && settings.dns.blockCnameCloaking) {
          // Trackers hide behind first-party CNAMEs: check every name in the chain.
          for (const rec of parse(response).answers) {
            if (rec.type !== TYPE.CNAME) continue;
            const r2 = engine.match(rec.data, { qtype: q.type, client });
            if (r2.action === 'allow') break;
            if (r2.action === 'block') {
              response = this.blockedResponse(buf, msg, q, r2.rule);
              entry.status = 'blocked';
              entry.cname = rec.data;
              result = r2;
              break;
            }
          }
        }
      }
      if (result.rule) {
        entry.rule = result.rule.text;
        entry.filterId = result.rule.filterId;
      }
    } catch (e) {
      log.debug(`resolve ${q.name} failed: ${e.message}`);
      response = buildResponse(buf, msg, { rcode: RCODE.SERVFAIL });
      entry.status = 'error';
      entry.error = e.message;
    }

    try {
      const out = parse(response);
      entry.rcode = RCODE_NAMES[out.rcode] || String(out.rcode);
      entry.answers = summarizeAnswers(out).slice(0, 10);
      const maxUdp = msg.edns ? msg.edns.udpSize : 512;
      if (proto === 'udp' && response.length > maxUdp) response = truncate(response, out);
    } catch {
      // keep the upstream bytes untouched if we cannot parse them
    }
    entry.ms = Date.now() - started;
    if (settings.queryLog.enabled) this.queryLog.add(entry);
    if (settings.stats.enabled) this.stats.record({ name: q.name, status: entry.status, client, ms: entry.ms, cached: entry.cached, filterId: entry.filterId });
    return response;
  }
}
