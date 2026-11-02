// Native messaging host (com.adhush.host) for the AdHush Assistant browser extension.
// Chrome/Edge start it per request and talk over stdio: a 4-byte little-endian length
// followed by UTF-8 JSON. It only accepts a fixed set of commands and calls the local API
// with the per-install token, so the extension never sees the token.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export function dataDir() {
  if (process.env.ADHUSH_DATA) return process.env.ADHUSH_DATA;
  const candidates = [
    path.join(process.env.ProgramData || 'C:\\ProgramData', 'AdHush'),
    path.join(HERE, '..', 'data'), // development checkout
  ];
  return candidates.find((d) => fs.existsSync(path.join(d, 'api-token'))) || candidates[0];
}

function apiBase(dir) {
  try {
    const s = JSON.parse(fs.readFileSync(path.join(dir, 'settings.json'), 'utf8'));
    if (s.api?.port) return `http://127.0.0.1:${s.api.port}`;
  } catch {}
  return 'http://127.0.0.1:8899';
}

export function normalizeHost(h) {
  return String(h || '').trim().toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
}

export function isAllowlisted(domains, host) {
  return domains.some((d) => d.enabled !== false && (host === d.name || host.endsWith('.' + d.name)));
}

// host##<css selector>; `##+js(...)` scriptlets and `##^` HTML filters are refused.
const SELECTOR_RULE = /^[a-z0-9.-]+##(?![+^])[^\n\r]{1,500}$/i;

export async function handle(msg, call) {
  switch (msg?.cmd) {
    case 'site': {
      const [status, list] = await Promise.all([call('GET', '/api/status'), call('GET', '/api/lists/allowlist')]);
      const host = normalizeHost(msg.host);
      return { ok: true, protection: status.protection, allowlisted: !!host && list.enabled && isAllowlisted(list.domains, host) };
    }
    case 'allow': {
      const host = normalizeHost(msg.host);
      if (!/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(host)) throw new Error('invalid host');
      const list = await call('GET', '/api/lists/allowlist');
      // Re-enabling filtering removes the exact entry and any parent entry that covers the host.
      const domains = msg.allowed
        ? [...list.domains.filter((d) => d.name !== host), { name: host, enabled: true }]
        : list.domains.filter((d) => !(host === d.name || host.endsWith('.' + d.name)));
      await call('PUT', '/api/lists/allowlist', { domains, ...(msg.allowed ? { enabled: true } : {}) });
      return { ok: true };
    }
    case 'pause': {
      const minutes = Math.min(1440, Math.max(1, Number(msg.minutes) || 30));
      return { ok: true, protection: await call('POST', '/api/protection/pause', { minutes }) };
    }
    case 'resume':
      return { ok: true, protection: await call('POST', '/api/protection', { enabled: true }) };
    case 'rule': {
      const rule = String(msg.rule || '').trim();
      if (!SELECTOR_RULE.test(rule)) throw new Error('only cosmetic rules (host##selector) can be added from the browser');
      await call('POST', '/api/rules/add', { rule });
      return { ok: true };
    }
    case 'broken': {
      // "This site isn't working": allowlist + never decrypt, in one step (see src/sites.js).
      const host = normalizeHost(msg.host);
      if (!/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(host)) throw new Error('invalid host');
      await call('POST', '/api/sites/broken', { host, broken: msg.broken !== false });
      return { ok: true };
    }
    case 'ui':
      return { ok: true, url: `${call.base}/` };
    default:
      throw new Error('unknown command');
  }
}

function makeCaller() {
  const dir = dataDir();
  const base = apiBase(dir);
  let token;
  try {
    token = fs.readFileSync(path.join(dir, 'api-token'), 'utf8').trim();
  } catch {
    throw new Error('AdHush is not installed (no API token found)');
  }
  const call = async (method, p, body) => {
    let res;
    try {
      res = await fetch(base + p, {
        method,
        headers: { 'x-adhush-token': token, ...(body ? { 'content-type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(5000),
      });
    } catch {
      throw new Error('AdHush is not running');
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  };
  call.base = base;
  return call;
}

function write(obj) {
  const json = Buffer.from(JSON.stringify(obj), 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32LE(json.length, 0);
  process.stdout.write(Buffer.concat([len, json]));
}

function main() {
  let buf = Buffer.alloc(0);
  let pending = 0;
  let ended = false;
  const maybeExit = () => { if (ended && pending === 0) process.exit(0); };
  process.stdin.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const n = buf.readUInt32LE(0);
      if (n > 1024 * 1024) process.exit(1);
      if (buf.length < 4 + n) break;
      const raw = buf.subarray(4, 4 + n).toString('utf8');
      buf = buf.subarray(4 + n);
      pending++;
      (async () => {
        try {
          write(await handle(JSON.parse(raw), makeCaller()));
        } catch (e) {
          write({ ok: false, error: e.message });
        } finally {
          pending--;
          maybeExit();
        }
      })();
    }
  });
  process.stdin.on('end', () => { ended = true; maybeExit(); });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
