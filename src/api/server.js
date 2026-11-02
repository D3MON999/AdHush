// Local control API + static web UI. Bound to loopback only. Every /api call must carry
// the per-install token (injected into the served UI page) and a loopback Host header,
// which blocks CSRF from web pages and DNS-rebinding attacks.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { RR_TYPES } from '../rules/parser.js';
import { GROUPS } from '../filters/catalog.js';
import { buildQuery, parse, summarizeAnswers, RCODE_NAMES } from '../dns/packet.js';
import { Upstream } from '../dns/upstream.js';
import { PRESETS, URL_TRACKING_FILTER_ID } from '../privacy.js';
import { appState, appPatch } from '../apps.js';
import { collectDiagnostics } from '../diagnostics.js';
import { siteHost, brokenSitePatch } from '../sites.js';
import { logger } from '../log.js';

const log = logger('api');
const RAW = Symbol('raw response'); // handler result carrying a file instead of JSON
const UI_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'ui');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

function readBody(req, limit = 32 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(httpError(413, 'body too large')); req.destroy(); }
      else chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(httpError(400, 'invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

export class ApiServer {
  constructor(app) {
    this.app = app;
    this.server = null;
    this.port = null;
    this.token = this.loadToken();
    this.routes = this.buildRoutes();
  }

  loadToken() {
    const file = path.join(this.app.dataDir, 'api-token');
    try {
      return fs.readFileSync(file, 'utf8').trim();
    } catch {
      const t = crypto.randomBytes(24).toString('hex');
      fs.writeFileSync(file, t);
      return t;
    }
  }

  buildRoutes() {
    const app = this.app;
    const S = () => app.settings.get();
    const listKey = (t) => {
      if (t !== 'allowlist' && t !== 'blocklist') throw httpError(404, 'unknown list');
      return t;
    };
    return [
      ['GET', '/api/status', () => app.status()],
      ['GET', '/api/notifications', (_b, _p, q) => app.notifications.since(Number(q.get('since')) || 0)],
      ['GET', '/api/updates', () => app.updateState()],
      ['POST', '/api/updates/check', () => { app.requestUpdate('check'); return { ok: true }; }],
      ['POST', '/api/updates/install', () => { app.requestUpdate('install'); return { ok: true }; }],
      ['GET', '/api/sites/broken', () => ({ sites: S().filtering.brokenSites })],
      ['POST', '/api/sites/broken', (b) => {
        const host = siteHost(b.host);
        app.settings.update(brokenSitePatch(S(), host, b.broken !== false));
        return { host, broken: b.broken !== false, sites: S().filtering.brokenSites };
      }],
      ['GET', '/api/diagnostics', () => ({
        [RAW]: true, type: 'application/zip', body: collectDiagnostics(app),
        filename: `AdHush-logs-${new Date().toISOString().slice(0, 16).replace(/[T:]/g, '-')}.zip`,
      })],      ['POST', '/api/protection', (b) => {
        app.settings.update({ protection: { enabled: !!b.enabled, pausedUntil: 0 } });
        return app.status().protection;
      }],
      ['POST', '/api/protection/pause', (b) => {
        const minutes = Number(b.minutes);
        if (!(minutes > 0 && minutes <= 24 * 60)) throw httpError(400, 'minutes must be 1..1440');
        app.settings.update({ protection: { enabled: true, pausedUntil: Date.now() + minutes * 60000 } });
        return app.status().protection;
      }],
      ['GET', '/api/settings', () => S()],
      ['PATCH', '/api/settings', (b) => {
        delete b.schemaVersion;
        app.settings.update(b);
        return S();
      }],
      ['GET', '/api/settings/export', () => ({
        app: 'adhush', exportedAt: new Date().toISOString(), settings: S(),
        filters: app.filters.filters.map(({ id, enabled, custom, name, url }) => ({ id, enabled, custom, name, url })),
      })],
      ['POST', '/api/settings/import', async (b) => {
        if (b.app !== 'adhush' || !b.settings) throw httpError(400, 'not a AdHush settings export');
        const { api, ...rest } = b.settings; // never import the API binding
        app.settings.replace({ ...rest, api: S().api });
        for (const f of b.filters || []) {
          if (f.custom && !app.filters.filters.some((x) => x.url === f.url)) await app.filters.add({ url: f.url, name: f.name }).catch(() => {});
          else if (app.filters.get(f.id) && !f.custom) await app.filters.setEnabled(f.id, f.enabled);
        }
        return { ok: true };
      }],
      ['POST', '/api/settings/reset', () => {
        const { api } = S();
        app.settings.replace({ api });
        return S();
      }],

      ['GET', '/api/filters', () => ({ groups: GROUPS, filters: app.filters.list(), engine: app.engineInfo })],
      ['POST', '/api/filters', (b) => app.filters.add({ url: String(b.url || '').trim(), name: b.name, scope: b.scope || 'dns' })],
      ['POST', '/api/filters/update', (b) => app.filters.updateAll({ force: !!b.force, ids: b.ids || null })],
      ['PATCH', '/api/filters/:id', async (b, p) => {
        if ('name' in b) app.filters.rename(p.id, b.name);
        if ('enabled' in b) await app.filters.setEnabled(p.id, b.enabled);
        return app.filters.get(p.id);
      }],
      ['DELETE', '/api/filters/:id', (b, p) => { app.filters.remove(p.id); return { ok: true }; }],
      ['GET', '/api/filters/:id/content', (b, p) => ({ text: app.filters.readText(p.id).slice(0, 2 * 1024 * 1024) })],

      ['GET', '/api/rules', () => ({ enabled: S().filtering.userRulesEnabled, text: S().filtering.userRules })],
      ['PUT', '/api/rules', (b) => {
        const patch = {};
        if ('text' in b) patch.userRules = String(b.text);
        if ('enabled' in b) patch.userRulesEnabled = !!b.enabled;
        app.settings.update({ filtering: patch });
        return { enabled: S().filtering.userRulesEnabled, text: S().filtering.userRules };
      }],
      ['POST', '/api/rules/add', (b) => {
        const rule = String(b.rule || '').trim();
        if (!rule) throw httpError(400, 'rule is required');
        const current = S().filtering.userRules;
        const lines = current.split(/\r?\n/);
        if (!lines.includes(rule)) app.settings.update({ filtering: { userRules: (current.trim() ? current.replace(/\s+$/, '') + '\n' : '') + rule } });
        return { ok: true };
      }],

      ['GET', '/api/lists/:type', (b, p) => S().filtering[listKey(p.type)]],
      ['PUT', '/api/lists/:type', (b, p) => {
        const key = listKey(p.type);
        const patch = {};
        if ('enabled' in b) patch.enabled = !!b.enabled;
        if (Array.isArray(b.domains)) {
          patch.domains = b.domains.map((d) => (typeof d === 'string' ? { name: d, enabled: true } : { name: String(d.name), enabled: d.enabled !== false }))
            .map((d) => ({ ...d, name: d.name.trim().toLowerCase() })).filter((d) => d.name);
        }
        app.settings.update({ filtering: { [key]: patch } });
        return S().filtering[key];
      }],

      ['GET', '/api/log', (b, p, q) => {
        const items = app.queryLog.query({ limit: Math.min(1000, Number(q.get('limit')) || 200), search: q.get('search') || '', status: q.get('status') || 'all', sinceId: Number(q.get('sinceId')) || 0 });
        return {
          items: items.map((e) => ({ ...e, filterName: e.filterId === null ? null : app.filterName(e.filterId), company: app.trackers.lookup(e.name)?.company || null })),
          lastId: app.queryLog.seq,
        };
      }],
      ['DELETE', '/api/log', () => { app.queryLog.clear(); return { ok: true }; }],

      ['GET', '/api/stats', (b, p, q) => {
        const hours = { '24h': 24, '7d': 168, '30d': 720 }[q.get('period') || '24h'] || 24;
        const sum = app.stats.summary(hours, Date.now(), (host) => app.trackers.lookup(host));
        sum.trackerDb = app.trackers.info();
        sum.byFilter = sum.byFilter.map((x) => ({ ...x, filter: app.filterName(Number(x.name)) }));
        return sum;
      }],
      ['DELETE', '/api/stats', () => { app.stats.clear(); return { ok: true }; }],

      ['GET', '/api/check', (b, p, q) => {
        const name = (q.get('name') || '').trim().toLowerCase();
        if (!name) throw httpError(400, 'name is required');
        const qtype = RR_TYPES[(q.get('type') || 'A').toUpperCase()] || 1;
        const r = app.engine.match(name, { qtype });
        const filterId = r.rule?.filterId ?? null;
        return { name, action: r.action, rule: r.rule?.text || null, filterId, filterName: filterId === null ? null : app.filterName(filterId), rewrite: r.rewrite || null };
      }],
      ['POST', '/api/dns/test', async (b) => {
        const spec = String(b.upstream || '').trim();
        if (!spec) throw httpError(400, 'upstream is required');
        const { bootstrap } = S().dns;
        const u = new Upstream(spec, { bootstrap, timeoutMs: 5000 });
        const started = Date.now();
        try {
          const res = parse(await u.exchange(buildQuery('example.org', 1)));
          return { ok: res.rcode === 0, ms: Date.now() - started, rcode: RCODE_NAMES[res.rcode], answers: summarizeAnswers(res) };
        } catch (e) {
          return { ok: false, ms: Date.now() - started, error: e.message };
        } finally {
          u.close();
        }
      }],
      ['POST', '/api/dns/cache/clear', () => { app.cache.clear(); return { ok: true }; }],

      ['POST', '/api/privacy/preset', async (b) => {
        const preset = String(b.preset || '');
        if (!PRESETS[preset]) throw httpError(400, 'preset must be standard, high or extreme');
        app.settings.update({ privacy: { ...structuredClone(PRESETS[preset]), preset, enabled: true } });
        // Stronger presets also strip tracking parameters with the URL-tracking web filter.
        if (preset !== 'standard' && app.filters.get(URL_TRACKING_FILTER_ID)) await app.filters.setEnabled(URL_TRACKING_FILTER_ID, true);
        return S().privacy;
      }],
      ['GET', '/api/privacy/windows', () => app.windowsPrivacy.status(S().privacy.windows)],

      ['GET', '/api/apps', async (b, p, q) => {
        const s = S();
        const [running, installed, coreApps] = await Promise.all([
          app.apps.running(),
          q.get('installed') === '1' ? app.apps.installed() : Promise.resolve(new Map()),
          app.core.child ? app.core.call('GET', '/apps').then((t) => JSON.parse(t).apps).catch(() => ({})) : Promise.resolve({}),
        ]);
        const exes = new Set([
          ...[...running.values()].filter((r) => r.connections > 0).map((r) => r.exe),
          ...installed.keys(), ...Object.keys(coreApps),
          ...s.https.driver.apps, ...s.https.driver.excluded, ...s.apps.bypass, ...s.apps.noHttps,
        ]);
        const apps = [...exes].map((exe) => {
          const r = running.get(exe);
          const i = installed.get(exe);
          const c = coreApps[exe];
          return {
            exe, name: i?.name || exe, publisher: i?.publisher || null, path: r?.path || i?.path || null,
            running: !!r, connections: r?.connections || 0, installed: !!i,
            requests: c?.requests || 0, blocked: c?.blocked || 0, lastSeen: c?.last_seen || null,
            ...appState(s, exe),
          };
        });
        apps.sort((a, b) => b.connections - a.connections || b.requests - a.requests || a.name.localeCompare(b.name));
        return { apps, driver: { enabled: s.https.driver.enabled, mode: s.https.driver.mode }, webFiltering: s.https.enabled };
      }],
      ['PATCH', '/api/apps/:exe', (b, p) => {
        const exe = String(p.exe).trim().toLowerCase();
        if (!/^[\w .()+-]+\.exe$/i.test(exe)) throw httpError(400, 'expected an executable name like chrome.exe');
        app.settings.update(appPatch(S(), exe, { filter: b.filter, https: b.https }));
        return { exe, ...appState(S(), exe) };
      }],

      ['GET', '/api/extensions', () => ({ items: app.userscripts.list(), settings: S().extensions })],
      ['POST', '/api/extensions', (b) => app.userscripts.install({ url: b.url ? String(b.url).trim() : null, code: b.code ? String(b.code) : null })],
      ['POST', '/api/extensions/update', () => app.userscripts.checkUpdates({ apply: true })],
      ['PATCH', '/api/extensions/:id', (b, p) => { app.userscripts.setEnabled(p.id, b.enabled); return app.userscripts.get(p.id); }],
      ['DELETE', '/api/extensions/:id', (b, p) => { app.userscripts.remove(p.id); return { ok: true }; }],
      ['GET', '/api/extensions/:id/code', (b, p) => ({ code: app.userscripts.code(p.id) })],
      ['PUT', '/api/extensions/:id/code', (b, p) => app.userscripts.updateCode(p.id, String(b.code || ''))],

      ['GET', '/api/https/status', () => app.core.status()],
      ['GET', '/api/https/log', async (b, p, q) => JSON.parse(await app.core.call('GET', `/log?limit=${Math.min(2000, Number(q.get('limit')) || 200)}`))],
      ['POST', '/api/https/clear-exclusions', async () => JSON.parse(await app.core.call('POST', '/clear-exclusions'))],
      ['POST', '/api/https/reload', async () => JSON.parse(await app.core.call('POST', '/reload'))],
      ['GET', '/api/https/ca', () => {
        const file = path.join(app.dataDir, 'ca', 'adhush-ca.pem');
        if (!fs.existsSync(file)) throw httpError(404, 'The certificate is created the first time HTTPS filtering starts.');
        return { path: file, pem: fs.readFileSync(file, 'utf8') };
      }],
    ];
  }

  match(method, pathname) {
    for (const [m, pattern, handler] of this.routes) {
      if (m !== method) continue;
      const pp = pattern.split('/');
      const ap = pathname.split('/');
      if (pp.length !== ap.length) continue;
      const params = {};
      let ok = true;
      for (let i = 0; i < pp.length; i++) {
        if (pp[i].startsWith(':')) params[pp[i].slice(1)] = decodeURIComponent(ap[i]);
        else if (pp[i] !== ap[i]) { ok = false; break; }
      }
      if (ok) return { handler, params };
    }
    return null;
  }

  hostAllowed(req) {
    const host = (req.headers.host || '').toLowerCase();
    return [`127.0.0.1:${this.port}`, `localhost:${this.port}`, `[::1]:${this.port}`].includes(host);
  }

  serveStatic(res, pathname) {
    const rel = pathname === '/' ? 'index.html' : pathname.slice(1);
    const file = path.normalize(path.join(UI_DIR, rel));
    if (!file.startsWith(UI_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404).end('not found');
      return;
    }
    let body = fs.readFileSync(file);
    if (rel === 'index.html') body = Buffer.from(body.toString('utf8').replace('__API_TOKEN__', this.token));
    res.writeHead(200, {
      'content-type': MIME[path.extname(file)] || 'application/octet-stream',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
    });
    res.end(body);
  }

  async handle(req, res) {
    const url = new URL(req.url, 'http://localhost');
    if (!this.hostAllowed(req)) {
      res.writeHead(403).end('forbidden host');
      return;
    }
    if (!url.pathname.startsWith('/api/')) {
      if (req.method !== 'GET') { res.writeHead(405).end(); return; }
      this.serveStatic(res, url.pathname);
      return;
    }
    const send = (status, obj) => {
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
      res.end(JSON.stringify(obj));
    };
    if (req.headers['x-adhush-token'] !== this.token) return send(401, { error: 'missing or invalid API token' });
    const route = this.match(req.method, url.pathname);
    if (!route) return send(404, { error: 'not found' });
    try {
      const body = ['POST', 'PUT', 'PATCH'].includes(req.method) ? await readBody(req) : {};
      const result = await route.handler(body, route.params, url.searchParams);
      if (result?.[RAW]) {
        res.writeHead(200, { 'content-type': result.type, 'content-disposition': `attachment; filename="${result.filename}"`, 'cache-control': 'no-store' });
        return res.end(result.body);
      }
      send(200, result);
    } catch (e) {
      if (!e.status) log.error(`${req.method} ${url.pathname} failed`, e);
      send(e.status || 500, { error: e.message });
    }
  }

  start(portOverride) {
    const { host, port } = this.app.settings.get().api;
    this.port = portOverride || port;
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => this.handle(req, res));
      this.server.once('error', reject);
      this.server.listen(this.port, host, () => {
        log.info(`UI and API on http://${host}:${this.port}/`);
        resolve();
      });
    });
  }

  stop() {
    return new Promise((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }
}
