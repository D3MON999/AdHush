// Filter list manager: catalog + custom lists, download with conditional requests,
// header metadata (Title/Version/Expires), scheduled updates, on-disk cache.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';
import { CATALOG, CUSTOM_ID_START } from './catalog.js';
import { parseList } from '../rules/parser.js';
import { logger } from '../log.js';
import { writeFileAtomic } from '../fsutil.js';

const log = logger('filters');
const MAX_BYTES = 64 * 1024 * 1024;
const STATE_FIELDS = ['enabled', 'lastUpdate', 'lastCheck', 'version', 'title', 'rulesCount', 'error', 'etag', 'lastModified', 'expiresHours'];

function parseExpiresHours(v) {
  const m = String(v).match(/(\d+)\s*(day|hour|d|h)/i);
  if (!m) return null;
  return Number(m[1]) * (m[2].toLowerCase().startsWith('d') ? 24 : 1);
}

export function parseHeader(text) {
  const meta = {};
  for (const line of text.split(/\r?\n/, 60)) {
    const m = line.match(/^[!#]\s*(Title|Version|Expires|Homepage|Description)\s*:\s*(.+)$/i);
    if (m) meta[m[1].toLowerCase()] = m[2].trim();
  }
  return meta;
}

export function countContentRules(text) {
  let n = 0;
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (t && !t.startsWith('!') && !t.startsWith('[')) n++;
  }
  return n;
}

function isLocalPath(url) {
  return url.startsWith('file://') || /^[a-z]:[\\/]/i.test(url) || url.startsWith('\\\\');
}

async function mapLimit(items, limit, fn) {
  const results = [];
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await fn(items[idx]);
    }
  });
  await Promise.all(workers);
  return results;
}

export class FilterManager extends EventEmitter {
  constructor(dataDir, settings) {
    super();
    this.dir = path.join(dataDir, 'filters');
    this.indexFile = path.join(this.dir, 'index.json');
    this.settings = settings;
    this.filters = [];
    this.timer = null;
    this.updating = null;
  }

  load() {
    fs.mkdirSync(this.dir, { recursive: true });
    let stored = [];
    try {
      stored = JSON.parse(fs.readFileSync(this.indexFile, 'utf8')).filters || [];
    } catch {
      // first run
    }
    const byId = new Map(stored.map((f) => [f.id, f]));
    const builtins = CATALOG.map((c) => {
      let s = byId.get(c.id) || {};
      if (s.url && s.url !== c.url) {
        // The catalog now points this list somewhere else (e.g. a smaller edition): drop the old
        // download and its cache headers so the new source is fetched, but keep the on/off choice.
        fs.rmSync(this.file(c.id), { force: true });
        s = { enabled: s.enabled };
      }
      const state = Object.fromEntries(STATE_FIELDS.filter((k) => k in s).map((k) => [k, s[k]]));
      return { ...c, custom: false, lastUpdate: 0, lastCheck: 0, rulesCount: 0, error: null, ...state };
    });
    const customs = stored.filter((f) => f.custom);
    this.filters = [...builtins, ...customs];
    this.save();
    return this;
  }

  save() {
    writeFileAtomic(this.indexFile, JSON.stringify({ version: 1, filters: this.filters }, null, 2));
  }

  file(id) {
    return path.join(this.dir, `${id}.txt`);
  }

  get(id) {
    return this.filters.find((f) => f.id === Number(id));
  }

  list() {
    return this.filters.map((f) => ({ ...f, downloaded: fs.existsSync(this.file(f.id)) }));
  }

  readText(id) {
    try {
      return fs.readFileSync(this.file(id), 'utf8');
    } catch {
      return '';
    }
  }

  // Filters that currently contribute rules to the given engine, honoring group toggles.
  activeFilters(scope = 'dns') {
    const s = this.settings.get();
    return this.filters.filter((f) => {
      if (!f.enabled || (f.scope || 'dns') !== scope) return false;
      if (f.group === 'security' && !s.security.enabled) return false;
      if (f.group === 'parental' && !(s.parental.enabled && (f.id !== 50 || s.parental.blockAdult))) return false;
      return true;
    });
  }

  async fetchText(f, force) {
    if (isLocalPath(f.url)) {
      const p = f.url.startsWith('file://') ? fileURLToPath(f.url) : f.url;
      return { text: fs.readFileSync(p, 'utf8'), notModified: false };
    }
    const headers = { 'user-agent': 'AdHush/0.1 (personal DNS filter)' };
    if (!force && fs.existsSync(this.file(f.id))) {
      if (f.etag) headers['if-none-match'] = f.etag;
      if (f.lastModified) headers['if-modified-since'] = f.lastModified;
    }
    const res = await fetch(f.url, { headers, redirect: 'follow', signal: AbortSignal.timeout(90000) });
    if (res.status === 304) return { notModified: true };
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const len = Number(res.headers.get('content-length') || 0);
    if (len > MAX_BYTES) throw new Error('list is larger than 64 MB');
    let text = await res.text();
    if (text.length > MAX_BYTES) throw new Error('list is larger than 64 MB');
    f.etag = res.headers.get('etag') || null;
    f.lastModified = res.headers.get('last-modified') || null;
    text = await this.expandIncludes(text, res.url || f.url, headers['user-agent']);
    return { text, notModified: false };
  }

  // Inlines `!#include file` directives (same origin as the list only, like uBlock Origin).
  async expandIncludes(text, baseUrl, userAgent, depth = 0) {
    if (depth > 2 || !text.includes('!#include')) return text;
    const base = new URL(baseUrl);
    const out = [];
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^!#include\s+(\S+)/);
      if (!m) {
        out.push(line);
        continue;
      }
      let target;
      try {
        target = new URL(m[1], base);
      } catch {
        continue;
      }
      if (target.origin !== base.origin) {
        log.warn(`ignoring cross-origin include ${target.href} in ${baseUrl}`);
        continue;
      }
      try {
        const res = await fetch(target, { headers: { 'user-agent': userAgent }, redirect: 'follow', signal: AbortSignal.timeout(90000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        out.push(`! >>> included from ${target.href}`, await this.expandIncludes(await res.text(), res.url || target.href, userAgent, depth + 1));
      } catch (e) {
        log.warn(`include ${target.href} failed: ${e.message}`);
      }
    }
    return out.join('\n');
  }

  // Returns true when the stored content changed.
  async download(f, { force = false } = {}) {
    const now = Date.now();
    try {
      const { text, notModified } = await this.fetchText(f, force);
      f.lastCheck = now;
      if (notModified) {
        f.error = null;
        return false;
      }
      const ruleCount = f.scope === 'content' ? countContentRules(text) : parseList(text, f.id).rules.length;
      if (!ruleCount) throw new Error(f.scope === 'content' ? 'no rules found (is this a filter list?)' : 'no DNS-applicable rules found (is this a filter list?)');
      if (/^\s*<(!doctype|html)/i.test(text)) throw new Error('the URL returned a web page, not a filter list');
      const meta = parseHeader(text);
      const changed = this.readText(f.id) !== text;
      fs.writeFileSync(this.file(f.id), text);
      Object.assign(f, {
        rulesCount: ruleCount, lastUpdate: now, error: null,
        version: meta.version || null, title: meta.title || null, expiresHours: meta.expires ? parseExpiresHours(meta.expires) : null,
      });
      log.info(`filter ${f.id} (${f.name}) updated: ${ruleCount} rules`);
      return changed;
    } catch (e) {
      f.lastCheck = now;
      f.error = e.message;
      log.warn(`filter ${f.id} (${f.name}) update failed: ${e.message}`);
      throw e;
    }
  }

  isDue(f, now = Date.now()) {
    if (!fs.existsSync(this.file(f.id))) return true;
    const hours = this.settings.get().filtering.updateIntervalHours;
    if (!hours) return false; // automatic updates disabled
    const interval = (f.expiresHours ? Math.min(f.expiresHours, hours) : hours) * 3600 * 1000;
    return now - (f.lastCheck || 0) >= interval;
  }

  async updateAll({ force = false, ids = null } = {}) {
    if (this.updating) return this.updating;
    const targets = this.filters.filter((f) => (ids ? ids.includes(f.id) : f.enabled) && (force || this.isDue(f)));
    this.updating = (async () => {
      const results = await mapLimit(targets, 4, async (f) => {
        try {
          return { id: f.id, name: f.name, status: (await this.download(f, { force })) ? 'updated' : 'up-to-date' };
        } catch (e) {
          return { id: f.id, name: f.name, status: 'failed', error: e.message };
        }
      });
      this.save();
      if (results.some((r) => r.status === 'updated')) this.emit('change');
      if (results.length) this.emit('updated', results);
      return results;
    })();
    try {
      return await this.updating;
    } finally {
      this.updating = null;
    }
  }

  async add({ url, name, scope = 'dns' }) {
    if (!url) throw Object.assign(new Error('url is required'), { status: 400 });
    if (!['dns', 'content'].includes(scope)) throw Object.assign(new Error('scope must be dns or content'), { status: 400 });
    if (this.filters.some((f) => f.url === url)) throw Object.assign(new Error('this list is already added'), { status: 409 });
    const id = Math.max(CUSTOM_ID_START - 1, ...this.filters.map((f) => f.id)) + 1;
    const f = { id, group: 'custom', scope, custom: true, enabled: true, name: name || url, url, homepage: null, description: scope === 'content' ? 'Custom web filter' : 'Custom DNS filter', lastUpdate: 0, lastCheck: 0, rulesCount: 0, error: null };
    try {
      await this.download(f, { force: true });
    } catch (e) {
      fs.rmSync(this.file(id), { force: true });
      throw Object.assign(e, { status: 400 });
    }
    if (!name && f.title) f.name = f.title;
    this.filters.push(f);
    this.save();
    this.emit('change');
    return f;
  }

  async setEnabled(id, enabled) {
    const f = this.get(id);
    if (!f) throw Object.assign(new Error('filter not found'), { status: 404 });
    f.enabled = !!enabled;
    this.save();
    if (f.enabled && !fs.existsSync(this.file(f.id))) await this.download(f).catch(() => {});
    this.save();
    this.emit('change');
    return f;
  }

  rename(id, name) {
    const f = this.get(id);
    if (!f) throw Object.assign(new Error('filter not found'), { status: 404 });
    f.name = String(name).slice(0, 200);
    this.save();
    return f;
  }

  remove(id) {
    const f = this.get(id);
    if (!f) throw Object.assign(new Error('filter not found'), { status: 404 });
    if (!f.custom) throw Object.assign(new Error('built-in filters can only be disabled'), { status: 400 });
    this.filters = this.filters.filter((x) => x !== f);
    fs.rmSync(this.file(f.id), { force: true });
    this.save();
    this.emit('change');
  }

  start() {
    this.updateAll().catch((e) => log.error('initial update failed', e));
    this.timer = setInterval(() => this.updateAll().catch(() => {}), 30 * 60 * 1000);
    this.timer.unref();
  }

  stop() {
    clearInterval(this.timer);
  }
}
