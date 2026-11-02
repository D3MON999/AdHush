// Userscripts (==UserScript==) and userstyles (==UserStyle== / UserCSS): install from a URL or
// pasted code, metadata parsing, @require bundling and update checks. adhush-core reads
// <data>/userscripts/index.json and injects enabled entries into matching pages.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { logger } from './log.js';
import { writeFileAtomic } from './fsutil.js';

const log = logger('userscripts');
const MAX_BYTES = 5 * 1024 * 1024;
const LIST_KEYS = new Set(['match', 'include', 'exclude', 'exclude-match', 'grant', 'require', 'connect', 'resource']);

function err(status, message) {
  return Object.assign(new Error(message), { status });
}

function metaBlock(code, open, close) {
  const start = code.indexOf(open);
  const end = code.indexOf(close, start);
  if (start < 0 || end < 0) return null;
  return code.slice(start + open.length, end);
}

export function parseUserscript(code) {
  const block = metaBlock(code, '==UserScript==', '==/UserScript==');
  if (block === null) throw err(400, 'not a userscript: the ==UserScript== header is missing');
  const meta = { match: [], include: [], exclude: [], 'exclude-match': [], grant: [], require: [], connect: [], resource: [] };
  for (const line of block.split(/\r?\n/)) {
    const m = line.match(/^\s*\/\/\s*@([\w:-]+)(?:\s+(.*?))?\s*$/);
    if (!m) continue;
    const key = m[1].split(':')[0].toLowerCase(); // ignore localized variants like @name:de
    const value = (m[2] || '').trim();
    if (m[1].includes(':')) continue;
    if (LIST_KEYS.has(key)) meta[key].push(value);
    else if (!(key in meta)) meta[key] = value || true;
  }
  if (!meta.name) throw err(400, 'userscript has no @name');
  if (!meta.match.length && !meta.include.length) throw err(400, 'userscript has no @match or @include');
  return meta;
}

/** Splits UserCSS into sections: { conditions: [{ type, value }], css }. Unconditional CSS applies everywhere. */
export function parseUserstyle(code) {
  const block = metaBlock(code, '==UserStyle==', '==/UserStyle==');
  if (block === null) throw err(400, 'not a userstyle: the ==UserStyle== header is missing');
  const meta = {};
  for (const line of block.split(/\r?\n/)) {
    const m = line.match(/^\s*@([\w-]+)\s+(.*?)\s*$/);
    if (m && !(m[1] in meta)) meta[m[1]] = m[2];
  }
  if (!meta.name) throw err(400, 'userstyle has no @name');
  if (meta.preprocessor && !['default', 'uso'].includes(meta.preprocessor)) {
    throw err(400, `userstyles using the "${meta.preprocessor}" preprocessor are not supported yet`);
  }
  const body = code.slice(code.indexOf('==/UserStyle==')).replace(/^==\/UserStyle==\s*\*\//, '');
  const sections = [];
  let global = '';
  let i = 0;
  const re = /@(?:-moz-)?document\s+/g;
  for (;;) {
    re.lastIndex = i;
    const m = re.exec(body);
    if (!m) {
      global += body.slice(i);
      break;
    }
    global += body.slice(i, m.index);
    const open = body.indexOf('{', re.lastIndex);
    if (open < 0) break;
    const condText = body.slice(re.lastIndex, open);
    const conditions = [...condText.matchAll(/(url-prefix|url|domain|regexp)\(\s*(?:(["'])((?:\\.|(?!\2).)*)\2|([^)]*?))\s*\)/g)]
      .map((c) => ({ type: c[1], value: (c[3] ?? c[4] ?? '').replace(/\\\\/g, '\\') }));
    let depth = 0;
    let j = open;
    for (; j < body.length; j++) {
      if (body[j] === '{') depth++;
      else if (body[j] === '}' && --depth === 0) break;
    }
    sections.push({ conditions, css: body.slice(open + 1, j).trim() });
    i = j + 1;
  }
  if (global.replace(/\/\*[\s\S]*?\*\//g, '').trim()) sections.push({ conditions: [], css: global.trim() });
  if (!sections.length) throw err(400, 'userstyle has no CSS');
  return { meta, sections };
}

export function compareVersions(a = '0', b = '0') {
  const pa = String(a).split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0) ? 1 : -1;
  }
  return 0;
}

export class UserscriptManager extends EventEmitter {
  constructor(dataDir) {
    super();
    this.dir = path.join(dataDir, 'userscripts');
    this.indexFile = path.join(this.dir, 'index.json');
    this.items = [];
  }

  load() {
    fs.mkdirSync(this.dir, { recursive: true });
    try {
      this.items = JSON.parse(fs.readFileSync(this.indexFile, 'utf8')).items || [];
    } catch {
      this.items = [];
      this.save();
    }
    return this;
  }

  save() {
    writeFileAtomic(this.indexFile, JSON.stringify({ version: 1, items: this.items }, null, 2));
  }

  get(id) {
    const item = this.items.find((x) => x.id === id);
    if (!item) throw err(404, 'extension not found');
    return item;
  }

  file(id, kind = 'user.js') {
    return path.join(this.dir, `${id}.${kind}`);
  }

  code(id) {
    const item = this.get(id);
    return fs.readFileSync(this.file(id, item.type === 'style' ? 'user.css' : 'user.js'), 'utf8');
  }

  async fetchText(url) {
    if (!/^https?:\/\//i.test(url)) throw err(400, 'only http(s) URLs can be installed');
    const res = await fetch(url, { headers: { 'user-agent': 'AdHush' }, redirect: 'follow', signal: AbortSignal.timeout(60000) });
    if (!res.ok) throw err(400, `download failed: HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_BYTES) throw err(400, 'file is larger than 5 MB');
    return text;
  }

  /** Installs (or replaces) an extension from `code` or by downloading `url`. */
  async install({ url = null, code = null }) {
    if (!code && !url) throw err(400, 'url or code is required');
    const text = code ?? (await this.fetchText(url));
    const isStyle = /==UserStyle==/.test(text) || (url && /\.user\.css(\?|$)/i.test(url));
    const entry = isStyle ? this.styleEntry(text) : await this.scriptEntry(text);
    entry.id = crypto.createHash('sha1').update(`${entry.type}:${entry.namespace || ''}/${entry.name}`).digest('hex').slice(0, 12);
    entry.sourceUrl = url || entry.downloadURL || null;
    const previous = this.items.find((x) => x.id === entry.id);
    entry.enabled = previous ? previous.enabled : true;
    entry.installedAt = previous?.installedAt || Date.now();
    entry.updatedAt = Date.now();
    this.write(entry, text);
    this.items = [...this.items.filter((x) => x.id !== entry.id), entry];
    this.save();
    this.emit('change');
    log.info(`${previous ? 'updated' : 'installed'} ${entry.type} "${entry.name}" ${entry.version || ''}`);
    return entry;
  }

  styleEntry(text) {
    const { meta, sections } = parseUserstyle(text);
    return {
      type: 'style', name: meta.name, namespace: meta.namespace || '', version: meta.version || '',
      description: meta.description || '', author: meta.author || '', updateURL: meta.updateURL || null, sections,
    };
  }

  async scriptEntry(text) {
    const m = parseUserscript(text);
    const requires = [];
    for (const r of m.require) {
      try {
        requires.push(`// @require ${r}\n${await this.fetchText(r)}`);
      } catch (e) {
        throw err(400, `could not download @require ${r}: ${e.message}`);
      }
    }
    return {
      type: 'script', name: m.name, namespace: m.namespace || '', version: m.version || '', description: m.description || '',
      author: m.author || '', matches: m.match, includes: m.include, excludes: m.exclude, excludeMatches: m['exclude-match'],
      runAt: ['document-start', 'document-end', 'document-idle', 'document-body'].includes(m['run-at']) ? m['run-at'] : 'document-idle',
      grants: m.grant, connects: m.connect, noframes: m.noframes === true,
      updateURL: m.updateURL || m.downloadURL || null, downloadURL: m.downloadURL || null,
      requires: requires.join('\n;\n'),
    };
  }

  write(entry, text) {
    if (entry.type === 'style') {
      fs.writeFileSync(this.file(entry.id, 'user.css'), text);
    } else {
      fs.writeFileSync(this.file(entry.id, 'user.js'), text);
      fs.writeFileSync(this.file(entry.id, 'require.js'), entry.requires || '');
      delete entry.requires;
    }
  }

  async updateCode(id, code) {
    const item = this.get(id);
    const entry = await this.install({ code, url: item.sourceUrl });
    if (entry.id !== id) this.remove(id); // renamed: drop the old entry
    return entry;
  }

  setEnabled(id, enabled) {
    this.get(id).enabled = !!enabled;
    this.save();
    this.emit('change');
  }

  remove(id) {
    this.get(id);
    this.items = this.items.filter((x) => x.id !== id);
    for (const kind of ['user.js', 'user.css', 'require.js']) fs.rmSync(this.file(id, kind), { force: true });
    fs.rmSync(path.join(this.dir, 'values', `${id}.json`), { force: true });
    this.save();
    this.emit('change');
  }

  /** Checks each extension's update URL; installs newer versions when `apply` is set. */
  async checkUpdates({ apply = true } = {}) {
    const results = [];
    for (const item of [...this.items]) {
      const url = item.updateURL || item.sourceUrl;
      if (!url) continue;
      try {
        const text = await this.fetchText(url);
        const remote = item.type === 'style' ? parseUserstyle(text).meta.version : parseUserscript(text).version;
        const newer = compareVersions(remote, item.version) > 0;
        if (newer && apply) await this.install({ url, code: text.includes('==/User') && /meta\.js(\?|$)/.test(url) && item.downloadURL ? await this.fetchText(item.downloadURL) : text });
        results.push({ id: item.id, name: item.name, from: item.version, to: remote, status: newer ? (apply ? 'updated' : 'available') : 'up-to-date' });
      } catch (e) {
        results.push({ id: item.id, name: item.name, status: 'failed', error: e.message });
      }
    }
    return results;
  }

  list() {
    return this.items.map(({ sections, ...rest }) => ({ ...rest, sections: sections?.length }));
  }
}
