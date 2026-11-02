#!/usr/bin/env node
// Builds core/resources/resources.json in adblock-rust's Resource format from uBlock Origin's
// scriptlets (src/js/resources/*.js) and redirect resources (src/web_accessible_resources).
// Run manually when you want newer scriptlets:  node scripts/build-resources.mjs [git-ref]
// The output is data only; the AdHush service never downloads or executes this code itself.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REF = process.argv[2] || 'master';
const RAW = `https://raw.githubusercontent.com/gorhill/uBlock/${REF}/`;
const API = `https://api.github.com/repos/gorhill/uBlock/contents/`;
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'core', 'resources', 'resources.json');
const TRUSTED = 1; // PermissionMask bit granted to built-in lists and user rules

const MIME = {
  '.js': 'application/javascript', '.css': 'text/css', '.html': 'text/html', '.gif': 'image/gif',
  '.png': 'image/png', '.mp3': 'audio/mp3', '.mp4': 'video/mp4', '.txt': 'text/plain',
  '.json': 'application/json', '.xml': 'text/xml', '.svg': 'image/svg+xml',
};

async function get(url, binary = false) {
  const res = await fetch(url, { headers: { 'user-agent': 'adhush-build-resources' }, signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return binary ? Buffer.from(await res.arrayBuffer()) : res.text();
}

const b64 = (s) => Buffer.from(s).toString('base64');

// Mirrors a repo file and, recursively, every relative module it imports.
async function mirror(tmp, repoPath, seen = new Set()) {
  if (seen.has(repoPath)) return;
  seen.add(repoPath);
  const source = await get(RAW + repoPath);
  const local = path.join(tmp, ...repoPath.split('/'));
  fs.mkdirSync(path.dirname(local), { recursive: true });
  fs.writeFileSync(local, source);
  const specs = [...source.matchAll(/(?:import|export)\s+(?:[^'"`;]*?\sfrom\s+)?['"](\.{1,2}\/[^'"]+)['"]/g)].map((m) => m[1]);
  for (const spec of specs) {
    await mirror(tmp, path.posix.normalize(path.posix.join(path.posix.dirname(repoPath), spec)), seen);
  }
}

async function scriptlets(tmp) {
  const listing = JSON.parse(await get(`${API}src/js/resources?ref=${REF}`));
  const seen = new Set();
  for (const f of listing.filter((x) => x.name.endsWith('.js'))) await mirror(tmp, `src/js/resources/${f.name}`, seen);
  fs.writeFileSync(path.join(tmp, 'package.json'), '{"type":"module"}');
  console.log(`  mirrored ${seen.size} modules`);
  const { builtinScriptlets } = await import(pathToFileURL(path.join(tmp, 'src', 'js', 'resources', 'scriptlets.js')).href);
  return builtinScriptlets.map((s) => {
    const source = s.fn.toString();
    // Injectable scriptlets are invoked by function name; helper dependencies (.fn) are inlined as-is.
    if (s.name.endsWith('.js') && !/^function\s+[^\s(]+\s*\(/.test(source)) throw new Error(`${s.name} is not a named function`);
    const r = {
      name: s.name,
      aliases: s.aliases || [],
      kind: { mime: s.name.endsWith('.fn') ? 'fn/javascript' : 'application/javascript' },
      content: b64(source),
      dependencies: (s.dependencies || []).map((d) => (typeof d === 'function' ? d.details.name : d)),
    };
    if (s.requiresTrust) r.permission = TRUSTED;
    return r;
  });
}

async function redirects(tmp) {
  await mirror(tmp, 'src/js/redirect-resources.js');
  const { default: map } = await import(pathToFileURL(path.join(tmp, 'src', 'js', 'redirect-resources.js')).href);
  const out = [];
  for (const [name, details] of map) {
    const ext = path.extname(name);
    const data = await get(`${RAW}src/web_accessible_resources/${name}`, true).catch(() => null);
    if (!data) {
      console.warn(`  skipped redirect ${name} (not found)`);
      continue;
    }
    const alias = details.alias;
    out.push({
      name,
      aliases: Array.isArray(alias) ? alias : alias ? [alias] : [],
      kind: { mime: MIME[ext] || 'application/octet-stream' },
      content: data.toString('base64'),
    });
  }
  return out;
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-ubo-'));
try {
  console.log(`fetching uBlock Origin resources @ ${REF}…`);
  const s = await scriptlets(tmp);
  const r = await redirects(tmp);
  const names = new Set();
  const all = [...s, ...r].filter((x) => !names.has(x.name) && names.add(x.name));
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(all));
  fs.writeFileSync(path.join(path.dirname(OUT), 'SOURCE.txt'),
    `Generated ${new Date().toISOString()} from https://github.com/gorhill/uBlock (${REF}).\n` +
    'uBlock Origin is licensed under GPLv3: https://github.com/gorhill/uBlock/blob/master/LICENSE.txt\n' +
    `${s.length} scriptlet resources, ${r.length} redirect resources.\n`);
  console.log(`wrote ${OUT}: ${s.length} scriptlets/helpers, ${r.length} redirect resources`);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
