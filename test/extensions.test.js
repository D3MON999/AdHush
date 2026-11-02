import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseUserscript, parseUserstyle, compareVersions, UserscriptManager } from '../src/userscripts.js';
import { parseNetstat, parseUninstall, appState, appPatch } from '../src/apps.js';
import { TrackerDb } from '../src/trackers.js';
import { Stats } from '../src/stats.js';
import { DEFAULTS } from '../src/settings.js';

const SCRIPT = `// ==UserScript==
// @name         Demo
// @name:de      Demo DE
// @namespace    test
// @version      1.2.0
// @match        https://example.com/*
// @exclude      *://example.com/private*
// @grant        GM_getValue
// @connect      api.example.com
// @run-at       document-start
// @noframes
// ==/UserScript==
console.log('hi');`;

test('userscript metadata', () => {
  const m = parseUserscript(SCRIPT);
  assert.equal(m.name, 'Demo');
  assert.deepEqual(m.match, ['https://example.com/*']);
  assert.deepEqual(m.exclude, ['*://example.com/private*']);
  assert.equal(m['run-at'], 'document-start');
  assert.equal(m.noframes, true);
  assert.throws(() => parseUserscript('// ==UserScript==\n// @name X\n// ==/UserScript=='), /@match/);
});

test('userstyle sections', () => {
  const css = `/* ==UserStyle==
@name Dark
@namespace t
@version 1.0
==/UserStyle== */
@-moz-document domain("example.com"), url-prefix("https://other.org/docs") {
  body { background: #000; }
  a { color: #0f0; }
}
@-moz-document regexp("https://x\\\\.com/.*") { p { margin: 0 } }
html { font-size: 15px }`;
  const { meta, sections } = parseUserstyle(css);
  assert.equal(meta.name, 'Dark');
  assert.deepEqual(sections[0].conditions, [{ type: 'domain', value: 'example.com' }, { type: 'url-prefix', value: 'https://other.org/docs' }]);
  assert.match(sections[0].css, /background: #000/);
  assert.equal(sections[1].conditions[0].type, 'regexp');
  assert.deepEqual(sections.at(-1), { conditions: [], css: 'html { font-size: 15px }' });
  assert.throws(() => parseUserstyle('/* ==UserStyle==\n@name S\n@preprocessor stylus\n==/UserStyle== */ a{}'), /stylus/);
});

test('version comparison', () => {
  assert.equal(compareVersions('1.10.0', '1.9.9'), 1);
  assert.equal(compareVersions('2.0', '2.0.0'), 0);
  assert.equal(compareVersions('1.0.0', '1.0.1'), -1);
});

test('manager installs, toggles and removes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-ext-'));
  const m = new UserscriptManager(dir).load();
  const e = await m.install({ code: SCRIPT });
  assert.equal(e.type, 'script');
  assert.equal(e.runAt, 'document-start');
  assert.ok(fs.existsSync(path.join(dir, 'userscripts', `${e.id}.user.js`)));
  const again = await m.install({ code: SCRIPT.replace('1.2.0', '1.3.0') });
  assert.equal(again.id, e.id, 'same name + namespace updates in place');
  assert.equal(m.list().length, 1);
  m.setEnabled(e.id, false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'userscripts', 'index.json'), 'utf8')).items[0].enabled, false);
  m.remove(e.id);
  assert.equal(m.list().length, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('netstat and uninstall parsing', () => {
  const ns = parseNetstat('  TCP    192.168.1.5:50000    142.250.1.1:443    ESTABLISHED     1234\n  TCP    127.0.0.1:5000    127.0.0.1:8080    ESTABLISHED     99\n  TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    4');
  assert.deepEqual([...ns], [[1234, 1]]);
  const apps = parseUninstall('HKEY_LOCAL_MACHINE\\...\\Chrome\n    DisplayName    REG_SZ    Google Chrome\n    DisplayIcon    REG_SZ    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",0\n    Publisher    REG_SZ    Google LLC\n');
  assert.equal(apps[0].exe, 'chrome.exe');
  assert.equal(apps[0].publisher, 'Google LLC');
});

test('per-app switches', () => {
  const s = structuredClone(DEFAULTS);
  assert.deepEqual(appState(s, 'discord.exe'), { filter: true, https: true });
  const p = appPatch(s, 'discord.exe', { filter: false, https: false });
  assert.deepEqual(p.apps.bypass, ['discord.exe']);
  assert.deepEqual(p.apps.noHttps, ['discord.exe']);
  s.https.driver.enabled = true;
  assert.equal(appState(s, 'notepad.exe').filter, false, 'driver "selected" mode filters only listed apps');
  assert.equal(appState(s, 'chrome.exe').filter, true);
});

test('company statistics', () => {
  const db = new TrackerDb(os.tmpdir());
  db.index(
    { categories: { 4: 'advertising', 6: 'site_analytics' }, trackers: { dc: { name: 'DoubleClick', categoryId: 4, companyId: 'google' }, ga: { name: 'Google Analytics', categoryId: 6, companyId: 'google' } }, trackerDomains: { 'doubleclick.net': 'dc', 'google-analytics.com': 'ga' } },
    { companies: { google: { name: 'Google', websiteUrl: 'https://google.com' } } },
  );
  assert.equal(db.lookup('ad.doubleclick.net').company, 'Google');
  assert.equal(db.lookup('example.org'), null);
  const stats = new Stats(os.tmpdir());
  for (const [name, status] of [['ad.doubleclick.net', 'blocked'], ['www.google-analytics.com', 'processed'], ['example.org', 'processed']]) stats.record({ name, status });
  const sum = stats.summary(24, Date.now(), (h) => db.lookup(h));
  assert.deepEqual(sum.topCompanies.map((c) => [c.name, c.requests, c.blocked]), [['Google', 2, 1]]);
  assert.deepEqual(sum.categories.map((c) => c.name).sort(), ['advertising', 'site_analytics']);
});
