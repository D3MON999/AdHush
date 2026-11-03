import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Notifications } from '../src/notifications.js';
import { Settings } from '../src/settings.js';
import { handle, isAllowlisted, normalizeHost } from '../host/host.mjs';

test('notifications feed', () => {
  let on = true;
  const n = new Notifications({ size: 3, enabled: () => on });
  for (let i = 0; i < 5; i++) n.push('info', `t${i}`);
  assert.equal(n.since(0).items.length, 3, 'ring buffer keeps the newest');
  assert.deepEqual(n.since(4).items.map((i) => i.title), ['t4']);
  assert.equal(n.since(5).last, 5);
  on = false;
  assert.equal(n.push('info', 'muted'), null);
  assert.equal(n.since(5).items.length, 0);
});

test('onboarding flag: new installs see the wizard, existing ones do not', () => {
  const fresh = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-ob-'));
  assert.equal(new Settings(fresh).load().get().ui.onboarded, false);
  const old = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-ob-'));
  fs.writeFileSync(path.join(old, 'settings.json'), JSON.stringify({ ui: { theme: 'dark' } }));
  assert.equal(new Settings(old).load().get().ui.onboarded, true);
  fs.rmSync(fresh, { recursive: true, force: true });
  fs.rmSync(old, { recursive: true, force: true });
});

test('themes: Midnight Mint by default, old light/dark choices migrate', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-theme-'));
  assert.equal(new Settings(dir).load().get().ui.theme, 'midnight');
  for (const [old, now] of [['dark', 'midnight'], ['light', 'sand'], ['auto', 'auto']]) {
    fs.writeFileSync(path.join(dir, 'settings.json'), JSON.stringify({ ui: { theme: old } }));
    assert.equal(new Settings(dir).load().get().ui.theme, now);
  }
  const s = new Settings(dir).load();
  assert.throws(() => s.update({ ui: { theme: 'neon' } }), /ui\.theme/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('default protection set', async () => {
  const { CATALOG } = await import('../src/filters/catalog.js');
  const on = new Set(CATALOG.filter((f) => f.enabled).map((f) => f.id));
  for (const id of [1, 7, 20, 32, 33, 40, 100, 101, 102, 103, 104, 105, 120, 122]) assert.ok(on.has(id), `list ${id} should be on by default`);
  for (const id of [21, 22, 51, 121]) assert.ok(!on.has(id), `list ${id} should be off by default`);
  const d = structuredClone((await import('../src/settings.js')).DEFAULTS);
  assert.deepEqual(d.parental, { enabled: false, safeSearch: false, blockAdult: false });
});

test('upgrade from 0.1: recommended lists switched on once', async () => {
  const { App, RECOMMENDED_V2 } = await import('../src/app.js');
  const { FilterManager } = await import('../src/filters/manager.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-upg-'));
  fs.writeFileSync(path.join(dir, 'settings.json'), JSON.stringify({ ui: { theme: 'dark' } })); // a 0.1 install
  const settings = new Settings(dir).load();
  assert.equal(settings.get().ui.defaultsVersion, 1);
  const filters = new FilterManager(dir, settings).load();
  for (const f of filters.filters) f.enabled = f.id === 1; // as 0.1 shipped (+ user turned others off)
  const enabled = [];
  filters.setEnabled = async (id, on) => { filters.get(id).enabled = on; enabled.push(id); };
  const pushed = [];
  const fake = { settings, filters, notifications: { push: (...a) => pushed.push(a) } };
  await App.prototype.upgradeDefaults.call(fake);
  assert.deepEqual(enabled.sort((a, b) => a - b), [...RECOMMENDED_V2].sort((a, b) => a - b));
  assert.equal(settings.get().ui.defaultsVersion, 2);
  assert.ok(pushed.some(([, title]) => /Stronger protection/.test(title)));
  assert.ok(pushed.some(([, title]) => /YouTube/.test(title)), 'web filtering off: suggest turning it on');
  assert.ok(!filters.get(51).enabled && !filters.get(121).enabled, 'lists outside the recommended set stay as they were');
  enabled.length = 0;
  await App.prototype.upgradeDefaults.call(fake);
  assert.deepEqual(enabled, [], 'runs only once');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('catalog address change drops the old download but keeps the on/off choice', async () => {
  const { FilterManager } = await import('../src/filters/manager.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-url-'));
  const settings = new Settings(dir).load();
  fs.mkdirSync(path.join(dir, 'filters'));
  fs.writeFileSync(path.join(dir, 'filters', '32.txt'), '||old.example^\n');
  fs.writeFileSync(path.join(dir, 'filters', 'index.json'), JSON.stringify({ filters: [{ id: 32, enabled: true, url: 'https://old.example/tif.txt', etag: '"abc"', rulesCount: 1879829 }] }));
  const f = new FilterManager(dir, settings).load().get(32);
  assert.equal(f.enabled, true);
  assert.match(f.url, /tif\.mini\.txt$/);
  assert.equal(f.etag, undefined);
  assert.equal(f.rulesCount, 0);
  assert.ok(!fs.existsSync(path.join(dir, 'filters', '32.txt')));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('native host commands', async () => {
  assert.equal(normalizeHost('WWW.Example.com.'), 'example.com');
  assert.ok(isAllowlisted([{ name: 'example.com' }], 'cdn.example.com'));
  assert.ok(!isAllowlisted([{ name: 'example.com', enabled: false }], 'example.com'));

  const calls = [];
  let list = { enabled: true, domains: [{ name: 'example.com', enabled: true }] };
  const call = async (method, p, body) => {
    calls.push([method, p, body]);
    if (p === '/api/status') return { protection: { enabled: true, active: true } };
    if (p === '/api/lists/allowlist' && method === 'GET') return list;
    if (p === '/api/lists/allowlist' && method === 'PUT') { list = { ...list, ...body }; return list; }
    return {};
  };
  call.base = 'http://127.0.0.1:8899';

  assert.equal((await handle({ cmd: 'site', host: 'news.example.com' }, call)).allowlisted, true);
  await handle({ cmd: 'allow', host: 'news.example.com', allowed: false }, call);
  assert.deepEqual(list.domains, [], 're-enabling filtering removes the covering parent entry');
  await handle({ cmd: 'allow', host: 'shop.test', allowed: true }, call);
  assert.deepEqual(list.domains.map((d) => d.name), ['shop.test']);

  await handle({ cmd: 'rule', rule: 'example.com##.ad-banner > div' }, call);
  assert.deepEqual(calls.at(-1), ['POST', '/api/rules/add', { rule: 'example.com##.ad-banner > div' }]);
  // The browser may only add cosmetic rules for a site: no network rules, exceptions or scriptlets.
  for (const rule of ['||ads.com^', '@@||example.com^', 'example.com#@#.x', '##.global', 'a.com##x\n||evil^', 'a.com##+js(abort-on-property-read, x)', 'a.com##^script']) {
    await assert.rejects(handle({ cmd: 'rule', rule }, call), /cosmetic/);
  }
  await handle({ cmd: 'broken', host: 'www.Gemini.google.com', broken: true }, call);
  assert.deepEqual(calls.at(-1), ['POST', '/api/sites/broken', { host: 'gemini.google.com', broken: true }]);
  await assert.rejects(handle({ cmd: 'broken', host: 'not a host' }, call), /invalid host/);
  await assert.rejects(handle({ cmd: 'eval', code: '1' }, call), /unknown command/);
  assert.equal((await handle({ cmd: 'ui' }, call)).url, 'http://127.0.0.1:8899/');
});
