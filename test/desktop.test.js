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
