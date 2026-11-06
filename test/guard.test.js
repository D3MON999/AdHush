import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { App } from '../src/app.js';
import { RuleEngine } from '../src/rules/engine.js';
import { DOH_HOSTS, SELFTEST_DOMAIN, SELFTEST_IP } from '../src/browserguard.js';
import { WINDOWS_TWEAKS, WindowsPrivacy } from '../src/privacy.js';
import { runSelfTest } from '../src/selftest.js';

function makeApp(t) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-guard-'));
  t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
  const app = new App({ dataDir, version: 'test' });
  app.windowsPrivacy.sync = () => {}; // never touch this PC's registry from a test
  return app;
}

const engine = (app) => RuleEngine.build(app.buildSources());
const marker = (app) => path.join(app.dataDir, 'gaming-active');

test('secure DNS guard: canary says NXDOMAIN and DoH hosts stop resolving', (t) => {
  const e = engine(makeApp(t));
  const canary = e.match('use-application-dns.net', { qtype: 1 });
  assert.equal(canary.action, 'rewrite');
  assert.equal(canary.rewrite.rcode, 3);
  for (const host of DOH_HOSTS) assert.equal(e.match(host, { qtype: 1 }).action, 'block', host);
});

test('secure DNS guard can be turned off', (t) => {
  const app = makeApp(t);
  app.settings.update({ system: { stopSecureDns: false } });
  const e = engine(app);
  assert.equal(e.match('dns.google', { qtype: 1 }).action, 'none');
  assert.equal(e.match('use-application-dns.net', { qtype: 1 }).action, 'none');
});

test('an allowlisted DoH host stays reachable', (t) => {
  const app = makeApp(t);
  app.settings.update({ filtering: { allowlist: { enabled: true, domains: ['dns.google'] } } });
  assert.equal(engine(app).match('dns.google', { qtype: 1 }).action, 'allow');
});

test('self-test name answers with its marker address, on any random subdomain', (t) => {
  const r = engine(makeApp(t)).match(`st-abc123.${SELFTEST_DOMAIN}`, { qtype: 1 });
  assert.equal(r.action, 'rewrite');
  assert.deepEqual(r.rewrite.records, [{ type: 'A', value: SELFTEST_IP }]);
});

test('browser policies apply only while Windows actually uses AdHush', (t) => {
  const app = makeApp(t);
  assert.equal(app.windowsWanted().browserDoh, false);
  app.settings.update({ system: { manageDns: true } });
  assert.equal(app.windowsWanted().browserDoh, true);
  app.settings.update({ system: { stopSecureDns: false } });
  assert.equal(app.windowsWanted().browserDoh, false);
});

test('browser policy is internal: not offered as a privacy switch', (t) => {
  assert.equal(WINDOWS_TWEAKS.browserDoh.internal, true);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-tweak-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  assert.ok(!('browserDoh' in new WindowsPrivacy(dir).status({})));
});

test('gaming: marker file lives only while a game is active', (t) => {
  const app = makeApp(t);
  const state = app.setGaming({ active: true, exe: 'Game.EXE' });
  assert.equal(state.active, true);
  assert.equal(state.exe, 'game.exe');
  assert.ok(fs.existsSync(marker(app)));
  assert.equal(app.setGaming({ active: false }).active, false);
  assert.ok(!fs.existsSync(marker(app)));
});

test('gaming: a game whose name is hidden from us still counts, and excludes nothing', (t) => {
  const app = makeApp(t);
  app.settings.update({ https: { driver: { mode: 'all' } } });
  const before = app.settings.get().https.driver.excluded;
  assert.equal(app.setGaming({ active: true, exe: '' }).active, true);
  assert.deepEqual(app.settings.get().https.driver.excluded, before);
  assert.deepEqual(app.settings.get().gaming.games, []);
});

test('gaming: switched off means never active', (t) => {
  const app = makeApp(t);
  app.settings.update({ gaming: { enabled: false } });
  assert.equal(app.setGaming({ active: true, exe: 'game.exe' }).active, false);
  assert.ok(!fs.existsSync(marker(app)));
});

test('gaming: a tray that stops reporting cannot leave the mode stuck', (t) => {
  const app = makeApp(t);
  app.setGaming({ active: true, exe: 'game.exe' });
  app.gaming.at = Date.now() - 3 * 60 * 1000;
  assert.equal(app.gamingState().active, false);
  assert.equal(app.gamingState().exe, null);
});

test('gaming: in all-apps mode the game leaves web filtering, and forgetting puts it back', (t) => {
  const app = makeApp(t);
  app.settings.update({ https: { driver: { mode: 'all', excluded: ['mine.exe'] } } });
  app.setGaming({ active: true, exe: 'game.exe' });
  app.setGaming({ active: true, exe: 'game.exe' }); // heartbeat adds nothing twice
  assert.deepEqual(app.settings.get().https.driver.excluded, ['mine.exe', 'game.exe']);
  assert.deepEqual(app.settings.get().gaming.games, ['game.exe']);
  app.forgetGame('game.exe');
  assert.deepEqual(app.settings.get().https.driver.excluded, ['mine.exe']);
  assert.deepEqual(app.settings.get().gaming.games, []);
});

test('gaming: selected-apps mode changes nothing', (t) => {
  const app = makeApp(t);
  app.settings.update({ https: { driver: { mode: 'selected', excluded: [] } } });
  app.setGaming({ active: true, exe: 'game.exe' });
  assert.deepEqual(app.settings.get().https.driver.excluded, []);
  assert.deepEqual(app.settings.get().gaming.games, []);
});

test('v4 upgrade tells whole-PC users once, and stays quiet for everyone else', async (t) => {
  const on = makeApp(t);
  on.settings.update({ ui: { defaultsVersion: 3 }, system: { manageDns: true } });
  await on.upgradeDefaults();
  await on.upgradeDefaults();
  assert.equal(on.notifications.since(0).items.filter((n) => n.title === 'Browsers now stay protected').length, 1);

  const off = makeApp(t);
  off.settings.update({ ui: { defaultsVersion: 3 } });
  await off.upgradeDefaults();
  assert.equal(off.notifications.since(0).items.length, 0);
});

test('self-test reports a paused PC honestly and never says all clear', async (t) => {
  const app = makeApp(t);
  app.settings.update({ protection: { enabled: false } });
  const report = await runSelfTest({
    ...app, settings: app.settings, engine: app.engine, filters: app.filters, windowsPrivacy: app.windowsPrivacy,
    dns: { listening: [], errors: [] },
    core: { status: async () => ({}) },
    systemDnsState: () => ({ managed: false, guard: false }),
    updateState: () => ({ service: false }),
  });
  assert.equal(report.result, 'fail');
  assert.equal(report.checks.find((c) => c.id === 'protection').status, 'fail');
  assert.equal(report.checks.find((c) => c.id === 'protection').fix.action, 'resume');
  assert.ok(!report.checks.some((c) => c.id === 'blocking'), 'cannot claim blocking while off');
});
