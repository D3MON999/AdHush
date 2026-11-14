import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { App } from '../src/app.js';
import { makeBackup, restoreBackup } from '../src/backup.js';

function makeApp(t) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-backup-'));
  t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
  const app = new App({ dataDir, version: 'test' });
  app.windowsPrivacy.sync = () => {};
  return app;
}

test('a backup carries choices but nothing tied to this PC', (t) => {
  const app = makeApp(t);
  app.settings.update({ ui: { theme: 'raspberry' }, filtering: { userRules: '||mine.example^' }, system: { manageDns: true }, api: { port: 9999 } });
  const b = makeBackup(app);
  assert.equal(b.app, 'adhush');
  assert.equal(b.settings.ui.theme, 'raspberry');
  assert.equal(b.settings.filtering.userRules, '||mine.example^');
  assert.equal(b.settings.api, undefined);
  assert.equal(b.settings.system.manageDns, undefined);
  assert.equal(b.settings.https.enabled, undefined);
  assert.equal(b.settings.dns.listen, undefined);
  assert.ok(b.filters.some((f) => Number.isInteger(f.id)));
});

test('restoring brings the choices back and leaves PC-specific settings alone', async (t) => {
  const from = makeApp(t);
  from.settings.update({ ui: { theme: 'sand' }, filtering: { userRules: '||mine.example^' }, privacy: { preset: 'high' } });
  const id = from.filters.list().find((f) => f.enabled).id;
  await from.filters.setEnabled(id, false);
  const backup = JSON.parse(JSON.stringify(makeBackup(from)));

  const to = makeApp(t);
  to.settings.update({ system: { manageDns: true } });
  const r = await restoreBackup(to, backup);
  assert.equal(r.ok, true);
  assert.equal(to.settings.get().ui.theme, 'sand');
  assert.equal(to.settings.get().filtering.userRules, '||mine.example^');
  assert.equal(to.settings.get().privacy.preset, 'high');
  assert.equal(to.settings.get().system.manageDns, true, 'whole-PC protection stays as it was');
  assert.equal(to.filters.get(id).enabled, false);
});

test('a broken, foreign or edited file changes nothing it shouldn\'t', async (t) => {
  const app = makeApp(t);
  const before = JSON.stringify(app.settings.get());
  await assert.rejects(restoreBackup(app, { hello: 'world' }), /isn't an AdHush backup/);
  await assert.rejects(restoreBackup(app, { app: 'adhush', format: 99, settings: {} }), /newer AdHush/);
  await assert.rejects(restoreBackup(app, { app: 'adhush', format: 1, settings: { dns: { upstreams: [] } } }), /must not be empty/);
  assert.equal(JSON.stringify(app.settings.get()), before);
  await restoreBackup(app, { app: 'adhush', format: 1, settings: { evil: { x: 1 }, ui: { theme: 'ember', extra: true, notifications: 'yes' }, api: { port: 1 } } });
  const s = app.settings.get();
  assert.equal(s.evil, undefined);
  assert.equal(s.ui.extra, undefined);
  assert.equal(s.ui.theme, 'ember');
  assert.equal(s.ui.notifications, true, 'wrong kind of value is ignored');
  assert.equal(s.api.port, 8899);
});

test('an export from AdHush 0.3 still restores', async (t) => {
  const app = makeApp(t);
  const id = app.filters.list().find((f) => f.enabled && !f.custom).id;
  const old = { app: 'adhush', exportedAt: '2026-10-01T00:00:00Z', settings: { ...app.settings.get(), ui: { ...app.settings.get().ui, theme: 'ember', defaultsVersion: 1 } },
    filters: [{ id, enabled: false, custom: false, name: 'x', url: 'https://x' }, { id: 1000, enabled: true, custom: true, name: 'Mine', url: 'notaurl' }] };
  const r = await restoreBackup(app, old);
  assert.equal(r.ok, true);
  assert.equal(app.settings.get().ui.theme, 'ember');
  assert.equal(app.settings.get().ui.defaultsVersion, 4, 'upgrade progress is never rolled back');
  assert.equal(app.filters.get(id).enabled, false);
});
