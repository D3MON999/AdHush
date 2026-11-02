import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PRESETS, WindowsPrivacy, WINDOWS_TWEAKS, parseRegQuery } from '../src/privacy.js';

test('presets escalate', () => {
  assert.equal(PRESETS.standard.thirdPartyCookies.enabled, false);
  assert.equal(PRESETS.high.thirdPartyCookies.minutes, 180);
  assert.equal(PRESETS.extreme.thirdPartyCookies.minutes, 0);
  for (const k of ['hideSearchQueries', 'sendDnt', 'stripTrackingParams']) assert.ok(PRESETS.standard[k] && PRESETS.high[k] && PRESETS.extreme[k]);
  assert.ok(PRESETS.extreme.hideUserAgent && !PRESETS.high.hideUserAgent);
});

test('parses reg query output', () => {
  const out = '\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\dmwappushservice\r\n    Start    REG_DWORD    0x3\r\n';
  assert.deepEqual(parseRegQuery(out, 'Start'), { type: 'REG_DWORD', data: '3' });
  assert.equal(parseRegQuery(out, 'Missing'), null);
});

// In-memory fake of reg.exe.
function fakeReg(initial = {}) {
  const store = new Map(Object.entries(initial));
  const calls = [];
  const reg = async (args) => {
    calls.push(args.join(' '));
    const [op, key, , name] = args;
    const id = `${key}\\${name}`;
    if (op === 'query') {
      const v = store.get(id);
      return v ? { code: 0, stdout: `\r\n${key}\r\n    ${name}    ${v.type}    ${v.data}\r\n` } : { code: 1, stdout: '', stderr: 'not found' };
    }
    if (op === 'add') {
      store.set(id, { type: args[5], data: args[7] });
      return { code: 0, stdout: '' };
    }
    if (op === 'delete') {
      store.delete(id);
      return { code: 0, stdout: '' };
    }
    return { code: 1, stdout: '' };
  };
  return { reg, store, calls };
}

test('windows switches snapshot and restore original values', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-wp-'));
  const svc = 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\dmwappushservice\\Start';
  const fake = fakeReg({ [svc]: { type: 'REG_DWORD', data: '0x3' } });
  const wp = new WindowsPrivacy(dir, { reg: fake.reg });

  await wp.sync({ wapPush: true, telemetry: true });
  assert.equal(fake.store.get(svc).data, '4');
  const tel = WINDOWS_TWEAKS.telemetry.values[0];
  assert.equal(fake.store.get(`${tel.key}\\${tel.name}`).data, '0');
  assert.ok(wp.status({ wapPush: true }).wapPush.applied);

  // State survives a restart, then turning the switches off restores the originals.
  const again = new WindowsPrivacy(dir, { reg: fake.reg });
  await again.sync({ wapPush: false, telemetry: false });
  assert.equal(fake.store.get(svc).data, '3', 'previous service start type restored');
  assert.equal(fake.store.has(`${tel.key}\\${tel.name}`), false, 'policy that did not exist is removed again');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('access denied is reported, not thrown', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-wp-'));
  const wp = new WindowsPrivacy(dir, { reg: async (args) => (args[0] === 'add' ? { code: 1, stdout: '', stderr: 'ERROR: Access is denied.' } : { code: 1, stdout: '' }) });
  await wp.sync({ recall: true });
  assert.match(wp.status({ recall: true }).recall.error, /administrator/);
  assert.equal(wp.status({ recall: true }).recall.applied, false);
  fs.rmSync(dir, { recursive: true, force: true });
});
