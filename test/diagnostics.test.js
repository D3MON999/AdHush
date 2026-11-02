import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { zip, crc32, collectDiagnostics } from '../src/diagnostics.js';

// Reads back our own zip format (central directory -> local entries).
function unzip(buf) {
  const end = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const count = buf.readUInt16LE(end + 10);
  let p = buf.readUInt32LE(end + 16);
  const out = {};
  for (let i = 0; i < count; i++) {
    const nameLen = buf.readUInt16LE(p + 28);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString();
    const local = buf.readUInt32LE(p + 42);
    const size = buf.readUInt32LE(p + 20);
    const lNameLen = buf.readUInt16LE(local + 26);
    const data = zlib.inflateRawSync(buf.subarray(local + 30 + lNameLen, local + 30 + lNameLen + size));
    assert.equal(crc32(data), buf.readUInt32LE(p + 16), `crc of ${name}`);
    out[name] = data.toString();
    p += 46 + nameLen;
  }
  return out;
}

test('zip round-trip', () => {
  const files = unzip(zip([{ name: 'a.txt', data: Buffer.from('hello') }, { name: 'logs/b.log', data: Buffer.from('x'.repeat(10000)) }]));
  assert.deepEqual(Object.keys(files), ['a.txt', 'logs/b.log']);
  assert.equal(files['a.txt'], 'hello');
  assert.equal(files['logs/b.log'].length, 10000);
});

test('diagnostics never include secrets or browsing data', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adhush-diag-'));
  for (const [f, body] of [['api-token', 'SECRET-TOKEN'], ['stats.json', '{"visited":"secret-site.example"}'], ['settings.json', '{"ui":{}}'], ['dns-state.json', '{"mode":"filtering"}']]) fs.writeFileSync(path.join(dir, f), body);
  fs.mkdirSync(path.join(dir, 'ca'));
  fs.writeFileSync(path.join(dir, 'ca', 'adhush-ca.key'), 'PRIVATE KEY');
  fs.mkdirSync(path.join(dir, 'logs'));
  fs.writeFileSync(path.join(dir, 'logs', 'adhush.log'), 'started\n');
  const app = {
    dataDir: dir, version: 'test', status: () => ({ ok: true }),
    filters: { list: () => [{ id: 1, name: 'List', enabled: true, url: 'https://x' }] },
    userscripts: { list: () => [{ id: 'a', name: 'Script', version: '1', enabled: true, type: 'script' }] },
  };
  const files = unzip(collectDiagnostics(app));
  assert.ok(files['logs/adhush.log'].includes('started'));
  assert.ok(files['dns-state.json']);
  const all = Object.values(files).join('\n');
  for (const secret of ['SECRET-TOKEN', 'PRIVATE KEY', 'secret-site.example']) assert.ok(!all.includes(secret), `leaked ${secret}`);
  assert.ok(!Object.keys(files).some((n) => n.includes('api-token') || n.startsWith('ca/') || n.includes('stats')));
  fs.rmSync(dir, { recursive: true, force: true });
});
