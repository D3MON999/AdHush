// "Send logs": a zip someone can email to whoever helps them. Contains logs, settings and the
// protection state. Never included: the API token, the certificate's private key (ca/),
// statistics (they list visited domains) and the query log.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';

const MAX_LOG_BYTES = 2 * 1024 * 1024; // keep the newest part of each log

const CRC_TABLE = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});

export function crc32(buf) {
  let c = -1;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function dosTime(d) {
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    date: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

// Minimal ZIP (deflate, no zip64): entries = [{ name, data: Buffer }].
export function zip(entries, now = new Date()) {
  const { time, date } = dosTime(now);
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, 'utf8');
    const packed = zlib.deflateRawSync(data);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuf, packed);
    centrals.push(central, nameBuf);
    offset += local.length + nameBuf.length + packed.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

function tail(file) {
  const size = fs.statSync(file).size;
  if (size <= MAX_LOG_BYTES) return fs.readFileSync(file);
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(MAX_LOG_BYTES);
    fs.readSync(fd, buf, 0, MAX_LOG_BYTES, size - MAX_LOG_BYTES);
    return Buffer.concat([Buffer.from(`[... ${size - MAX_LOG_BYTES} earlier bytes omitted ...]\n`), buf]);
  } finally {
    fs.closeSync(fd);
  }
}

export function collectDiagnostics(app) {
  const dir = app.dataDir;
  const entries = [];
  const add = (name, data) => entries.push({ name, data: Buffer.isBuffer(data) ? data : Buffer.from(data) });
  const json = (v) => JSON.stringify(v, null, 2);

  add('README.txt', `AdHush diagnostics, created ${new Date().toString()}
Contains: logs, settings, protection state, filter list status, installed userscript names.
Not included: the API token, the certificate private key, statistics and the query log.
`);
  add('system.json', json({
    adhush: app.version, node: process.version, os: `${os.type()} ${os.release()} ${os.version?.() || ''}`.trim(),
    arch: os.arch(), uptimeHours: Math.round(os.uptime() / 360) / 10, memoryGb: Math.round(os.totalmem() / 1e8) / 10,
  }));
  add('status.json', json(app.status()));
  add('filters.json', json(app.filters.list().map(({ id, name, enabled, scope, rulesCount, lastUpdate, lastCheck, error }) => ({ id, name, enabled, scope, rulesCount, lastUpdate, lastCheck, error }))));
  add('userscripts.json', json(app.userscripts.list().map(({ id, name, version, enabled, type }) => ({ id, name, version, enabled, type }))));
  for (const f of ['settings.json', 'dns-state.json', 'dns-backup.json', 'windows-privacy.json']) {
    const p = path.join(dir, f);
    if (fs.existsSync(p)) add(f, fs.readFileSync(p));
  }
  const logs = path.join(dir, 'logs');
  if (fs.existsSync(logs)) {
    for (const f of fs.readdirSync(logs)) {
      const p = path.join(logs, f);
      if (fs.statSync(p).isFile()) add(`logs/${f}`, tail(p));
    }
  }
  return zip(entries);
}
