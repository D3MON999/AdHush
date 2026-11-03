// Draws the AdHush shield and writes extension/icon{32,128}.png and installer/adhush.ico.
// No image tools needed: the PNG encoder is ~20 lines on top of zlib.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const GREEN = [0x10, 0xb9, 0x81]; // brand emerald (Midnight Mint theme)

// Same outline as the UI's SVG path: M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z (32-unit box).
function insideShield(x, y) {
  if (y < 2 || y > 30) return false;
  if (y < 7) return Math.abs(x - 16) <= 12 * ((y - 2) / 5);
  if (y <= 15) return x >= 4 && x <= 28;
  const t = (y - 15) / 15; // bottom curve narrows to the point at y=30
  const half = 12 * Math.sqrt(Math.max(0, 1 - t * t));
  return Math.abs(x - 16) <= half;
}

function insideCheck(x, y) {
  const d1 = Math.abs((y - 16.5) - (x - 10.5)) / Math.SQRT2; // short stroke going down-right
  const d2 = Math.abs(10 * (x - 15.5) + 7.5 * (y - 21.5)) / 12.5; // long stroke going steeply up-right
  return (x >= 11 && x <= 15.8 && d1 <= 1.6) || (x >= 14.6 && x <= 23 && d2 <= 1.6);
}

function draw(size) {
  const px = Buffer.alloc(size * size * 4);
  const ss = 4;
  for (let j = 0; j < size; j++) {
    for (let i = 0; i < size; i++) {
      let cover = 0, white = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const x = ((i + (sx + 0.5) / ss) / size) * 32, y = ((j + (sy + 0.5) / ss) / size) * 32;
          if (!insideShield(x, y)) continue;
          cover++;
          if (insideCheck(x, y)) white++;
        }
      }
      if (!cover) continue;
      const w = white / cover;
      const o = (j * size + i) * 4;
      for (let c = 0; c < 3; c++) px[o + c] = Math.round(GREEN[c] * (1 - w) + 255 * w);
      px[o + 3] = Math.round((cover / (ss * ss)) * 255);
    }
  }
  return px;
}

const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
function crc32(buf) {
  let c = -1;
  for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size) {
  const rgba = draw(size);
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
// ICO with PNG-compressed frames (supported since Windows Vista).
function ico(sizes) {
  const images = sizes.map(png);
  const head = Buffer.alloc(6 + 16 * sizes.length);
  head.writeUInt16LE(1, 2);
  head.writeUInt16LE(sizes.length, 4);
  let offset = head.length;
  sizes.forEach((s, k) => {
    const e = 6 + 16 * k;
    head[e] = s >= 256 ? 0 : s;
    head[e + 1] = s >= 256 ? 0 : s;
    head.writeUInt16LE(1, e + 4);
    head.writeUInt16LE(32, e + 6);
    head.writeUInt32LE(images[k].length, e + 8);
    head.writeUInt32LE(offset, e + 12);
    offset += images[k].length;
  });
  return Buffer.concat([head, ...images]);
}

fs.writeFileSync(path.join(ROOT, 'extension', 'icon32.png'), png(32));
fs.writeFileSync(path.join(ROOT, 'extension', 'icon128.png'), png(128));
fs.mkdirSync(path.join(ROOT, 'installer'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'installer', 'adhush.ico'), ico([16, 24, 32, 48, 64, 256]));
console.log('icons written');
