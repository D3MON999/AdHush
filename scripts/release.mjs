// Update signing for AdHush releases.
//
//   node scripts/release.mjs keygen
//       Creates the Ed25519 signing key once: keys/update-signing.pem (PRIVATE: back it up, never
//       share or ship it) and service/update-key.pub (public, compiled into adhush-service.exe).
//       Losing the private key means installed copies can no longer be updated automatically.
//
//   node scripts/release.mjs sign --setup <AdHushSetup-x.y.z.exe> [--url <download url>] [--notes "..."]
//       Writes latest.json + latest.json.sig next to the setup. Upload all three. `url` may be
//       relative to the feed URL (default: just the file name, which suits GitHub's
//       .../releases/latest/download/latest.json feed).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PRIVATE = path.join(ROOT, 'keys', 'update-signing.pem');
const PUBLIC = path.join(ROOT, 'service', 'update-key.pub');

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

export function publicKeyB64(keyObject) {
  // SPKI DER for Ed25519 is a 12-byte header followed by the 32-byte raw key.
  return crypto.createPublicKey(keyObject).export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
}

function keygen() {
  if (fs.existsSync(PRIVATE)) throw new Error(`${PRIVATE} already exists; refusing to replace the signing key`);
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.mkdirSync(path.dirname(PRIVATE), { recursive: true });
  fs.writeFileSync(PRIVATE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(PUBLIC, publicKeyB64(privateKey) + '\n');
  console.log(`private key: ${PRIVATE}  (BACK THIS UP, never share it)`);
  console.log(`public key:  ${PUBLIC}`);
}

function sign() {
  const setup = arg('setup');
  if (!setup || !fs.existsSync(setup)) throw new Error('--setup <path to AdHushSetup-x.y.z.exe> is required');
  const key = crypto.createPrivateKey(fs.readFileSync(PRIVATE));
  if (publicKeyB64(key) !== fs.readFileSync(PUBLIC, 'utf8').trim()) throw new Error('keys/update-signing.pem does not match service/update-key.pub');
  const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
  const data = fs.readFileSync(setup);
  const manifest = {
    app: 'adhush',
    version,
    url: arg('url') || path.basename(setup),
    sha256: crypto.createHash('sha256').update(data).digest('hex'),
    size: data.length,
    notes: arg('notes') || '',
    published: new Date().toISOString(),
  };
  const body = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
  const out = path.join(path.dirname(setup), 'latest.json');
  fs.writeFileSync(out, body);
  fs.writeFileSync(out + '.sig', crypto.sign(null, body, key).toString('base64') + '\n');
  console.log(`signed ${manifest.version} (${manifest.sha256.slice(0, 12)}…) -> ${out} + .sig`);
}

const cmd = process.argv[2];
if (cmd === 'keygen') keygen();
else if (cmd === 'sign') sign();
else if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.error('usage: node scripts/release.mjs keygen | sign --setup <exe> [--url <url>] [--notes <text>]');
  process.exit(2);
}
