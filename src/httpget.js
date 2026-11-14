// Downloads for filter lists, the tracker database and userscripts, with Node's plain http/https
// modules. Node's built-in fetch (undici) sometimes threw an internal assertion when a server closed a
// connection mid-download; this keeps that code out of the always-on service. The result looks like a
// small fetch Response: { status, ok, url, headers.get(), text(), json() }, with the body already read.
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

function decoder(encoding) {
  switch (String(encoding || '').toLowerCase()) {
    case 'gzip': case 'x-gzip': return zlib.createGunzip();
    case 'deflate': return zlib.createInflate();
    case 'br': return zlib.createBrotliDecompress();
    default: return null;
  }
}

function once(url, headers, timeoutMs, maxBytes) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'http:' ? http : https;
    const req = lib.get(url, { headers: { 'accept-encoding': 'gzip, deflate, br', ...headers } }, (res) => {
      if (REDIRECTS.has(res.statusCode) || res.statusCode === 304 || res.statusCode >= 400) {
        res.resume(); // nothing useful in these bodies; drain them so the socket is released
        return resolve({ res, body: Buffer.alloc(0) });
      }
      const declared = Number(res.headers['content-length'] || 0);
      if (declared > maxBytes) {
        req.destroy();
        return reject(new Error(`the file is larger than ${Math.round(maxBytes / 1048576)} MB`));
      }
      const unzip = decoder(res.headers['content-encoding']);
      const stream = unzip ? res.pipe(unzip) : res;
      const parts = [];
      let size = 0;
      stream.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          req.destroy();
          stream.destroy();
          reject(new Error(`the file is larger than ${Math.round(maxBytes / 1048576)} MB`));
          return;
        }
        parts.push(chunk);
      });
      stream.on('end', () => resolve({ res, body: Buffer.concat(parts) }));
      stream.on('error', reject);
      res.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => req.destroy(Object.assign(new Error(`timed out after ${timeoutMs / 1000} s`), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
  });
}

export async function httpGet(url, { headers = {}, timeoutMs = 90000, maxBytes = 64 * 1024 * 1024, maxRedirects = 5 } = {}) {
  let target = new URL(url);
  for (let hop = 0; ; hop++) {
    if (target.protocol !== 'https:' && target.protocol !== 'http:') throw new Error(`unsupported address ${target.protocol}`);
    const { res, body } = await once(target, headers, timeoutMs, maxBytes);
    if (REDIRECTS.has(res.statusCode) && res.headers.location) {
      if (hop >= maxRedirects) throw new Error('too many redirects');
      target = new URL(res.headers.location, target);
      continue;
    }
    const text = () => Promise.resolve(body.toString('utf8'));
    return {
      status: res.statusCode,
      ok: res.statusCode >= 200 && res.statusCode < 300,
      url: target.href,
      headers: { get: (name) => res.headers[String(name).toLowerCase()] ?? null },
      text,
      json: async () => JSON.parse(await text()),
    };
  }
}
