import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import { httpGet } from '../src/httpget.js';

async function server(t) {
  const srv = http.createServer((req, res) => {
    if (req.url === '/plain') return res.end('||ads.example^\n');
    if (req.url === '/gzip') { res.writeHead(200, { 'content-encoding': 'gzip' }); return res.end(zlib.gzipSync('gzipped list')); }
    if (req.url === '/br') { res.writeHead(200, { 'content-encoding': 'br' }); return res.end(zlib.brotliCompressSync('brotli list')); }
    if (req.url === '/moved') { res.writeHead(302, { location: '/plain' }); return res.end('moved'); }
    if (req.url === '/loop') { res.writeHead(301, { location: '/loop' }); return res.end(); }
    if (req.url === '/same') { res.writeHead(304, { etag: '"x"' }); return res.end(); }
    if (req.url === '/big') return res.end('x'.repeat(5000));
    if (req.url === '/slow') return setTimeout(() => res.end('late'), 2000);
    res.writeHead(404);
    res.end('missing');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  t.after(() => { srv.closeAllConnections(); srv.close(); });
  return `http://127.0.0.1:${srv.address().port}`;
}

test('downloads plain, gzip and brotli bodies, and follows redirects', async (t) => {
  const base = await server(t);
  assert.equal(await (await httpGet(`${base}/plain`)).text(), '||ads.example^\n');
  assert.equal(await (await httpGet(`${base}/gzip`)).text(), 'gzipped list');
  assert.equal(await (await httpGet(`${base}/br`)).text(), 'brotli list');
  const moved = await httpGet(`${base}/moved`);
  assert.equal(moved.url, `${base}/plain`);
  assert.equal(await moved.text(), '||ads.example^\n');
});

test('reports status codes, limits and timeouts like fetch would', async (t) => {
  const base = await server(t);
  const same = await httpGet(`${base}/same`);
  assert.equal(same.status, 304);
  assert.equal(same.headers.get('ETag'), '"x"');
  const missing = await httpGet(`${base}/missing`);
  assert.equal(missing.ok, false);
  assert.equal(missing.status, 404);
  await assert.rejects(httpGet(`${base}/loop`), /too many redirects/);
  await assert.rejects(httpGet(`${base}/big`, { maxBytes: 1000 }), /larger than/);
  await assert.rejects(httpGet(`${base}/slow`, { timeoutMs: 300 }), /timed out/);
  await assert.rejects(httpGet('ftp://example.org/x'), /unsupported/);
});
