import test from 'node:test';
import assert from 'node:assert/strict';
import { buildQuery, parse, buildResponse, truncate, TYPE, RCODE } from '../src/dns/packet.js';
import { DnsCache } from '../src/dns/cache.js';
import { parseUpstream } from '../src/dns/upstream.js';
import { decodeStamp } from '../src/dns/stamp.js';

test('query round-trips through the parser', () => {
  const q = parse(buildQuery('Ads.Example.COM', TYPE.AAAA, 4242));
  assert.equal(q.id, 4242);
  assert.equal(q.rd, true);
  assert.deepEqual(q.questions, [{ name: 'ads.example.com', type: TYPE.AAAA, class: 1 }]);
});

test('synthesized responses carry answers, CNAME chains and rcodes', () => {
  const qbuf = buildQuery('a.com', TYPE.A, 7);
  const q = parse(qbuf);
  const r = parse(buildResponse(qbuf, q, { records: [{ type: 'CNAME', value: 'b.net' }, { type: 'A', value: '1.2.3.4', name: 'b.net' }], ttl: 30 }));
  assert.equal(r.id, 7);
  assert.equal(r.qr, true);
  assert.equal(r.answers[0].data, 'b.net');
  assert.equal(r.answers[1].name, 'b.net');
  assert.equal(r.answers[1].data, '1.2.3.4');
  assert.equal(r.answers[1].ttl, 30);
  assert.equal(parse(buildResponse(qbuf, q, { rcode: RCODE.NXDOMAIN })).rcode, RCODE.NXDOMAIN);
});

test('AAAA encode/decode including :: compression', () => {
  const qbuf = buildQuery('a.com', TYPE.AAAA);
  const q = parse(qbuf);
  for (const ip of ['::', '2001:db8::1', 'fe80::1:2:3:4', '1:2:3:4:5:6:7:8']) {
    const r = parse(buildResponse(qbuf, q, { records: [{ type: 'AAAA', value: ip }] }));
    assert.equal(r.answers[0].data, ip);
  }
});

test('truncate keeps only header + question with TC set', () => {
  const qbuf = buildQuery('a.com', TYPE.A);
  const q = parse(qbuf);
  const full = buildResponse(qbuf, q, { records: [{ type: 'A', value: '1.1.1.1' }] });
  const t = parse(truncate(full, parse(full)));
  assert.equal(t.tc, true);
  assert.equal(t.answers.length, 0);
});

test('cache returns the client ID and honours TTL', () => {
  const qbuf = buildQuery('a.com', TYPE.A, 1);
  const q = parse(qbuf);
  const cache = new DnsCache();
  const key = DnsCache.key(q.questions[0], false);
  cache.set(key, buildResponse(qbuf, q, { records: [{ type: 'A', value: '5.6.7.8' }], ttl: 300 }));
  const hit = parse(cache.get(key, 999));
  assert.equal(hit.id, 999);
  assert.equal(hit.answers[0].data, '5.6.7.8');
  assert.ok(hit.answers[0].ttl <= 300);
  cache.set('zero', buildResponse(qbuf, q, { records: [{ type: 'A', value: '5.6.7.8' }], ttl: 0 }));
  assert.equal(cache.get('zero', 1), null);
});

test('upstream specs', () => {
  assert.deepEqual(parseUpstream('1.1.1.1'), { proto: 'udp', host: '1.1.1.1', port: 53, path: null, ip: null, spec: '1.1.1.1' });
  assert.equal(parseUpstream('[2606:4700::1111]:5353').port, 5353);
  assert.equal(parseUpstream('2606:4700::1111').host, '2606:4700::1111');
  assert.equal(parseUpstream('tls://dns.quad9.net').port, 853);
  const doh = parseUpstream('https://dns.cloudflare.com/dns-query');
  assert.equal(doh.proto, 'https');
  assert.equal(doh.path, '/dns-query');
  assert.throws(() => parseUpstream('quic://dns.adguard-dns.com'));
});

test('DNS stamp decoding (DoH)', () => {
  // Build a DoH stamp: proto 0x02, props, addr "1.1.1.1", no hashes, host, path
  const lp = (s) => Buffer.concat([Buffer.from([Buffer.byteLength(s)]), Buffer.from(s)]);
  const buf = Buffer.concat([Buffer.from([0x02, 0, 0, 0, 0, 0, 0, 0, 0]), lp('1.1.1.1'), Buffer.from([0]), lp('dns.example'), lp('/dns-query')]);
  const r = decodeStamp('sdns://' + buf.toString('base64url'));
  assert.deepEqual(r, { url: 'https://dns.example:443/dns-query', ip: '1.1.1.1' });
});
