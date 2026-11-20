import test from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { buildQuery, buildResponse, parse } from '../src/dns/packet.js';
import { Resolver } from '../src/dns/upstream.js';
import { parseBackup, parseInterfaces } from '../src/network.js';

test('reads the network DNS servers from the registry and the DNS backup', () => {
  const reg = [
    'HKEY_LOCAL_MACHINE\\...\\Interfaces\\{abc}',
    '    DhcpNameServer    REG_SZ    192.168.1.1 8.8.8.8',
    '    NameServer    REG_SZ    127.0.0.1',
    '    NameServer    REG_SZ    10.0.0.53,10.0.0.54',
    '    DhcpNameServer    REG_SZ    fe80::1',
  ].join('\r\n');
  assert.deepEqual(parseInterfaces(reg), ['192.168.1.1', '8.8.8.8', '10.0.0.53', '10.0.0.54']);
  assert.deepEqual(parseBackup('﻿[{"IPv4":["192.168.0.1"],"IPv6":["fe80::1"]},{"IPv4":[]}]'), ['192.168.0.1']);
  assert.deepEqual(parseBackup('not json'), []);
});

// A tiny DNS server standing in for the hotel router: answers every A query with 10.9.9.9.
async function router(t) {
  const sock = dgram.createSocket('udp4');
  t.after(() => { try { sock.close(); } catch {} });
  let served = 0;
  sock.on('message', (msg, rinfo) => {
    served++;
    sock.send(buildResponse(msg, parse(msg), { records: [{ type: 'A', value: '10.9.9.9' }], ttl: 5 }), rinfo.port, rinfo.address);
  });
  await new Promise((r) => sock.bind(0, '127.0.0.1', r));
  return { port: sock.address().port, sock, get served() { return served; } };
}

function resolverWith(r, { secureUp }) {
  const modes = [];
  const res = new Resolver({ upstreamMode: 'parallel', upstreams: [], fallback: [], bootstrap: [], timeoutMs: 500 }, {
    networkDns: async () => ['127.0.0.1'],
    onNetworkMode: (on) => modes.push(on),
  });
  // Point "port 53" at the stand-in router, and decide whether secure DNS works.
  res.viaNetwork = async function viaNetwork(query) {
    return new Promise((resolve, reject) => {
      const s = dgram.createSocket('udp4');
      // Resend like a real DNS client: other network software on a PC can drop a first UDP packet.
      const resend = setInterval(() => s.send(query, r.port, '127.0.0.1'), 150);
      const t = setTimeout(() => { clearInterval(resend); s.close(); reject(new Error('timeout')); }, 2000);
      s.on('message', (m) => { clearTimeout(t); clearInterval(resend); s.close(); resolve({ response: m, upstream: 'network 127.0.0.1' }); });
      s.send(query, r.port, '127.0.0.1');
    });
  };
  res.resolveSecure = async () => { if (secureUp.value) return { response: Buffer.alloc(12), upstream: 'secure' }; throw new Error('blocked by the hotel'); };
  return { res, modes };
}

test('falls back to the network DNS when secure DNS is blocked, and returns when it works again', async (t) => {
  const r = await router(t);
  const secureUp = { value: false };
  const { res, modes } = resolverWith(r, { secureUp });
  const answer = await res.resolve(buildQuery('captive.example', 1));
  assert.equal(answer.upstream, 'network 127.0.0.1');
  assert.equal(res.usingNetwork, true);
  assert.deepEqual(modes, [true]);

  secureUp.value = true;
  res.nextProbe = 0; // as if the probe interval had passed
  await res.resolve(buildQuery('captive.example', 1));
  await new Promise((done) => setTimeout(done, 20));
  assert.equal(res.usingNetwork, false);
  assert.deepEqual(modes, [true, false]);
  assert.equal((await res.resolve(buildQuery('example.org', 1))).upstream, 'secure');
});

test('nothing changes while secure DNS works', async (t) => {
  const r = await router(t);
  const { res, modes } = resolverWith(r, { secureUp: { value: true } });
  assert.equal((await res.resolve(buildQuery('example.org', 1))).upstream, 'secure');
  assert.equal(r.served, 0);
  assert.deepEqual(modes, []);
});

test('a lost UDP packet is resent instead of waiting out the timeout', async (t) => {
  const { udpExchange } = await import('../src/dns/upstream.js');
  const sock = dgram.createSocket('udp4');
  t.after(() => sock.close());
  let seen = 0;
  sock.on('message', (msg, rinfo) => {
    if (++seen === 1) return; // drop the first question
    sock.send(buildResponse(msg, parse(msg), { records: [{ type: 'A', value: '10.9.9.9' }], ttl: 5 }), rinfo.port, rinfo.address);
  });
  await new Promise((r) => sock.bind(0, '127.0.0.1', r));
  const started = Date.now();
  const res = parse(await udpExchange('127.0.0.1', sock.address().port, buildQuery('lost.example', 1), 3000, 200));
  assert.equal(res.answers[0].data, '10.9.9.9');
  assert.ok(Date.now() - started < 1500);
});
