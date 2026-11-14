import test from 'node:test';
import assert from 'node:assert/strict';
import { Upstream } from '../src/dns/upstream.js';

// A stand-in for a persistent DoH/DoT connection.
class FakeConn {
  constructor(fail) {
    this.fail = fail;
    this.closed = false;
    this.pending = [];
  }

  exchange(query) {
    return new Promise((resolve, reject) => {
      if (this.closed) return reject(new Error('used after close'));
      this.pending.push(reject);
      setTimeout(() => (this.fail ? reject(new Error('New streams cannot be created after receiving a GOAWAY')) : resolve(query)), 5);
    });
  }

  close() {
    this.closed = true;
    for (const reject of this.pending) reject(new Error('closed by another query'));
  }
}

function upstreamWith(first) {
  const up = new Upstream('https://192.0.2.1/dns-query');
  const made = [];
  up.conn = first;
  up.connection = async function connection() {
    if (!this.conn) {
      this.conn = new FakeConn(false);
      made.push(this.conn);
    }
    return { ip: '192.0.2.1', conn: this.conn };
  };
  return { up, made };
}

test('lookups that fail together retry on one fresh connection without closing it', async () => {
  const stale = new FakeConn(true);
  const { up, made } = upstreamWith(stale);
  const queries = [1, 2, 3, 4, 5].map((n) => Buffer.from([0, n, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
  const answers = await Promise.all(queries.map((q) => up.exchange(q)));
  assert.equal(answers.length, 5);
  assert.equal(made.length, 1, 'one replacement connection');
  assert.equal(made[0].closed, false, 'the replacement stays open');
  assert.equal(up.info().errors, 0);
});

test('a timeout is not retried', async () => {
  const conn = { exchange: () => Promise.reject(Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' })), close() {} };
  const { up } = upstreamWith(conn);
  await assert.rejects(up.exchange(Buffer.alloc(12)), /timed out/);
  assert.equal(up.info().errors, 1);
});
