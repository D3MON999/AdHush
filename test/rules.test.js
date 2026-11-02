import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRule, parseList } from '../src/rules/parser.js';
import { RuleEngine } from '../src/rules/engine.js';

const build = (text) => RuleEngine.build([{ filterId: 1, text }]);

test('parser accepts DNS rules and rejects HTTP-only ones', () => {
  assert.equal(parseRule('||ads.example.com^')[0].kind, 'suffix');
  assert.equal(parseRule('|ads.example.com^')[0].kind, 'exact');
  assert.equal(parseRule('ads.example.com')[0].kind, 'suffix');
  assert.equal(parseRule('/^ad[0-9]+\\./')[0].kind, 'regex');
  assert.equal(parseRule('*ads*.net^')[0].kind, 'regex');
  assert.equal(parseRule('||example.com/path^'), null);
  assert.equal(parseRule('||example.com^$third-party'), null);
  assert.equal(parseRule('example.com##.banner'), null);
  assert.equal(parseRule('! comment'), null);
  assert.equal(parseRule('# hosts comment'), null);
  assert.equal(parseRule('||*^'), null);
});

test('hosts syntax: blocking IPs block, other IPs rewrite, localhost ignored', () => {
  const rules = parseRule('0.0.0.0 a.com b.com # trailing');
  assert.deepEqual(rules.map((r) => r.domain), ['a.com', 'b.com']);
  assert.equal(rules[0].rewrite, null);
  assert.equal(parseRule('127.0.0.1 localhost').length, 0);
  assert.deepEqual(parseRule('10.0.0.5 nas.home.lan')[0].rewrite, { rcode: 0, records: [{ type: 'A', value: '10.0.0.5' }] });
});

test('suffix rules cover subdomains, exact rules do not', () => {
  const e = build('||ads.com^\n|exact.com^');
  assert.equal(e.match('ads.com').action, 'block');
  assert.equal(e.match('x.y.ads.com').action, 'block');
  assert.equal(e.match('notads.com').action, 'none');
  assert.equal(e.match('exact.com').action, 'block');
  assert.equal(e.match('sub.exact.com').action, 'none');
});

test('precedence: allow > block, important block > allow, important allow > all', () => {
  assert.equal(build('||a.com^\n@@||a.com^').match('a.com').action, 'allow');
  assert.equal(build('||a.com^$important\n@@||a.com^').match('a.com').action, 'block');
  assert.equal(build('||a.com^$important\n@@||a.com^$important').match('a.com').action, 'allow');
});

test('badfilter disables the matching rule', () => {
  const e = build('||a.com^\n||a.com^$badfilter\n||b.com^');
  assert.equal(e.match('a.com').action, 'none');
  assert.equal(e.match('b.com').action, 'block');
});

test('dnstype, denyallow and client modifiers', () => {
  const e = build('||v6.com^$dnstype=AAAA\n||cdn.com^$denyallow=ok.cdn.com\n||kid.com^$client=10.0.0.9');
  assert.equal(e.match('v6.com', { qtype: 28 }).action, 'block');
  assert.equal(e.match('v6.com', { qtype: 1 }).action, 'none');
  assert.equal(e.match('x.cdn.com').action, 'block');
  assert.equal(e.match('ok.cdn.com').action, 'none');
  assert.equal(e.match('kid.com', { client: '10.0.0.9' }).action, 'block');
  assert.equal(e.match('kid.com', { client: '10.0.0.1' }).action, 'none');
});

test('dnsrewrite forms', () => {
  const e = build('||r1.com^$dnsrewrite=1.2.3.4\n||r2.com^$dnsrewrite=NXDOMAIN\n||r3.com^$dnsrewrite=NOERROR;CNAME;target.net');
  assert.deepEqual(e.match('r1.com').rewrite, { rcode: 0, records: [{ type: 'A', value: '1.2.3.4' }] });
  assert.equal(e.match('r2.com').rewrite.rcode, 3);
  assert.deepEqual(e.match('r3.com').rewrite.records, [{ type: 'CNAME', value: 'target.net' }]);
});

test('regex and wildcard rules', () => {
  const e = build('/^ad[0-9]+\\.example\\.org$/\n*track*.net^');
  assert.equal(e.match('ad12.example.org').action, 'block');
  assert.equal(e.match('adx.example.org').action, 'none');
  assert.equal(e.match('mytracker.net').action, 'block');
  assert.equal(e.match('mytracker.net.evil.com').action, 'none');
});

test('parseList counts rules and skips comments', () => {
  const { rules } = parseList('! Title: x\n# comment\n||a.com^\n0.0.0.0 b.com c.com\nsite.com##.ad\n');
  assert.equal(rules.length, 3);
});
