import test from 'node:test';
import assert from 'node:assert/strict';
import { siteHost, brokenSitePatch } from '../src/sites.js';
import { DEFAULTS, deepMerge } from '../src/settings.js';

test('site host parsing', () => {
  assert.equal(siteHost('https://www.Gemini.google.com/app?x=1'), 'gemini.google.com');
  assert.equal(siteHost('example.com.'), 'example.com');
  assert.equal(siteHost('shop.example.co.uk:8443/cart'), 'shop.example.co.uk');
  assert.throws(() => siteHost('not a site'), /example\.com/);
  assert.throws(() => siteHost(''), /example\.com/);
});

test('broken site: allowlist + HTTPS exclusion, undone exactly', () => {
  let s = structuredClone(DEFAULTS);
  s.filtering.allowlist.domains = [{ name: 'mine.org', enabled: true }];
  s.https.exclusions = ['bank.example'];
  s = deepMerge(s, brokenSitePatch(s, 'gemini.google.com', true));
  assert.deepEqual(s.filtering.allowlist.domains.map((d) => d.name), ['mine.org', 'gemini.google.com']);
  assert.deepEqual(s.https.exclusions, ['bank.example', 'gemini.google.com']);
  assert.deepEqual(s.filtering.brokenSites, ['gemini.google.com']);
  // marking twice changes nothing
  const again = deepMerge(s, brokenSitePatch(s, 'gemini.google.com', true));
  assert.deepEqual(again, s);
  s = deepMerge(s, brokenSitePatch(s, 'gemini.google.com', false));
  assert.deepEqual(s.filtering.allowlist.domains.map((d) => d.name), ['mine.org']);
  assert.deepEqual(s.https.exclusions, ['bank.example']);
  assert.deepEqual(s.filtering.brokenSites, []);
});
