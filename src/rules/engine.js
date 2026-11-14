// Compiled rule set with the usual adblock-list precedence:
//   @@...$important  >  ...$important  >  @@...  >  $dnsrewrite / hosts rewrite  >  block
//
// Memory: most of the ~700,000 rules in the default lists are plain blocks such as "||ads.com^" or
// "0.0.0.0 ads.com". Those are stored as one small number (which list, which spelling) instead of a
// rule object, and rebuilt into the same object only when a lookup touches them. The answers are
// identical; a rule that can't be rebuilt exactly from its domain stays a full object.
import { parseList, parseRule } from './parser.js';

function isSameOrSubdomain(host, domain) {
  return host === domain || host.endsWith('.' + domain);
}

// How a packed rule was written. The text must round-trip exactly, or the rule isn't packed.
const HOSTS_IPS = ['0.0.0.0', '127.0.0.1', '::', '::1'];
const SPELLINGS = [
  { kind: 'suffix', text: (d) => `||${d}^` },
  { kind: 'suffix', text: (d) => d },
  ...HOSTS_IPS.map((ip) => ({ kind: 'exact', text: (d) => `${ip} ${d}`, hosts: ip })),
  { kind: 'exact', text: (d) => `|${d}^` },
];
const SLOTS = 8; // SPELLINGS.length rounded up

function pack(rule) {
  if (rule.allow || rule.important || rule.badfilter || rule.rewrite || rule.dnstype || rule.denyallow || rule.clients || rule.modKey) return null;
  if (!Number.isInteger(rule.filterId)) return null;
  const style = SPELLINGS.findIndex((s) => s.kind === rule.kind && !!s.hosts === rule.hostsStyle && s.text(rule.domain) === rule.text);
  return style < 0 ? null : rule.filterId * SLOTS + style;
}

function unpack(code, domain) {
  const style = ((code % SLOTS) + SLOTS) % SLOTS;
  const s = SPELLINGS[style];
  return {
    text: s.text(domain), filterId: (code - style) / SLOTS, allow: false, important: false, badfilter: false,
    kind: s.kind, domain, regex: null, dnstype: null, denyallow: null, clients: null, rewrite: null,
    hostsStyle: !!s.hosts, modKey: '', key: s.hosts ? `hosts:${s.hosts}:${domain}` : `${s.kind}:${domain}$`,
  };
}

// A map value is one entry or an array of them; an entry is a packed number or a rule object.
function pushTo(map, key, entry) {
  const cur = map.get(key);
  if (cur === undefined) map.set(key, entry);
  else if (Array.isArray(cur)) cur.push(entry);
  else map.set(key, [cur, entry]);
}

function expand(value, domain, out) {
  if (value === undefined) return;
  for (const e of Array.isArray(value) ? value : [value]) out.push(typeof e === 'number' ? unpack(e, domain) : e);
}

export class RuleEngine {
  constructor() {
    this.exact = new Map();
    this.suffix = new Map();
    this.generic = [];
    this.count = 0;
    this.invalid = 0;
    this.perFilter = new Map();
  }

  // sources: [{ filterId, text }]. compact: false keeps every rule as an object (tests compare both).
  static build(sources, { compact = true } = {}) {
    const engine = new RuleEngine();
    // $badfilter can cancel a rule in any list, so collect those first; then add one list at a time,
    // which keeps the peak memory of a rebuild close to the size of a single list.
    const badfilters = new Set();
    for (const { filterId, text } of sources) {
      if (!text || !text.includes('badfilter')) continue;
      for (const line of text.split(/\r?\n/)) {
        if (!line.includes('badfilter')) continue;
        for (const r of parseRule(line, filterId) || []) if (r.badfilter) badfilters.add(r.key);
      }
    }
    for (const { filterId, text } of sources) {
      const { rules, invalid } = parseList(text || '', filterId);
      engine.invalid += invalid;
      for (const r of rules) {
        if (r.badfilter || badfilters.has(r.key)) continue;
        engine.add(r, compact);
      }
    }
    return engine;
  }

  add(rule, compact = true) {
    const packed = compact ? pack(rule) : null;
    const entry = packed ?? rule;
    if (rule.kind === 'exact') pushTo(this.exact, rule.domain, entry);
    else if (rule.kind === 'suffix') pushTo(this.suffix, rule.domain, entry);
    else this.generic.push(rule);
    this.count++;
    this.perFilter.set(rule.filterId, (this.perFilter.get(rule.filterId) || 0) + 1);
  }

  candidates(host) {
    const out = [];
    expand(this.exact.get(host), host, out);
    let d = host;
    for (;;) {
      expand(this.suffix.get(d), d, out);
      const dot = d.indexOf('.');
      if (dot < 0) break;
      d = d.slice(dot + 1);
    }
    for (const r of this.generic) if (r.regex.test(host)) out.push(r);
    return out;
  }

  static applies(rule, host, qtype, client) {
    if (rule.dnstype) {
      if (rule.dnstype.include.size && !rule.dnstype.include.has(qtype)) return false;
      if (rule.dnstype.exclude.has(qtype)) return false;
    }
    if (rule.clients && !(client && rule.clients.includes(client))) return false;
    if (rule.denyallow && rule.denyallow.some((d) => isSameOrSubdomain(host, d))) return false;
    return true;
  }

  static rewriteResult(rewrites) {
    const rcodeRule = rewrites.find((r) => r.rewrite.rcode !== 0);
    if (rcodeRule) return { action: 'rewrite', rule: rcodeRule, rewrite: rcodeRule.rewrite };
    const records = rewrites.flatMap((r) => r.rewrite.records);
    return { action: 'rewrite', rule: rewrites[0], rewrite: { rcode: 0, records } };
  }

  // Returns { action: 'allow'|'block'|'rewrite'|'none', rule, rewrite? }
  match(name, { qtype = 1, client = null } = {}) {
    const host = String(name).toLowerCase().replace(/\.$/, '');
    if (!host) return { action: 'none', rule: null };
    const rules = this.candidates(host).filter((r) => RuleEngine.applies(r, host, qtype, client));
    if (!rules.length) return { action: 'none', rule: null };

    const allowImportant = rules.find((r) => r.allow && r.important);
    if (allowImportant) return { action: 'allow', rule: allowImportant };
    const importantRewrites = rules.filter((r) => !r.allow && r.important && r.rewrite);
    if (importantRewrites.length) return RuleEngine.rewriteResult(importantRewrites);
    const blockImportant = rules.find((r) => !r.allow && r.important && !r.rewrite);
    if (blockImportant) return { action: 'block', rule: blockImportant };
    const allow = rules.find((r) => r.allow && !r.rewrite);
    if (allow) return { action: 'allow', rule: allow };
    const rewrites = rules.filter((r) => !r.allow && r.rewrite);
    if (rewrites.length) return RuleEngine.rewriteResult(rewrites);
    const block = rules.find((r) => !r.allow);
    if (block) return { action: 'block', rule: block };
    return { action: 'none', rule: null };
  }
}
