// Compiled rule set with the usual adblock-list precedence:
//   @@...$important  >  ...$important  >  @@...  >  $dnsrewrite / hosts rewrite  >  block
import { parseList } from './parser.js';

function isSameOrSubdomain(host, domain) {
  return host === domain || host.endsWith('.' + domain);
}

function pushTo(map, key, rule) {
  const list = map.get(key);
  if (list) list.push(rule);
  else map.set(key, [rule]);
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

  // sources: [{ filterId, text }]
  static build(sources) {
    const engine = new RuleEngine();
    const all = [];
    const badfilters = new Set();
    for (const { filterId, text } of sources) {
      const { rules, invalid } = parseList(text, filterId);
      engine.invalid += invalid;
      for (const r of rules) {
        if (r.badfilter) badfilters.add(r.key);
        else all.push(r);
      }
    }
    for (const r of all) {
      if (badfilters.has(r.key)) continue;
      engine.add(r);
    }
    return engine;
  }

  add(rule) {
    if (rule.kind === 'exact') pushTo(this.exact, rule.domain, rule);
    else if (rule.kind === 'suffix') pushTo(this.suffix, rule.domain, rule);
    else this.generic.push(rule);
    this.count++;
    this.perFilter.set(rule.filterId, (this.perFilter.get(rule.filterId) || 0) + 1);
  }

  candidates(host) {
    const out = [];
    const ex = this.exact.get(host);
    if (ex) out.push(...ex);
    let d = host;
    for (;;) {
      const s = this.suffix.get(d);
      if (s) out.push(...s);
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
