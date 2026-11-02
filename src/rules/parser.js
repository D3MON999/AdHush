// Parses DNS-level filtering rules: adblock-style (||example.org^$important),
// hosts-style (0.0.0.0 example.org), plain domains and /regex/ rules.
// Rules that only make sense for HTTP filtering (paths, cosmetic, $third-party...) are rejected.
import net from 'node:net';

export const RR_TYPES = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, NAPTR: 35,
  DS: 43, RRSIG: 46, DNSKEY: 48, SVCB: 64, HTTPS: 65, ANY: 255, CAA: 257,
};
export const RR_NAMES = Object.fromEntries(Object.entries(RR_TYPES).map(([k, v]) => [v, k]));

const RCODES = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 };
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;
const BLOCKING_IPS = new Set(['0.0.0.0', '127.0.0.1', '::', '::1', '0:0:0:0:0:0:0:0', '0:0:0:0:0:0:0:1']);
const HOSTS_IGNORED = new Set(['localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost',
  'ip6-loopback', 'ip6-localnet', 'ip6-mcastprefix', 'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts', '0.0.0.0']);
const IGNORED_MODIFIERS = new Set(['all', 'document', 'doc', 'match-case', 'ctag', 'popup']);

export function isDomain(s) {
  return DOMAIN_RE.test(s) && s.includes('.') || s === 'localhost';
}

function isCosmetic(line) {
  return /#[@$%?]?#|#@?\$\??#|\$\$|\$@\$/.test(line);
}

function escapeRegex(s) {
  return s.replace(/[.+?${}()[\]\\]/g, '\\$&');
}

// Converts an adblock hostname pattern to a RegExp matched against a bare hostname.
function patternToRegex(p) {
  let src = '';
  let rest = p;
  if (rest.startsWith('||')) { src = '(?:^|\\.)'; rest = rest.slice(2); }
  else if (rest.startsWith('|')) { src = '^'; rest = rest.slice(1); }
  let tail = '';
  if (rest.endsWith('|')) { tail = '$'; rest = rest.slice(0, -1); }
  for (const ch of rest) {
    if (ch === '*') src += '.*';
    else if (ch === '^') src += '$'; // inside a hostname a separator can only be the end
    else src += escapeRegex(ch);
  }
  return new RegExp(src + tail);
}

function parseDnsRewrite(value) {
  const v = value.trim();
  const upper = v.toUpperCase();
  if (upper in RCODES) return { rcode: RCODES[upper], records: [] };
  if (v.includes(';')) {
    const [rcodeStr, type, data = ''] = v.split(';');
    const rcode = RCODES[rcodeStr.toUpperCase()];
    if (rcode === undefined) return null;
    const t = type.toUpperCase();
    if (t === 'A' && net.isIPv4(data)) return { rcode, records: [{ type: 'A', value: data }] };
    if (t === 'AAAA' && net.isIPv6(data)) return { rcode, records: [{ type: 'AAAA', value: data }] };
    if (t === 'CNAME' && isDomain(data.toLowerCase())) return { rcode, records: [{ type: 'CNAME', value: data.toLowerCase() }] };
    if (!t) return { rcode, records: [] };
    return null;
  }
  if (net.isIPv4(v)) return { rcode: 0, records: [{ type: 'A', value: v }] };
  if (net.isIPv6(v)) return { rcode: 0, records: [{ type: 'AAAA', value: v }] };
  if (isDomain(v.toLowerCase())) return { rcode: 0, records: [{ type: 'CNAME', value: v.toLowerCase() }] };
  return null;
}

function parseModifiers(str, rule) {
  const kept = [];
  for (const raw of str.split(',')) {
    const m = raw.trim();
    if (!m) continue;
    const eq = m.indexOf('=');
    const name = (eq < 0 ? m : m.slice(0, eq)).toLowerCase();
    const value = eq < 0 ? '' : m.slice(eq + 1);
    switch (name) {
      case 'important': rule.important = true; kept.push('important'); break;
      case 'badfilter': rule.badfilter = true; break;
      case 'dnstype': {
        const include = new Set();
        const exclude = new Set();
        for (const t of value.split('|')) {
          const neg = t.startsWith('~');
          const code = RR_TYPES[(neg ? t.slice(1) : t).toUpperCase()];
          if (code === undefined) return false;
          (neg ? exclude : include).add(code);
        }
        rule.dnstype = { include, exclude };
        kept.push(`dnstype=${value.toUpperCase()}`);
        break;
      }
      case 'dnsrewrite': {
        const rw = parseDnsRewrite(value);
        if (!rw) return false;
        rule.rewrite = rw;
        kept.push(`dnsrewrite=${value}`);
        break;
      }
      case 'denyallow': {
        const domains = value.toLowerCase().split('|').filter(Boolean);
        if (!domains.length || !domains.every(isDomain)) return false;
        rule.denyallow = domains;
        kept.push(`denyallow=${domains.sort().join('|')}`);
        break;
      }
      case 'client': {
        rule.clients = value.split('|').map((c) => c.trim().replace(/^'|'$/g, '')).filter(Boolean);
        kept.push(`client=${rule.clients.sort().join('|')}`);
        break;
      }
      default:
        if (IGNORED_MODIFIERS.has(name)) break;
        return false; // modifier not applicable to DNS filtering
    }
  }
  rule.modKey = kept.sort().join(',');
  return true;
}

function baseRule(text, filterId) {
  return {
    text, filterId, allow: false, important: false, badfilter: false,
    kind: null, domain: null, regex: null, dnstype: null, denyallow: null,
    clients: null, rewrite: null, hostsStyle: false, modKey: '', key: '',
  };
}

function parseHostsLine(line, filterId) {
  const hashAt = line.indexOf('#');
  const body = (hashAt >= 0 ? line.slice(0, hashAt) : line).trim();
  const parts = body.split(/\s+/);
  if (parts.length < 2) return null;
  const ip = parts[0].replace(/%.*$/, '');
  if (!net.isIP(ip)) return null;
  const rules = [];
  for (const host of parts.slice(1)) {
    const h = host.toLowerCase().replace(/\.$/, '');
    if (HOSTS_IGNORED.has(h) || !isDomain(h)) continue;
    const r = baseRule(`${ip} ${h}`, filterId);
    r.kind = 'exact';
    r.domain = h;
    r.hostsStyle = true;
    if (!BLOCKING_IPS.has(ip)) {
      r.rewrite = { rcode: 0, records: [{ type: net.isIPv4(ip) ? 'A' : 'AAAA', value: ip }] };
    }
    r.key = `hosts:${ip}:${h}`;
    rules.push(r);
  }
  return rules;
}

// Returns an array of rules (hosts lines may produce several) or null if the line is
// a comment, empty, or not applicable to DNS filtering.
export function parseRule(line, filterId = 0) {
  const text = line.trim();
  if (!text || text.startsWith('!') || text.startsWith('[')) return null;
  if (text.startsWith('#')) return null;
  if (isCosmetic(text)) return null;

  if (/^[0-9a-f.:]+(%\w+)?\s/i.test(text)) return parseHostsLine(text, filterId);

  const rule = baseRule(text, filterId);
  let body = text;
  if (body.startsWith('@@')) { rule.allow = true; body = body.slice(2); }

  let pattern = body;
  let mods = '';
  if (body.startsWith('/')) {
    const close = body.lastIndexOf('/');
    if (close <= 0) return null;
    const dollar = body.indexOf('$', close);
    pattern = dollar >= 0 ? body.slice(0, dollar) : body;
    mods = dollar >= 0 ? body.slice(dollar + 1) : '';
  } else {
    const dollar = body.lastIndexOf('$');
    if (dollar >= 0) { pattern = body.slice(0, dollar); mods = body.slice(dollar + 1); }
  }
  if (mods && !parseModifiers(mods, rule)) return null;

  if (pattern.startsWith('/') && pattern.endsWith('/') && pattern.length > 2) {
    try {
      rule.kind = 'regex';
      rule.regex = new RegExp(pattern.slice(1, -1), 'i');
    } catch {
      return null;
    }
  } else {
    const p = pattern.toLowerCase();
    if (!p || p.includes('/') || p.includes(':') || p === '*' || p === '||' || p === '|') return null;
    const core = p.replace(/^\|\|/, '').replace(/^\|/, '').replace(/\^?\|?$/, '');
    if (p.startsWith('||') && isDomain(core) && /^\|\|[^*|^]+\^?\|?$/.test(p)) {
      rule.kind = 'suffix';
      rule.domain = core;
    } else if (p.startsWith('|') && !p.startsWith('||') && isDomain(core) && /\^|\|$/.test(p)) {
      rule.kind = 'exact';
      rule.domain = core;
    } else if (isDomain(p)) {
      rule.kind = 'suffix'; // a bare domain blocks the domain and its subdomains
      rule.domain = p;
    } else {
      if (!/^[a-z0-9_.\-*|^]+$/.test(p)) return null;
      if (p.replace(/[*|^.]/g, '').length < 3) return null; // too broad, e.g. "*.*"
      rule.kind = 'regex';
      rule.regex = patternToRegex(p);
    }
  }
  rule.key = `${rule.allow ? '@@' : ''}${rule.kind}:${rule.domain ?? rule.regex.source}$${rule.modKey}`;
  return [rule];
}

export function parseList(text, filterId = 0) {
  const rules = [];
  let invalid = 0;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('!') || trimmed.startsWith('#') && !trimmed.startsWith('##')) continue;
    const parsed = parseRule(trimmed, filterId);
    if (parsed) rules.push(...parsed);
    else if (!isCosmetic(trimmed)) invalid++;
  }
  return { rules, invalid };
}
