// Hourly statistics buckets persisted to disk (queries, blocks, top domains, clients).
import fs from 'node:fs';
import path from 'node:path';
import { writeFileAtomic } from './fsutil.js';

const HOUR = 3600 * 1000;
const TOP_KEEP = 500;

function bump(obj, key, n = 1) {
  obj[key] = (obj[key] || 0) + n;
}

function trimTop(obj, keep = TOP_KEEP) {
  const entries = Object.entries(obj);
  if (entries.length <= keep) return obj;
  return Object.fromEntries(entries.sort((a, b) => b[1] - a[1]).slice(0, keep));
}

function newBucket(hour) {
  return { hour, total: 0, blocked: 0, rewritten: 0, cached: 0, totalMs: 0, domains: {}, blockedDomains: {}, clients: {}, filters: {} };
}

export class Stats {
  constructor(dataDir, retentionDays = 30) {
    this.file = path.join(dataDir, 'stats.json');
    this.retentionDays = retentionDays;
    this.buckets = [];
    this.dirty = false;
  }

  load() {
    try {
      this.buckets = JSON.parse(fs.readFileSync(this.file, 'utf8')).buckets || [];
    } catch {
      this.buckets = [];
    }
    return this;
  }

  save() {
    if (!this.dirty) return;
    this.prune();
    writeFileAtomic(this.file, JSON.stringify({ version: 1, buckets: this.buckets }));
    this.dirty = false;
  }

  prune(now = Date.now()) {
    const minHour = Math.floor(now / HOUR) - this.retentionDays * 24;
    this.buckets = this.buckets.filter((b) => b.hour >= minHour);
  }

  current(now = Date.now()) {
    const hour = Math.floor(now / HOUR);
    let b = this.buckets[this.buckets.length - 1];
    if (!b || b.hour !== hour) {
      if (b) {
        b.domains = trimTop(b.domains);
        b.blockedDomains = trimTop(b.blockedDomains);
      }
      b = newBucket(hour);
      this.buckets.push(b);
    }
    return b;
  }

  record({ name, status, client, ms = 0, cached = false, filterId = null }) {
    const b = this.current();
    b.total++;
    b.totalMs += ms;
    if (cached) b.cached++;
    bump(b.domains, name);
    if (client) bump(b.clients, client);
    if (status === 'blocked') {
      b.blocked++;
      bump(b.blockedDomains, name);
      if (filterId !== null) bump(b.filters, String(filterId));
    } else if (status === 'rewritten') b.rewritten++;
    this.dirty = true;
  }

  // `classify(host)` → { company, companyId, category } | null attributes traffic to companies.
  summary(periodHours = 24, now = Date.now(), classify = null) {
    const fromHour = Math.floor(now / HOUR) - periodHours + 1;
    const sel = this.buckets.filter((b) => b.hour >= fromHour);
    const sum = newBucket(fromHour);
    for (const b of sel) {
      sum.total += b.total;
      sum.blocked += b.blocked;
      sum.rewritten += b.rewritten;
      sum.cached += b.cached;
      sum.totalMs += b.totalMs;
      for (const [k, v] of Object.entries(b.domains)) bump(sum.domains, k, v);
      for (const [k, v] of Object.entries(b.blockedDomains)) bump(sum.blockedDomains, k, v);
      for (const [k, v] of Object.entries(b.clients)) bump(sum.clients, k, v);
      for (const [k, v] of Object.entries(b.filters)) bump(sum.filters, k, v);
    }
    const top = (o, n = 20) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n).map(([name, count]) => ({ name, count }));
    // Time series: one point per hour (24h) or per day (longer periods).
    const step = periodHours <= 48 ? 1 : 24;
    const series = [];
    for (let h = fromHour; h <= Math.floor(now / HOUR); h += step) {
      const pts = sel.filter((b) => b.hour >= h && b.hour < h + step);
      series.push({ time: h * HOUR, total: pts.reduce((a, b) => a + b.total, 0), blocked: pts.reduce((a, b) => a + b.blocked, 0) });
    }
    const companies = {};
    const categories = {};
    if (classify) {
      const add = (map, key, field, n, extra) => {
        const e = (map[key] ||= { name: key, requests: 0, blocked: 0, ...extra });
        e[field] += n;
      };
      for (const [field, domains] of [['requests', sum.domains], ['blocked', sum.blockedDomains]]) {
        for (const [domain, n] of Object.entries(domains)) {
          const c = classify(domain);
          if (!c) continue;
          add(companies, c.company, field, n, { id: c.companyId, category: c.category });
          add(categories, c.category, field, n);
        }
      }
    }
    const rank = (o, n) => Object.values(o).sort((a, b) => b.requests - a.requests).slice(0, n);
    return {
      periodHours,
      topCompanies: rank(companies, 25),
      categories: rank(categories, 20),
      trackerRequests: Object.values(categories).reduce((a, c) => a + c.requests, 0),
      total: sum.total,
      blocked: sum.blocked,
      rewritten: sum.rewritten,
      cached: sum.cached,
      blockedPercent: sum.total ? +(100 * sum.blocked / sum.total).toFixed(1) : 0,
      avgMs: sum.total ? +(sum.totalMs / sum.total).toFixed(1) : 0,
      topDomains: top(sum.domains),
      topBlocked: top(sum.blockedDomains),
      topClients: top(sum.clients, 10),
      byFilter: top(sum.filters, 50),
      series,
    };
  }

  clear() {
    this.buckets = [];
    this.dirty = true;
    this.save();
  }
}
