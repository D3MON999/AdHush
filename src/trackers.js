// Tracker/company database (AdguardTeam/companiesdb, CC BY-SA 4.0): maps domains to the tracker,
// its category (advertising, analytics, social…) and the company behind it.
import fs from 'node:fs';
import path from 'node:path';
import { logger } from './log.js';
import { writeFileAtomic } from './fsutil.js';

const log = logger('trackers');
const BASE = 'https://raw.githubusercontent.com/AdguardTeam/companiesdb/main/dist/';
const MAX_AGE = 7 * 24 * 3600 * 1000;

export class TrackerDb {
  constructor(dataDir) {
    this.dir = path.join(dataDir, 'trackers');
    this.domains = new Map(); // domain → tracker id
    this.trackers = {};
    this.companies = {};
    this.categories = {};
    this.updatedAt = 0;
    this.timer = null;
  }

  load() {
    try {
      const t = JSON.parse(fs.readFileSync(path.join(this.dir, 'trackers.json'), 'utf8'));
      const c = JSON.parse(fs.readFileSync(path.join(this.dir, 'companies.json'), 'utf8'));
      this.index(t, c);
      this.updatedAt = fs.statSync(path.join(this.dir, 'trackers.json')).mtimeMs;
    } catch {
      // not downloaded yet
    }
    return this;
  }

  index(t, c) {
    this.trackers = t.trackers || {};
    this.categories = t.categories || {};
    this.companies = c.companies || {};
    this.domains = new Map(Object.entries(t.trackerDomains || {}));
  }

  async update() {
    const get = async (name) => {
      const res = await fetch(BASE + name, { headers: { 'user-agent': 'AdHush' }, signal: AbortSignal.timeout(60000) });
      if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
      return res.json();
    };
    const [t, c] = await Promise.all([get('trackers.json'), get('companies.json')]);
    if (!t.trackers || !t.trackerDomains || !c.companies) throw new Error('unexpected companiesdb format');
    fs.mkdirSync(this.dir, { recursive: true });
    writeFileAtomic(path.join(this.dir, 'trackers.json'), JSON.stringify(t));
    writeFileAtomic(path.join(this.dir, 'companies.json'), JSON.stringify(c));
    this.index(t, c);
    this.updatedAt = Date.now();
    log.info(`tracker database updated: ${this.domains.size} domains, ${Object.keys(this.companies).length} companies`);
  }

  start() {
    const check = () => {
      if (Date.now() - this.updatedAt > MAX_AGE) this.update().catch((e) => log.warn(`update failed: ${e.message}`));
    };
    check();
    this.timer = setInterval(check, 6 * 3600 * 1000);
    this.timer.unref();
  }

  stop() {
    clearInterval(this.timer);
  }

  /** { tracker, category, companyId, company } for a hostname, matching parent domains too. */
  lookup(host) {
    let d = String(host).toLowerCase();
    for (;;) {
      const id = this.domains.get(d);
      if (id) {
        const t = this.trackers[id] || {};
        const company = this.companies[t.companyId] || {};
        return {
          tracker: t.name || id,
          category: this.categories[t.categoryId] || 'unknown',
          companyId: t.companyId || id,
          company: company.name || t.name || id,
          url: company.websiteUrl || t.url || null,
        };
      }
      const dot = d.indexOf('.');
      if (dot < 0) return null;
      d = d.slice(dot + 1);
    }
  }

  info() {
    return { domains: this.domains.size, companies: Object.keys(this.companies).length, updatedAt: this.updatedAt };
  }
}
