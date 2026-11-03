// Composition root: wires settings, filters, rule engine, resolver, DNS server, stats and API.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Settings } from './settings.js';
import { FilterManager } from './filters/manager.js';
import { RuleEngine } from './rules/engine.js';
import { safeSearchRules } from './rules/safesearch.js';
import { Resolver } from './dns/upstream.js';
import { DnsCache } from './dns/cache.js';
import { DnsServer } from './dns/server.js';
import { QueryLog } from './querylog.js';
import { Stats } from './stats.js';
import { ApiServer } from './api/server.js';
import { CoreProcess } from './core.js';
import { WindowsPrivacy } from './privacy.js';
import { TrackerDb } from './trackers.js';
import { AppCatalog } from './apps.js';
import { UserscriptManager } from './userscripts.js';
import { Notifications } from './notifications.js';
import { logger } from './log.js';

const log = logger('app');
// Lists switched on by default from 0.2 (catalog ids): HaGeZi Multi PRO, Windows trackers, TIF mini,
// fake/scam, pop-up ads, AdGuard Base (web), cookie banners (web), uBlock annoyances (web).
export const RECOMMENDED_V2 = [7, 20, 32, 33, 40, 103, 120, 122];
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
// Unpacked browser extension: <install dir>\extension next to app\, or <repo>\extension.
const EXTENSION_DIR = [path.join(ROOT, '..', 'extension'), path.join(ROOT, 'extension')]
  .find((d) => fs.existsSync(path.join(d, 'manifest.json'))) || null;

export const SPECIAL_FILTERS = {
  [-1]: 'User rules',
  [-2]: 'Allowlist',
  [-3]: 'Blocklist',
  [-4]: 'Safe search',
};

export function normalizeDomain(input) {
  return String(input).trim().toLowerCase()
    .replace(/^@@/, '').replace(/^\|\|/, '').replace(/^\*\./, '').replace(/^https?:\/\//, '')
    .replace(/[/^$].*$/, '').replace(/\.$/, '');
}

export class App {
  constructor({ dataDir, version, overrides = {} }) {
    this.dataDir = dataDir;
    this.version = version;
    this.overrides = overrides;
    this.startedAt = Date.now();
    this.settings = new Settings(dataDir).load();
    this.notifications = new Notifications({ enabled: () => this.settings.get().ui.notifications });    this.filters = new FilterManager(dataDir, this.settings).load();
    this.stats = new Stats(dataDir, this.settings.get().stats.retentionDays).load();
    this.queryLog = new QueryLog(this.settings.get().queryLog.size);
    this.cache = new DnsCache(this.settings.get().dns.cache);
    this.engine = new RuleEngine();
    this.engineInfo = { builtAt: 0, ms: 0 };
    this.resolver = new Resolver(this.settings.get().dns);
    this.dns = new DnsServer({
      settings: this.settings,
      getEngine: () => this.engine,
      getResolver: () => this.resolver,
      cache: this.cache,
      queryLog: this.queryLog,
      stats: this.stats,
    });
    this.api = new ApiServer(this);
    this.core = new CoreProcess(this);
    this.windowsPrivacy = new WindowsPrivacy(dataDir);
    this.trackers = new TrackerDb(dataDir).load();
    this.apps = new AppCatalog();
    this.userscripts = new UserscriptManager(dataDir).load();
    this.rebuildTimer = null;
  }

  filterName(id) {
    return SPECIAL_FILTERS[id] || this.filters.get(id)?.name || `filter #${id}`;
  }

  listenAddresses() {
    const { listen } = this.settings.get().dns;
    const port = this.overrides.dnsPort;
    return port ? listen.map((l) => ({ ...l, port })) : listen;
  }

  buildSources() {
    const s = this.settings.get();
    const sources = this.filters.activeFilters().map((f) => ({ filterId: f.id, text: this.filters.readText(f.id) }));
    if (s.filtering.userRulesEnabled) sources.push({ filterId: -1, text: s.filtering.userRules });
    const domains = (list) => list.filter((d) => d.enabled !== false).map((d) => normalizeDomain(d.name ?? d)).filter(Boolean);
    if (s.filtering.allowlist.enabled) sources.push({ filterId: -2, text: domains(s.filtering.allowlist.domains).map((d) => `@@||${d}^$important`).join('\n') });
    if (s.filtering.blocklist.enabled) sources.push({ filterId: -3, text: domains(s.filtering.blocklist.domains).map((d) => `||${d}^$important`).join('\n') });
    if (s.parental.enabled && s.parental.safeSearch) sources.push({ filterId: -4, text: safeSearchRules() });
    return sources;
  }

  rebuildEngine() {
    const started = Date.now();
    this.engine = RuleEngine.build(this.buildSources());
    this.engineInfo = { builtAt: Date.now(), ms: Date.now() - started, rules: this.engine.count, invalid: this.engine.invalid };
    this.cache.clear();
    log.info(`rule engine built: ${this.engine.count} rules in ${this.engineInfo.ms} ms`);
  }

  scheduleRebuild() {
    clearTimeout(this.rebuildTimer);
    this.rebuildTimer = setTimeout(() => this.rebuildEngine(), 300);
  }

  onSettingsChange(sections) {
    const s = this.settings.get();
    if (sections.includes('dns')) {
      this.resolver.close();
      this.resolver = new Resolver(s.dns);
      Object.assign(this.cache, { size: s.dns.cache.size, minTtl: s.dns.cache.minTtl, maxTtl: s.dns.cache.maxTtl });
      this.cache.clear();
    }
    if (sections.some((k) => ['filtering', 'parental', 'security'].includes(k))) this.scheduleRebuild();
    if (sections.includes('queryLog')) this.queryLog.resize(s.queryLog.size);
    if (sections.includes('stats')) this.stats.retentionDays = s.stats.retentionDays;
    if (sections.includes('protection')) {
      this.cache.clear();
      this.schedulePauseEnd();
    }
    if (sections.includes('https')) this.core.sync();
    if (sections.some((k) => ['filtering', 'parental', 'security', 'protection', 'https', 'privacy', 'apps', 'extensions'].includes(k))) this.core.scheduleReload();
    if (sections.includes('privacy')) this.windowsPrivacy.sync(s.privacy.windows);
  }

  // Announces the end of a timed pause (the pause itself needs no timer: isProtectionActive checks the clock).
  schedulePauseEnd() {
    clearTimeout(this.pauseTimer);
    const { enabled, pausedUntil } = this.settings.get().protection;
    const ms = pausedUntil - Date.now();
    if (!enabled || ms <= 0) return;
    this.pauseTimer = setTimeout(() => {
      this.cache.clear();
      this.notifications.push('info', 'Protection resumed', 'The pause has ended and filtering is active again.');
    }, ms);
    this.pauseTimer.unref();
  }

  async start() {
    this.rebuildEngine();
    this.settings.on('change', (sections) => this.onSettingsChange(sections));
    this.filters.on('change', () => {
      this.scheduleRebuild();
      this.core.scheduleReload();
    });
    this.filters.on('updated', (results) => {
      const updated = results.filter((r) => r.status === 'updated');
      const failed = results.filter((r) => r.status === 'failed');
      if (updated.length) this.notifications.push('info', 'Filters updated', `${updated.length} filter list${updated.length > 1 ? 's' : ''} updated: ${updated.slice(0, 3).map((r) => r.name).join(', ')}${updated.length > 3 ? '…' : ''}`);
      if (failed.length) this.notifications.push('warning', 'Filter update failed', failed.slice(0, 3).map((r) => `${r.name}: ${r.error}`).join('\n'));
    });
    this.schedulePauseEnd();
    // The tray polls notifications after start-up, so announce a fresh update a little later.
    setTimeout(() => {
      this.announceUpdate();
      this.upgradeDefaults().catch((e) => log.error('upgrading defaults failed', e));
    }, 20000).unref();
    await this.dns.start(this.listenAddresses());
    if (this.dns.errors.length) this.notifications.push('error', 'DNS filtering is not running', this.dns.errors.map((e) => e.message || String(e)).join('\n'));
    await this.api.start(this.overrides.apiPort);
    this.filters.start();
    this.trackers.start();
    this.userscripts.on('change', () => this.core.scheduleReload());
    this.extensionTimer = setInterval(() => {
      if (!this.settings.get().extensions.autoUpdate) return;
      this.userscripts.checkUpdates().then((results) => {
        for (const r of results.filter((x) => x.status === 'updated')) this.notifications.push('info', 'Extension updated', `${r.name} ${r.from} → ${r.to}`);
      }).catch(() => {});
    }, 24 * 3600 * 1000);
    this.extensionTimer.unref();
    this.core.sync();
    this.windowsPrivacy.sync(this.settings.get().privacy.windows);
    this.statsTimer = setInterval(() => this.stats.save(), 60000);
    this.statsTimer.unref();
  }

  async stop() {
    clearInterval(this.statsTimer);
    clearInterval(this.extensionTimer);
    clearTimeout(this.pauseTimer);
    this.core.stop();
    this.filters.stop();
    this.trackers.stop();
    await this.dns.stop();
    await this.api.stop();
    this.resolver.close();
    this.stats.save();
    this.settings.save();
  }

  // Written by the Windows service's DNS guard; absent when AdHush runs outside the service.
  systemDnsState() {
    let state = null;
    try {
      state = JSON.parse(fs.readFileSync(path.join(this.dataDir, 'dns-state.json'), 'utf8'));
    } catch {}
    return { managed: this.settings.get().system.manageDns, guard: !!state, ...state };
  }

  // Brings installs from older releases up to the current recommended filter set, once.
  // Only ever switches lists on; lists turned on by this release stay as the user leaves them.
  async upgradeDefaults() {
    const s = this.settings.get();
    if (s.ui.defaultsVersion >= 2) return;
    this.settings.update({ ui: { defaultsVersion: 2 } });
    const added = [];
    for (const id of RECOMMENDED_V2) {
      const f = this.filters.get(id);
      if (f && !f.enabled) {
        await this.filters.setEnabled(id, true).catch((e) => log.warn(`enabling ${f.name} failed: ${e.message}`));
        added.push(f.name);
      }
    }
    log.info(`upgraded to recommended filter set v2: ${added.join(', ') || 'nothing to add'}`);
    if (added.length) this.notifications.push('info', 'Stronger protection turned on', `AdHush 0.2 added ${added.length} recommended lists (malware feeds, pop-up ads, cookie banners and annoyances).`);
    if (!this.settings.get().https.enabled) {
      this.notifications.push('info', 'New: block YouTube ads', 'Open AdHush → Web filtering and click "Turn on" to also block ads inside web pages.');
    }
  }

  // Written by the service's updater; absent when AdHush runs outside the service.
  updateState() {
    let state = null;
    try {
      state = JSON.parse(fs.readFileSync(path.join(this.dataDir, 'update-state.json'), 'utf8'));
    } catch {}
    const { feedUrl, auto } = this.settings.get().updates;
    return { configured: !!feedUrl, auto, service: !!state, current: this.version, ...state };
  }

  // The service watches these files (it runs the installer, Node cannot: the installer stops Node).
  requestUpdate(kind) {
    fs.writeFileSync(path.join(this.dataDir, kind === 'install' ? 'update-install' : 'update-check'), String(Date.now()));
  }

  announceUpdate() {
    const u = this.updateState().lastUpdate;
    if (u && Date.now() - u.at < 15 * 60 * 1000) this.notifications.push('info', `AdHush updated to ${u.to}`, `Updated automatically from ${u.from}.`);
  }

  status() {
    const s = this.settings.get();
    return {
      version: this.version,
      uptimeSec: Math.round((Date.now() - this.startedAt) / 1000),
      protection: { enabled: s.protection.enabled, pausedUntil: s.protection.pausedUntil, active: this.settings.isProtectionActive() },
      dns: { listening: this.dns.listening, errors: this.dns.errors, ...this.resolver.info(), cache: this.cache.info() },
      engine: this.engineInfo,
      filters: { enabled: this.filters.activeFilters().length, total: this.filters.filters.length },      onboarded: s.ui.onboarded,
      // Written by setup after it trusts this PC's root certificate; web filtering is unsafe without it.
      caInstalled: fs.existsSync(path.join(this.dataDir, 'ca', 'installed-thumbprint')),
      extensionDir: EXTENSION_DIR,
      systemDns: this.systemDnsState(),
      updates: this.updateState(),
      dataDir: this.dataDir,
    };
  }
}
