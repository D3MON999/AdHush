// Composition root: wires settings, filters, rule engine, resolver, DNS server, stats and API.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Settings } from './settings.js';
import { FilterManager } from './filters/manager.js';
import { RuleEngine } from './rules/engine.js';
import { safeSearchRules } from './rules/safesearch.js';
import { Resolver } from './dns/upstream.js';
import { ConnectedNetworks, NetworkDns } from './network.js';
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
import { secureDnsRules, SELFTEST_RULE } from './browserguard.js';
import { runSelfTest } from './selftest.js';
import { logger } from './log.js';

const log = logger('app');
// Lists switched on by default from 0.2 (catalog ids): HaGeZi Multi PRO, Windows trackers, TIF mini,
// fake/scam, pop-up ads, AdGuard Base (web), cookie banners (web), uBlock annoyances (web).
export const RECOMMENDED_V2 = [7, 20, 32, 33, 40, 103, 120, 122];
// Bump when adding a step to App.upgradeDefaults (and set settings DEFAULTS.ui.defaultsVersion to match).
export const DEFAULTS_VERSION = 4;
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
// Unpacked browser extension: <install dir>\extension next to app\, or <repo>\extension.
const EXTENSION_DIR = [path.join(ROOT, '..', 'extension'), path.join(ROOT, 'extension')]
  .find((d) => fs.existsSync(path.join(d, 'manifest.json'))) || null;

export const SPECIAL_FILTERS = {
  [-1]: 'User rules',
  [-2]: 'Allowlist',
  [-3]: 'Blocklist',
  [-4]: 'Safe search',
  [-5]: 'Browser guard',
  [-6]: 'AdHush self-test',
};

export function normalizeDomain(input) {
  return String(input).trim().toLowerCase()
    .replace(/^@@/, '').replace(/^\|\|/, '').replace(/^\*\./, '').replace(/^https?:\/\//, '')
    .replace(/[/^$].*$/, '').replace(/\.$/, '');
}

const CHECK_FIRST_MS = 3 * 60 * 1000;
const CHECK_EVERY_MS = 3 * 60 * 60 * 1000;

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
    this.network = new NetworkDns(dataDir);
    this.networks = new ConnectedNetworks();
    this.onExcludedNetwork = false;
    this.resolver = this.makeResolver();
    this.dns = new DnsServer({
      settings: this.settings,
      getEngine: () => this.engine,
      getResolver: () => this.resolver,
      bypass: () => this.onExcludedNetwork,
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

  makeResolver() {
    return new Resolver(this.settings.get().dns, {
      networkDns: () => this.network.servers(),
      onNetworkMode: (on) => {
        log.info(on ? 'secure DNS unreachable: using the network\'s own DNS' : 'secure DNS reachable again');
        // A flaky network can switch back and forth: tell the user at most once every 10 minutes.
        if (on && Date.now() - (this.networkNoticeAt || 0) > 10 * 60 * 1000) {
          this.networkNoticeAt = Date.now();
          this.notifications.push('info', 'Using this network\'s DNS', 'This Wi-Fi may need you to sign in, or it blocks secure DNS. AdHush is using the network\'s own DNS for now, and ads are still blocked.');
        }
      },
    });
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
    if (s.system.stopSecureDns) sources.push({ filterId: -5, text: secureDnsRules() });
    sources.push({ filterId: -6, text: SELFTEST_RULE });
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
      this.resolver = this.makeResolver();
      Object.assign(this.cache, { size: s.dns.cache.size, minTtl: s.dns.cache.minTtl, maxTtl: s.dns.cache.maxTtl });
      this.cache.clear();
    }
    if (sections.some((k) => ['filtering', 'parental', 'security', 'system'].includes(k))) this.scheduleRebuild();
    if (sections.includes('queryLog')) this.queryLog.resize(s.queryLog.size);
    if (sections.includes('stats')) this.stats.retentionDays = s.stats.retentionDays;
    if (sections.includes('protection')) {
      this.cache.clear();
      this.schedulePauseEnd();
    }
    if (sections.includes('https')) this.core.sync();
    if (sections.some((k) => ['filtering', 'parental', 'security', 'protection', 'https', 'privacy', 'apps', 'extensions'].includes(k))) this.core.scheduleReload();
    if (sections.includes('privacy') || sections.includes('system')) this.windowsPrivacy.sync(this.windowsWanted());
    if (sections.includes('system')) this.checkNetworks();
  }

  // Registry changes to keep in place: the user's privacy switches, plus the browser guard while
  // Windows actually points at AdHush (without that, turning off Secure DNS would gain nothing).
  windowsWanted() {
    const s = this.settings.get();
    return { ...s.privacy.windows, browserDoh: s.system.manageDns && s.system.stopSecureDns };
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
    this.windowsPrivacy.sync(this.windowsWanted());
    this.statsTimer = setInterval(() => this.stats.save(), 60000);
    this.statsTimer.unref();
    this.checkTimer = setTimeout(() => this.backgroundCheck(), CHECK_FIRST_MS);
    this.checkTimer.unref();
    this.checkNetworks();
    this.networkTimer = setInterval(() => this.checkNetworks(), 60000);
    this.networkTimer.unref();
  }

  // Is this PC on a network the person chose not to filter (Settings → Whole-PC protection)? Checked
  // every minute, and only when there are such networks.
  async checkNetworks() {
    const excluded = this.settings.get().system.excludedNetworks.map((n) => n.toLowerCase());
    let now = false;
    let name = '';
    if (excluded.length) {
      const names = await this.networks.names().catch(() => []);
      name = names.find((n) => excluded.includes(n.toLowerCase())) || '';
      now = !!name;
    }
    if (now === this.onExcludedNetwork) return;
    this.onExcludedNetwork = now;
    this.cache.clear();
    log.info(now ? `on "${name}": not filtering, as set in Settings` : 'left the excluded network: filtering again');
    if (now) this.notifications.push('info', `Not filtering on ${name}`, 'You chose not to filter on this network. Change it in Settings → Whole-PC protection.');
  }

  // "Check my protection", run quietly every few hours: a notification only when a problem appears
  // (once per problem, again only if it comes back after being fixed). Choices the user made on
  // purpose, like turning protection off, aren't problems.
  async backgroundCheck() {
    this.checkTimer = setTimeout(() => this.backgroundCheck(), CHECK_EVERY_MS);
    this.checkTimer.unref();
    if (!this.settings.get().system.backgroundCheck || !this.settings.isProtectionActive()) return;
    let report;
    try {
      report = await (this.selfTest || runSelfTest)(this); // selfTest: replaced in tests
    } catch (e) {
      log.warn(`background check failed: ${e.message}`);
      return;
    }
    const problems = report.checks.filter((c) => (c.status === 'fail' && c.id !== 'protection') || (c.status === 'warn' && c.id === 'wholepc'));
    const fresh = problems.filter((c) => !this.reportedProblems?.has(c.id));
    this.reportedProblems = new Set(problems.map((c) => c.id));
    if (!fresh.length) return;
    log.warn(`background check: ${fresh.map((c) => `${c.id}: ${c.detail}`).join(' | ')}`);
    const title = fresh.length === 1 ? `${fresh[0].name} needs a look` : 'AdHush found some problems';
    this.notifications.push('warning', title, `${fresh.map((c) => c.detail).join(' ')} Open AdHush and choose Check my protection for details.`);
  }

  async stop() {
    clearInterval(this.statsTimer);
    clearTimeout(this.checkTimer);
    clearInterval(this.networkTimer);
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

  // Brings installs from older releases up to the current defaults, one step per release, each
  // exactly once (ui.defaultsVersion records the last step applied).
  async upgradeDefaults() {
    const from = this.settings.get().ui.defaultsVersion;
    if (from >= DEFAULTS_VERSION) return;
    this.settings.update({ ui: { defaultsVersion: DEFAULTS_VERSION } }); // never re-run, even after a crash
    if (from < 2) await this.addRecommendedLists();
    if (from < 3 && !this.settings.get().parental.enabled) {
      // Before 0.2, safe search and adult blocking defaulted to on (inert while parental control is
      // off). Clear those leftovers so upgraded installs match new ones.
      this.settings.update({ parental: { safeSearch: false, blockAdult: false } });
      log.info('cleared leftover parental sub-options');
    }
    if (from < 4 && this.settings.get().system.manageDns) {
      this.notifications.push('info', 'Browsers now stay protected', 'AdHush turned off Secure DNS in your browsers so they can no longer skip ad blocking. You can change this in Settings.');
    }
  }

  // 0.2: only ever switches lists on; afterwards they stay as the user leaves them.
  async addRecommendedLists() {
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

  // Reported by the tray every few seconds while a full-screen game has focus. While active, the tray
  // holds notifications and the service holds automatic updates (it reads <data>\gaming-active).
  setGaming({ active, exe }) {
    const g = this.settings.get().gaming;
    const name = String(exe || '').trim().toLowerCase();
    const file = path.join(this.dataDir, 'gaming-active');
    if (!active || !g.enabled) {
      this.gaming = null;
      fs.rmSync(file, { force: true });
      return this.gamingState();
    }
    // The name can be missing: some anti-cheat protected games refuse to tell us who they are.
    const known = /^[\w .()+-]{1,120}\.exe$/.test(name);
    this.gaming = { exe: known ? name : 'Full-screen game', at: Date.now() };
    fs.writeFileSync(file, this.gaming.exe);
    // Games and anti-cheat dislike filtered connections: in all-apps mode, leave this one alone.
    const d = this.settings.get().https.driver;
    if (known && d.mode === 'all' && !d.excluded.includes(name)) {
      this.settings.update({ https: { driver: { excluded: [...d.excluded, name] } }, gaming: { games: [...new Set([...g.games, name])] } });
      log.info(`gaming mode: left ${name} out of web filtering`);
    }
    return this.gamingState();
  }

  forgetGame(exe) {
    const s = this.settings.get();
    const name = String(exe || '').toLowerCase();
    this.settings.update({ gaming: { games: s.gaming.games.filter((x) => x !== name) }, https: { driver: { excluded: s.https.driver.excluded.filter((x) => x !== name) } } });
  }

  gamingState() {
    const g = this.settings.get().gaming;
    // A tray that stops reporting (closed, crashed) must not leave the mode stuck on.
    const active = !!this.gaming && Date.now() - this.gaming.at < 2 * 60 * 1000;
    return { enabled: g.enabled, active, exe: active ? this.gaming.exe : null, games: g.games };
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
      filters: { enabled: this.filters.activeFilters().length, total: this.filters.filters.length },
      onboarded: s.ui.onboarded,
      gaming: this.gamingState(),
      network: { excluded: this.onExcludedNetwork },
      // Written by setup after it trusts this PC's root certificate; web filtering is unsafe without it.
      caInstalled: fs.existsSync(path.join(this.dataDir, 'ca', 'installed-thumbprint')),
      extensionDir: EXTENSION_DIR,
      systemDns: this.systemDnsState(),
      updates: this.updateState(),
      dataDir: this.dataDir,
    };
  }
}
