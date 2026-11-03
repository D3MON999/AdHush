import fs from 'node:fs';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { writeFileAtomic } from './fsutil.js';

export const THEMES = ['midnight', 'sand', 'ember', 'raspberry', 'auto'];
export const BLOCKING_MODES =['default', 'refused', 'nxdomain', 'unspecified', 'custom'];

export const DEFAULTS = {
  schemaVersion: 1,
  protection: { enabled: true, pausedUntil: 0 },
  dns: {
    listen: [{ host: '127.0.0.1', port: 53 }, { host: '::1', port: 53 }],
    upstreams: ['https://dns.cloudflare.com/dns-query', 'https://dns.quad9.net/dns-query'],
    upstreamMode: 'parallel', // parallel = fastest answer wins, sequential = in order
    bootstrap: ['1.1.1.1', '9.9.9.9'],
    fallback: ['1.1.1.1', '8.8.8.8'],
    timeoutMs: 5000,
    cache: { enabled: true, size: 10000, minTtl: 0, maxTtl: 86400 },
    blockingMode: 'default',
    customIpv4: '',
    customIpv6: '',
    blockedTtl: 10,
    blockCnameCloaking: true,
  },
  filtering: {
    userRulesEnabled: true,
    userRules: '',
    allowlist: { enabled: true, domains: [] },
    blocklist: { enabled: true, domains: [] },
    brokenSites: [], // sites switched off with "This site isn't working" (see sites.js)
    updateIntervalHours: 24,
  },
  https: {
    enabled: false,
    port: 8080,
    controlPort: 8901,
    cosmetic: true,
    skipEv: true,
    autoExclude: true,
    exclusions: [],
    corePath: '',
    // Driver mode: WinDivert redirects selected apps' traffic (needs administrator rights).
    driver: {
      enabled: false,
      mode: 'selected', // selected = only `apps`; all = every app except `excluded`
      apps: ['chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'vivaldi.exe', 'waterfox.exe', 'librewolf.exe', 'iexplore.exe'],
      excluded: [],
      blockQuic: true,
      port: 18443,
      httpPort: 18480,
    },
  },
  // Userscripts and userstyles (injected by the web filter).
  extensions: { enabled: true, autoUpdate: true, detectInstall: true },
  // Per-app rules (lower-case executable names). bypass: never filtered; noHttps: HTTPS not decrypted.
  apps: { bypass: [], noHttps: [] },
  // Tracking protection (applied by the web filter) and Windows privacy switches.
  privacy: {
    enabled: true,
    preset: 'standard',
    hideSearchQueries: true,
    sendDnt: true,
    removeXClientData: true,
    stripTrackingParams: true,
    thirdPartyCookies: { enabled: false, minutes: 180 },
    firstPartyCookies: { enabled: false, minutes: 4320 },
    hideReferrer: false,
    customReferrer: '',
    hideUserAgent: false,
    customUserAgent: '',
    maskIp: false,
    customIp: '',
    blockWebRtc: false,
    blockPushApi: false,
    blockLocationApi: false,
    blockThirdPartyAuth: false,
    disableThirdPartyCache: false,
    antiDpi: { enabled: false, tlsFragment: 1, http: true },
    windows: { telemetry: false, advertisingId: false, recall: false, wapPush: false, feedback: false },
  },
  security: { enabled: true },
  // safeSearch / blockAdult only apply while parental control is enabled.
  parental: { enabled: false, safeSearch: false, blockAdult: false },
  stats: { enabled: true, retentionDays: 30 },
  queryLog: { enabled: true, size: 5000 },
  api: { host: '127.0.0.1', port: 8899 },
  // manageDns: the AdHush service points Windows DNS at AdHush (and restores it if AdHush stops answering).
  system: { manageDns: false },
  // Signed automatic updates, applied by the AdHush service (service/src/updater.rs).
  updates: { feedUrl: '', auto: true },
  // notifications: tray toasts; onboarded: the first-run wizard has been completed or skipped.
  // theme: midnight | sand | ember | raspberry | auto (sand or midnight, following Windows)
  // defaultsVersion: which release's recommended filter set this install has received (see App.upgradeDefaults).
  ui: { theme: 'midnight', notifications: true, onboarded: false, defaultsVersion: 3 },
};

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// Objects merge recursively, arrays and scalars replace.
export function deepMerge(base, patch) {
  if (!isPlainObject(base) || !isPlainObject(patch)) return structuredClone(patch);
  const out = structuredClone(base);
  for (const [k, v] of Object.entries(patch)) {
    out[k] = isPlainObject(v) && isPlainObject(out[k]) ? deepMerge(out[k], v) : structuredClone(v);
  }
  return out;
}

function validate(s) {
  const errors = [];
  if (!Array.isArray(s.dns.upstreams) || s.dns.upstreams.length === 0) errors.push('dns.upstreams must not be empty');
  if (!BLOCKING_MODES.includes(s.dns.blockingMode)) errors.push(`dns.blockingMode must be one of ${BLOCKING_MODES.join(', ')}`);
  if (!['parallel', 'sequential'].includes(s.dns.upstreamMode)) errors.push('dns.upstreamMode must be parallel or sequential');
  if (!(s.dns.timeoutMs >= 200 && s.dns.timeoutMs <= 60000)) errors.push('dns.timeoutMs must be between 200 and 60000');
  for (const l of s.dns.listen) if (!(l.port > 0 && l.port < 65536)) errors.push(`invalid listen port ${l.port}`);
  for (const k of ['port', 'controlPort']) if (!(s.https[k] > 0 && s.https[k] < 65536)) errors.push(`https.${k} must be a valid port`);
  if (s.https.port === s.https.controlPort) errors.push('https.port and https.controlPort must differ');
  if (!['standard', 'high', 'extreme', 'custom'].includes(s.privacy.preset)) errors.push('privacy.preset must be standard, high, extreme or custom');
  for (const k of ['thirdPartyCookies', 'firstPartyCookies']) {
    if (!(Number.isInteger(s.privacy[k].minutes) && s.privacy[k].minutes >= 0)) errors.push(`privacy.${k}.minutes must be a whole number of minutes`);
  }
  if (!(s.privacy.antiDpi.tlsFragment >= 1 && s.privacy.antiDpi.tlsFragment <= 100)) errors.push('privacy.antiDpi.tlsFragment must be 1..100');
  if (!THEMES.includes(s.ui.theme)) errors.push(`ui.theme must be one of ${THEMES.join(', ')}`);
  const d = s.https.driver;
  if (!['selected', 'all'].includes(d.mode)) errors.push('https.driver.mode must be selected or all');
  const ports = [s.https.port, s.https.controlPort, d.port, d.httpPort];
  if (new Set(ports).size !== ports.length || ports.some((p) => !(p > 0 && p < 65536))) errors.push('proxy, control and driver ports must be distinct valid ports');
  return errors;
}

export class Settings extends EventEmitter {
  constructor(dataDir) {
    super();
    this.file = path.join(dataDir, 'settings.json');
    this.data = structuredClone(DEFAULTS);
  }

  load() {
    try {
      // Tolerate a byte-order mark (Windows PowerShell adds one when scripts edit this file).
      const stored = JSON.parse(fs.readFileSync(this.file, 'utf8').replace(/^﻿/, ''));
      this.data = deepMerge(DEFAULTS, stored);
      // Installs that predate the wizard are already set up.
      if (stored.ui?.onboarded === undefined) this.data.ui.onboarded = true;
      // Installs from before defaultsVersion existed got the 0.1 filter set.
      if (stored.ui?.defaultsVersion === undefined) this.data.ui.defaultsVersion = 1;
      // Themes before 0.2 were light / dark / auto.
      const legacy = { light: 'sand', dark: 'midnight' }[this.data.ui.theme];
      if (legacy) this.data.ui.theme = legacy;
    } catch (e) {
      if (e.code !== 'ENOENT') throw new Error(`cannot read ${this.file}: ${e.message}`);
      this.save();
    }
    return this;
  }

  get() {
    return this.data;
  }

  // Applies a partial update. Returns the list of top-level sections that changed.
  update(patch) {
    const next = deepMerge(this.data, patch);
    const errors = validate(next);
    if (errors.length) {
      const err = new Error(errors.join('; '));
      err.status = 400;
      throw err;
    }
    const changed = Object.keys(patch).filter((k) => JSON.stringify(next[k]) !== JSON.stringify(this.data[k]));
    this.data = next;
    this.save();
    if (changed.length) this.emit('change', changed);
    return changed;
  }

  replace(full) {
    return this.update(deepMerge(DEFAULTS, full));
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    writeFileAtomic(this.file, JSON.stringify(this.data, null, 2));
  }

  isProtectionActive(now = Date.now()) {
    const p = this.data.protection;
    return p.enabled && now >= (p.pausedUntil || 0);
  }
}
