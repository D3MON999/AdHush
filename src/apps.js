// Application inventory: running processes with network connections, installed programs
// (Uninstall registry keys) and per-app filtering rules.
import { execFile } from 'node:child_process';
import path from 'node:path';

function run(file, args, timeout = 20000) {
  return new Promise((resolve) => {
    execFile(file, args, { windowsHide: true, maxBuffer: 64 * 1024 * 1024, timeout }, (err, stdout) => resolve(err && !stdout ? '' : stdout || ''));
  });
}

export function parseNetstat(text) {
  const conns = new Map(); // pid → count of established remote connections
  for (const line of text.split(/\r?\n/)) {
    const m = line.trim().match(/^TCP\s+(\S+)\s+(\S+)\s+ESTABLISHED\s+(\d+)$/i);
    if (!m) continue;
    const remote = m[2];
    if (/^(127\.|\[::1\]|\[::ffff:127\.|0\.0\.0\.0)/.test(remote)) continue;
    const pid = Number(m[3]);
    conns.set(pid, (conns.get(pid) || 0) + 1);
  }
  return conns;
}

export function parseUninstall(text) {
  const apps = [];
  let cur = null;
  const flush = () => {
    if (cur?.DisplayName && !cur.SystemComponent) apps.push(cur);
  };
  for (const line of text.split(/\r?\n/)) {
    if (/^HKEY_/i.test(line)) {
      flush();
      cur = {};
      continue;
    }
    const m = line.match(/^\s{4}(\S+)\s+REG_(?:SZ|EXPAND_SZ|DWORD)\s+(.*)$/);
    if (m && cur) cur[m[1]] = m[2].trim();
  }
  flush();
  return apps.map((a) => {
    const icon = (a.DisplayIcon || '').replace(/^"|"$/g, '').replace(/,-?\d+$/, '').replace(/^"|"$/g, '');
    const exePath = /\.exe$/i.test(icon) ? icon : null;
    return { name: a.DisplayName, publisher: a.Publisher || null, version: a.DisplayVersion || null, path: exePath, exe: exePath ? path.win32.basename(exePath).toLowerCase() : null };
  });
}

export class AppCatalog {
  constructor() {
    this.runningCache = { at: 0, value: null };
    this.installedCache = { at: 0, value: null };
  }

  async running() {
    if (this.runningCache.value && Date.now() - this.runningCache.at < 15000) return this.runningCache.value;
    const [procJson, netstat] = await Promise.all([
      run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath | ConvertTo-Json -Compress']),
      run('netstat.exe', ['-ano', '-p', 'TCP']).then(async (v4) => v4 + (await run('netstat.exe', ['-ano', '-p', 'TCPv6']))),
    ]);
    let procs = [];
    try {
      procs = JSON.parse(procJson || '[]');
    } catch {
      procs = [];
    }
    const conns = parseNetstat(netstat);
    const byExe = new Map();
    for (const p of Array.isArray(procs) ? procs : [procs]) {
      if (!p?.Name) continue;
      const exe = p.Name.toLowerCase();
      const e = byExe.get(exe) || { exe, path: p.ExecutablePath || null, processes: 0, connections: 0 };
      e.processes++;
      e.connections += conns.get(p.ProcessId) || 0;
      if (!e.path && p.ExecutablePath) e.path = p.ExecutablePath;
      byExe.set(exe, e);
    }
    this.runningCache = { at: Date.now(), value: byExe };
    return byExe;
  }

  async installed() {
    if (this.installedCache.value && Date.now() - this.installedCache.at < 600000) return this.installedCache.value;
    const keys = [
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
    ];
    const out = (await Promise.all(keys.map((k) => run('reg.exe', ['query', k, '/s'])))).join('\n');
    const byExe = new Map();
    for (const a of parseUninstall(out)) if (a.exe && !byExe.has(a.exe)) byExe.set(a.exe, a);
    this.installedCache = { at: Date.now(), value: byExe };
    return byExe;
  }
}

/** Is this app filtered, given settings (bypass list and driver app selection)? */
export function appState(settings, exe) {
  const d = settings.https.driver;
  const bypass = settings.apps.bypass.includes(exe) || (d.enabled && d.excluded.includes(exe));
  const notSelected = d.enabled && d.mode === 'selected' && !d.apps.includes(exe);
  return { filter: !bypass && !notSelected, https: !settings.apps.noHttps.includes(exe) };
}

/** Settings patch that turns filtering / HTTPS decryption for one app on or off. */
export function appPatch(settings, exe, { filter, https }) {
  const without = (list) => list.filter((x) => x !== exe);
  const withExe = (list) => (list.includes(exe) ? list : [...list, exe]);
  const d = settings.https.driver;
  const patch = { apps: { ...settings.apps }, https: { driver: { apps: d.apps, excluded: d.excluded } } };
  if (filter !== undefined) {
    patch.apps.bypass = filter ? without(settings.apps.bypass) : withExe(settings.apps.bypass);
    patch.https.driver.excluded = filter ? without(d.excluded) : withExe(d.excluded);
    patch.https.driver.apps = filter ? withExe(d.apps) : without(d.apps);
  }
  if (https !== undefined) patch.apps.noHttps = https ? without(settings.apps.noHttps) : withExe(settings.apps.noHttps);
  return patch;
}
