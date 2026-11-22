// The DNS servers the network itself provides: what the router hands out (DHCP), or what an adapter
// used before AdHush pointed it at itself. Hotel and café Wi-Fi often only lets these through until
// you sign in, so they are the last resort when every secure DNS server is unreachable.
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';

const KEY = 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces';
const CACHE_MS = 30000;

const usable = (ip) => net.isIPv4(ip) && !ip.startsWith('127.') && ip !== '0.0.0.0';

// `reg query <KEY> /s` output: "    DhcpNameServer    REG_SZ    192.168.1.1 8.8.8.8"
export function parseInterfaces(stdout) {
  const out = [];
  for (const line of String(stdout).split(/\r?\n/)) {
    const m = line.match(/^\s+(DhcpNameServer|NameServer)\s+REG_SZ\s+(.+)$/);
    if (m) out.push(...m[2].split(/[\s,]+/).filter(usable));
  }
  return out;
}

export function parseBackup(text) {
  try {
    const list = JSON.parse(String(text).replace(/^﻿/, ''));
    return (Array.isArray(list) ? list : [list]).flatMap((a) => [].concat(a?.IPv4 || [])).filter(usable);
  } catch {
    return [];
  }
}

export class NetworkDns {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.cache = { at: 0, servers: [] };
  }

  async servers() {
    if (Date.now() - this.cache.at < CACHE_MS) return this.cache.servers;
    let found = [];
    if (process.platform === 'win32') {
      found = await new Promise((resolve) => {
        execFile('reg.exe', ['query', KEY, '/s'], { windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => resolve(err ? [] : parseInterfaces(stdout)));
      });
    }
    try {
      found.push(...parseBackup(fs.readFileSync(path.join(this.dataDir, 'dns-backup.json'), 'utf8')));
    } catch {}
    this.cache = { at: Date.now(), servers: [...new Set(found)].slice(0, 4) };
    return this.cache.servers;
  }
}

// The names Windows gives the networks this PC is connected to: the Wi-Fi name, or "Network" (or
// "Network 2") for most cables. Read with Get-NetConnectionProfile, which works for the SYSTEM service
// and, unlike `netsh wlan`, doesn't need location permission.
export function parseProfiles(json) {
  try {
    const list = JSON.parse(String(json || '').replace(/^\uFEFF/, '') || '[]');
    return [...new Set((Array.isArray(list) ? list : [list]).map((p) => String(p?.Name || '').trim()).filter(Boolean))];
  } catch {
    return [];
  }
}

export class ConnectedNetworks {
  constructor() {
    this.cache = { at: 0, names: [] };
  }

  async names({ fresh = false } = {}) {
    if (!fresh && Date.now() - this.cache.at < 20000) return this.cache.names;
    if (process.platform !== 'win32') return [];
    const names = await new Promise((resolve) => {
      execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Get-NetConnectionProfile | Select-Object Name | ConvertTo-Json -Compress'],
        { windowsHide: true, timeout: 15000 }, (err, stdout) => resolve(err ? null : parseProfiles(stdout)));
    });
    if (names) this.cache = { at: Date.now(), names };
    return this.cache.names;
  }
}
