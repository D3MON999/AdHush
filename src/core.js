// Supervises the Rust HTTPS filtering proxy (adhush-core): starts it when HTTPS filtering is
// enabled, restarts it with backoff if it exits, and tells it to reload rules on changes.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { logger } from './log.js';

const log = logger('core');
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

export class CoreProcess {
  constructor(app) {
    this.app = app;
    this.child = null;
    this.restarts = 0;
    this.lastError = null;
    this.startedAt = 0;
    this.restartTimer = null;
    this.reloadTimer = null;
    this.running = null;
  }

  // Settings that need a process restart when they change.
  static launchKey(h) {
    return JSON.stringify([h.port, h.controlPort, h.driver.enabled, h.driver.port, h.driver.httpPort]);
  }

  binary() {
    const configured = this.app.settings.get().https.corePath;
    const candidates = [
      configured,
      path.join(ROOT, '..', 'bin', 'adhush-core.exe'), // installed layout: <Program Files>\AdHush\{app,bin}
      path.join(ROOT, 'core', 'target', 'release', 'adhush-core.exe'),
      path.join(ROOT, 'core', 'target', 'release', 'adhush-core'),
      path.join(ROOT, 'core', 'target', 'debug', 'adhush-core.exe'),
      path.join(ROOT, 'core', 'target', 'debug', 'adhush-core'),
    ].filter(Boolean);
    return candidates.find((p) => fs.existsSync(p)) || null;
  }

  // Brings the process in line with settings (start, stop, or restart on port change).
  sync() {
    const h = this.app.settings.get().https;
    if (!h.enabled) return this.stop();
    if (this.child && this.running.key !== CoreProcess.launchKey(h)) this.stop();
    if (!this.child) this.start();
  }

  start() {
    clearTimeout(this.restartTimer);
    const exe = this.binary();
    if (!exe) {
      this.lastError = 'adhush-core binary not found. Build it with: cd core && cargo build --release';
      log.error(this.lastError);
      return;
    }
    const h = this.app.settings.get().https;
    // Our own process is never redirected by driver mode (its DNS upstream traffic must flow directly).
    const args = ['--data', this.app.dataDir, '--port', String(h.port), '--control-port', String(h.controlPort), '--exclude-pid', String(process.pid)];
    log.info(`starting ${exe} ${args.join(' ')}`);
    const child = spawn(exe, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, env: { ...process.env, RUST_LOG: process.env.RUST_LOG || 'info' } });
    this.child = child;
    this.running = { port: h.port, controlPort: h.controlPort, key: CoreProcess.launchKey(h) };
    this.startedAt = Date.now();
    this.lastError = null;
    const pipe = (stream) => {
      let buf = '';
      stream.on('data', (d) => {
        buf += d.toString();
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i).trim();
          buf = buf.slice(i + 1);
          if (line) log.info(line.replace(/^\[[^\]]*\]\s*/, ''));
        }
      });
    };
    pipe(child.stdout);
    pipe(child.stderr);
    child.on('error', (e) => { this.lastError = e.message; });
    child.on('exit', (code, signal) => {
      if (this.child !== child) return;
      this.child = null;
      if (child.intentional) return;
      this.lastError = `adhush-core exited (${signal || `code ${code}`})`;
      log.warn(this.lastError);
      if (!this.app.settings.get().https.enabled) return;
      if (this.restarts === 2) this.app.notifications?.push('error', 'Web filtering keeps stopping', `${this.lastError}. AdHush is restarting it; see the log for details.`);
      if (Date.now() - this.startedAt > 60000) this.restarts = 0;
      const delay = Math.min(30000, 1000 * 2 ** this.restarts++);
      this.restartTimer = setTimeout(() => this.sync(), delay);
    });
  }

  stop() {
    clearTimeout(this.restartTimer);
    if (!this.child) return;
    this.child.intentional = true;
    this.child.kill();
    this.child = null;
    log.info('adhush-core stopped');
  }

  async call(method, urlPath) {
    if (!this.child) throw Object.assign(new Error('HTTPS filtering is not running'), { status: 409 });
    const res = await fetch(`http://127.0.0.1:${this.running.controlPort}${urlPath}`, {
      method,
      headers: { 'x-adhush-token': this.app.api.token },
      signal: AbortSignal.timeout(60000),
    });
    const text = await res.text();
    if (!res.ok) throw Object.assign(new Error(`core: ${text}`), { status: 502 });
    return text;
  }

  scheduleReload() {
    if (!this.child) return;
    clearTimeout(this.reloadTimer);
    this.reloadTimer = setTimeout(() => {
      this.call('POST', '/reload').catch((e) => log.warn(`reload failed: ${e.message}`));
    }, 500);
  }

  async status() {
    const base = { enabled: this.app.settings.get().https.enabled, running: !!this.child, pid: this.child?.pid ?? null, binary: this.binary(), lastError: this.lastError };
    if (!this.child) return base;
    try {
      return { ...base, core: JSON.parse(await this.call('GET', '/status')) };
    } catch (e) {
      return { ...base, core: null, lastError: e.message.includes('fetch failed') ? 'starting…' : e.message };
    }
  }
}
