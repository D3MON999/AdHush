#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { App } from './app.js';
import { configureLogger, logger } from './log.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--data') out.data = argv[++i];
    else if (a === '--dns-port') out.dnsPort = Number(argv[++i]);
    else if (a === '--api-port') out.apiPort = Number(argv[++i]);
    else if (a === '--debug') out.debug = true;
    else throw new Error(`unknown argument ${a}`);
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  console.log(`AdHush ${pkg.version} — personal DNS ad blocker

Usage: node src/index.js [--data DIR] [--dns-port N] [--api-port N] [--debug]

  --data DIR      data directory (default: ADHUSH_DATA env or ./data)
  --dns-port N    override the DNS listen port (default from settings: 53)
  --api-port N    override the UI/API port (default from settings: 8899)
  --debug         verbose logging`);
  process.exit(0);
}

const dataDir = path.resolve(args.data || process.env.ADHUSH_DATA || path.join(ROOT, 'data'));
fs.mkdirSync(dataDir, { recursive: true });
configureLogger({ level: args.debug ? 'debug' : 'info', dir: path.join(dataDir, 'logs') });
const log = logger('main');

const app = new App({ dataDir, version: pkg.version, overrides: { dnsPort: args.dnsPort, apiPort: args.apiPort } });

let stopping = false;
async function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  log.info(`received ${signal}, shutting down`);
  await app.stop().catch((e) => log.error('shutdown error', e));
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
// Under the Windows service wrapper there are no signals: it closes our stdin to request a stop.
if (process.env.ADHUSH_SERVICE === '1') {
  process.stdin.on('end', () => shutdown('service stop'));
  process.stdin.on('error', () => shutdown('service stop'));
  process.stdin.resume();
}
process.on('uncaughtException', (e) => log.error('uncaught exception', e));
process.on('unhandledRejection', (e) => log.error('unhandled rejection', e));

app.start().then(() => {
  log.info(`AdHush ${pkg.version} started (data: ${dataDir})`);
  if (app.dns.errors.length) {
    log.warn('Some DNS listeners failed. Port 53 may be in use or need admin rights; try --dns-port 5300 for testing.');
  }
}).catch((e) => {
  log.error('startup failed', e);
  process.exit(1);
});
