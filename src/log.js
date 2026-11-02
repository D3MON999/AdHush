import fs from 'node:fs';
import path from 'node:path';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MAX_FILE_BYTES = 5 * 1024 * 1024;

let minLevel = LEVELS.info;
let filePath = null;

export function configureLogger({ level = 'info', dir = null } = {}) {
  minLevel = LEVELS[level] ?? LEVELS.info;
  if (dir) {
    fs.mkdirSync(dir, { recursive: true });
    filePath = path.join(dir, 'adhush.log');
  }
}

function rotateIfNeeded() {
  try {
    if (fs.statSync(filePath).size > MAX_FILE_BYTES) {
      fs.renameSync(filePath, filePath + '.1');
    }
  } catch {
    // file does not exist yet
  }
}

function write(level, scope, msg, extra) {
  if (LEVELS[level] < minLevel) return;
  const line = `${new Date().toISOString()} ${level.toUpperCase().padEnd(5)} [${scope}] ${msg}` +
    (extra instanceof Error ? ` :: ${extra.stack || extra.message}` : extra !== undefined ? ` ${JSON.stringify(extra)}` : '');
  (level === 'error' || level === 'warn' ? console.error : console.log)(line);
  if (filePath) {
    rotateIfNeeded();
    fs.appendFile(filePath, line + '\n', () => {});
  }
}

export function logger(scope) {
  return {
    debug: (m, e) => write('debug', scope, m, e),
    info: (m, e) => write('info', scope, m, e),
    warn: (m, e) => write('warn', scope, m, e),
    error: (m, e) => write('error', scope, m, e),
  };
}
