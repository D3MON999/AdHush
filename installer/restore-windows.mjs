// Run by the uninstaller (as administrator) after the service stops: undoes every registry change
// AdHush made (browser Secure DNS policies, Windows privacy switches) from the snapshot it saved
// when applying them, so values that existed before AdHush come back exactly as they were.
//   node restore-windows.mjs --data <dir>
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const i = process.argv.indexOf('--data');
const dataDir = i > 0 ? process.argv[i + 1] : null;
if (!dataDir) throw new Error('--data is required');

const appDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'app');
const { WindowsPrivacy } = await import(pathToFileURL(path.join(appDir, 'src', 'privacy.js')).href);

const windows = new WindowsPrivacy(dataDir);
await windows.sync({}); // nothing wanted: every applied switch is restored
const failed = Object.entries(windows.errors);
for (const [id, msg] of failed) console.error(`${id}: ${msg}`);
process.exit(failed.length ? 1 : 0);
