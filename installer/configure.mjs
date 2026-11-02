// Run by setup (as administrator) before the service starts: seeds settings.json in the data
// directory from the choices made on the setup's task page. Existing settings are kept on upgrade.
//   node configure.mjs --data <dir> --web <0|1> --dns <0|1> [--feed <update feed url>]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []));
const dataDir = args.data;
if (!dataDir) throw new Error('--data is required');
fs.mkdirSync(dataDir, { recursive: true });

const appDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'app');
const { Settings } = await import(pathToFileURL(path.join(appDir, 'src', 'settings.js')).href);

const fresh = !fs.existsSync(path.join(dataDir, 'settings.json'));
const settings = new Settings(dataDir).load();
if (fresh) {
  const web = args.web === '1';
  // The service's DNS guard points Windows at AdHush once it answers (and undoes it if AdHush stops).
  // Driver mode filters browsers without any proxy settings; the service runs as SYSTEM so it may load WinDivert.
  settings.update({ system: { manageDns: args.dns === '1' }, https: { enabled: web, driver: { enabled: web } }, ui: { onboarded: false } });
  console.log(`seeded ${path.join(dataDir, 'settings.json')} (whole-PC ${args.dns === '1' ? 'on' : 'off'}, web filtering ${web ? 'on' : 'off'})`);
} else if (args.dns === '1' && !settings.get().system.manageDns) {
  // Upgrade from a version that set DNS directly: hand it over to the guard.
  settings.update({ system: { manageDns: true } });
  console.log('keeping existing settings; whole-PC protection now managed by the service');
} else {
  console.log('keeping existing settings');
}
// The update feed comes from the build (installer\update-feed.txt) and follows each release.
if (args.feed && settings.get().updates.feedUrl !== args.feed) {
  settings.update({ updates: { feedUrl: args.feed } });
  console.log(`update feed: ${args.feed}`);
}
