// Settings backup: what a person chose (filter lists, rules, allow and block lists, switches, theme),
// as one JSON file to restore on this or another PC. Things tied to this PC are left out and never
// changed by a restore: the API port, DNS listen addresses, whether Windows uses AdHush, whether web
// filtering (and its certificate) is on, the update source, a pause in progress, and setup progress.
export const BACKUP_FORMAT = 1;

const PC_SPECIFIC = [
  ['api'], ['dns', 'listen'], ['system', 'manageDns'], ['https', 'enabled'], ['https', 'driver', 'enabled'],
  ['https', 'port'], ['https', 'controlPort'], ['updates', 'feedUrl'], ['protection', 'pausedUntil'],
  ['ui', 'onboarded'], ['ui', 'defaultsVersion'],
];

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function stripPcSpecific(settings) {
  const out = structuredClone(settings);
  for (const keys of PC_SPECIFIC) {
    let o = out;
    for (const k of keys.slice(0, -1)) o = isPlainObject(o) ? o[k] : undefined;
    if (isPlainObject(o)) delete o[keys.at(-1)];
  }
  return out;
}

// Keeps only keys this version knows, with the same kind of value, so an old, newer or edited file
// can't add settings that don't exist.
function pickKnown(base, patch) {
  const out = {};
  for (const [k, v] of Object.entries(patch)) {
    if (!(k in base)) continue;
    const b = base[k];
    if (isPlainObject(b)) {
      if (isPlainObject(v)) out[k] = pickKnown(b, v);
    } else if (Array.isArray(b) ? Array.isArray(v) : typeof v === typeof b) {
      out[k] = v;
    }
  }
  return out;
}

export function makeBackup(app) {
  return {
    app: 'adhush',
    format: BACKUP_FORMAT,
    version: app.version,
    exportedAt: new Date().toISOString(),
    settings: stripPcSpecific(app.settings.get()),
    filters: app.filters.list().map((f) => (f.custom
      ? { url: f.url, name: f.name, scope: f.scope || 'dns', enabled: !!f.enabled }
      : { id: f.id, enabled: !!f.enabled })),
  };
}

export async function restoreBackup(app, data) {
  if (!isPlainObject(data) || data.app !== 'adhush' || !isPlainObject(data.settings)) {
    throw Object.assign(new Error("This isn't an AdHush backup file."), { status: 400 });
  }
  if (data.format > BACKUP_FORMAT) {
    throw Object.assign(new Error('This backup is from a newer AdHush. Update AdHush, then restore it.'), { status: 400 });
  }
  const patch = pickKnown(app.settings.get(), stripPcSpecific(data.settings));
  app.settings.update(patch); // validates the whole result first: an invalid file changes nothing

  const failed = [];
  let lists = 0;
  for (const f of Array.isArray(data.filters) ? data.filters : []) {
    try {
      if (Number.isInteger(f?.id) && !f.custom) {
        const mine = app.filters.get(f.id);
        if (mine && !mine.custom && mine.enabled !== !!f.enabled) {
          await app.filters.setEnabled(f.id, !!f.enabled);
          lists++;
        }
      } else if (typeof f?.url === 'string' && /^https?:\/\//i.test(f.url)) {
        let mine = app.filters.list().find((x) => x.url === f.url);
        if (!mine) {
          mine = await app.filters.add({ url: f.url, name: typeof f.name === 'string' ? f.name.slice(0, 200) : undefined, scope: f.scope === 'content' ? 'content' : 'dns' });
          lists++;
        }
        if (mine.enabled !== !!f.enabled) await app.filters.setEnabled(mine.id, !!f.enabled);
      }
    } catch (e) {
      failed.push(`${f?.name || f?.url || `list ${f?.id}`}: ${e.message}`);
    }
  }
  return { ok: true, lists, failed };
}
