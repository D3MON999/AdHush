// Tracking-protection presets and Windows privacy switches (registry policies with
// snapshot/restore so turning a switch off puts the original value back).
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { logger } from './log.js';
import { writeFileAtomic } from './fsutil.js';

const log = logger('privacy');

const OFF = {
  hideSearchQueries: false, sendDnt: false, removeXClientData: false, stripTrackingParams: false,
  thirdPartyCookies: { enabled: false, minutes: 180 }, firstPartyCookies: { enabled: false, minutes: 4320 },
  hideReferrer: false, hideUserAgent: false, maskIp: false,
  blockWebRtc: false, blockPushApi: false, blockLocationApi: false, blockThirdPartyAuth: false, disableThirdPartyCache: false,
};

const STANDARD = { ...OFF, hideSearchQueries: true, sendDnt: true, removeXClientData: true, stripTrackingParams: true };
const HIGH = {
  ...STANDARD,
  thirdPartyCookies: { enabled: true, minutes: 180 },
  hideReferrer: true, blockThirdPartyAuth: true, disableThirdPartyCache: true, blockPushApi: true, blockWebRtc: true,
};
const EXTREME = {
  ...HIGH,
  thirdPartyCookies: { enabled: true, minutes: 0 },
  firstPartyCookies: { enabled: true, minutes: 4320 },
  blockLocationApi: true, hideUserAgent: true, maskIp: true,
};

export const PRESETS = { standard: STANDARD, high: HIGH, extreme: EXTREME };
/** Web filter list enabled by the High and Extreme presets (URL tracking parameters). */
export const URL_TRACKING_FILTER_ID = 111;

// ---------- Windows privacy switches ----------

const DWORD = 'REG_DWORD';
export const WINDOWS_TWEAKS = {
  telemetry: {
    label: 'Limit Windows diagnostic data (telemetry)',
    values: [
      { key: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection', name: 'AllowTelemetry', type: DWORD, data: '0' },
      { key: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection', name: 'DisableOneSettingsDownloads', type: DWORD, data: '1' },
    ],
  },
  advertisingId: {
    label: 'Turn off the advertising ID',
    values: [{ key: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo', name: 'DisabledByGroupPolicy', type: DWORD, data: '1' }],
  },
  recall: {
    label: 'Turn off Windows Recall snapshots',
    values: [
      { key: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI', name: 'DisableAIDataAnalysis', type: DWORD, data: '1' },
      { key: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI', name: 'AllowRecallEnablement', type: DWORD, data: '0' },
    ],
  },
  wapPush: {
    label: 'Disable the WAP Push message routing service',
    values: [{ key: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\dmwappushservice', name: 'Start', type: DWORD, data: '4' }],
  },
  feedback: {
    label: 'Stop Windows feedback prompts',
    values: [{ key: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection', name: 'DoNotShowFeedbackNotifications', type: DWORD, data: '1' }],
  },
};

function defaultReg(args) {
  return new Promise((resolve) => {
    execFile('reg.exe', args, { windowsHide: true }, (err, stdout, stderr) => {
      resolve({ code: err ? (err.code ?? 1) : 0, stdout: stdout || '', stderr: (stderr || '').trim() });
    });
  });
}

export function parseRegQuery(stdout, name) {
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.match(/^\s+(\S+)\s+(REG_\w+)\s*(.*)$/);
    if (m && m[1].toLowerCase() === name.toLowerCase()) {
      let data = m[3].trim();
      if (m[2] === 'REG_DWORD' && /^0x[0-9a-f]+$/i.test(data)) data = String(parseInt(data, 16));
      return { type: m[2], data };
    }
  }
  return null;
}

export class WindowsPrivacy {
  constructor(dataDir, { reg = defaultReg } = {}) {
    this.file = path.join(dataDir, 'windows-privacy.json');
    this.reg = reg;
    this.state = { snapshots: {} }; // tweak → [{ key, name, existed, type, data }]
    this.errors = {};
    this.running = null;
    try {
      this.state = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch {
      // nothing applied yet
    }
  }

  save() {
    writeFileAtomic(this.file, JSON.stringify(this.state, null, 2));
  }

  async read(v) {
    const r = await this.reg(['query', v.key, '/v', v.name]);
    return r.code === 0 ? parseRegQuery(r.stdout, v.name) : null;
  }

  async apply(id) {
    const snapshot = [];
    for (const v of WINDOWS_TWEAKS[id].values) {
      const current = await this.read(v);
      snapshot.push({ key: v.key, name: v.name, existed: !!current, type: current?.type ?? v.type, data: current?.data ?? null });
    }
    for (const v of WINDOWS_TWEAKS[id].values) {
      const r = await this.reg(['add', v.key, '/v', v.name, '/t', v.type, '/d', v.data, '/f']);
      if (r.code !== 0) throw new Error(r.stderr || `reg add failed (${r.code})`);
    }
    this.state.snapshots[id] = snapshot;
    this.save();
  }

  async restore(id) {
    for (const s of this.state.snapshots[id] || []) {
      const r = s.existed
        ? await this.reg(['add', s.key, '/v', s.name, '/t', s.type, '/d', s.data, '/f'])
        : await this.reg(['delete', s.key, '/v', s.name, '/f']);
      if (r.code !== 0 && s.existed) throw new Error(r.stderr || `reg restore failed (${r.code})`);
    }
    delete this.state.snapshots[id];
    this.save();
  }

  /** Brings the registry in line with settings.privacy.windows (serialized). */
  sync(wanted) {
    const run = async () => {
      for (const id of Object.keys(WINDOWS_TWEAKS)) {
        const want = !!wanted?.[id];
        const applied = !!this.state.snapshots[id];
        try {
          if (want && !applied) await this.apply(id);
          else if (!want && applied) await this.restore(id);
          delete this.errors[id];
        } catch (e) {
          const msg = /access is denied/i.test(e.message) ? 'needs administrator rights (run AdHush as a service)' : e.message;
          this.errors[id] = msg;
          log.warn(`windows privacy "${id}": ${msg}`);
        }
      }
    };
    this.running = (this.running || Promise.resolve()).then(run);
    return this.running;
  }

  status(wanted) {
    return Object.fromEntries(Object.entries(WINDOWS_TWEAKS).map(([id, t]) => [id, {
      label: t.label, wanted: !!wanted?.[id], applied: !!this.state.snapshots[id], error: this.errors[id] || null,
    }]));
  }
}
