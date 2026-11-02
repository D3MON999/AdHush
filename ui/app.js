const TOKEN = document.querySelector('meta[name="api-token"]').content;
const view = document.getElementById('view');
let timers = [];
let currentRoute = null;

// ---------- helpers ----------
async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { 'x-adhush-token': TOKEN, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (n) => Number(n || 0).toLocaleString();
const $ = (sel, root = view) => root.querySelector(sel);
const $$ = (sel, root = view) => [...root.querySelectorAll(sel)];

function ago(ts) {
  if (!ts) return 'never';
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

function toast(msg, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (isError ? ' error' : '');
  el.textContent = msg;
  document.getElementById('toasts').append(el);
  setTimeout(() => el.remove(), isError ? 6000 : 3000);
}

async function act(fn, okMsg) {
  try {
    const r = await fn();
    if (okMsg) toast(okMsg);
    return r;
  } catch (e) {
    toast(e.message, true);
    throw e;
  }
}

function every(ms, fn) {
  timers.push(setInterval(fn, ms));
}

function sw(id, checked, extra = '') {
  return `<label class="switch ${extra}"><input type="checkbox" id="${id}" ${checked ? 'checked' : ''}><span></span></label>`;
}

const SHIELD = '<svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z"/><path d="m11 16 3.5 3.5L21.5 12" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function applyTheme(theme) {
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}

async function refreshSidebar() {
  try {
    const s = await api('GET', '/api/status');
    const p = s.protection;
    const state = !p.enabled ? 'off' : !p.active ? 'paused' : 'on';
    const text = { off: 'Protection off', paused: `Paused until ${new Date(p.pausedUntil).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`, on: 'Protection on' }[state];
    document.getElementById('side-status').innerHTML = `<span class="dot ${state}"></span><div><strong>${esc(text)}</strong><br>${fmt(s.engine.rules)} rules · v${esc(s.version)}</div>`;
  } catch {
    document.getElementById('side-status').innerHTML = '<span class="dot down"></span><div><strong>Service not running</strong><br>Start AdHush to filter</div>';
  }
}

// ---------- views ----------
const views = {};

views.home = async (params) => {
  let focusFix = params?.has('fix'); // #/home?fix (tray menu) jumps to the "site not working" box
  const render = async () => {
    const [st, stats, { sites: broken }] = await Promise.all([api('GET', '/api/status'), api('GET', '/api/stats?period=24h'), api('GET', '/api/sites/broken')]);
    const p = st.protection;
    const state = !p.enabled ? 'off' : p.active ? 'on' : 'paused';
    const until = new Date(p.pausedUntil).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const title = { on: 'Your PC is protected', off: 'Protection is turned off', paused: `Protection resumes at ${until}` }[state];
    const pill = { on: 'Active', off: 'Off', paused: 'Paused' }[state];
    view.innerHTML = `
      <h1>Overview</h1><p class="sub">Blocks ads, trackers, malware and phishing for every app on this PC.</p>
      <div class="card hero ${state}">
        <div class="shield">${SHIELD}</div>
        <div><span class="state-pill">${pill}</span><div class="title">${esc(title)}</div>
          <div class="hint">${fmt(st.engine.rules)} active rules from ${st.filters.enabled} filters · updated ${ago(st.engine.builtAt)}</div></div>
        <div class="spacer"></div>
        <div class="row">
          ${state !== 'off' ? '<button data-pause="5">Pause 5 min</button><button data-pause="30">30 min</button><button data-pause="60">1 h</button>' : ''}
          ${state === 'paused' ? '<button id="resume" class="primary">Resume</button>' : ''}
          <label class="switch big" title="Protection on/off"><input type="checkbox" id="prot" aria-label="Protection" ${p.enabled ? 'checked' : ''}><span></span></label>
        </div>
      </div>
      <div class="tiles">
        <div class="tile"><div class="v">${fmt(stats.total)}</div><div class="l">DNS queries (24 h)</div></div>
        <div class="tile"><div class="v">${fmt(stats.blocked)}</div><div class="l">Blocked</div></div>
        <div class="tile"><div class="v">${stats.blockedPercent}%</div><div class="l">Blocked share</div></div>
        <div class="tile"><div class="v">${stats.avgMs} ms</div><div class="l">Avg. processing</div></div>
      </div>
      <div class="card" id="fix-card"><h2>A website not working?</h2>
        <p class="hint" style="margin-top:0">Turn AdHush off for just that site: nothing is blocked there and its traffic is left untouched. Everything else stays protected.</p>
        <div class="row"><input type="text" id="fix-site" placeholder="example.com or paste the page address" style="flex:1;min-width:220px" aria-label="Website address"><button id="fix-btn" class="primary">Turn off for this site</button></div>
        ${broken.length ? `<div class="hint" style="margin-top:12px">AdHush is off for:</div><ul class="list">${broken.map((h) => `<li><span class="name">${esc(h)}</span><button class="small" data-unfix="${esc(h)}">Turn back on</button></li>`).join('')}</ul>` : ''}
      </div>
      <div class="grid">
        <div class="card"><h2>Most blocked (24 h)</h2>
          ${stats.topBlocked.length ? `<ul class="list">${stats.topBlocked.slice(0, 10).map((d) => `<li><span class="name">${esc(d.name)}</span><span>${fmt(d.count)}</span></li>`).join('')}</ul>` : '<div class="empty">Nothing blocked yet</div>'}
        </div>
        <div class="card"><h2>Check a domain</h2>
          <div class="row"><input type="text" id="chk" placeholder="ads.example.com" style="flex:1"><button id="chk-btn">Check</button></div>
          <div id="chk-out" class="hint" style="margin-top:10px"></div>
          <h2 style="margin-top:22px">DNS service</h2>
          ${st.dns.listening.length ? `<div class="hint">Listening on ${st.dns.listening.map((l) => `<code>${esc(l)}</code>`).join(' ')}</div>` : ''}
          ${st.dns.errors.map((e) => `<div class="err">${esc(e)}</div>`).join('')}
          <div class="hint" style="margin-top:8px">To filter every app on this PC, turn on <a href="#/settings">Settings → Whole-PC protection</a>.</div>
        </div>
      </div>`;
    $('#prot').onchange = (e) => act(() => api('POST', '/api/protection', { enabled: e.target.checked }), e.target.checked ? 'Protection enabled' : 'Protection disabled').then(render).then(refreshSidebar);
    $$('[data-pause]').forEach((b) => (b.onclick = () => act(() => api('POST', '/api/protection/pause', { minutes: Number(b.dataset.pause) }), `Paused for ${b.dataset.pause} min`).then(render).then(refreshSidebar)));
    if ($('#resume')) $('#resume').onclick = () => act(() => api('POST', '/api/protection', { enabled: true })).then(render).then(refreshSidebar);
    const check = async () => {
      const name = $('#chk').value.trim();
      if (!name) return;
      const r = await act(() => api('GET', `/api/check?name=${encodeURIComponent(name)}`));
      const src = r.filterName || '';
      $('#chk-out').innerHTML = r.action === 'none' ? `<span class="ok">${esc(r.name)} is not filtered.</span>`
        : `<span class="badge ${r.action === 'block' ? 'blocked' : r.action === 'allow' ? 'allowed' : 'rewritten'}">${esc(r.action)}</span> by <code>${esc(r.rule)}</code> (${esc(src)})`;
    };
    $('#chk-btn').onclick = check;
    $('#chk').onkeydown = (e) => e.key === 'Enter' && check();
    const fix = () => {
      const host = $('#fix-site').value.trim();
      if (!host) return $('#fix-site').focus();
      act(() => api('POST', '/api/sites/broken', { host, broken: true }), null)
        .then((r) => { toast(`AdHush is now off for ${r.host}. Reload the page.`); return render(); }).catch(() => {});
    };
    $('#fix-btn').onclick = fix;
    $('#fix-site').onkeydown = (e) => e.key === 'Enter' && fix();
    $$('[data-unfix]').forEach((b) => (b.onclick = () => act(() => api('POST', '/api/sites/broken', { host: b.dataset.unfix, broken: false }), `AdHush is on again for ${b.dataset.unfix}`).then(render)));
    if (focusFix) {
      focusFix = false;
      $('#fix-card').scrollIntoView({ block: 'center' });
      $('#fix-site').focus();
    }
  };
  await render();
  every(10000, () => { if (!['chk', 'fix-site'].includes(document.activeElement?.id)) render().catch(() => {}); });
};

views.filters = async () => {
  const render = async () => {
    const [{ groups, filters, engine }, settings] = await Promise.all([api('GET', '/api/filters'), api('GET', '/api/settings')]);
    const byGroup = {};
    for (const f of filters) (byGroup[f.group] ||= []).push(f);
    const webNote = settings.https.enabled ? '' : 'Web filtering is off: these lists apply once you enable it on the Web filtering page.';
    const gateNote = { security: settings.security.enabled ? '' : 'Browsing security is off in Settings: these lists are inactive.',
      parental: settings.parental.enabled ? '' : 'Parental control is off in Settings: these lists are inactive.',
      webads: webNote, webprivacy: webNote, webannoyances: webNote };
    view.innerHTML = `
      <h1>Filters</h1><p class="sub">${fmt(engine.rules)} rules active. Lists update automatically every ${settings.filtering.updateIntervalHours || '—'} h.</p>
      <div class="card"><div class="row">
        <input type="text" id="add-url" placeholder="https://example.com/list.txt or C:\\path\\list.txt" style="flex:2;min-width:240px">
        <input type="text" id="add-name" placeholder="Name (optional)" style="flex:1;min-width:140px">
        <select id="add-scope" title="Where the list is applied"><option value="dns">DNS list</option><option value="content">Web (HTTPS) list</option></select>
        <button id="add" class="primary">Add list</button>
        <button id="upd">Check for updates</button>
      </div></div>
      ${Object.entries(groups).filter(([g]) => byGroup[g]).map(([g, label]) => `
        <div class="card"><h2>${esc(label)}</h2>${gateNote[g] ? `<div class="hint" style="margin-bottom:8px">${esc(gateNote[g])}</div>` : ''}
          ${byGroup[g].map((f) => `
            <div class="toggle-row">
              ${sw(`f-${f.id}`, f.enabled)}
              <div class="body">
                <div class="name">${esc(f.name)} ${f.homepage ? `<a href="${esc(f.homepage)}" target="_blank" rel="noopener" class="hint">site</a>` : ''}</div>
                <div class="desc">${f.custom ? `<span class="badge">${f.scope === 'content' ? 'web' : 'dns'}</span> ` : ''}${esc(f.description || f.url)}</div>
                <div class="hint">${f.downloaded ? `${fmt(f.rulesCount)} rules · updated ${ago(f.lastUpdate)}${f.version ? ` · v${esc(f.version)}` : ''}` : 'not downloaded'}
                  ${f.error ? ` · <span class="err">${esc(f.error)}</span>` : ''}</div>
              </div>
              ${f.custom ? `<button class="small danger" data-del="${f.id}">Remove</button>` : ''}
            </div>`).join('')}
        </div>`).join('')}`;
    $$('input[id^="f-"]').forEach((el) => (el.onchange = () => act(() => api('PATCH', `/api/filters/${el.id.slice(2)}`, { enabled: el.checked }), 'Filter updated').then(render).then(refreshSidebar)));
    $$('[data-del]').forEach((b) => (b.onclick = () => confirm('Remove this filter list?') && act(() => api('DELETE', `/api/filters/${b.dataset.del}`), 'Removed').then(render)));
    $('#add').onclick = async (e) => {
      e.target.disabled = true;
      try {
        await act(() => api('POST', '/api/filters', { url: $('#add-url').value, name: $('#add-name').value || undefined, scope: $('#add-scope').value }), 'List added');
        await render();
      } catch { e.target.disabled = false; }
    };
    $('#upd').onclick = async (e) => {
      e.target.disabled = true;
      e.target.textContent = 'Updating…';
      const results = await act(() => api('POST', '/api/filters/update', { force: true })).catch(() => []);
      const failed = results.filter((r) => r.status === 'failed').length;
      toast(`${results.length} lists checked${failed ? `, ${failed} failed` : ''}`, failed > 0);
      await render();
    };
  };
  await render();
};

function driverStatus(d) {
  if (!d) return '';
  if (d.running) {
    return `<div class="hint" style="margin-bottom:8px"><span class="badge allowed">active</span> ${fmt(d.activeConnections)} connections redirected now · ${fmt(d.redirected)} total · ${fmt(d.quicDropped)} QUIC packets dropped</div>`;
  }
  return d.error ? `<div class="err" style="margin-bottom:8px">${esc(d.error)}</div>` : '';
}

views.https = async () => {
  const render = async () => {
    const [st, s] = await Promise.all([api('GET', '/api/https/status'), api('GET', '/api/settings')]);
    const h = s.https;
    const c = st.core;
    const state = !h.enabled ? 'off' : c ? 'on' : 'paused';
    const title = !h.enabled ? 'Web filtering is off' : c ? `Proxy running on 127.0.0.1:${c.proxyPort}` : st.lastError || 'Starting…';
    const t = c?.stats || {};
    view.innerHTML = `
      <h1>Web filtering</h1><p class="sub">HTTPS-aware filtering: blocks ad and tracker requests, hides page elements, strips tracking parameters.</p>
      ${h.enabled ? '' : `<div class="card notice"><strong>Advanced feature, off by default.</strong> DNS blocking already stops most ads for every app. Web filtering goes further (for example YouTube ads) but decrypts HTTPS traffic and can break some sites and apps. If a site breaks, add it to the exclusions below or switch this off.</div>`}
      <div class="card hero ${state}">
        <div class="shield">${SHIELD}</div>
        <div><div class="title">${esc(title)}</div>
          <div class="hint">${c ? `${fmt(c.engine.rules)} rules from ${c.engine.lists} web lists · engine built in ${c.engine.ms} ms` : esc(st.binary ? '' : 'Core binary missing: run "cargo build --release" in adhush\\core')}</div></div>
        <div class="spacer"></div>${sw('h-on', h.enabled, 'big')}
      </div>
      ${c ? `<div class="tiles">
        <div class="tile"><div class="v">${fmt(t.requests)}</div><div class="l">Requests filtered</div></div>
        <div class="tile"><div class="v">${fmt(t.blocked)}</div><div class="l">Blocked</div></div>
        <div class="tile"><div class="v">${fmt(t.injected)}</div><div class="l">Pages cleaned (CSS)</div></div>
        <div class="tile"><div class="v">${fmt(t.rewritten)}</div><div class="l">URLs de-tracked</div></div>
        <div class="tile"><div class="v">${fmt(t.mitm)}</div><div class="l">HTTPS sessions inspected</div></div>
        <div class="tile"><div class="v">${fmt(t.tunneled)}</div><div class="l">Passed through</div></div>
      </div>` : ''}
      <div class="grid">
        <div class="card"><h2>Setup</h2>
          <ol class="hint" style="padding-left:18px;margin:0">
            <li style="margin-bottom:10px"><strong>Trust the AdHush certificate</strong> so HTTPS pages can be filtered. It is unique to this PC and its private key never leaves it.<br>
              <button id="ca" class="small" style="margin-top:6px">Download certificate</button> then run <code>scripts\\install-ca.ps1</code>. Windows asks you to confirm.</li>
            <li style="margin-bottom:10px"><strong>Route traffic through the filter</strong>: run <code>scripts\\set-system-proxy.ps1</code> (no admin needed). Undo it with <code>scripts\\restore-system-proxy.ps1</code>.</li>
            <li><strong>Firefox</strong> uses its own certificate store: set <code>security.enterprise_roots.enabled</code> to <code>true</code> in <code>about:config</code>.</li>
          </ol>
        </div>
        <div class="card"><h2>Options</h2>
          <div class="toggle-row">${sw('h-cos', h.cosmetic)}<div class="body"><div class="name">Hide page elements</div><div class="desc">Inject cosmetic rules (element hiding) into web pages.</div></div></div>
          <div class="toggle-row">${sw('h-ev', h.skipEv)}<div class="body"><div class="name">Don't filter sites with EV certificates</div><div class="desc">Banks and payment sites often use Extended Validation certificates.</div></div></div>
          <div class="toggle-row">${sw('h-auto', h.autoExclude)}<div class="body"><div class="name">Auto-exclude apps that reject the certificate</div><div class="desc">Apps with certificate pinning keep working: their hosts are passed through for an hour.</div></div></div>
          <label class="field" style="margin-top:10px"><span>Never decrypt these domains (one per line)</span><textarea id="h-ex" rows="5">${esc(h.exclusions.map((d) => d.name ?? d).join('\n'))}</textarea></label>
          <div class="row"><label class="field" style="flex:1"><span>Proxy port</span><input type="number" id="h-port" value="${h.port}"></label>
            <label class="field" style="flex:1"><span>Control port</span><input type="number" id="h-cport" value="${h.controlPort}"></label></div>
          <button id="h-save" class="primary">Save</button>
          ${c?.autoExcluded?.length ? `<h2 style="margin-top:16px">Auto-excluded hosts</h2><div class="hint mono">${c.autoExcluded.map(esc).join('<br>')}</div><button id="h-clear" class="small" style="margin-top:8px">Clear auto-exclusions</button>` : ''}
        </div>
        <div class="card"><h2>Driver mode (per-app interception)</h2>
          <p class="hint" style="margin-top:0">Uses the WinDivert driver to send chosen apps' web traffic through AdHush, even apps that ignore the Windows proxy. AdHush must run as administrator (the autostart task does).</p>
          ${driverStatus(c?.driver)}
          <div class="toggle-row">${sw('d-on', h.driver.enabled)}<div class="body"><div class="name">Enable driver mode</div></div></div>
          <label class="field"><span>Apps to filter</span><select id="d-mode"><option value="selected">Only the apps listed below</option><option value="all">All apps except the excluded ones</option></select></label>
          <label class="field"><span>Filtered apps (executable names, one per line)</span><textarea id="d-apps" rows="5">${esc(h.driver.apps.join('\n'))}</textarea></label>
          <label class="field"><span>Never filter these apps</span><textarea id="d-ex" rows="3">${esc(h.driver.excluded.join('\n'))}</textarea></label>
          <div class="toggle-row">${sw('d-quic', h.driver.blockQuic)}<div class="body"><div class="name">Block QUIC (HTTP/3) for filtered apps</div><div class="desc">Browsers then use HTTP/1.1–2 over TCP, which AdHush can filter.</div></div></div>
          <button id="d-save" class="primary">Save driver settings</button>
        </div>
      </div>
      ${c ? `<div class="card"><h2>Recent web requests</h2>
        <table><thead><tr><th>Time</th><th>URL</th><th>Type</th><th>Action</th><th>Rule</th><th class="num">Status</th></tr></thead><tbody id="h-rows"></tbody></table></div>` : ''}`;
    $('#h-on').onchange = (e) => act(() => api('PATCH', '/api/settings', { https: { enabled: e.target.checked } }), e.target.checked ? 'Web filtering enabled' : 'Web filtering disabled').then(() => setTimeout(render, 1500));
    $('#h-save').onclick = () => act(() => api('PATCH', '/api/settings', { https: {
      cosmetic: $('#h-cos').checked, skipEv: $('#h-ev').checked, autoExclude: $('#h-auto').checked,
      exclusions: $('#h-ex').value.split(/\r?\n/).map((x) => x.trim().toLowerCase()).filter(Boolean),
      port: Number($('#h-port').value), controlPort: Number($('#h-cport').value),
    } }), 'Saved').then(() => setTimeout(render, 1000));
    if ($('#h-clear')) $('#h-clear').onclick = () => act(() => api('POST', '/api/https/clear-exclusions'), 'Cleared').then(render);
    $('#d-mode').value = h.driver.mode;
    const exeList = (id) => $(id).value.split(/[\r\n,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean);
    $('#d-save').onclick = () => act(() => api('PATCH', '/api/settings', { https: { driver: {
      enabled: $('#d-on').checked, mode: $('#d-mode').value, apps: exeList('#d-apps'), excluded: exeList('#d-ex'), blockQuic: $('#d-quic').checked,
    } } }), 'Driver settings saved').then(() => setTimeout(render, 2500));
    $('#ca').onclick = async () => {
      const { pem } = await act(() => api('GET', '/api/https/ca'));
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([pem], { type: 'application/x-x509-ca-cert' }));
      a.download = 'adhush-ca.cer';
      a.click();
      URL.revokeObjectURL(a.href);
    };
    if (c) await loadLog();
  };
  const ACTION_BADGE = { blocked: 'blocked', redirected: 'blocked', rewritten: 'rewritten', cosmetic: 'allowed', error: 'error' };
  const loadLog = async () => {
    if (!$('#h-rows')) return;
    const { items } = await api('GET', '/api/https/log?limit=150');
    $('#h-rows').innerHTML = items.length ? items.map((e) => `<tr>
        <td class="hint">${new Date(e.time).toLocaleTimeString()}</td>
        <td class="mono">${esc(e.url)}</td><td>${esc(e.type)}</td>
        <td><span class="badge ${ACTION_BADGE[e.action] || ''}">${esc(e.action)}</span></td>
        <td class="mono">${esc(e.rule || '')}</td><td class="num">${e.status || ''}</td></tr>`).join('')
      : '<tr><td colspan="6" class="empty">No web requests yet. Route traffic through the proxy (see Setup).</td></tr>';
  };
  await render();
  every(3000, () => loadLog().catch(() => {}));
};

const PRIVACY_TOGGLES = [
  ['General', [
    ['hideSearchQueries', 'Hide your search queries', 'Search engines do not pass what you searched for to the sites you open.'],
    ['sendDnt', 'Ask websites not to track you', 'Sends Do-Not-Track and Global Privacy Control signals.'],
    ['removeXClientData', 'Remove the X-Client-Data header', 'Chrome sends this identifying header to Google services.'],
    ['stripTrackingParams', 'Strip tracking parameters from links', 'Removes utm_*, fbclid, gclid, msclkid and similar from URLs.'],
  ]],
  ['Tracking methods', [
    ['hideReferrer', 'Hide referrer from third parties', 'Third-party requests do not learn which page you were on.'],
    ['disableThirdPartyCache', 'Disable third-party cache', 'Prevents tracking through cached files (ETag tracking).'],
    ['blockThirdPartyAuth', 'Block third-party Authorization header', 'Stops third parties from tracking you via HTTP authentication.'],
  ]],
  ['Browser APIs', [
    ['blockWebRtc', 'Block WebRTC', 'Prevents your real IP address leaking through WebRTC (breaks video calls in the browser).'],
    ['blockPushApi', 'Block Push API', 'Sites cannot ask to send you push notifications.'],
    ['blockLocationApi', 'Block Location API', 'Sites cannot request your location.'],
  ]],
  ['Identity', [
    ['hideUserAgent', 'Hide your User-Agent', 'Sends a generic browser identity (or your custom value below).'],
    ['maskIp', 'Mask your IP address', 'Adds a fake X-Forwarded-For header. It does not hide your real IP from the server.'],
  ]],
];

views.privacy = async () => {
  const render = async () => {
    const [s, win, st] = await Promise.all([api('GET', '/api/settings'), api('GET', '/api/privacy/windows'), api('GET', '/api/https/status')]);
    const p = s.privacy;
    const presetBtn = (id, label) => `<button data-preset="${id}" class="${p.preset === id ? 'active' : ''}">${label}</button>`;
    const cookieRow = (key, title, desc) => `<div class="toggle-row">${sw(`pv-${key}`, p[key].enabled)}<div class="body"><div class="name">${title}</div><div class="desc">${desc}</div>
      <label class="hint">Delete after <input type="number" id="pv-${key}-min" min="0" value="${p[key].minutes}" style="width:90px"> minutes (0 = block entirely)</label></div></div>`;
    view.innerHTML = `
      <h1>Tracking protection</h1><p class="sub">Stops websites and apps from following you around. These options work on traffic AdHush filters (turn on <a href="#/https">Web filtering</a>).</p>
      ${!st.enabled ? '<div class="card"><span class="err">Web filtering is off, so tracking protection is not active yet.</span></div>' : ''}
      <div class="card hero ${p.enabled ? 'on' : 'off'}"><div class="shield">${SHIELD}</div>
        <div><div class="title">Tracking protection is ${p.enabled ? 'on' : 'off'}</div><div class="hint">Level: ${esc(p.preset)}</div></div>
        <div class="spacer"></div>${sw('pv-on', p.enabled, 'big')}</div>
      <div class="card"><h2>Protection level</h2>
        <div class="tabs" style="margin:0">${presetBtn('standard', 'Standard')}${presetBtn('high', 'High')}${presetBtn('extreme', 'Extreme')}${presetBtn('custom', 'Custom')}</div>
        <p class="hint" style="margin-bottom:0">Standard is safe for every site. High limits third-party cookies, referrers and caches. Extreme blocks third-party cookies and can break some sites.</p>
      </div>
      <div class="grid">
        ${PRIVACY_TOGGLES.map(([group, items]) => `<div class="card"><h2>${group}</h2>${items.map(([k, t, d]) => `<div class="toggle-row">${sw(`pv-${k}`, p[k])}<div class="body"><div class="name">${t}</div><div class="desc">${d}</div></div></div>`).join('')}</div>`).join('')}
        <div class="card"><h2>Cookies</h2>
          ${cookieRow('thirdPartyCookies', 'Self-destruct third-party cookies', 'Cookies set by other sites (ads, trackers) expire quickly.')}
          ${cookieRow('firstPartyCookies', 'Self-destruct first-party cookies', 'Also limits the site\'s own cookies. You will be logged out more often.')}
        </div>
        <div class="card"><h2>Custom values</h2>
          <label class="field"><span>Custom referrer (empty = remove)</span><input type="text" id="pv-customReferrer" value="${esc(p.customReferrer)}"></label>
          <label class="field"><span>Custom User-Agent (empty = generic)</span><input type="text" id="pv-customUserAgent" value="${esc(p.customUserAgent)}"></label>
          <label class="field"><span>Custom IP for masking (empty = random)</span><input type="text" id="pv-customIp" value="${esc(p.customIp)}"></label>
        </div>
        <div class="card"><h2>Protect against DPI</h2>
          <p class="hint" style="margin-top:0">Some internet providers block sites by reading the site name in the first packet. Splitting that packet often gets around the block.</p>
          <div class="toggle-row">${sw('pv-dpi', p.antiDpi.enabled)}<div class="body"><div class="name">Split the first packet of each connection</div></div></div>
          <label class="field"><span>First TLS fragment size (bytes)</span><input type="number" id="pv-dpi-tls" min="1" max="100" value="${p.antiDpi.tlsFragment}"></label>
          <div class="toggle-row">${sw('pv-dpi-http', p.antiDpi.http)}<div class="body"><div class="name">Also split plain HTTP requests</div></div></div>
        </div>
        <div class="card"><h2>Windows tracking</h2>
          <p class="hint" style="margin-top:0">Changes Windows policies. Turning a switch off restores the previous value. Needs AdHush to run as administrator (the autostart task does).</p>
          ${Object.entries(win).map(([id, w]) => `<div class="toggle-row">${sw(`win-${id}`, w.wanted)}<div class="body"><div class="name">${esc(w.label)}</div>
            <div class="desc">${w.applied ? '<span class="ok">applied</span>' : w.wanted ? '<span class="hint">pending</span>' : ''}${w.error ? ` <span class="err">${esc(w.error)}</span>` : ''}</div></div></div>`).join('')}
        </div>
      </div>
      <button id="pv-save" class="primary">Save</button>`;
    $('#pv-on').onchange = (e) => act(() => api('PATCH', '/api/settings', { privacy: { enabled: e.target.checked } }), 'Saved').then(render);
    $$('[data-preset]').forEach((b) => (b.onclick = () => {
      if (b.dataset.preset === 'custom') return act(() => api('PATCH', '/api/settings', { privacy: { preset: 'custom' } })).then(render);
      return act(() => api('POST', '/api/privacy/preset', { preset: b.dataset.preset }), `${b.textContent} protection applied`).then(render);
    }));
    $('#pv-save').onclick = () => {
      const patch = { preset: 'custom' };
      for (const [, items] of PRIVACY_TOGGLES) for (const [k] of items) patch[k] = $(`#pv-${k}`).checked;
      for (const k of ['thirdPartyCookies', 'firstPartyCookies']) patch[k] = { enabled: $(`#pv-${k}`).checked, minutes: Math.max(0, Math.round(Number($(`#pv-${k}-min`).value) || 0)) };
      for (const k of ['customReferrer', 'customUserAgent', 'customIp']) patch[k] = $(`#pv-${k}`).value.trim();
      patch.antiDpi = { enabled: $('#pv-dpi').checked, tlsFragment: Number($('#pv-dpi-tls').value) || 1, http: $('#pv-dpi-http').checked };
      patch.windows = Object.fromEntries(Object.keys(win).map((id) => [id, $(`#win-${id}`).checked]));
      return act(() => api('PATCH', '/api/settings', { privacy: patch }), 'Tracking protection saved').then(() => setTimeout(render, 800));
    };
  };
  await render();
};

views.apps = async (params) => {
  const showInstalled = params.get('installed') === '1';
  let data = null;
  const render = () => {
    const q = ($('#ap-q')?.value || '').toLowerCase();
    const rows = data.apps.filter((a) => !q || a.exe.includes(q) || a.name.toLowerCase().includes(q));
    $('#ap-rows').innerHTML = rows.length ? rows.map((a) => `<tr>
        <td><strong>${esc(a.name)}</strong><div class="hint mono">${esc(a.exe)}${a.publisher ? ` · ${esc(a.publisher)}` : ''}</div></td>
        <td class="hint">${a.running ? `<span class="badge allowed">running</span> ` : ''}${a.connections ? `${a.connections} connections` : ''}${a.installed && !a.running ? 'installed' : ''}</td>
        <td class="num">${fmt(a.requests)}</td><td class="num">${fmt(a.blocked)}</td>
        <td>${sw(`ap-f-${a.exe}`, a.filter)}</td><td>${sw(`ap-h-${a.exe}`, a.https)}</td></tr>`).join('')
      : '<tr><td colspan="6" class="empty">No apps match</td></tr>';
    for (const a of rows) {
      const patch = (body, msg) => act(() => api('PATCH', `/api/apps/${encodeURIComponent(a.exe)}`, body), msg);
      document.getElementById(`ap-f-${a.exe}`).onchange = (e) => patch({ filter: e.target.checked }, `${a.exe}: filtering ${e.target.checked ? 'on' : 'off'}`);
      document.getElementById(`ap-h-${a.exe}`).onchange = (e) => patch({ https: e.target.checked }, `${a.exe}: HTTPS filtering ${e.target.checked ? 'on' : 'off'}`);
    }
  };
  view.innerHTML = `
    <h1>Apps</h1><p class="sub">Choose which programs AdHush filters. Request counts come from web filtering (proxy and driver mode).</p>
    <div class="card"><div class="row">
      <input type="search" id="ap-q" placeholder="Search apps" style="flex:1;min-width:180px">
      <label class="row hint"><input type="checkbox" id="ap-inst" ${showInstalled ? 'checked' : ''}> Show installed apps</label>
      <input type="text" id="ap-add" placeholder="app.exe" style="width:160px"><button id="ap-add-btn">Add app</button>
    </div><div id="ap-note" class="hint" style="margin-top:8px"></div></div>
    <div class="card"><table><thead><tr><th>App</th><th>Activity</th><th class="num">Requests</th><th class="num">Blocked</th><th>Filter</th><th>HTTPS</th></tr></thead>
      <tbody id="ap-rows"><tr><td colspan="6" class="empty">Loading apps…</td></tr></tbody></table></div>`;
  $('#ap-inst').onchange = (e) => { location.hash = e.target.checked ? '#/apps?installed=1' : '#/apps'; };
  $('#ap-q').oninput = () => data && render();
  $('#ap-add-btn').onclick = () => {
    const exe = $('#ap-add').value.trim().toLowerCase();
    if (exe) act(() => api('PATCH', `/api/apps/${encodeURIComponent(exe)}`, { filter: true }), `${exe} added`).then(() => views.apps(params));
  };
  data = await api('GET', `/api/apps${showInstalled ? '?installed=1' : ''}`);
  $('#ap-note').innerHTML = !data.webFiltering ? 'Web filtering is off: only DNS filtering applies, which works for every app regardless of these switches.'
    : data.driver.enabled ? `Driver mode is on (${data.driver.mode === 'all' ? 'all apps except those switched off' : 'only apps switched on'}).`
    : 'Proxy mode: apps that use the Windows proxy are filtered unless switched off here.';
  render();
};

views.extensions = async (params) => {
  const pending = params.get('install');
  const render = async () => {
    const { items, settings } = await api('GET', '/api/extensions');
    view.innerHTML = `
      <h1>Userscripts &amp; styles</h1><p class="sub">Userscripts (Tampermonkey/Greasemonkey format) and userstyles (UserCSS). They run in every browser filtered by <a href="#/https">Web filtering</a>.</p>
      ${pending ? `<div class="card"><h2>Install from link</h2><p class="mono">${esc(pending)}</p>
        <p class="hint">Only install extensions you trust: a userscript can read and change the pages it runs on.</p>
        <div class="row"><button id="ex-confirm" class="primary">Install</button><a href="#/extensions" class="btn">Cancel</a></div></div>` : ''}
      <div class="card"><h2>Add an extension</h2>
        <div class="row" style="margin-bottom:10px"><input type="text" id="ex-url" placeholder="https://…/script.user.js or style.user.css" style="flex:1;min-width:220px"><button id="ex-install" class="primary">Install from URL</button></div>
        <details><summary class="hint">…or paste code</summary><textarea id="ex-code" rows="8" spellcheck="false" placeholder="// ==UserScript==" style="margin-top:8px"></textarea><button id="ex-paste" style="margin-top:8px">Install pasted code</button></details>
      </div>
      <div class="card"><div class="row" style="margin-bottom:8px"><h2 style="margin:0">Installed (${items.length})</h2><div class="spacer"></div><button id="ex-update">Check for updates</button></div>
        ${items.length ? items.map((x) => `<div class="toggle-row">${sw(`ex-${x.id}`, x.enabled)}<div class="body">
            <div class="name">${esc(x.name)} <span class="badge">${x.type === 'style' ? 'userstyle' : 'userscript'}</span> <span class="hint">${esc(x.version || '')}</span></div>
            <div class="desc">${esc(x.description || '')}</div>
            <div class="hint mono">${esc(x.type === 'style' ? `${x.sections} section(s)` : [...(x.matches || []), ...(x.includes || [])].slice(0, 4).join('  '))}</div>
          </div><button class="small" data-edit="${x.id}">Edit</button><button class="small danger" data-del="${x.id}">Remove</button></div>`).join('') : '<div class="empty">No extensions installed</div>'}
      </div>
      <div class="card"><h2>Options</h2>
        <div class="toggle-row">${sw('ex-on', settings.enabled)}<div class="body"><div class="name">Run extensions</div></div></div>
        <div class="toggle-row">${sw('ex-auto', settings.autoUpdate)}<div class="body"><div class="name">Update extensions automatically (daily)</div></div></div>
        <div class="toggle-row">${sw('ex-detect', settings.detectInstall)}<div class="body"><div class="name">Offer to install when opening .user.js / .user.css links</div></div></div>
      </div>
      <div class="card" id="ex-editor" hidden><h2 id="ex-ed-title">Edit</h2><textarea id="ex-ed-code" class="editor" spellcheck="false"></textarea>
        <div class="row" style="margin-top:8px"><button id="ex-ed-save" class="primary">Save</button><button id="ex-ed-close">Close</button></div></div>`;
    const install = (body, msg) => act(() => api('POST', '/api/extensions', body), msg).then((e) => { toast(`${e.name} ${e.version || ''} installed`); location.hash = '#/extensions'; return render(); });
    if ($('#ex-confirm')) $('#ex-confirm').onclick = () => install({ url: pending });
    $('#ex-install').onclick = () => $('#ex-url').value.trim() && install({ url: $('#ex-url').value.trim() });
    $('#ex-paste').onclick = () => $('#ex-code').value.trim() && install({ code: $('#ex-code').value });
    $('#ex-update').onclick = async (e) => {
      e.target.disabled = true;
      const r = await act(() => api('POST', '/api/extensions/update')).catch(() => []);
      const updated = r.filter((x) => x.status === 'updated').length;
      toast(`${r.length} checked, ${updated} updated${r.some((x) => x.status === 'failed') ? ', some failed' : ''}`);
      render();
    };
    for (const x of items) {
      $(`#ex-${x.id}`).onchange = (e) => act(() => api('PATCH', `/api/extensions/${x.id}`, { enabled: e.target.checked }), `${x.name} ${e.target.checked ? 'enabled' : 'disabled'}`);
    }
    $$('[data-del]').forEach((b) => (b.onclick = () => confirm('Remove this extension?') && act(() => api('DELETE', `/api/extensions/${b.dataset.del}`), 'Removed').then(render)));
    $$('[data-edit]').forEach((b) => (b.onclick = async () => {
      const { code } = await api('GET', `/api/extensions/${b.dataset.edit}/code`);
      $('#ex-editor').hidden = false;
      $('#ex-ed-title').textContent = `Edit ${items.find((x) => x.id === b.dataset.edit).name}`;
      $('#ex-ed-code').value = code;
      $('#ex-ed-save').onclick = () => act(() => api('PUT', `/api/extensions/${b.dataset.edit}/code`, { code: $('#ex-ed-code').value }), 'Saved').then(render);
      $('#ex-ed-close').onclick = () => { $('#ex-editor').hidden = true; };
      $('#ex-editor').scrollIntoView({ behavior: 'smooth' });
    }));
    const saveOpt = () => act(() => api('PATCH', '/api/settings', { extensions: { enabled: $('#ex-on').checked, autoUpdate: $('#ex-auto').checked, detectInstall: $('#ex-detect').checked } }), 'Saved');
    for (const id of ['#ex-on', '#ex-auto', '#ex-detect']) $(id).onchange = saveOpt;
  };
  await render();
};

views.rules = async () => {
  const r = await api('GET', '/api/rules');
  view.innerHTML = `
    <h1>User rules</h1><p class="sub">Your own rules. They are applied together with the filter lists.</p>
    <div class="grid" style="grid-template-columns: minmax(0,2fr) minmax(260px,1fr)">
      <div class="card">
        <div class="row" style="margin-bottom:10px">${sw('ur-on', r.enabled)}<strong>Enabled</strong><div class="spacer"></div><button id="save" class="primary">Save</button></div>
        <textarea id="rules" class="editor" spellcheck="false" placeholder="||ads.example.com^">${esc(r.text)}</textarea>
      </div>
      <div class="card"><h2>Syntax</h2>
        <ul class="list hint">
          <li><code>||example.com^</code><span>block domain + subdomains</span></li>
          <li><code>@@||example.com^</code><span>allow (unblock)</span></li>
          <li><code>|example.com^</code><span>exact domain only</span></li>
          <li><code>0.0.0.0 example.com</code><span>hosts syntax</span></li>
          <li><code>/^ad[0-9]+\\./</code><span>regular expression</span></li>
          <li><code>*ads*.net^</code><span>wildcards</span></li>
          <li><code>$important</code><span>beats allow rules</span></li>
          <li><code>$dnstype=AAAA</code><span>only these query types</span></li>
          <li><code>$dnsrewrite=1.2.3.4</code><span>answer with an IP / CNAME / NXDOMAIN</span></li>
          <li><code>$denyallow=a.com|b.com</code><span>exclude domains</span></li>
          <li><code>$client=192.168.1.5</code><span>only for this client</span></li>
          <li><code>$badfilter</code><span>disable a rule from a list</span></li>
          <li><code>! comment</code><span>comment line</span></li>
        </ul>
      </div>
    </div>`;
  $('#save').onclick = () => act(() => api('PUT', '/api/rules', { text: $('#rules').value, enabled: $('#ur-on').checked }), 'Rules saved').then(refreshSidebar);
  $('#ur-on').onchange = () => act(() => api('PUT', '/api/rules', { enabled: $('#ur-on').checked }), 'Saved');
  $('#rules').onkeydown = (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); $('#save').click(); }
  };
};

views.lists = async (params) => {
  const type = params.get('type') === 'blocklist' ? 'blocklist' : 'allowlist';
  const render = async () => {
    const l = await api('GET', `/api/lists/${type}`);
    view.innerHTML = `
      <h1>Allow &amp; block lists</h1><p class="sub">Domains here always win over filter lists. Subdomains are included.</p>
      <div class="tabs"><button data-t="allowlist" class="${type === 'allowlist' ? 'active' : ''}">Allowlist</button><button data-t="blocklist" class="${type === 'blocklist' ? 'active' : ''}">Blocklist</button></div>
      <div class="card">
        <div class="row" style="margin-bottom:12px">${sw('l-on', l.enabled)}<strong>${type === 'allowlist' ? 'Allowlist' : 'Blocklist'} enabled</strong></div>
        <div class="row" style="margin-bottom:12px"><input type="text" id="dom" placeholder="example.com (one or more, separated by spaces)" style="flex:1"><button id="add" class="primary">Add</button></div>
        ${l.domains.length ? `<table><thead><tr><th style="width:60px">On</th><th>Domain</th><th></th></tr></thead><tbody>
          ${l.domains.map((d, i) => `<tr><td><input type="checkbox" data-en="${i}" ${d.enabled !== false ? 'checked' : ''}></td><td class="mono">${esc(d.name)}</td><td style="text-align:right"><button class="small danger" data-rm="${i}">Remove</button></td></tr>`).join('')}
        </tbody></table>` : '<div class="empty">No domains yet</div>'}
      </div>`;
    const save = (domains, msg) => act(() => api('PUT', `/api/lists/${type}`, { domains }), msg).then(render);
    $$('[data-t]').forEach((b) => (b.onclick = () => { location.hash = `#/lists?type=${b.dataset.t}`; }));
    $('#l-on').onchange = () => act(() => api('PUT', `/api/lists/${type}`, { enabled: $('#l-on').checked }), 'Saved');
    const add = () => {
      const names = $('#dom').value.split(/[\s,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
      if (!names.length) return;
      const existing = new Set(l.domains.map((d) => d.name));
      save([...l.domains, ...names.filter((n) => !existing.has(n)).map((name) => ({ name, enabled: true }))], 'Added');
    };
    $('#add').onclick = add;
    $('#dom').onkeydown = (e) => e.key === 'Enter' && add();
    $$('[data-rm]').forEach((b) => (b.onclick = () => save(l.domains.filter((_, i) => i !== Number(b.dataset.rm)), 'Removed')));
    $$('[data-en]').forEach((c) => (c.onchange = () => save(l.domains.map((d, i) => (i === Number(c.dataset.en) ? { ...d, enabled: c.checked } : d)))));
  };
  await render();
};

views.log = async () => {
  let paused = false;
  view.innerHTML = `
    <h1>Query log</h1><p class="sub">Live DNS requests from this computer (most recent first).</p>
    <div class="card">
      <div class="row" style="margin-bottom:12px">
        <input type="search" id="q" placeholder="Search domain, client or rule" style="flex:1;min-width:200px">
        <select id="st"><option value="all">All</option><option value="blocked">Blocked</option><option value="allowed">Allowed</option><option value="rewritten">Rewritten</option><option value="processed">Processed</option><option value="error">Errors</option></select>
        <button id="pause">Pause</button><button id="clear" class="danger">Clear</button>
      </div>
      <table><thead><tr><th>Time</th><th>Domain</th><th>Type</th><th>Status</th><th>Rule / answer</th><th>Client</th><th class="num">ms</th><th></th></tr></thead><tbody id="rows"></tbody></table>
    </div>`;
  const load = async () => {
    if (paused) return;
    const { items } = await api('GET', `/api/log?limit=300&search=${encodeURIComponent($('#q').value)}&status=${$('#st').value}`);
    $('#rows').innerHTML = items.length ? items.map((e) => `
      <tr>
        <td class="hint">${new Date(e.time).toLocaleTimeString()}</td>
        <td class="mono">${esc(e.name)}${e.company ? ` <span class="badge">${esc(e.company)}</span>` : ''}${e.cname ? `<div class="hint">via CNAME ${esc(e.cname)}</div>` : ''}</td>
        <td>${esc(e.type)}</td>
        <td><span class="badge ${esc(e.status)}">${esc(e.status)}</span>${e.cached ? ' <span class="badge">cache</span>' : ''}</td>
        <td class="mono">${e.rule ? `${esc(e.rule)}<div class="hint">${esc(e.filterName)}</div>` : esc((e.answers || []).join(', ') || e.rcode || e.error || '')}</td>
        <td class="mono">${esc(e.client)}</td>
        <td class="num">${e.ms}</td>
        <td>${e.status === 'blocked' ? `<button class="small" data-allow="${esc(e.name)}">Unblock</button>` : `<button class="small" data-block="${esc(e.name)}">Block</button>`}</td>
      </tr>`).join('') : '<tr><td colspan="8" class="empty">No requests yet</td></tr>';
    $$('[data-allow]').forEach((b) => (b.onclick = () => act(() => api('POST', '/api/rules/add', { rule: `@@||${b.dataset.allow}^` }), `Unblocked ${b.dataset.allow}`)));
    $$('[data-block]').forEach((b) => (b.onclick = () => act(() => api('POST', '/api/rules/add', { rule: `||${b.dataset.block}^` }), `Blocked ${b.dataset.block}`)));
  };
  $('#q').oninput = load;
  $('#st').onchange = load;
  $('#pause').onclick = (e) => { paused = !paused; e.target.textContent = paused ? 'Resume' : 'Pause'; if (!paused) load(); };
  $('#clear').onclick = () => act(() => api('DELETE', '/api/log'), 'Log cleared').then(load);
  await load();
  every(2000, () => load().catch(() => {}));
};

views.stats = async (params) => {
  const period = ['24h', '7d', '30d'].includes(params.get('period')) ? params.get('period') : '24h';
  const [s, apps] = await Promise.all([api('GET', `/api/stats?period=${period}`), api('GET', '/api/apps').catch(() => ({ apps: [] }))]);
  const max = Math.max(1, ...s.series.map((p) => p.total));
  const list = (items, title) => `<div class="card"><h2>${title}</h2>${items.length ? `<ul class="list">${items.map((d) => `<li><span class="name">${esc(d.filter || d.name)}</span><span>${fmt(d.count)}</span></li>`).join('')}</ul>` : '<div class="empty">No data</div>'}</div>`;
  const table = (title, rows, empty) => `<div class="card"><h2>${title}</h2>${rows.length ? `<table><thead><tr><th>Name</th><th class="num">Requests</th><th class="num">Blocked</th></tr></thead><tbody>
      ${rows.map((r) => `<tr><td>${esc(r.name)}${r.category ? `<div class="hint">${esc(r.category.replace(/_/g, ' '))}</div>` : ''}</td><td class="num">${fmt(r.requests)}</td><td class="num">${fmt(r.blocked)}</td></tr>`).join('')}</tbody></table>` : `<div class="empty">${empty}</div>`}</div>`;
  const appRows = apps.apps.filter((a) => a.requests).sort((a, b) => b.requests - a.requests).slice(0, 15).map((a) => ({ name: a.name, requests: a.requests, blocked: a.blocked }));
  view.innerHTML = `
    <h1>Statistics</h1>
    <div class="row" style="margin-bottom:18px"><div class="tabs" style="margin:0">${['24h', '7d', '30d'].map((p) => `<button data-p="${p}" class="${p === period ? 'active' : ''}">${p}</button>`).join('')}</div><div class="spacer"></div><button id="clr" class="danger">Clear statistics</button></div>
    <div class="tiles">
      <div class="tile"><div class="v">${fmt(s.total)}</div><div class="l">Queries</div></div>
      <div class="tile"><div class="v">${fmt(s.blocked)}</div><div class="l">Blocked (${s.blockedPercent}%)</div></div>
      <div class="tile"><div class="v">${fmt(s.rewritten)}</div><div class="l">Rewritten</div></div>
      <div class="tile"><div class="v">${fmt(s.cached)}</div><div class="l">From cache</div></div>
      <div class="tile"><div class="v">${s.avgMs} ms</div><div class="l">Avg. processing</div></div>
    </div>
    <div class="card"><h2>Queries over time <span class="hint">(green = total, red = blocked)</span></h2>
      <div class="chart">${s.series.map((p) => `<div class="bar" title="${new Date(p.time).toLocaleString()}: ${p.total} queries, ${p.blocked} blocked" style="height:${(100 * p.total) / max}%"><b style="height:100%"></b><i style="height:${p.total ? (100 * p.blocked) / p.total : 0}%"></i></div>`).join('')}</div>
    </div>
    <div class="grid">
      ${table('Companies tracking you', s.topCompanies, s.trackerDb?.domains ? 'No known trackers contacted' : 'Tracker database not downloaded yet')}
      ${table('Tracker categories', s.categories, 'No data')}
      ${table('Apps (web filtering, since start)', appRows, 'No app traffic yet')}
    </div>
    <div class="grid">${list(s.topDomains, 'Top queried domains')}${list(s.topBlocked, 'Top blocked domains')}${list(s.topClients, 'Top clients')}${list(s.byFilter, 'Blocks by filter')}</div>
    <p class="hint">Company data: <a href="https://github.com/AdguardTeam/companiesdb" target="_blank" rel="noopener">AdGuard companiesdb</a> (CC BY-SA 4.0).</p>`;
  $$('[data-p]').forEach((b) => (b.onclick = () => { location.hash = `#/stats?period=${b.dataset.p}`; }));
  $('#clr').onclick = () => confirm('Delete all statistics?') && act(() => api('DELETE', '/api/stats'), 'Statistics cleared').then(() => views.stats(params));
};

views.settings = async () => {
  const s = await api('GET', '/api/settings');
  const d = s.dns;
  const lines = (a) => esc((a || []).join('\n'));
  view.innerHTML = `
    <h1>Settings</h1><p class="sub">Changes apply immediately after saving.</p>
    <div class="grid">
      <div class="card"><h2>Whole-PC protection</h2>
        <div class="toggle-row">${sw('mdns', s.system.manageDns)}<div class="body"><div class="name">Filter every app on this PC</div>
          <div class="desc">Points Windows at AdHush for name lookups, including networks you connect to later. If AdHush ever stops answering, your normal internet settings come back automatically within a minute.</div></div></div>
        <div id="mdns-state" class="hint" style="margin-top:4px"></div>
      </div>
      <div class="card"><h2>Updates</h2>
        <div id="upd-body" class="hint">…</div>
        <div class="toggle-row" style="margin-top:6px">${sw('upd-auto', s.updates.auto)}<div class="body"><div class="name">Install updates automatically</div><div class="desc">Updates are checked every few hours and installed in the background. Only updates signed by the AdHush author are accepted.</div></div></div>
        <div class="row"><button id="upd-check">Check for updates</button><button id="upd-install" class="primary" hidden>Install update</button></div>
      </div>
      <div class="card"><h2>Get help</h2>
        <p class="hint" style="margin-top:0">Something not working? Save a logs file and send it to whoever helps you. It contains AdHush's logs and settings, but not your browsing statistics, the query log or any passwords or keys.</p>
        <div class="row"><button id="diag" class="primary">Save logs file</button></div>
        <p class="hint">No internet at all? Use <strong>Restore normal internet</strong> in the Start menu (AdHush folder) or the tray icon's menu.</p>
        <p class="hint">AdHush is free software under the GNU GPL v3. Licences and third-party notices are in the <code>licenses</code> folder of the installation.</p>
      </div>
      <div class="card"><h2>Upstream DNS servers</h2>
        <label class="field"><span>Upstreams</span><textarea id="up" rows="4">${lines(d.upstreams)}</textarea>
          <small>One per line: <code>1.1.1.1</code>, <code>tcp://9.9.9.9</code>, <code>tls://dns.quad9.net</code>, <code>https://dns.cloudflare.com/dns-query</code>, <code>sdns://…</code></small></label>
        <label class="field"><span>Mode</span><select id="mode"><option value="parallel">Parallel: fastest answer wins</option><option value="sequential">Sequential: in listed order</option></select></label>
        <label class="field"><span>Fallback servers</span><textarea id="fb" rows="2">${lines(d.fallback)}</textarea><small>Used when every upstream fails.</small></label>
        <label class="field"><span>Bootstrap servers</span><textarea id="bs" rows="2">${lines(d.bootstrap)}</textarea><small>Plain-IP servers used to resolve encrypted upstream hostnames.</small></label>
        <label class="field"><span>Timeout (ms)</span><input type="number" id="to" min="200" max="60000" value="${d.timeoutMs}"></label>
        <div class="row"><button id="save-up" class="primary">Save</button><button id="test-up">Test upstreams</button></div>
        <div id="test-out" class="hint" style="margin-top:10px"></div>
      </div>
      <div class="card"><h2>Blocking behaviour</h2>
        <label class="field"><span>Blocking mode</span><select id="bm">
          <option value="default">Default: 0.0.0.0 / :: (hosts rules use their IP)</option><option value="refused">REFUSED</option>
          <option value="nxdomain">NXDOMAIN</option><option value="unspecified">Unspecified IP (0.0.0.0 / ::)</option><option value="custom">Custom IP</option></select></label>
        <div class="row"><label class="field" style="flex:1"><span>Custom IPv4</span><input type="text" id="c4" value="${esc(d.customIpv4)}"></label>
          <label class="field" style="flex:1"><span>Custom IPv6</span><input type="text" id="c6" value="${esc(d.customIpv6)}"></label></div>
        <label class="field"><span>Blocked response TTL (s)</span><input type="number" id="bttl" min="0" max="86400" value="${d.blockedTtl}"></label>
        <div class="toggle-row">${sw('cname', d.blockCnameCloaking)}<div class="body"><div class="name">Block CNAME cloaking</div><div class="desc">Also check every CNAME in an answer, catching first-party-disguised trackers.</div></div></div>
        <h2 style="margin-top:14px">Cache</h2>
        <div class="toggle-row">${sw('cache', d.cache.enabled)}<div class="body"><div class="name">Enable DNS cache</div></div></div>
        <div class="row"><label class="field" style="flex:1"><span>Size</span><input type="number" id="csize" min="0" value="${d.cache.size}"></label>
          <label class="field" style="flex:1"><span>Min TTL</span><input type="number" id="cmin" min="0" value="${d.cache.minTtl}"></label>
          <label class="field" style="flex:1"><span>Max TTL</span><input type="number" id="cmax" min="0" value="${d.cache.maxTtl}"></label></div>
        <div class="row"><button id="save-bl" class="primary">Save</button><button id="flush">Clear cache</button></div>
      </div>
      <div class="card"><h2>Protection modules</h2>
        <div class="toggle-row">${sw('sec', s.security.enabled)}<div class="body"><div class="name">Browsing security</div><div class="desc">Block known malware and phishing domains (Security filter group).</div></div></div>
        <div class="toggle-row">${sw('pc', s.parental.enabled)}<div class="body"><div class="name">Parental control</div><div class="desc">Enables the Parental filter group and the options below.</div></div></div>
        <div class="toggle-row">${sw('ss', s.parental.safeSearch)}<div class="body"><div class="name">Enforce safe search</div><div class="desc">Google, Bing, DuckDuckGo, YouTube (restricted mode), Pixabay.</div></div></div>
        <div class="toggle-row">${sw('adult', s.parental.blockAdult)}<div class="body"><div class="name">Block adult websites</div></div></div>
        <label class="field" style="margin-top:12px"><span>Filter update interval</span><select id="ui">
          ${[[0, 'Never (manual only)'], [1, 'Every hour'], [6, 'Every 6 hours'], [12, 'Every 12 hours'], [24, 'Every day'], [48, 'Every 2 days'], [168, 'Every week']].map(([v, l]) => `<option value="${v}" ${v === s.filtering.updateIntervalHours ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        <button id="save-mod" class="primary">Save</button>
      </div>
      <div class="card"><h2>Logs &amp; statistics</h2>
        <div class="toggle-row">${sw('ql', s.queryLog.enabled)}<div class="body"><div class="name">Keep query log</div></div></div>
        <label class="field"><span>Query log size (entries, in memory)</span><input type="number" id="qls" min="100" max="100000" value="${s.queryLog.size}"></label>
        <div class="toggle-row">${sw('stt', s.stats.enabled)}<div class="body"><div class="name">Collect statistics</div></div></div>
        <label class="field"><span>Statistics retention (days)</span><input type="number" id="ret" min="1" max="365" value="${s.stats.retentionDays}"></label>
        <label class="field"><span>Theme</span><select id="theme"><option value="auto">Follow system</option><option value="light">Light</option><option value="dark">Dark</option></select></label>
        <div class="toggle-row">${sw('notif', s.ui.notifications)}<div class="body"><div class="name">Tray notifications</div><div class="desc">Filter updates, pause ending, and problems that need attention.</div></div></div>
        <div class="row"><button id="save-log" class="primary">Save</button><button id="rerun">Run setup wizard again</button></div>
        <h2 style="margin-top:22px">Backup</h2>
        <div class="row"><button id="exp">Export settings</button><label class="btn">Import…<input type="file" id="imp" accept=".json" hidden></label><button id="reset" class="danger">Reset to defaults</button></div>
      </div>
      <div class="card" id="browser-ext"><h2>Browser extension</h2>
        <p class="hint" style="margin-top:0">Optional. Adds a per-site on/off switch, a pause button and <em>Block element</em> to Chrome, Edge or Brave. Ad blocking works without it.</p>
        <div id="bx-body"><div class="hint">…</div></div>
      </div>
    </div>`;
  api('GET', '/api/status').then((st) => {
    renderExtensionCard($('#bx-body'), st);
    renderDnsState($('#mdns-state'), st.systemDns);
  }).catch(() => {});
  $('#mdns').onchange = (e) => act(() => api('PATCH', '/api/settings', { system: { manageDns: e.target.checked } }),
    e.target.checked ? 'Whole-PC protection on: applying within 15 seconds' : 'Whole-PC protection off: restoring normal DNS')
    .then(() => setTimeout(() => api('GET', '/api/status').then((st) => renderDnsState($('#mdns-state'), st.systemDns)).catch(() => {}), 16000));
  $('#diag').onclick = () => saveDiagnostics($('#diag'));
  const showUpdates = () => api('GET', '/api/updates').then((u) => renderUpdates(u)).catch(() => {});
  showUpdates();
  every(5000, showUpdates);
  $('#upd-auto').onchange = (e) => act(() => api('PATCH', '/api/settings', { updates: { auto: e.target.checked } }), 'Saved');
  $('#upd-check').onclick = () => act(() => api('POST', '/api/updates/check'), 'Checking for updates…');
  $('#upd-install').onclick = () => act(() => api('POST', '/api/updates/install'), 'Downloading the update…');
  $('#mode').value = d.upstreamMode;
  $('#bm').value = d.blockingMode;
  $('#theme').value = s.ui.theme;
  const split = (id) => $(id).value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  const num = (id) => Number($(id).value);
  const patch = (p) => act(() => api('PATCH', '/api/settings', p), 'Settings saved');
  $('#save-up').onclick = () => patch({ dns: { upstreams: split('#up'), upstreamMode: $('#mode').value, fallback: split('#fb'), bootstrap: split('#bs'), timeoutMs: num('#to') } });
  $('#test-up').onclick = async () => {
    $('#test-out').innerHTML = 'Testing…';
    const results = await Promise.all(split('#up').map(async (u) => ({ u, r: await api('POST', '/api/dns/test', { upstream: u }).catch((e) => ({ ok: false, error: e.message })) })));
    $('#test-out').innerHTML = results.map(({ u, r }) => `<div><code>${esc(u)}</code> ${r.ok ? `<span class="ok">OK, ${r.ms} ms</span>` : `<span class="err">${esc(r.error || r.rcode)}</span>`}</div>`).join('');
  };
  $('#save-bl').onclick = () => patch({ dns: { blockingMode: $('#bm').value, customIpv4: $('#c4').value.trim(), customIpv6: $('#c6').value.trim(), blockedTtl: num('#bttl'), blockCnameCloaking: $('#cname').checked, cache: { enabled: $('#cache').checked, size: num('#csize'), minTtl: num('#cmin'), maxTtl: num('#cmax') } } });
  $('#flush').onclick = () => act(() => api('POST', '/api/dns/cache/clear'), 'Cache cleared');
  $('#save-mod').onclick = () => patch({ security: { enabled: $('#sec').checked }, parental: { enabled: $('#pc').checked, safeSearch: $('#ss').checked, blockAdult: $('#adult').checked }, filtering: { updateIntervalHours: num('#ui') } }).then(refreshSidebar);
  $('#save-log').onclick = () => patch({ queryLog: { enabled: $('#ql').checked, size: num('#qls') }, stats: { enabled: $('#stt').checked, retentionDays: num('#ret') }, ui: { theme: $('#theme').value, notifications: $('#notif').checked } }).then(() => applyTheme($('#theme').value));
  $('#rerun').onclick = () => { location.hash = '#/welcome'; };
  $('#exp').onclick = async () => {
    const data = await act(() => api('GET', '/api/settings/export'));
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    a.download = `adhush-settings-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  $('#imp').onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    let data;
    try { data = JSON.parse(await file.text()); } catch { return toast('That file is not valid JSON', true); }
    await act(() => api('POST', '/api/settings/import', data), 'Settings imported');
    route();
  };
  $('#reset').onclick = () => confirm('Reset all settings, rules and lists to defaults?') && act(() => api('POST', '/api/settings/reset'), 'Settings reset').then(route);
};

// ---------- desktop bridge (only inside the tray's AdHush window) ----------
// The service runs as a background service and cannot open windows on the desktop; the tray can.
const native = (() => {
  let seq = 0;
  const pending = new Map();
  window.adhushNative = (m) => {
    pending.get(m.id)?.(m.reply);
    pending.delete(m.id);
  };
  return (msg) => new Promise((resolve, reject) => {
    if (!window.ipc) return reject(new Error('Open AdHush from the tray icon to use this button'));
    const id = ++seq;
    pending.set(id, resolve);
    window.ipc.postMessage(JSON.stringify({ ...msg, id }));
    setTimeout(() => pending.delete(id) && reject(new Error('the AdHush tray did not answer')), 5000);
  });
})();

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

const EXT_PAGES = { chrome: 'chrome://extensions', edge: 'edge://extensions', brave: 'brave://extensions' };

// Browsers do not let other programs install extensions silently (that is what adware does),
// so this opens the right page, copies the folder path, and walks through the three clicks.
async function renderExtensionCard(box, st) {
  const dir = st.extensionDir;
  if (!dir) {
    box.innerHTML = '<div class="hint">The extension files are not part of this installation.</div>';
    return;
  }
  const steps = (browser) => `
    <ol class="steps-list">
      ${browser ? '' : `<li>Open ${Object.values(EXT_PAGES).map((p) => `<code>${esc(p)}</code>`).join(', ')} (whichever browser you use) in the address bar.</li>`}
      <li>Turn on <strong>Developer mode</strong>${browser === 'edge' ? ' (left side of the page)' : browser ? ' (top right)' : ''}.</li>
      <li>Click <strong>Load unpacked</strong>.</li>
      <li>Click <strong>Copy path</strong> below, paste it in the folder window with <kbd>Ctrl</kbd>+<kbd>V</kbd>, then click <strong>Select Folder</strong>.</li>
      <li>Click the puzzle-piece icon in the toolbar and pin <strong>AdHush Assistant</strong>.</li>
    </ol>`;
  const pathRow = `<div class="row" style="margin-top:8px"><code class="path" style="flex:1">${esc(dir)}</code><button id="bx-copy">Copy path</button></div>`;
  let browsers = [];
  if (window.ipc) browsers = (await native({ cmd: 'browsers' }).catch(() => ({ browsers: [] }))).browsers || [];
  box.innerHTML = window.ipc && browsers.length
    ? `<div class="row">${browsers.map((b) => `<button class="primary" data-bx="${esc(b.id)}">Add to ${esc(b.name)}</button>`).join('')}</div><div id="bx-guide"></div>`
    : `${window.ipc ? '<div class="hint">No supported browser found (Chrome, Edge or Brave).</div>' : ''}${steps(null)}${pathRow}`;
  if ($('#bx-copy', box)) $('#bx-copy', box).onclick = () => copyText(dir).then(() => toast('Folder path copied'));
  box.querySelectorAll('[data-bx]').forEach((b) => (b.onclick = async () => {
    // Browsers won't open their extensions page for another program, so hand over its address.
    await copyText(EXT_PAGES[b.dataset.bx]);
    const r = await native({ cmd: 'openExtensions', browser: b.dataset.bx }).catch((e) => ({ ok: false, error: e.message }));
    if (!r.ok) return toast(r.error, true);
    const name = esc(b.textContent.replace('Add to ', ''));
    $('#bx-guide', box).innerHTML = `<p class="hint" style="margin-top:12px">${name} opened a setup guide. In ${name}:</p>
      <ol class="steps-list"><li>Click the address bar, press <kbd>Ctrl</kbd>+<kbd>V</kbd> and <kbd>Enter</kbd> (<code>${esc(EXT_PAGES[b.dataset.bx])}</code> is copied).</li></ol>${steps(b.dataset.bx).replace('<ol class="steps-list">', '<ol class="steps-list" start="2">')}${pathRow}`;
    $('#bx-copy', box).onclick = () => copyText(dir).then(() => toast('Folder path copied'));
  }));
}

function renderDnsState(el, d) {
  if (!el || !d) return;
  if (!d.guard) {
    el.textContent = 'This switch takes effect when AdHush is installed with its setup (it is managed by the AdHush service).';
    return;
  }
  const when = d.since ? new Date(d.since).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '';
  const label = {
    filtering: '<span class="badge allowed">Active</span> Every app on this PC is filtered.',
    fallback: '<span class="badge error">Paused automatically</span> ',
    starting: '<span class="badge">Starting</span> ',
    off: '<span class="badge">Off</span> ',
  }[d.mode] || '';
  el.innerHTML = `${label}${d.mode === 'filtering' ? '' : esc(d.detail || '')} ${when ? `<br>Since ${esc(when)}` : ''}`;
}

function renderUpdates(u) {
  const el = $('#upd-body');
  if (!el) return;
  const when = (ms) => (ms ? new Date(ms).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'never');
  const disabled = !u.configured || !u.service;
  $('#upd-check').disabled = disabled;
  $('#upd-install').hidden = u.status !== 'available' || u.auto;
  if (!u.service) return void (el.textContent = `Version ${u.current}. Updates are handled by the AdHush service, which runs when AdHush is installed with its setup.`);
  if (!u.configured) return void (el.textContent = `Version ${u.current}. This copy has no update source configured.`);
  const status = {
    'up-to-date': `<span class="badge allowed">Up to date</span>`,
    available: `<span class="badge rewritten">Version ${esc(u.latest)} available</span>`,
    downloading: `<span class="badge">Downloading ${esc(u.latest)}…</span>`,
    installing: `<span class="badge">Installing ${esc(u.latest)}… AdHush restarts in a moment</span>`,
    error: `<span class="badge error">Update problem</span> ${esc(u.error || '')}`,
    disabled: '<span class="badge">Off</span>',
  }[u.status] || '';
  el.innerHTML = `Version <strong>${esc(u.current)}</strong> ${status}<br>Last checked: ${esc(when(u.checkedAt))}
    ${u.lastUpdate ? `<br>Last update: ${esc(u.lastUpdate.from)} → ${esc(u.lastUpdate.to)} on ${esc(when(u.lastUpdate.at))}` : ''}
    ${u.status === 'available' && u.notes ? `<br>What's new: ${esc(u.notes)}` : ''}`;
}

// Saves the logs zip: through the tray (to the Desktop) inside the AdHush window, else as a browser download.
async function saveDiagnostics(btn) {
  btn.disabled = true;
  try {
    if (window.ipc) {
      const r = await native({ cmd: 'saveDiagnostics' });
      if (!r.ok) throw new Error(r.error);
      toast(`Saved to your Desktop: ${r.file.split('\\').pop()}`);
      return;
    }
    const res = await fetch('/api/diagnostics', { headers: { 'x-adhush-token': TOKEN } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const name = (res.headers.get('content-disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'AdHush-logs.zip';
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(await res.blob()), download: name });
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Logs file downloaded');
  } catch (e) {
    toast(`Could not save logs: ${e.message}`, true);
  } finally {
    btn.disabled = false;
  }
}

// ---------- first-run wizard ----------
const ANNOYANCE_FILTERS = [40, 120, 122]; // pop-up ads (DNS), cookie notices, uBlock annoyances
views.welcome = async () => {
  const [s, st] = await Promise.all([api('GET', '/api/settings'), api('GET', '/api/status')]);
  const choice = {
    ads: true, annoyances: false, security: s.security.enabled, parental: s.parental.enabled,
    mdns: s.system.manageDns, web: s.https.enabled, preset: s.privacy.preset === 'custom' ? 'standard' : s.privacy.preset, notifications: s.ui.notifications,
  };
  let step = 0;
  const row = (id, name, desc) => `<div class="toggle-row">${sw(id, choice[id])}<div class="body"><div class="name">${name}</div><div class="desc">${desc}</div></div></div>`;
  const steps = [
    () => `<h2>Welcome to AdHush</h2>
      <p>AdHush blocks ads, trackers and dangerous websites for every app on this PC: browsers, games and Windows itself.</p>
      <p class="hint">This takes under a minute. Everything can be changed later in the app.</p>`,
    () => `<h2>What should be blocked?</h2>
      ${st.systemDns?.guard ? row('mdns', 'Filter every app on this PC', 'Recommended. If AdHush ever stops working, normal internet comes back on its own.') : ''}
      ${row('ads', 'Ads and trackers', 'The core blocklists. Recommended for everyone.')}
      ${row('annoyances', 'Annoyances', 'Cookie banners, pop-ups and "subscribe" overlays.')}
      ${row('security', 'Malware and phishing', 'Stops known scam and malware websites.')}
      ${row('parental', 'Parental control', 'Blocks adult websites and enforces safe search.')}`,
    () => `<h2>Web filtering and privacy</h2>
      ${st.caInstalled || choice.web
        ? row('web', 'Advanced: filter inside web pages', 'Removes ads DNS blocking cannot see (YouTube, in-page banners). Can break some sites and apps, so leave it off unless you need it.')
        : `<div class="toggle-row">${sw('web', false)}<div class="body"><div class="name">Filter inside web pages</div><div class="desc">Not available: setup did not install this PC's certificate. Run setup again and tick "remove ads inside web pages".</div></div></div>`}
      <label class="field" style="margin-top:12px"><span>Tracking protection</span><select id="preset">
        <option value="standard">Standard: block trackers, keep sites working</option>
        <option value="high">High: also strip referrers and third-party cookies</option>
        <option value="extreme">Extreme: maximum privacy, some sites may break</option></select></label>
      ${row('notifications', 'Show notifications', 'Small pop-ups from the tray icon when filters update or something needs attention.')}`,
    () => `<h2>You're protected</h2>
      <p>AdHush is running ${st.dns.listening.length ? '' : '<span class="err">(DNS listener not started: see Overview)</span>'}. The shield icon in the notification area turns
      <strong style="color:var(--accent)">green</strong> when protection is on and amber while paused.</p>
      <p class="hint">Right-click the tray icon to pause protection, for example when a site does not work.</p>
      <p class="hint">Optional: add the browser extension for a per-site switch and element blocking under <strong>Settings → Browser extension</strong>.</p>`,
  ];
  const render = () => {
    view.innerHTML = `
      <div class="wizard card">
        <div class="steps">${steps.map((_, i) => `<span class="${i <= step ? 'on' : ''}"></span>`).join('')}</div>
        <div class="wbody">${steps[step]()}</div>
        <div class="row wfoot">
          ${step === 0 ? '<button id="w-skip">Skip setup</button>' : '<button id="w-back">Back</button>'}
          <div class="spacer"></div>
          <button id="w-next" class="primary">${step === steps.length - 1 ? 'Finish' : step === 0 ? 'Get started' : 'Next'}</button>
        </div>
      </div>`;
    $$('.wbody input[type=checkbox]').forEach((el) => (el.onchange = () => { choice[el.id] = el.checked; }));
    if (!st.caInstalled && !choice.web && $('#web')) $('#web').disabled = true;
    if ($('#preset')) {
      $('#preset').value = choice.preset;
      $('#preset').onchange = (e) => { choice.preset = e.target.value; };
    }
    if ($('#w-back')) $('#w-back').onclick = () => { step--; render(); };
    if ($('#w-skip')) $('#w-skip').onclick = () => finish(false);
    $('#w-next').onclick = async () => {
      if (step === steps.length - 1) return finish(true);
      // Choices are applied when leaving the last question page.
      if (step === steps.length - 2) {
        $('#w-next').disabled = true;
        $('#w-next').textContent = 'Applying…'; // enabling a list downloads it first
        try { await apply(); } catch { $('#w-next').disabled = false; $('#w-next').textContent = 'Next'; return; }
      }
      step++;
      render();
    };
  };
  const apply = () => act(async () => {
    const { filters } = await api('GET', '/api/filters');
    const want = (f) => (f.group === 'ads' && f.id === 1 ? choice.ads : ANNOYANCE_FILTERS.includes(f.id) ? choice.annoyances : null);
    for (const f of filters) {
      const on = want(f);
      if (on !== null && f.enabled !== on) await api('PATCH', `/api/filters/${f.id}`, { enabled: on });
    }
    await api('POST', '/api/privacy/preset', { preset: choice.preset });
    await api('PATCH', '/api/settings', {
      security: { enabled: choice.security }, parental: { enabled: choice.parental },
      ...(st.systemDns?.guard ? { system: { manageDns: choice.mdns } } : {}),
      // Installed copies filter browsers through the WinDivert driver (the service runs elevated).
      https: { enabled: choice.web, ...(st.caInstalled ? { driver: { enabled: choice.web } } : {}) }, ui: { notifications: choice.notifications },
    });
  });
  const finish = async (done) => {
    await act(() => api('PATCH', '/api/settings', { ui: { onboarded: true } }), done ? 'All set' : null);
    location.hash = '#/home';
  };
  render();
};

// ---------- router ----------
async function route() {
  timers.forEach(clearInterval);
  timers = [];
  const [path, query = ''] = (location.hash.replace(/^#\/?/, '') || 'home').split('?');
  const name = views[path] ? path : 'home';
  currentRoute = name;
  document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === name));
  try {
    await views[name](new URLSearchParams(query));
  } catch (e) {
    if (currentRoute === name) view.innerHTML = `<h1>Something went wrong</h1><p class="err">${esc(e.message)}</p>`;
  }
}

window.addEventListener('hashchange', route);
refreshSidebar();
setInterval(refreshSidebar, 15000);
api('GET', '/api/settings').then((s) => {
  applyTheme(s.ui.theme);
  if (!s.ui.onboarded && !location.hash.startsWith('#/welcome')) location.hash = '#/welcome'; // fires route()
  else route();
}).catch(() => route());
