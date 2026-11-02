const $ = (id) => document.getElementById(id);
const native = (body) => chrome.runtime.sendMessage({ type: 'native', body });

let tab = null;
let host = '';

function showError(msg) {
  $('err').textContent = msg;
  $('err').hidden = !msg;
}

function render(s) {
  const state = !s.protection.enabled ? 'off' : s.protection.active ? 'on' : 'paused';
  $('state').textContent = { on: 'Protected', off: 'Off', paused: 'Paused' }[state];
  $('state').className = 'pill ' + state;
  $('pause').textContent = state === 'paused' ? 'Resume' : 'Pause 30 min';
  $('pause').disabled = state === 'off';
  $('pause').dataset.state = state;
  $('site').checked = !s.allowlisted;
  $('site-desc').textContent = s.allowlisted ? 'AdHush is off for this site' : 'Filtering on this site';
  $('broken').hidden = !!s.allowlisted || !host;
}

async function refresh() {
  const r = await native({ cmd: 'site', host });
  if (!r.ok) {
    showError(r.error);
    for (const id of ['site', 'pick', 'pause', 'broken']) $(id).disabled = true;
    return;
  }
  showError('');
  render(r);
}

async function run(body) {
  const r = await native(body);
  if (!r.ok) showError(r.error);
  await refresh();
}

(async () => {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    const u = new URL(tab.url);
    if (u.protocol === 'http:' || u.protocol === 'https:') host = u.hostname.replace(/^www\./, '');
  } catch {}
  $('host').textContent = host || 'This page';
  if (!host) {
    $('site').disabled = true;
    $('pick').disabled = true;
  }
  // Off for a site = allowlisted and never decrypted (cmd "broken"), so it can't break the site.
  $('site').onchange = (e) => run({ cmd: 'broken', host, broken: !e.target.checked }).then(() => chrome.tabs.reload(tab.id));
  $('broken').onclick = () => run({ cmd: 'broken', host, broken: true }).then(() => chrome.tabs.reload(tab.id));
  $('pause').onclick = () => run($('pause').dataset.state === 'paused' ? { cmd: 'resume' } : { cmd: 'pause', minutes: 30 });
  $('pick').onclick = async () => {
    const r = await chrome.runtime.sendMessage({ type: 'pick', tabId: tab.id });
    if (r.ok) window.close();
    else showError(r.error);
  };
  $('open').onclick = async () => {
    const r = await native({ cmd: 'ui' });
    if (r.ok) chrome.tabs.create({ url: r.url });
    else showError(r.error);
  };
  if (host) await refresh();
  else {
    const r = await native({ cmd: 'site', host: '' });
    if (r.ok) render({ ...r, allowlisted: false });
    else showError(r.error);
  }
})();
