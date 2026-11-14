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

// "Blocked on this page": the sites this tab contacted that AdHush blocks, each with an Allow button.
const ALL_SITES = { origins: ['<all_urls>'] };

function note(text, button) {
  const p = document.createElement('p');
  p.className = 'note';
  p.textContent = text;
  if (button) p.append(button);
  $('blocked-body').replaceChildren(p);
}

function makeButton(label, onclick) {
  const b = document.createElement('button');
  b.textContent = label;
  b.onclick = onclick;
  return b;
}

async function showBlocked() {
  $('blocked').hidden = false;
  $('blocked-count').textContent = '';
  if (!(await chrome.permissions.contains(ALL_SITES))) {
    note('AdHush can list the ads and trackers it blocked on each page. Your browser will ask you to allow this, and the list never leaves your PC.',
      makeButton('Show what was blocked', async () => {
        if (await chrome.permissions.request(ALL_SITES)) note('Reload the page so AdHush can see what it asks for.', makeButton('Reload page', () => { chrome.tabs.reload(tab.id); window.close(); }));
      }));
    return;
  }
  const seen = await chrome.runtime.sendMessage({ type: 'seen', tabId: tab.id });
  if (!seen || seen.page !== new URL(tab.url).hostname.toLowerCase()) {
    note('Reload the page to see what was blocked on it.', makeButton('Reload page', () => { chrome.tabs.reload(tab.id); window.close(); }));
    return;
  }
  const r = await native({ cmd: 'blocked', hosts: Object.keys(seen.hosts) });
  if (!r.ok) return note(r.error);
  $('blocked-count').textContent = String(r.blocked.length);
  if (!r.blocked.length) return note('Nothing was blocked on this page.');
  const list = document.createElement('ul');
  for (const b of r.blocked.sort((x, y) => (seen.hosts[y.host]?.count || 0) - (seen.hosts[x.host]?.count || 0))) {
    const li = document.createElement('li');
    const info = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'name';
    name.textContent = b.host;
    name.title = b.host;
    const desc = document.createElement('div');
    desc.className = 'desc';
    const n = seen.hosts[b.host]?.count || 0;
    desc.textContent = `${n} request${n === 1 ? '' : 's'}${b.filter ? ` · ${b.filter}` : ''}`;
    info.append(name, desc);
    const allow = makeButton('Allow', async () => {
      const allowing = allow.textContent === 'Allow';
      allow.disabled = true;
      const res = await native({ cmd: 'allow', host: b.host, allowed: allowing });
      allow.disabled = false;
      if (!res.ok) return showError(res.error);
      allow.textContent = allowing ? 'Undo' : 'Allow';
      desc.textContent = allowing ? 'Allowed on every site. Reload to see it.' : `${n} request${n === 1 ? '' : 's'}${b.filter ? ` · ${b.filter}` : ''}`;
    });
    allow.title = `Stop blocking ${b.host} on every site`;
    li.append(info, allow);
    list.append(li);
  }
  $('blocked-body').replaceChildren(list);
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
  if (host) {
    await refresh();
    showBlocked().catch((e) => note(e.message));
  } else {
    const r = await native({ cmd: 'site', host: '' });
    if (r.ok) render({ ...r, allowlisted: false });
    else showError(r.error);
  }
})();
