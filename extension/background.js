// Relays requests from the popup and the element picker to the AdHush native host.
// The host (com.adhush.host) only accepts a fixed set of commands; see host/host.mjs.
const HOST = 'com.adhush.host';

function native(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(HOST, msg, (res) => {
      if (chrome.runtime.lastError) resolve({ ok: false, error: 'AdHush is not installed or not running (' + chrome.runtime.lastError.message + ')' });
      else resolve(res || { ok: false, error: 'no response' });
    });
  });
}

async function startPicker(tabId) {
  await chrome.scripting.executeScript({ target: { tabId }, files: ['picker.js'] });
}

// "What was blocked on this page": only after the user allows it from the popup (an optional
// permission), the extension notes which sites each tab contacts. The list stays in this browser's
// session storage, is cleared when the tab loads a new page or closes, and only host names are kept.
const MAX_HOSTS = 300;
let tabs = {};
const loaded = chrome.storage.session.get('tabs').then((v) => { tabs = v.tabs || {}; }, () => {});
let saveTimer = null;

function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => chrome.storage.session.set({ tabs }).catch(() => {}), 400);
}

function hostOf(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.hostname.toLowerCase() : '';
  } catch {
    return '';
  }
}

function note(details, failed) {
  if (details.tabId < 0) return;
  const host = hostOf(details.url);
  if (!host) return;
  loaded.then(() => {
    const key = String(details.tabId);
    if (details.type === 'main_frame' && !failed) tabs[key] = { page: host, hosts: {} };
    const tab = tabs[key] || (tabs[key] = { page: '', hosts: {} });
    let h = tab.hosts[host];
    if (!h) {
      if (Object.keys(tab.hosts).length >= MAX_HOSTS) return;
      h = tab.hosts[host] = { count: 0, failed: 0 };
    }
    if (failed) h.failed++;
    else h.count++;
    save();
  });
}

chrome.webRequest.onBeforeRequest.addListener((d) => note(d, false), { urls: ['<all_urls>'] });
chrome.webRequest.onErrorOccurred.addListener((d) => note(d, true), { urls: ['<all_urls>'] });
chrome.tabs.onRemoved.addListener((tabId) => loaded.then(() => { delete tabs[String(tabId)]; save(); }));

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg?.type === 'native') native(msg.body).then(reply);
  else if (msg?.type === 'pick') startPicker(msg.tabId).then(() => reply({ ok: true }), (e) => reply({ ok: false, error: e.message }));
  else if (msg?.type === 'seen') loaded.then(() => reply(tabs[String(msg.tabId)] || null));
  else return false;
  return true; // async reply
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'adhush-pick', title: 'Block element…', contexts: ['page', 'image', 'link', 'frame'] });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'adhush-pick' && tab?.id !== undefined) startPicker(tab.id).catch(() => {});
});
