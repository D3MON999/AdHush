// Relays requests from the popup and the element picker to the AdHush native host.
// The host (com.adhush.host) only accepts a fixed set of commands; see host/host.js.
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

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg?.type === 'native') native(msg.body).then(reply);
  else if (msg?.type === 'pick') startPicker(msg.tabId).then(() => reply({ ok: true }), (e) => reply({ ok: false, error: e.message }));
  else return false;
  return true; // async reply
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'adhush-pick', title: 'Block element…', contexts: ['page', 'image', 'link', 'frame'] });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'adhush-pick' && tab?.id !== undefined) startPicker(tab.id).catch(() => {});
});
