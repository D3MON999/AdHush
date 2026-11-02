// Guide page the tray opens in the chosen browser: #b=<chrome|edge|brave>&dir=<extension folder>.
const BROWSERS = {
  chrome: { name: 'Google Chrome', page: 'chrome://extensions', dev: 'The switch is at the top right of the extensions page.' },
  edge: { name: 'Microsoft Edge', page: 'edge://extensions', dev: 'The switch is on the left side of the extensions page (if the window is narrow, open the menu at the top left first).' },
  brave: { name: 'Brave', page: 'brave://extensions', dev: 'The switch is at the top right of the extensions page.' },
};
const params = new URLSearchParams(location.hash.slice(1));
const b = BROWSERS[params.get('b')] || BROWSERS.chrome;
const dir = params.get('dir') || '';

document.getElementById('bname').textContent = b.name;
document.getElementById('page').textContent = b.page;
document.getElementById('devhint').textContent = b.dev;
document.getElementById('dir').textContent = dir || 'C:\\Program Files\\AdHush\\extension';

function toast(msg) {
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  document.getElementById('toasts').append(el);
  setTimeout(() => el.remove(), 2500);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast('Copied');
}

for (const btn of document.querySelectorAll('[data-copy]')) {
  btn.onclick = () => copy(document.getElementById(btn.dataset.copy).textContent);
}
