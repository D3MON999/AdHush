// Element picker: highlight on hover, click to choose, then confirm to add `host##selector`
// as a AdHush user rule. Injected on demand; a second injection while active is a no-op.
(() => {
  if (window.__adhushPicker) return;
  window.__adhushPicker = true;

  const host = location.hostname.replace(/^www\./, '');
  const root = document.createElement('div');
  root.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none';
  const shadow = root.attachShadow({ mode: 'closed' });
  shadow.innerHTML = `<style>
    .box { position: fixed; border: 2px solid #0f766e; background: rgba(15,118,110,.18); pointer-events: none; transition: all .05s; }
    .bar { position: fixed; left: 50%; bottom: 18px; transform: translateX(-50%); pointer-events: auto; font: 13px/1.4 system-ui, "Segoe UI", sans-serif;
      background: #19201d; color: #e6ece9; border-radius: 10px; padding: 10px 12px; box-shadow: 0 6px 24px rgba(0,0,0,.35); display: flex; gap: 8px; align-items: center; max-width: 92vw; }
    input { flex: 1; min-width: 260px; font: 12px ui-monospace, Consolas, monospace; padding: 6px 8px; border-radius: 6px; border: 1px solid #2b3531; background: #111614; color: #e6ece9; }
    button { font: inherit; padding: 6px 12px; border-radius: 6px; border: 1px solid #2b3531; background: transparent; color: inherit; cursor: pointer; }
    button.go { background: #2dd4bf; color: #042f2b; border-color: #2dd4bf; font-weight: 600; }
    .n { color: #95a39c; white-space: nowrap; }
  </style><div class="box" hidden></div>
  <div class="bar"><span class="n">Click an element to block it</span><input hidden spellcheck="false"><button class="up" hidden title="Select parent">▲</button><button class="go" hidden>Block</button><button class="x">Cancel</button></div>`;
  document.documentElement.append(root);
  const box = shadow.querySelector('.box');
  const input = shadow.querySelector('input');
  const count = shadow.querySelector('.n');
  const go = shadow.querySelector('.go');
  const up = shadow.querySelector('.up');
  let picked = null;

  const cssEscape = (s) => (window.CSS?.escape ? CSS.escape(s) : s.replace(/[^\w-]/g, '\\$&'));
  // Short, stable selector: id if unique, else tag + stable classes, walking up until unique.
  function selectorFor(el) {
    const parts = [];
    for (let n = el; n && n.nodeType === 1 && n !== document.documentElement; n = n.parentElement) {
      if (n.id && !/\d{3,}/.test(n.id) && document.querySelectorAll('#' + cssEscape(n.id)).length === 1) {
        parts.unshift('#' + cssEscape(n.id));
        break;
      }
      let part = n.localName;
      const classes = [...n.classList].filter((c) => !/\d{3,}|^(active|hover|open|show|visible)$/.test(c)).slice(0, 3);
      if (classes.length) part += classes.map((c) => '.' + cssEscape(c)).join('');
      else if (n.parentElement) {
        const same = [...n.parentElement.children].filter((c) => c.localName === n.localName);
        if (same.length > 1) part += `:nth-of-type(${same.indexOf(n) + 1})`;
      }
      parts.unshift(part);
      if (document.querySelectorAll(parts.join(' > ')).length === 1) break;
    }
    return parts.join(' > ');
  }

  function outline(el) {
    if (!el) return (box.hidden = true);
    const r = el.getBoundingClientRect();
    Object.assign(box.style, { left: r.left + 'px', top: r.top + 'px', width: r.width + 'px', height: r.height + 'px' });
    box.hidden = false;
  }

  function matches(sel) {
    try { return document.querySelectorAll(sel).length; } catch { return -1; }
  }

  function choose(el) {
    picked = el;
    input.value = selectorFor(el);
    input.hidden = go.hidden = false;
    up.hidden = !el.parentElement || el.parentElement === document.body;
    preview();
  }

  function preview() {
    const n = matches(input.value);
    count.textContent = n < 0 ? 'Invalid selector' : `${n} element${n === 1 ? '' : 's'}`;
    go.disabled = n <= 0;
    const first = n > 0 ? document.querySelector(input.value) : null;
    outline(first);
  }

  const onMove = (e) => { if (!picked) outline(document.elementFromPoint(e.clientX, e.clientY)); };
  const onClick = (e) => {
    if (picked || e.composedPath().includes(root)) return;
    e.preventDefault();
    e.stopPropagation();
    const el = document.elementFromPoint(e.clientX, e.clientY);
    if (el && el !== document.body && el !== document.documentElement) choose(el);
  };
  const onKey = (e) => { if (e.key === 'Escape') stop(); };
  function stop() {
    document.removeEventListener('mousemove', onMove, true);
    document.removeEventListener('click', onClick, true);
    document.removeEventListener('keydown', onKey, true);
    root.remove();
    window.__adhushPicker = false;
  }
  document.addEventListener('mousemove', onMove, true);
  document.addEventListener('click', onClick, true);
  document.addEventListener('keydown', onKey, true);

  input.oninput = preview;
  up.onclick = () => picked?.parentElement && choose(picked.parentElement);
  shadow.querySelector('.x').onclick = stop;
  go.onclick = async () => {
    const selector = input.value.trim();
    go.disabled = true;
    const r = await chrome.runtime.sendMessage({ type: 'native', body: { cmd: 'rule', rule: `${host}##${selector}` } });
    if (!r?.ok) {
      count.textContent = r?.error || 'Failed';
      go.disabled = false;
      return;
    }
    // Hide right away; the filter applies the rule on the next page load.
    document.querySelectorAll(selector).forEach((el) => el.style.setProperty('display', 'none', 'important'));
    stop();
  };
})();
