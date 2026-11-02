// AdHush in-page runtime. Injected (with a CSP nonce) into filtered HTML pages.
//  * applies procedural cosmetic filters (:has-text, :upward, :xpath, :matches-css, …) and
//    action filters (:remove(), :style(), :remove-attr(), :remove-class()),
//  * keeps generic element hiding working for content added after load by asking the proxy
//    (same-origin endpoint) for selectors matching newly seen classes and ids.
// `CFG` is replaced by the proxy: { p: [procedural filters], e: endpoint|null, n: nonce }.
(function (cfg) {
  'use strict';
  if (window.__adhushRuntime) return;
  window.__adhushRuntime = true;
  const doc = document;

  const toRegex = (arg) => {
    const m = /^\/(.+)\/([a-z]*)$/s.exec(arg);
    if (!m) return null;
    try { return new RegExp(m[1], m[2]); } catch { return null; }
  };
  const matcher = (arg) => {
    const re = toRegex(arg);
    return re ? (s) => re.test(s) : (s) => s.includes(arg);
  };
  const unquote = (s) => s.trim().replace(/^(["'])(.*)\1$/, '$2');

  const ops = {
    'css-selector': (nodes, arg) => {
      if (nodes === null) return [...doc.querySelectorAll(arg)];
      // A selector following a procedural step applies to descendants (":scope > x", ":scope x").
      return nodes.flatMap((n) => [...n.querySelectorAll(`:scope ${arg}`)]);
    },
    'has-text': (nodes, arg) => {
      const m = matcher(arg);
      return nodes.filter((n) => m(n.textContent || ''));
    },
    'min-text-length': (nodes, arg) => nodes.filter((n) => (n.textContent || '').length >= Number(arg)),
    'matches-path': (nodes, arg) => (matcher(arg)(location.pathname + location.search) ? nodes : []),
    'matches-attr': (nodes, arg) => {
      const eq = arg.indexOf('=');
      const name = matcher(unquote(eq < 0 ? arg : arg.slice(0, eq)));
      const value = eq < 0 ? null : matcher(unquote(arg.slice(eq + 1)));
      return nodes.filter((n) => [...n.attributes].some((a) => name(a.name) && (!value || value(a.value))));
    },
    'upward': (nodes, arg) => {
      const n = Number(arg);
      return nodes.map((el) => {
        if (Number.isInteger(n) && n > 0) {
          let p = el;
          for (let i = 0; i < n && p; i++) p = p.parentElement;
          return p;
        }
        return el.parentElement ? el.parentElement.closest(arg) : null;
      }).filter(Boolean);
    },
    'xpath': (nodes, arg) => {
      const out = [];
      for (const ctx of nodes === null ? [doc] : nodes) {
        const r = doc.evaluate(arg, ctx, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
        for (let i = 0; i < r.snapshotLength; i++) if (r.snapshotItem(i).nodeType === 1) out.push(r.snapshotItem(i));
      }
      return out;
    },
  };
  const cssOp = (pseudo) => (nodes, arg) => {
    const colon = arg.indexOf(':');
    if (colon < 0) return [];
    const prop = arg.slice(0, colon).trim();
    const m = matcher(unquote(arg.slice(colon + 1)));
    return nodes.filter((n) => m(getComputedStyle(n, pseudo).getPropertyValue(prop)));
  };
  ops['matches-css'] = cssOp(null);
  ops['matches-css-before'] = cssOp('::before');
  ops['matches-css-after'] = cssOp('::after');

  function select(selector) {
    let nodes = null;
    for (const step of selector) {
      const op = ops[step.type];
      if (!op) return [];
      if (nodes === null && step.type !== 'css-selector' && step.type !== 'xpath') nodes = [...doc.querySelectorAll('*')];
      nodes = op(nodes, step.arg);
      if (!nodes.length) return [];
    }
    return nodes || [];
  }

  const done = new WeakSet();
  function act(el, action) {
    if (!action) {
      if (done.has(el)) return;
      el.style.setProperty('display', 'none', 'important');
      done.add(el);
      return;
    }
    switch (action.type) {
      case 'remove': el.remove(); break;
      case 'style': el.setAttribute('style', `${el.getAttribute('style') || ''};${action.arg}`); break;
      case 'remove-attr': el.removeAttribute(action.arg); break;
      case 'remove-class': el.classList.remove(action.arg); break;
      default: break;
    }
  }

  const filters = (cfg.p || []).map((f) => { try { return typeof f === 'string' ? JSON.parse(f) : f; } catch { return null; } }).filter(Boolean);
  function applyProcedural() {
    for (const f of filters) {
      try { for (const el of select(f.selector)) act(el, f.action); } catch { /* bad filter */ }
    }
  }

  // Generic hiding for dynamically added content.
  const seenClasses = new Set();
  const seenIds = new Set();
  let style = null;
  let pendingClasses = [];
  let pendingIds = [];
  function collect(root) {
    const els = root.querySelectorAll ? [root, ...root.querySelectorAll('[class],[id]')] : [];
    for (const el of els) {
      if (!el.getAttribute) continue;
      for (const c of el.classList || []) if (!seenClasses.has(c)) { seenClasses.add(c); pendingClasses.push(c); }
      const id = el.id;
      if (id && !seenIds.has(id)) { seenIds.add(id); pendingIds.push(id); }
    }
  }
  async function flushGeneric() {
    if (!cfg.e || (!pendingClasses.length && !pendingIds.length)) return;
    const c = pendingClasses.splice(0, 300);
    const i = pendingIds.splice(0, 300);
    const q = new URLSearchParams({ u: location.href, c: c.join(' '), i: i.join(' ') });
    try {
      const res = await fetch(`${cfg.e}?${q}`, { credentials: 'omit', cache: 'no-store' });
      const sel = await res.json();
      if (!Array.isArray(sel) || !sel.length) return;
      if (!style) {
        style = doc.createElement('style');
        style.setAttribute('nonce', cfg.n);
        style.setAttribute('data-adhush', '');
        (doc.head || doc.documentElement).appendChild(style);
      }
      style.textContent += sel.map((s) => `${s}{display:none!important}`).join('\n');
    } catch { /* endpoint unreachable (CSP connect-src): static hiding still applies */ }
    if (pendingClasses.length || pendingIds.length) flushGeneric();
  }

  let timer = 0;
  function schedule() {
    if (timer) return;
    timer = setTimeout(() => {
      timer = 0;
      applyProcedural();
      flushGeneric();
    }, 120);
  }

  function start() {
    collect(doc.documentElement);
    pendingClasses = []; // classes present at load were already handled by the proxy
    pendingIds = [];
    applyProcedural();
    new MutationObserver((records) => {
      for (const r of records) for (const n of r.addedNodes) if (n.nodeType === 1) collect(n);
      schedule();
    }).observe(doc.documentElement, { childList: true, subtree: true });
  }
  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})(CFG);
