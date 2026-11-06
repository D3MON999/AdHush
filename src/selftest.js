// "Is my protection working?": runs the real paths end to end and explains each result in plain
// words. Every check returns { id, name, status: ok|warn|fail|off, detail, fix? }; a fix is either
// { action, label } (the page applies it) or { href, label } (the page links there).
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import dns from 'node:dns';
import fs from 'node:fs';
import path from 'node:path';
import { buildQuery, parse, summarizeAnswers } from './dns/packet.js';
import { Upstream } from './dns/upstream.js';
import { SELFTEST_DOMAIN, SELFTEST_IP } from './browserguard.js';

const TIMEOUT_MS = 5000;
const RESEND_MS = 1000;

function withTimeout(promise, ms = TIMEOUT_MS) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timed out')), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// Asks AdHush's own DNS listener directly, the way any app on this PC would.
function askLocal(name, port) {
  const sock = dgram.createSocket('udp4');
  const query = buildQuery(name, 1);
  const send = () => sock.send(query, port, '127.0.0.1');
  // UDP can lose a packet (the first one after start-up often goes missing while another network
  // filter is running), so resend like any DNS client instead of reporting a false problem.
  const resend = setInterval(send, RESEND_MS);
  return withTimeout(new Promise((resolve, reject) => {
    sock.once('error', reject);
    sock.once('message', (msg) => resolve(parse(msg)));
    send();
  })).finally(() => {
    clearInterval(resend);
    sock.close();
  });
}

function localPort(app) {
  const udp = app.dns.listening.find((l) => l.startsWith('udp://127.0.0.1:'));
  return udp ? Number(udp.split(':').pop()) : null;
}

async function checkUpstreams(app) {
  const { upstreams, bootstrap } = app.settings.get().dns;
  let lastError = '';
  for (const spec of upstreams) {
    const u = new Upstream(spec, { bootstrap, timeoutMs: TIMEOUT_MS });
    try {
      const res = parse(await u.exchange(buildQuery('example.org', 1)));
      if (res.rcode === 0) return { status: 'ok', detail: `AdHush can look up websites securely (${new URL(spec.includes('://') ? spec : `dns://${spec}`).hostname}).` };
    } catch (e) {
      lastError = e.message;
    } finally {
      u.close();
    }
  }
  return { status: 'fail', detail: `AdHush can't reach its DNS servers, so websites may not load${lastError ? ` (${lastError})` : ''}. Check your internet connection, or a firewall or VPN.` };
}

export async function runSelfTest(app) {
  const s = app.settings.get();
  const checks = [];
  const add = (id, name, result) => checks.push({ id, name, ...result });
  const active = app.settings.isProtectionActive();
  const dnsState = app.systemDnsState();
  const random = `st-${crypto.randomBytes(5).toString('hex')}.${SELFTEST_DOMAIN}`;
  const port = localPort(app);

  add('protection', 'Protection', active ? { status: 'ok', detail: 'Protection is switched on.' }
    : !s.protection.enabled ? { status: 'fail', detail: 'Protection is switched off, so nothing is being blocked.', fix: { action: 'resume', label: 'Turn on' } }
      : { status: 'warn', detail: 'Protection is paused, so nothing is being blocked right now.', fix: { action: 'resume', label: 'Resume' } });

  add('listener', 'DNS filter', port ? { status: 'ok', detail: 'AdHush is answering DNS requests on this PC.' }
    : { status: 'fail', detail: `AdHush isn't answering DNS requests${app.dns.errors.length ? `: ${app.dns.errors[0]}` : ''}. Another program may be using port 53.` });

  add('lists', 'Filter lists', app.engine.count > 0 ? { status: 'ok', detail: `${app.engine.count.toLocaleString()} blocking rules loaded from ${app.filters.activeFilters().length} lists.` }
    : { status: 'fail', detail: 'No blocking rules are loaded yet. The lists may still be downloading.', fix: { href: '#/filters', label: 'Open Filters' } });

  add('upstream', 'Internet lookups', await checkUpstreams(app));

  if (port && active) {
    try {
      const res = await askLocal('doubleclick.net', port);
      const answer = summarizeAnswers(res).join(' ');
      const verdict = app.engine.match('doubleclick.net', { qtype: 1 });
      add('blocking', 'Ad blocking', verdict.action === 'block' || res.rcode !== 0 || /^(0\.0\.0\.0|::)?$/.test(answer.trim())
        ? { status: 'ok', detail: 'A known ad server was blocked correctly.' }
        : { status: 'warn', detail: 'A known ad server was not blocked. It may be on your allowlist.', fix: { href: '#/lists', label: 'Open lists' } });
    } catch (e) {
      add('blocking', 'Ad blocking', { status: 'fail', detail: `The test request failed (${e.message}).` });
    }
  }

  // The real question: do apps on this PC actually go through AdHush?
  if (s.system.manageDns || dnsState.guard) {
    if (!s.system.manageDns) {
      add('wholepc', 'Whole-PC protection', { status: 'off', detail: 'Windows is not using AdHush for lookups, so most apps are not filtered.', fix: { action: 'wholePc', label: 'Turn on' } });
    } else if (dnsState.mode === 'fallback') {
      add('wholepc', 'Whole-PC protection', { status: 'fail', detail: dnsState.detail || 'AdHush stopped answering, so normal internet settings were restored.' });
    } else {
      try {
        const { address } = await withTimeout(dns.promises.lookup(random, { family: 4 }));
        add('wholepc', 'Whole-PC protection', address === SELFTEST_IP ? { status: 'ok', detail: 'Windows sends its lookups through AdHush, so every app is covered.' }
          : { status: 'warn', detail: "Windows answered the test without AdHush. A VPN or another DNS tool may be taking over." });
      } catch {
        add('wholepc', 'Whole-PC protection', { status: 'warn', detail: "Windows didn't send the test through AdHush. A VPN or another DNS tool may be taking over, or it may still be applying (wait 15 seconds and run this again)." });
      }
    }
  }

  // Browsers with Secure DNS skip system DNS entirely.
  if (!s.system.stopSecureDns) {
    add('browsers', 'Browsers', { status: 'warn', detail: 'Browsers using "Secure DNS" can skip AdHush and show ads.', fix: { action: 'browserGuard', label: 'Stop the bypass' } });
  } else if (!s.system.manageDns) {
    add('browsers', 'Browsers', { status: 'off', detail: 'The Secure DNS guard starts working once whole-PC protection is on.' });
  } else if (app.windowsPrivacy.errors.browserDoh) {
    add('browsers', 'Browsers', { status: 'fail', detail: `Couldn't apply the browser settings: ${app.windowsPrivacy.errors.browserDoh}` });
  } else if (app.windowsPrivacy.state.snapshots.browserDoh) {
    add('browsers', 'Browsers', { status: 'ok', detail: 'Chrome, Edge, Brave and Firefox are set to use AdHush. Restart a browser if it was already open.' });
  } else {
    add('browsers', 'Browsers', { status: 'warn', detail: 'The browser settings are still being applied. Run this again in a few seconds.' });
  }

  if (!s.https.enabled) {
    add('web', 'Web filtering', { status: 'off', detail: 'Off, so YouTube and in-page ads are not blocked.', fix: { href: '#/https', label: 'Open Web filtering' } });
  } else {
    const core = await app.core.status();
    const trusted = fs.existsSync(path.join(app.dataDir, 'ca', 'installed-thumbprint'));
    const driver = core.core?.driver;
    if (!trusted && dnsState.guard) add('web', 'Web filtering', { status: 'fail', detail: "This PC's certificate isn't trusted, so secure sites may show errors.", fix: { href: '#/https', label: 'Open Web filtering' } });
    else if (!core.core) add('web', 'Web filtering', { status: 'fail', detail: core.lastError || 'The web filter is not running.' });
    else if (s.https.driver.enabled && !driver?.running) add('web', 'Web filtering', { status: 'fail', detail: driver?.error || 'The network driver is not running.' });
    else add('web', 'Web filtering', { status: 'ok', detail: `Filtering inside ${s.https.driver.mode === 'all' ? 'all apps' : 'your browsers'}.` });
  }

  const u = app.updateState();
  if (u.service) {
    add('updates', 'Updates', !u.configured ? { status: 'off', detail: 'This copy has no update source.' }
      : u.status === 'error' ? { status: 'warn', detail: u.error || "The last update check didn't work." }
        : { status: 'ok', detail: `Version ${u.current}.` });
  }

  const worst = checks.some((c) => c.status === 'fail') ? 'fail' : checks.some((c) => c.status === 'warn') ? 'warn' : 'ok';
  return { at: Date.now(), result: worst, checks };
}
