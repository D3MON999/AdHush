# AdHush

A free, open-source, system-wide ad, tracker, malware and phishing blocker for Windows.

- **DNS protection** for every app on the PC, with encrypted upstreams and public filter lists (Node.js, no npm dependencies).
- **Optional web filtering** inside pages (Rust: HTTPS-aware proxy or per-app WinDivert driver mode).
- A desktop app (tray icon, WebView2 window), a Windows service with a DNS safety net, signed automatic updates, and a browser companion extension.

Licensed under GPL-3.0-or-later; see [LICENSE](LICENSE) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Quick start

```bash
npm test
```

```bash
node src/index.js --dns-port 5300 --api-port 8899
```

Open http://127.0.0.1:8899/ and test with:

```bash
node scripts/dig.js doubleclick.net A 127.0.0.1 5300
```

### Protect the whole PC
1. Run AdHush on port 53. From an **administrator** PowerShell:
   ```bash
   powershell -ExecutionPolicy Bypass -File scripts/install-autostart.ps1
   ```
   This registers a boot-time task running as SYSTEM, with data in `C:\ProgramData\AdHush`.
2. Point Windows DNS at it (it saves your current DNS first):
   ```bash
   powershell -ExecutionPolicy Bypass -File scripts/set-system-dns.ps1
   ```
3. To undo everything:
   ```bash
   powershell -ExecutionPolicy Bypass -File scripts/uninstall-autostart.ps1
   ```

> Turn off DNS filtering in any other ad blocker, firewall or VPN on the same PC before you switch. Two filtering stacks on one PC can interfere with each other (for example, dropping packets on the loopback interface).

> Browsers with "Secure DNS" (DoH) enabled bypass system DNS. Turn it off in the browser, or add the browser DoH hostnames to the blocklist (`dns.google`, `chrome.cloudflare-dns.com`, `mozilla.cloudflare-dns.com`…).

## Web (HTTPS) filtering (optional)

`core/` is a Rust proxy (`adhush-core`) that the Node service starts when **Web filtering** is enabled in the UI.
It blocks ad and tracker requests with EasyList-syntax rules (via [adblock-rust](https://github.com/brave/adblock-rust)), hides page elements, strips tracking parameters (`$removeparam`) and passes WebSockets through.

Build it once (requires Rust and the MSVC Build Tools):
```bash
cargo build --release --manifest-path core/Cargo.toml
```

Then:
1. Enable **Web filtering** in the UI. This creates a per-install root CA in `<data>/ca/` (the private key is ACL-restricted).
2. Trust the CA:
   ```bash
   powershell -ExecutionPolicy Bypass -File scripts/install-ca.ps1
   ```
   Windows asks for confirmation. Remove it again with `scripts/uninstall-ca.ps1`.
3. Route apps through the proxy (current user, no admin):
   ```bash
   powershell -ExecutionPolicy Bypass -File scripts/set-system-proxy.ps1
   ```
   Undo it with `scripts/restore-system-proxy.ps1`.
4. Firefox: set `security.enterprise_roots.enabled = true` in `about:config`.

Safety behaviour:
- Hosts with **EV certificates** and hosts with an **invalid upstream certificate** are never decrypted, so the browser shows the real certificate or error.
- Hosts whose client **rejects our certificate** (pinning) are passed through for an hour.
- The same applies to hosts that answer with a **Cloudflare bot challenge**. Our TLS handshake does not look like a browser's yet.
- A **user exclusion list** covers anything else that should never be decrypted.

### Driver mode (per-app interception)
Driver mode filters apps that ignore the Windows proxy. It uses the signed [WinDivert 2.2.2](https://github.com/basil00/WinDivert) driver, which is vendored in `core/vendor/windivert`.

How it works:
- Outbound TCP 80/443 traffic from the selected apps is reflected to local listeners on ports 18480 (HTTP) and 18443 (HTTPS). Those listeners see the original server as the peer address, so no NAT table is needed.
- App ownership comes from WinDivert's socket-connect events.
- UDP 443 (QUIC) is dropped for selected apps so browsers fall back to TCP.
- Listeners refuse connections that did not come through the driver.

Requirements:
- AdHush must run **as administrator** (the autostart task runs as SYSTEM).
- On first start it adds the firewall rule "AdHush transparent proxy" for `adhush-core.exe`.
- Microsoft Defender flags WinDivert as potentially unwanted software, so `core/vendor` needs a Defender exclusion.

Enable it on the Web filtering page under **Driver mode**. By default only browsers are filtered; you can choose your own app list or filter all apps.

### Apps
- Every web request is attributed to the program that made it. In proxy mode this uses the Windows TCP table (`GetExtendedTcpTable`); in driver mode it comes from WinDivert's socket events.
- The **Apps** page lists programs with network activity (and, optionally, installed programs from the Uninstall registry keys), with request and block counts.
- Per app you can switch **Filter** off (never filtered) and **HTTPS** off (never decrypted).

### Extensions (userscripts and userstyles)
- **Install:** from a URL or pasted code. Opening a `.user.js` / `.user.css` link in a filtered browser shows an install prompt.
- **Userscripts:** Tampermonkey/Greasemonkey metadata: `@match`, `@include`, `@exclude`, `@exclude-match`, `@run-at`, `@noframes`, `@require` (bundled at install time), `@connect`. GM API: `GM_getValue`/`setValue`/`deleteValue`/`listValues` (persisted), `GM_addStyle`, `GM_xmlhttpRequest`, `GM_info`, `GM_openInTab`, `GM_setClipboard`, `GM.*` promise versions.
- **`GM_xmlhttpRequest` limits:** only reaches the page's own host or `@connect` hosts, never private or loopback addresses, and only for pages the script runs on.
- **Userstyles:** UserCSS with `@-moz-document` `url()`, `url-prefix()`, `domain()` and `regexp()` sections. Stylus/LESS preprocessors are not supported.
- **Updates:** daily, using `@updateURL` / `@downloadURL`.
- **Security note:** GM values and the request endpoint are same-origin URLs, so a page an extension runs on could also call them for that extension.

### Statistics by company
Domains are mapped to trackers, categories (advertising, analytics, social…) and companies using [AdGuard companiesdb](https://github.com/AdguardTeam/companiesdb) (CC BY-SA 4.0). It is downloaded weekly as data. The query log shows the company next to each tracker domain.

### Tracking protection (Tracking protection page)
Presets: **Standard** (safe everywhere), **High**, **Extreme**, or **Custom**. Applied by the web filter to every request it handles:
- **General:** hide search queries from the sites you open, send DNT + Global Privacy Control, remove `X-Client-Data`, strip `utm_*`/`fbclid`/`gclid`/… from URLs.
- **Third parties:** hide the referrer, disable cache-based tracking (ETag), drop `Authorization` headers, self-destruct cookies after N minutes (0 = block). First-party cookies can be limited too.
- **Browser APIs:** block WebRTC, the Push API and the Location API.
- **Identity:** generic User-Agent (and no high-entropy client hints), fake `X-Forwarded-For` ("mask IP" does not hide your real IP from the server).
- **Anti-DPI:** splits the first packet of each outbound connection (TLS ClientHello / HTTP Host) so provider-level blocking cannot read the site name.
- **Windows tracking:** telemetry, advertising ID, Recall, WAP Push service and feedback prompts, set through policy registry values. The original values are snapshotted and restored when a switch is turned off. Needs administrator rights.

### Extended rule syntax
On top of adblock-rust, AdHush understands:
- `#$#` CSS injection and `#%#` JavaScript injection. JavaScript injection is only allowed from built-in lists and user rules.
- Scriptlets written as `#%#//scriptlet(...)`, converted to uBlock scriptlets.
- `$removeheader` (request and response, with protected headers kept), `$cookie` (by name or regex, optional `maxAge`), and `$csp`.

### Scriptlets, redirects and procedural filters
- `##+js(...)` scriptlets and `$redirect` resources are supported. They come from uBlock Origin's resources (GPLv3), converted into `core/resources/resources.json`.
- Refresh them with:
  ```bash
  node scripts/build-resources.mjs
  ```
  Then rebuild the core. The running service never downloads or executes this code itself.
- Privileged `trusted-*` scriptlets are only allowed from built-in lists and your user rules, never from custom lists you add.
- Procedural cosmetic filters (`:has-text`, `:upward`, `:xpath`, `:matches-css`, `:matches-attr`, `:min-text-length`) and actions (`:remove()`, `:style()`, `:remove-attr()`, `:remove-class()`) run in a small injected runtime.
- That runtime also keeps generic element hiding working for content added after the page loads, by asking the proxy (via the same-origin `/__adhush__/cosmetic` endpoint) for selectors.
- A browser-like TLS fingerprint.

## Architecture

```
src/
  index.js             CLI entry (--data, --dns-port, --api-port, --debug)
  app.js               composition root, rule-engine rebuilds, settings reactions
  settings.js          JSON settings store with defaults, validation, deep-merge patches
  rules/parser.js      adblock / hosts / domain / regex rules + DNS modifiers
  rules/engine.js      indexed matcher (exact + suffix hash maps, regex list), $important/allowlist precedence
  rules/safesearch.js  safe-search CNAME rewrites
  dns/packet.js        RFC 1035 codec (parse, build, truncate, TTL offsets)
  dns/upstream.js      UDP, TCP, DoT (multiplexed), DoH (HTTP/2), bootstrap resolution
  dns/stamp.js         sdns:// stamps (plain, DoH, DoT)
  dns/cache.js         LRU cache with TTL aging
  dns/server.js        UDP+TCP server: block / rewrite / forward / CNAME-cloaking check
  filters/catalog.js   built-in public blocklists
  filters/manager.js   downloads, ETag/If-Modified-Since, Expires header, scheduler, custom lists
  querylog.js          in-memory query log
  stats.js             hourly buckets persisted to stats.json
  api/server.js        loopback REST API + static UI (token + Host-header protection)
  notifications.js     event feed the tray turns into Windows toasts
ui/                    single-page app (vanilla JS, light/dark) incl. first-run wizard (#/welcome)
scripts/               system DNS switch/restore, autostart task, dig test client, icons, browser host registration
test/                  node:test unit tests
core/                  Rust HTTPS filter (adhush-core.exe), WinDivert driver mode
tray/                  Rust tray app (adhush-tray.exe): shield icon, menu, WebView2 window, toasts
service/               Rust Windows service wrapper (adhush-service.exe) supervising Node in a job object
host/                  native messaging host for the browser extension (com.adhush.host)
extension/             "AdHush Assistant" MV3 extension (Chrome, Edge, Brave)
installer/             Inno Setup script, post-install / pre-uninstall scripts, build.ps1
```

## Desktop app, browser extension and installer

### Building the setup for family and friends
```bash
winget install JRSoftware.InnoSetup
```
```bash
powershell -ExecutionPolicy Bypass -File installer/build.ps1
```
This builds the three Rust programs, stages everything (with the local `node.exe`, so the people you share it with need nothing else), and writes `installer/output/AdHushSetup-<version>.exe`.

What the setup does on their PC:
- Installs to `C:\Program Files\AdHush` and registers the **AdHush** Windows service (automatic start, restarts on failure). Data lives in `C:\ProgramData\AdHush`.
- *Block ads for the whole PC* (task, on by default): turns on **whole-PC protection** (`system.manageDns`), which the service's DNS guard applies (see below).
- *Advanced: filter inside web pages* (task, off by default): creates a root certificate **unique to that PC** (`adhush-core --init-ca`; the private key is readable by SYSTEM and Administrators only), trusts it machine-wide, and turns on web filtering in driver mode, so browsers need no proxy settings.
- Starts the tray icon at sign-in. On first run the tray opens the welcome wizard.
- Registers the browser extension host for Chrome, Edge and Brave.
- The uninstaller restores DNS first, then removes the service, the certificate, the firewall rule, the host registration and `C:\ProgramData\AdHush`.

Setup steps are logged to `C:\ProgramData\AdHush\logs\setup.log`; the service wrapper logs to `service.log` in the same folder.
All three programs embed the AdHush icon and version info (`installer/adhush.rc`, compiled by each crate's `build.rs`).

### Whole-PC protection and its safety net (DNS guard)
The service (`service/src/dns_guard.rs`, running as SYSTEM independently of the Node engine) checks every 15 s that AdHush answers:
- healthy and *Filter every app on this PC* is on: every active adapter points at `127.0.0.1` / `::1`. It re-checks every 2 minutes, so adapters connected later are covered. Each adapter's previous DNS is backed up the first time (`dns-backup.json`).
- not answering for 60 s: the previous DNS is restored so the PC keeps working, the tray shows a toast, and protection is re-applied automatically once AdHush recovers.
- service stopping (including Windows shutdown) or the switch turned off: the previous DNS is restored first.
The current state is in `dns-state.json` and shown under Settings → Whole-PC protection.
*Restore normal internet* (Start menu, tray menu) is the manual emergency switch: it turns whole-PC protection off and restores DNS (`scripts/restore-internet.cmd`, asks for admin rights).
*Settings → Get help → Save logs file* writes a zip of logs, settings and protection state to the Desktop. It excludes the API token, the certificate key, statistics and the query log.

### Automatic updates (signed)
The service checks `settings.updates.feedUrl` every 6 hours (Settings → Updates → *Check for updates* asks immediately). The feed is `latest.json` plus `latest.json.sig`, an Ed25519 signature checked against the public key compiled into `adhush-service.exe` (`service/update-key.pub`). The installer is downloaded into a folder only SYSTEM and administrators can write, its SHA-256 must match the signed manifest, and it then runs silently with `/UPDATE`. Unsigned, altered or mismatched releases are refused. During the install, trays close and relaunch themselves, and whole-PC DNS is restored, then re-applied.

One-time setup: `node scripts/release.mjs keygen` creates `keys/update-signing.pem`. **Back it up and never share it**: without it, installed copies can't be updated.
Each release, with GitHub Releases as the host (any static HTTPS host works):
1. Bump `version` in `package.json` (and `installer/adhush.rc`).
2. Build: `powershell -ExecutionPolicy Bypass -File installer/build.ps1 -FeedUrl https://github.com/<you>/<repo>/releases/latest/download/latest.json -Notes "What changed"`. The feed URL is remembered in `installer/update-feed.txt` for later builds.
3. Publish the source: `powershell -ExecutionPolicy Bypass -File installer/publish-source.ps1` copies the audited source archive into the GitHub Desktop clone (`C:\dev\adhush-upload\AdHush`); then in GitHub Desktop, *Commit to main* and *Push origin*.
4. On GitHub, *Releases → Draft a new release*, tag `v<version>` (no spaces), and attach the four files from `installer/output`: `AdHushSetup-<version>.exe`, `latest.json`, `latest.json.sig`, `AdHush-<version>-source.zip`. Keep *Set as the latest release* ticked.
5. Optional check: `service\target\release\adhush-service.exe --check-feed <feed url>` runs the real update check against the live release without installing anything.
Installed copies pick it up within 6 hours. Only copies installed from a setup built *with* `-FeedUrl` know where to look.

### "A website isn't working"
Overview → *A website not working?*, the tray menu, and the browser extension's popup all turn AdHush off for one site: it is added to the allowlist **and** the HTTPS exclusions (and recorded in `filtering.brokenSites`, so *Turn back on* removes exactly that).

### Tray
Shield icon coloured by state (teal on, amber paused, grey off, red service not running). Only one copy runs per Windows user; launching it again opens the existing window. Left-click opens the app window (WebView2, the same UI as the browser). Right-click menu: status, Open, Protection on/off, Pause 30 min / Resume, Filtering log, Statistics, Restore normal internet…, Quit. Toasts appear for filter updates, the end of a pause, DNS start failures and repeated web-filter crashes (switch them off under Settings → Tray notifications).

### Browser extension (AdHush Assistant)
The popup shows the protection state and has a per-site switch (adds or removes the site on the allowlist), Pause 30 min / Resume, Block element, and Open AdHush. *Block element* (also on the page's right-click menu) highlights elements under the mouse, lets you widen the choice to the parent, previews how many elements match, and saves a `site##selector` user rule.
The extension never sees the API token: it talks to `host/host.mjs` through native messaging, and the host accepts only those commands (cosmetic rules only, no scriptlets or network rules).
To add it, use **Settings → Browser extension** in the AdHush window: it lists the installed Chromium browsers, copies the browser's extensions-page address, and opens a step-by-step guide page (`ui/extension-setup.html`) in that browser. Browsers block both silent installs and opening `chrome://`/`edge://` pages from other programs, so the person still flips Developer mode and clicks Load unpacked (about 20 seconds). Its ID is fixed at `ffcidpjioddohnenfclgdineaimihlmd`. For a development checkout, register the host with `scripts/install-browser-host.ps1`.

## Features

- **DNS protection:** DoH / DoT / TCP / UDP upstreams, DNS stamps, bootstrap and fallback servers, parallel or sequential mode; DNS cache; CNAME-cloaking protection; blocking modes (default, REFUSED, NXDOMAIN, unspecified or custom IP).
- **Filters:** a catalog of public lists plus custom lists by URL, automatic updates (honouring `Expires`), user rules (`||`, `@@`, hosts, regex, wildcards, `$important`, `$badfilter`, `$dnstype`, `$dnsrewrite`, `$denyallow`, `$client`), allow and block lists.
- **Security and parental control:** malware/phishing lists, safe search, adult-site blocking.
- **Visibility:** live query log with one-click block/unblock, statistics (24 h / 7 d / 30 d, by domain, client, filter, company and tracker category).
- **Web filtering (optional, advanced):** local per-PC root certificate, network and cosmetic rules, `removeparam`, scriptlets and `$redirect` resources, procedural and dynamic cosmetic filtering, popular extended rule syntaxes (`#$#`, `#%#`, `$removeheader`, `$cookie`, `$csp`), EV/pinned/invalid-certificate pass-through, per-app driver mode with QUIC blocking.
- **Privacy:** tracking-protection presets (cookies, referrer, user agent, DNT/GPC, WebRTC/Push/Geolocation), anti-DPI, optional Windows privacy switches with snapshot/restore.
- **Apps and extensions:** per-app filtering switches, userscripts and userstyles with a GM API.
- **Themes:** Midnight Mint (default), Sand, Graphite & Ember, Raspberry, or match Windows (Settings → Appearance).
- **Desktop:** tray icon and window, notifications, first-run wizard, "website not working" switch, Windows service with DNS safety net, logs bundle, signed automatic updates, installer and clean uninstaller, browser companion extension (Chromium).
- Not included on purpose: accounts, licensing, telemetry. DoQ and DNSCrypt upstreams are not supported yet.

## License

AdHush is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3 or (at your option) any later version. See [LICENSE](LICENSE).
It bundles or downloads third-party components under their own licences; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Filter lists and the tracker database are maintained by their respective authors and fetched from their public sources.
AdHush is an independent project and is not affiliated with or endorsed by any other ad-blocking product or company.

## API
All endpoints need the header `x-adhush-token: <data>/api-token` and are bound to 127.0.0.1.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/status` | Protection, listeners, upstream health, cache, engine |
| POST | `/api/protection` `{enabled}` · `/api/protection/pause` `{minutes}` | Toggle / pause |
| GET/PATCH | `/api/settings` | Read / partial update |
| GET · POST | `/api/settings/export` · `/api/settings/import` · `/api/settings/reset` | Backup |
| GET/POST | `/api/filters` | List / add custom `{url, name}` |
| PATCH/DELETE | `/api/filters/:id` | Enable, rename / remove custom |
| POST | `/api/filters/update` `{force, ids}` | Update lists |
| GET/PUT | `/api/rules` · POST `/api/rules/add` `{rule}` | User rules |
| GET/PUT | `/api/lists/allowlist` · `/api/lists/blocklist` | Domain lists |
| GET/DELETE | `/api/log?limit&search&status` | Query log |
| GET/DELETE | `/api/stats?period=24h\|7d\|30d` | Statistics |
| GET | `/api/check?name&type` | Which rule applies to a domain |
| POST | `/api/dns/test` `{upstream}` · `/api/dns/cache/clear` | Upstream test, cache flush |
