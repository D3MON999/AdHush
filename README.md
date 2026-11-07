<p align="center">
  <img src="assets/readme/banner.png" alt="AdHush: block ads, trackers and malware across your whole PC">
</p>

<p align="center">
  <a href="https://github.com/D3MON999/AdHush/releases/latest"><img alt="Latest version" src="https://img.shields.io/github/v/release/D3MON999/AdHush?style=for-the-badge&label=latest&color=1c1c1c&labelColor=000000"></a>
  <a href="https://github.com/D3MON999/AdHush/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/D3MON999/AdHush/total?style=for-the-badge&color=1c1c1c&labelColor=000000"></a>
  <img alt="Windows 10 and 11" src="https://img.shields.io/badge/Windows-10%20%7C%2011-1c1c1c?style=for-the-badge&labelColor=000000">
  <a href="LICENSE"><img alt="GPL-3.0 license" src="https://img.shields.io/badge/license-GPL--3.0-1c1c1c?style=for-the-badge&labelColor=000000"></a>
</p>

<p align="center">
  <a href="https://github.com/D3MON999/AdHush/releases/latest"><b>Download AdHush</b></a>
</p>

<p align="center">A free ad blocker for your whole Windows PC, in every browser and every app, with no account and nothing left behind if you uninstall.</p>

<p align="center">
  <img src="assets/readme/overview.png" alt="The AdHush Overview showing protection on, blocked requests over 24 hours and the most blocked domains">
</p>

## Why AdHush

- **Your whole PC.** A browser extension protects one browser. AdHush filters at the system level, so every app is covered.
- **You can check it works.** One click runs real tests and explains the results in plain English.
- **Browsers can't skip it.** "Secure DNS" can quietly bypass ad blocking, so AdHush stops that in Chrome, Edge, Brave and Firefox.
- **Quiet while you play.** Notifications and updates wait until your full-screen game is over.
- **Nothing extra.** There are no accounts, ads or telemetry, and it's free and open source.

## What it does

<table>
  <tr>
    <td width="50%"><b>Check my protection</b><br>Tests the real path from your PC to the filter, then tells you what's working and what to fix.</td>
    <td width="50%"><b>Web filtering</b><br>Optional filtering inside pages for YouTube and in-page ads. It starts with just your browsers.</td>
  </tr>
  <tr>
    <td><img src="assets/readme/check.png" alt="The Check my protection page reporting that everything is working"></td>
    <td><img src="assets/readme/web-filtering.png" alt="The Web filtering page with requests blocked and the choice of apps"></td>
  </tr>
  <tr>
    <td><b>Statistics</b><br>See what was blocked and which companies track you the most. It all stays on your PC.</td>
    <td><b>Query log</b><br>Watch every request live, and block or unblock anything in one click.</td>
  </tr>
  <tr>
    <td><img src="assets/readme/statistics.png" alt="Statistics showing queries over time and the companies tracking you"></td>
    <td><img src="assets/readme/query-log.png" alt="The live query log with blocked and processed requests"></td>
  </tr>
  <tr>
    <td><b>Tracking protection</b><br>Pick Standard, High or Extreme, or go switch by switch. Tracking parameters are stripped from links too.</td>
    <td><b>Apps</b><br>Choose which programs are filtered, with a count of what was blocked in each.</td>
  </tr>
  <tr>
    <td><img src="assets/readme/tracking.png" alt="The Tracking protection page with protection levels and switches"></td>
    <td><img src="assets/readme/apps.png" alt="The Apps page with filtering switches for each program"></td>
  </tr>
</table>

There's more in the app: custom filter lists, your own rules, allow and block lists, encrypted DNS, userscripts and a browser extension for Chromium browsers. Safe search and adult-site blocking are there too, off until you want them.

## Safe by design

An ad blocker sits between you and the internet, so it has to fail safely.

- **Safety net.** If AdHush stops answering, your normal internet settings come back within a minute.
- **Restore normal internet.** A Start menu shortcut puts everything back, even if the app won't open.
- **Off for one site.** If a site breaks, turn AdHush off for just that site.
- **Signed updates.** Only updates signed by the developer are installed.
- **Your certificate, your choice.** Web filtering is optional. Its certificate is created on your PC and removed when you uninstall.
- **Clean uninstall.** Your DNS, browser settings and certificates go back the way they were.

**About anti-cheat:** Gaming mode reads no game memory and injects nothing into games, and web filtering only touches your browsers by default. No tool can promise what an anti-cheat will do, though, so if you play ranked, keep web filtering on *Only my browsers*.

<img src="assets/readme/settings.png" alt="Settings with whole-PC protection, the browser guard, Gaming mode, themes and updates">

## Make it yours

Choose from five themes, or match your Windows light or dark mode.

<table>
  <tr>
    <td width="50%"><b>Midnight Mint</b><br><img src="assets/readme/theme-midnight.png" alt="The Midnight Mint theme"></td>
    <td width="50%"><b>Sand</b><br><img src="assets/readme/theme-sand.png" alt="The Sand theme"></td>
  </tr>
  <tr>
    <td><b>Graphite &amp; Ember</b><br><img src="assets/readme/theme-ember.png" alt="The Graphite and Ember theme"></td>
    <td><b>Raspberry</b><br><img src="assets/readme/theme-raspberry.png" alt="The Raspberry theme"></td>
  </tr>
</table>

Obsidian, the black theme shown at the top, is the default.

## Install

1. Download `AdHushSetup` from the [latest release](https://github.com/D3MON999/AdHush/releases/latest).
2. Run it. Windows will show an unknown publisher warning because the app has no paid certificate, so choose **More info**, then **Run anyway**.
3. Open AdHush. A short setup walks you through your theme and protection.

You'll need 64-bit Windows 10 or 11 and the Microsoft Edge WebView2 Runtime, which most PCs already have. AdHush updates itself from then on.

Your browser may say it's "managed by your organization" while whole-PC protection is on. That's the Secure DNS setting, and it goes away if you turn the feature off or uninstall.

## For developers

How AdHush is built, and how to build it yourself, is in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## License

AdHush is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3 or (at your option) any later version. See [LICENSE](LICENSE).

It bundles or downloads third-party components under their own licences; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Filter lists and the tracker database are maintained by their respective authors and fetched from their public sources.

AdHush is an independent project and is not affiliated with or endorsed by any other ad-blocking product or company.

Screenshots use sample data.
