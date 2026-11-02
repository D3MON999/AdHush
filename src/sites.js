// "This site isn't working": switches AdHush off for one site in every layer at once.
// Allowlisting alone is not enough (web filtering still decrypts the site), so a broken site is
// added to the DNS/web allowlist *and* to the HTTPS exclusions, and remembered in
// filtering.brokenSites so undoing it removes exactly what was added.
export function siteHost(input) {
  const host = String(input || '').trim().toLowerCase()
    .replace(/^[a-z]+:\/\//, '').replace(/[/?#:].*$/, '').replace(/\.$/, '').replace(/^www\./, '');
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host)) throw Object.assign(new Error('enter a site like example.com'), { status: 400 });
  return host;
}

// Returns the settings patch that marks (broken = true) or unmarks a site.
export function brokenSitePatch(s, host, broken) {
  const allow = s.filtering.allowlist.domains.map((d) => (typeof d === 'string' ? { name: d, enabled: true } : d));
  const excl = s.https.exclusions.map((d) => d.name ?? d);
  const list = s.filtering.brokenSites || [];
  if (broken) {
    return {
      filtering: {
        brokenSites: [...new Set([...list, host])],
        allowlist: { enabled: true, domains: allow.some((d) => d.name === host) ? allow : [...allow, { name: host, enabled: true }] },
      },
      https: { exclusions: excl.includes(host) ? excl : [...excl, host] },
    };
  }
  return {
    filtering: { brokenSites: list.filter((h) => h !== host), allowlist: { domains: allow.filter((d) => d.name !== host) } },
    https: { exclusions: excl.filter((d) => d !== host) },
  };
}
