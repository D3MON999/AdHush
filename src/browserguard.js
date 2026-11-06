// Browser guard: browsers with "Secure DNS" (DNS-over-HTTPS) talk straight to their own resolver,
// so system-wide DNS filtering never sees them. Two layers keep them on AdHush:
//   * DNS rules (always, when the switch is on): Firefox's official canary domain answers NXDOMAIN,
//     which turns off its automatic DoH, and well-known DoH hostnames stop resolving for browsers.
//     AdHush's own upstreams are unaffected: they are reached through bootstrap IPs, not these rules.
//   * browser policies (when whole-PC protection is on): see WINDOWS_TWEAKS.browserDoh in privacy.js.
export const DOH_HOSTS = [
  'dns.google', 'dns.google.com', 'chrome.cloudflare-dns.com', 'mozilla.cloudflare-dns.com', 'cloudflare-dns.com',
  'dns.quad9.net', 'doh.opendns.com', 'doh.cleanbrowsing.org', 'dns.nextdns.io', 'dns.adguard-dns.com', 'doh.mullvad.net',
];

export function secureDnsRules() {
  return ['||use-application-dns.net^$dnsrewrite=NXDOMAIN,important', ...DOH_HOSTS.map((h) => `||${h}^$important`)].join('\n');
}

// A name only AdHush answers, with an address nothing else would return: getting this answer from
// Windows' own resolver proves the PC's DNS really goes through AdHush (and can't come from a cache,
// because each test asks for a fresh random subdomain).
export const SELFTEST_DOMAIN = 'adhush-selftest.test';
export const SELFTEST_IP = '127.0.0.99';
export const SELFTEST_RULE = `||${SELFTEST_DOMAIN}^$dnsrewrite=NOERROR;A;${SELFTEST_IP},important`;
