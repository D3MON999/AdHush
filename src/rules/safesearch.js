// Safe search enforcement via DNS: search engines expose "safe" hostnames that
// force strict filtering when the regular hostname resolves to them.
const GOOGLE_TLDS = ['com', 'co.uk', 'de', 'fr', 'es', 'it', 'ca', 'com.au', 'co.in', 'co.jp', 'com.br', 'ru', 'nl',
  'pl', 'com.mx', 'co.za', 'se', 'ch', 'at', 'be', 'pt', 'com.tr', 'co.kr', 'com.ar', 'cl', 'co.id', 'com.sg', 'ie',
  'dk', 'no', 'fi', 'cz', 'gr', 'hu', 'ro', 'com.ua', 'com.pk', 'com.eg', 'com.sa', 'ae', 'co.nz', 'com.hk',
  'com.tw', 'com.vn', 'com.ph', 'com.my', 'co.th', 'com.bd', 'com.ng', 'co.il'];

const TARGETS = [
  ...GOOGLE_TLDS.flatMap((tld) => [[`google.${tld}`, 'forcesafesearch.google.com'], [`www.google.${tld}`, 'forcesafesearch.google.com']]),
  ['www.youtube.com', 'restrict.youtube.com'],
  ['m.youtube.com', 'restrict.youtube.com'],
  ['youtubei.googleapis.com', 'restrict.youtube.com'],
  ['youtube.googleapis.com', 'restrict.youtube.com'],
  ['www.youtube-nocookie.com', 'restrict.youtube.com'],
  ['www.bing.com', 'strict.bing.com'],
  ['bing.com', 'strict.bing.com'],
  ['duckduckgo.com', 'safe.duckduckgo.com'],
  ['www.duckduckgo.com', 'safe.duckduckgo.com'],
  ['start.duckduckgo.com', 'safe.duckduckgo.com'],
  ['pixabay.com', 'safesearch.pixabay.com'],
  ['www.pixabay.com', 'safesearch.pixabay.com'],
];

export function safeSearchRules() {
  return TARGETS.map(([host, target]) => `|${host}^$dnsrewrite=NOERROR;CNAME;${target},dnstype=A|AAAA,important`).join('\n');
}
