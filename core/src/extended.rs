//! AdGuard rule syntax that adblock-rust does not understand. Lines are extracted from each list
//! before it is handed to adblock-rust:
//!   * `domains#$#css` / `#@$#`   – CSS injection (and its exceptions)
//!   * `domains#%#js`  / `#@%#`   – JavaScript injection (trusted lists only)
//!   * `domains#%#//scriptlet('name', args…)` – AdGuard scriptlet syntax, converted to `##+js()`
//!   * `||host^$removeheader=[request:]name` – strip request/response headers
//!   * `||host^$cookie[=name|/regex/][;maxAge=N]` – strip or shorten cookies
use hyper::header::{HeaderMap, HeaderValue};
use regex::Regex;

use crate::filter::url_host;
use crate::privacy::{is_third_party, limit_cookie_lifetime, registrable};

/// Domain scope of a cosmetic-style rule: include list (empty = every site) and exclusions.
#[derive(Debug, Clone, Default)]
struct Scope {
    include: Vec<String>,
    exclude: Vec<String>,
}

fn domain_matches(host: &str, pattern: &str) -> bool {
    if let Some(base) = pattern.strip_suffix(".*") {
        // "example.*" matches example.com, example.co.uk, www.example.de …
        let reg = registrable(host);
        return reg.starts_with(&format!("{base}.")) && reg.len() > base.len() + 1;
    }
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

impl Scope {
    fn parse(list: &str) -> Self {
        let mut s = Scope::default();
        for d in list.split([',', '|']).map(|d| d.trim().to_ascii_lowercase()).filter(|d| !d.is_empty()) {
            match d.strip_prefix('~') {
                Some(x) => s.exclude.push(x.to_string()),
                None => s.include.push(d),
            }
        }
        s
    }

    fn matches(&self, host: &str) -> bool {
        if self.exclude.iter().any(|d| domain_matches(host, d)) {
            return false;
        }
        self.include.is_empty() || self.include.iter().any(|d| domain_matches(host, d))
    }

    fn is_generic(&self) -> bool {
        self.include.is_empty()
    }
}

#[derive(Debug)]
struct Injection {
    scope: Scope,
    body: String,
    exception: bool,
}

#[derive(Debug)]
enum CookieName {
    Any,
    Exact(String),
    Pattern(Regex),
}

impl CookieName {
    fn matches(&self, name: &str) -> bool {
        match self {
            CookieName::Any => true,
            CookieName::Exact(n) => n == name,
            CookieName::Pattern(re) => re.is_match(name),
        }
    }
}

#[derive(Debug)]
enum NetAction {
    RemoveHeader { request: bool, name: String },
    Cookie { name: CookieName, max_age: Option<u64> },
}

#[derive(Debug)]
struct NetRule {
    /// From `||host^`; None means any host.
    host: Option<String>,
    /// `$domain=` (page domains).
    pages: Scope,
    third_party: Option<bool>,
    action: NetAction,
}

/// Headers that must never be removed: removing them would weaken security or break the proxy.
const PROTECTED_HEADERS: &[&str] = &[
    "host", "content-length", "content-type", "transfer-encoding", "connection", "upgrade",
    "access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-headers",
    "access-control-allow-methods", "access-control-expose-headers", "access-control-max-age",
    "strict-transport-security", "cookie", "set-cookie",
];

#[derive(Default)]
pub struct Extended {
    css: Vec<Injection>,
    js: Vec<Injection>,
    net: Vec<NetRule>,
}

/// What a page receives from AdGuard-syntax rules.
#[derive(Default, Debug)]
pub struct PageInjections {
    pub css: Vec<String>,
    pub js: Vec<String>,
}

fn split_cosmetic(line: &str, marker: &str) -> Option<(String, String)> {
    let i = line.find(marker)?;
    Some((line[..i].to_string(), line[i + marker.len()..].trim().to_string()))
}

/// Converts `//scriptlet('name', 'a', "b")` to the uBlock `+js(name, a, b)` argument list.
fn convert_scriptlet(body: &str) -> Option<String> {
    let inner = body.strip_prefix("//scriptlet(")?.strip_suffix(')')?;
    let mut args = Vec::new();
    let mut chars = inner.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
            chars.next();
        }
        let Some(q) = chars.next() else { break };
        if q != '\'' && q != '"' {
            return None;
        }
        let mut arg = String::new();
        loop {
            match chars.next()? {
                '\\' => arg.push(chars.next()?),
                c if c == q => break,
                c => arg.push(c),
            }
        }
        args.push(arg);
    }
    let name = args.first()?.trim_start_matches("ubo-").trim_end_matches(".js").to_string();
    let rest: Vec<String> = args[1..].iter().map(|a| a.replace(',', "\\,")).collect();
    Some(if rest.is_empty() { name } else { format!("{name}, {}", rest.join(", ")) })
}

fn parse_net_rule(line: &str) -> Option<NetRule> {
    let (pattern, mods) = line.rsplit_once('$')?;
    let pattern = pattern.trim();
    let host = if pattern.is_empty() || pattern == "*" {
        None
    } else {
        let h = pattern.strip_prefix("||")?.trim_end_matches('^').trim_end_matches('/');
        if h.is_empty() || h.contains(['/', '*', '^']) {
            return None;
        }
        Some(h.to_ascii_lowercase())
    };
    let mut action = None;
    let mut pages = Scope::default();
    let mut third_party = None;
    for m in mods.split(',') {
        let m = m.trim();
        let (name, value) = m.split_once('=').map(|(n, v)| (n.trim(), Some(v))).unwrap_or((m, None));
        match name {
            "removeheader" => {
                let v = value?;
                let (request, header) = match v.strip_prefix("request:") {
                    Some(h) => (true, h),
                    None => (false, v),
                };
                let header = header.trim().to_ascii_lowercase();
                if PROTECTED_HEADERS.contains(&header.as_str()) {
                    return None;
                }
                action = Some(NetAction::RemoveHeader { request, name: header });
            }
            "cookie" => {
                let mut name = CookieName::Any;
                let mut max_age = None;
                if let Some(v) = value {
                    let mut parts = v.split(';');
                    let n = parts.next().unwrap_or("").trim();
                    if let Some(re) = n.strip_prefix('/').and_then(|r| r.strip_suffix('/')) {
                        name = CookieName::Pattern(Regex::new(re).ok()?);
                    } else if !n.is_empty() {
                        name = CookieName::Exact(n.to_string());
                    }
                    for p in parts {
                        if let Some(a) = p.trim().strip_prefix("maxAge=") {
                            max_age = a.parse().ok();
                        }
                    }
                }
                action = Some(NetAction::Cookie { name, max_age });
            }
            "domain" => pages = Scope::parse(value?),
            "third-party" | "3p" => third_party = Some(true),
            "~third-party" | "first-party" | "1p" => third_party = Some(false),
            "important" | "all" | "document" | "doc" => {}
            _ => return None, // unknown modifier: not one of ours
        }
    }
    Some(NetRule { host, pages, third_party, action: action? })
}

impl Extended {
    /// Extracts the rules handled here and returns the remaining text for adblock-rust (with
    /// AdGuard scriptlets rewritten to uBlock syntax). `trusted` gates raw JavaScript injection.
    pub fn extract(&mut self, text: &str, trusted: bool) -> String {
        let mut rest = String::with_capacity(text.len());
        for line in text.lines() {
            let l = line.trim();
            let handled = if l.starts_with('!') || l.is_empty() {
                false
            } else if let Some((domains, body)) = split_cosmetic(l, "#@$#").or_else(|| split_cosmetic(l, "#$#")) {
                let exception = l.contains("#@$#");
                if body.contains('{') && !body.contains('<') {
                    self.css.push(Injection { scope: Scope::parse(&domains), body, exception });
                }
                true
            } else if let Some((domains, body)) = split_cosmetic(l, "#@%#").or_else(|| split_cosmetic(l, "#%#")) {
                let exception = l.contains("#@%#");
                if let Some(args) = convert_scriptlet(&body) {
                    rest.push_str(&format!("{domains}{}+js({args})\n", if exception { "#@#" } else { "##" }));
                } else if trusted && !body.is_empty() {
                    self.js.push(Injection { scope: Scope::parse(&domains), body, exception });
                }
                true
            } else if l.contains("$removeheader=") || l.contains("$cookie") || l.contains(",cookie") {
                if let Some(rule) = parse_net_rule(l.trim_start_matches("@@")) {
                    if !l.starts_with("@@") {
                        self.net.push(rule);
                    }
                }
                true
            } else {
                false
            };
            if !handled {
                rest.push_str(line);
                rest.push('\n');
            }
        }
        rest
    }

    pub fn rule_count(&self) -> usize {
        self.css.len() + self.js.len() + self.net.len()
    }

    fn select(rules: &[Injection], host: &str) -> Vec<String> {
        let excepted: Vec<&Injection> = rules.iter().filter(|r| r.exception && r.scope.matches(host)).collect();
        let mut out: Vec<String> = rules
            .iter()
            .filter(|r| !r.exception && r.scope.matches(host))
            .filter(|r| !excepted.iter().any(|e| e.body == r.body || (e.body.is_empty() && e.scope.is_generic())))
            .map(|r| r.body.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn page(&self, page_url: &str) -> PageInjections {
        let host = url_host(page_url).to_ascii_lowercase();
        PageInjections { css: Self::select(&self.css, &host), js: Self::select(&self.js, &host) }
    }

    fn net_matches<'a>(&'a self, request_host: &'a str, page_host: &'a str) -> impl Iterator<Item = &'a NetRule> + 'a {
        let third = is_third_party(request_host, page_host);
        self.net.iter().filter(move |r| {
            r.host.as_deref().is_none_or(|h| domain_matches(request_host, h))
                && (r.pages.include.is_empty() && r.pages.exclude.is_empty() || r.pages.matches(page_host))
                && r.third_party.is_none_or(|t| t == third)
        })
    }

    pub fn apply_request(&self, h: &mut HeaderMap, request_host: &str, page_host: &str) {
        for rule in self.net_matches(request_host, page_host) {
            match &rule.action {
                NetAction::RemoveHeader { request: true, name } => {
                    h.remove(name.as_str());
                }
                NetAction::Cookie { name, max_age: None } => {
                    let Some(cookie) = h.get("cookie").and_then(|v| v.to_str().ok()).map(str::to_string) else { continue };
                    let kept: Vec<&str> = cookie.split(';').map(str::trim).filter(|c| !name.matches(c.split('=').next().unwrap_or(""))).collect();
                    if kept.is_empty() {
                        h.remove("cookie");
                    } else if let Ok(v) = HeaderValue::from_str(&kept.join("; ")) {
                        h.insert("cookie", v);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn apply_response(&self, h: &mut HeaderMap, request_host: &str, page_host: &str) {
        for rule in self.net_matches(request_host, page_host) {
            match &rule.action {
                NetAction::RemoveHeader { request: false, name } => {
                    h.remove(name.as_str());
                }
                NetAction::Cookie { name, max_age } => {
                    let cookies: Vec<String> = h.get_all("set-cookie").iter().filter_map(|v| v.to_str().ok().map(str::to_string)).collect();
                    h.remove("set-cookie");
                    for c in cookies {
                        let cname = c.split('=').next().unwrap_or("").trim().to_string();
                        let value = match (name.matches(&cname), max_age) {
                            (false, _) => Some(c),
                            (true, Some(age)) => Some(limit_cookie_lifetime(&c, *age)),
                            (true, None) => None,
                        };
                        if let Some(v) = value.and_then(|v| HeaderValue::from_str(&v).ok()) {
                            h.append("set-cookie", v);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(text: &str, trusted: bool) -> (Extended, String) {
        let mut e = Extended::default();
        let rest = e.extract(text, trusted);
        (e, rest)
    }

    #[test]
    fn css_and_js_injection() {
        let (e, rest) = ext("site.org#$#.ad { display: none !important; }\n#$#body { overflow: auto !important; }\n~other.org#$#.x { color: red; }\nsite.org#%#window.x = 1;\n||ads.com^", true);
        assert_eq!(rest, "||ads.com^\n");
        let p = e.page("https://www.site.org/");
        assert!(p.css.iter().any(|c| c.starts_with(".ad")) && p.css.iter().any(|c| c.starts_with("body")) && p.css.iter().any(|c| c.starts_with(".x")));
        assert_eq!(p.js, vec!["window.x = 1;"]);
        assert!(!e.page("https://other.org/").css.iter().any(|c| c.starts_with(".x")));
        let (untrusted, _) = ext("site.org#%#window.x = 1;", false);
        assert!(untrusted.page("https://site.org/").js.is_empty(), "custom lists cannot inject raw JS");
    }

    #[test]
    fn exceptions_and_wildcard_tld() {
        let (e, _) = ext("example.*#$#.promo { display: none !important; }\nexample.de#@$#.promo { display: none !important; }", true);
        assert_eq!(e.page("https://www.example.co.uk/").css.len(), 1);
        assert!(e.page("https://example.de/").css.is_empty());
    }

    #[test]
    fn adguard_scriptlets_become_ublock() {
        let (_, rest) = ext("site.org#%#//scriptlet('ubo-set-constant', 'ads.enabled', 'false')\nsite.org#@%#//scriptlet('abort-on-property-read', 'a,b')", true);
        assert_eq!(rest, "site.org##+js(set-constant, ads.enabled, false)\nsite.org#@#+js(abort-on-property-read, a\\,b)\n");
    }

    #[test]
    fn removeheader_and_cookie_rules() {
        let (e, rest) = ext("||site.org^$removeheader=refresh\n||site.org^$removeheader=request:x-tracker\n||track.net^$cookie=/^_ga/,third-party\n||site.org^$removeheader=content-type", true);
        assert!(rest.trim().is_empty());
        let mut req = HeaderMap::new();
        req.insert("x-tracker", HeaderValue::from_static("1"));
        e.apply_request(&mut req, "www.site.org", "www.site.org");
        assert!(req.get("x-tracker").is_none());
        let mut res = HeaderMap::new();
        res.insert("refresh", HeaderValue::from_static("5"));
        res.insert("content-type", HeaderValue::from_static("text/html"));
        e.apply_response(&mut res, "www.site.org", "www.site.org");
        assert!(res.get("refresh").is_none() && res.get("content-type").is_some(), "protected headers survive");

        let mut c = HeaderMap::new();
        c.insert("cookie", HeaderValue::from_static("_ga=1; session=2; _gat=3"));
        e.apply_request(&mut c, "track.net", "news.com");
        assert_eq!(c.get("cookie").unwrap(), "session=2");
        let mut same = HeaderMap::new();
        same.insert("cookie", HeaderValue::from_static("_ga=1"));
        e.apply_request(&mut same, "track.net", "track.net");
        assert!(same.get("cookie").is_some(), "rule is third-party only");
    }
}
