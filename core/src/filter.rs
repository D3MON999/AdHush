//! Content filtering on top of adblock-rust: network rules (block / exception / redirect /
//! removeparam) and cosmetic rules (element hiding, generic class/id hiding, procedural
//! filters, scriptlets).
use std::collections::HashSet;

use adblock::Engine;
use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;
use adblock::resources::PermissionMask;

use crate::config::Loaded;

/// Permission bit for privileged ("trusted-*") scriptlets; see scripts/build-resources.mjs.
const TRUSTED: PermissionMask = PermissionMask::from_bits(1);
/// Lists with an id below this are curated built-ins; higher ids are user-added custom lists.
const CUSTOM_ID_START: i64 = 1000;

pub struct ContentFilter {
    engine: Engine,
    /// AdGuard-specific rules adblock-rust does not handle (#$#, #%#, $removeheader, $cookie).
    pub extended: crate::extended::Extended,
    allowlist: Vec<String>,
    pub rules: usize,
    pub lists: usize,
    pub resources: usize,
}

pub enum Verdict {
    Allow,
    Block { rule: Option<String>, redirect: Option<String> },
    Rewrite { url: String, rule: Option<String> },
}

/// Everything a page needs from cosmetic filtering.
#[derive(Default)]
pub struct Cosmetics {
    pub selectors: Vec<String>,
    pub scriptlets: String,
    /// JSON-encoded procedural/action filters for the in-page runtime.
    pub procedural: Vec<String>,
    /// `$generichide`: generic class/id rules must not be applied on this page.
    pub generichide: bool,
}

impl Cosmetics {
    pub fn is_empty(&self) -> bool {
        self.selectors.is_empty() && self.scriptlets.trim().is_empty() && self.procedural.is_empty()
    }
}

pub fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    if let Some(stripped) = authority.strip_prefix('[') {
        return stripped.split(']').next().unwrap_or("");
    }
    authority.split(':').next().unwrap_or("")
}

fn count_rules(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('!') && !l.starts_with('['))
        .count()
}

impl ContentFilter {
    pub fn empty() -> Self {
        Self { engine: Engine::default(), extended: Default::default(), allowlist: Vec::new(), rules: 0, lists: 0, resources: 0 }
    }

    pub fn build(loaded: &Loaded) -> Self {
        let mut set = FilterSet::new(true); // debug: keep raw rule text for the log
        let trusted = ParseOptions { permissions: TRUSTED, ..Default::default() };
        let mut extended = crate::extended::Extended::default();
        let mut rules = 0;
        for (id, text) in &loaded.lists {
            rules += count_rules(text);
            let is_trusted = *id < CUSTOM_ID_START;
            let rest = extended.extract(text, is_trusted);
            set.add_filter_list(rest, if is_trusted { trusted.clone() } else { ParseOptions::default() });
        }
        if let Some(user) = &loaded.user_rules {
            rules += count_rules(user);
            let rest = extended.extract(user, true);
            set.add_filter_list(rest, trusted);
        }
        let mut engine = Engine::new_with_filter_set(set);
        engine.use_resources(loaded.resources.iter().cloned());
        Self { engine, extended, allowlist: loaded.allowlist.clone(), rules, lists: loaded.lists.len(), resources: loaded.resources.len() }
    }

    /// Allowlisted sites are not filtered at all (neither the page nor anything it loads).
    pub fn is_allowlisted(&self, page_url: &str) -> bool {
        let host = url_host(page_url).to_ascii_lowercase();
        self.allowlist.iter().any(|d| host == *d || host.ends_with(&format!(".{d}")))
    }

    pub fn check(&self, url: &str, source: &str, request_type: &str, method: &str) -> Verdict {
        if self.is_allowlisted(source) || self.is_allowlisted(url) {
            return Verdict::Allow;
        }
        let Ok(req) = Request::new(url, source, request_type, &method.to_ascii_lowercase()) else {
            return Verdict::Allow;
        };
        let res = self.engine.check_network_request(&req);
        let rule = res.filter.as_ref().and_then(|f| f.raw_line.clone());
        if res.should_block() {
            return Verdict::Block { rule, redirect: res.redirect };
        }
        if let Some(url) = res.rewritten_url {
            return Verdict::Rewrite { url, rule };
        }
        Verdict::Allow
    }

    /// Cosmetic resources for a page, including generic rules for the classes and ids already
    /// present in its HTML.
    pub fn cosmetics(&self, url: &str, classes: &HashSet<String>, ids: &HashSet<String>) -> Cosmetics {
        if self.is_allowlisted(url) {
            return Cosmetics { generichide: true, ..Default::default() };
        }
        let res = self.engine.url_cosmetic_resources(url);
        let mut selectors: Vec<String> = res.hide_selectors.into_iter().collect();
        if !res.generichide {
            selectors.extend(self.engine.hidden_class_id_selectors(classes, ids, &res.exceptions));
        }
        selectors.sort();
        selectors.dedup();
        let mut procedural: Vec<String> = res.procedural_actions.into_iter().collect();
        procedural.sort();
        Cosmetics { selectors, scriptlets: res.injected_script, procedural, generichide: res.generichide }
    }

    /// Extra Content-Security-Policy from `$csp` rules for a document or frame.
    pub fn csp(&self, url: &str, source: &str, request_type: &str) -> Option<String> {
        if self.is_allowlisted(source) || self.is_allowlisted(url) {
            return None;
        }
        let req = Request::new(url, source, request_type, "get").ok()?;
        self.engine.get_csp_directives(&req)
    }

    /// Generic hiding selectors for classes/ids that appeared after the page loaded.
    pub fn generic_selectors(&self, page_url: &str, classes: &[&str], ids: &[&str]) -> Vec<String> {
        if self.is_allowlisted(page_url) {
            return Vec::new();
        }
        let res = self.engine.url_cosmetic_resources(page_url);
        if res.generichide {
            return Vec::new();
        }
        self.engine.hidden_class_id_selectors(classes, ids, &res.exceptions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Loaded};
    use adblock::resources::{MimeType, Resource, ResourceType};

    fn resources() -> Vec<Resource> {
        let b64 = |s: &str| {
            // tiny base64 encoder for tests
            const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in s.as_bytes().chunks(3) {
                let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
                let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
                for i in 0..4 {
                    if i <= chunk.len() { out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char) } else { out.push('=') }
                }
            }
            out
        };
        vec![
            Resource {
                name: "set-constant.js".into(), aliases: vec!["set.js".into()],
                kind: ResourceType::Mime(MimeType::ApplicationJavascript),
                content: b64("function setConstant(a, b) { window[a] = b; }"), dependencies: vec![], permission: Default::default(),
            },
            Resource {
                name: "trusted-set-cookie.js".into(), aliases: vec![],
                kind: ResourceType::Mime(MimeType::ApplicationJavascript),
                content: b64("function trustedSetCookie(a) { document.cookie = a; }"), dependencies: vec![], permission: TRUSTED,
            },
            Resource {
                name: "noop.js".into(), aliases: vec!["noopjs".into()],
                kind: ResourceType::Mime(MimeType::ApplicationJavascript),
                content: b64("(function(){})();"), dependencies: vec![], permission: Default::default(),
            },
        ]
    }

    fn filter_with(lists: Vec<(i64, &str)>, allow: &[&str]) -> ContentFilter {
        ContentFilter::build(&Loaded {
            config: Config::default(),
            lists: lists.into_iter().map(|(id, t)| (id, t.to_string())).collect(),
            user_rules: None,
            allowlist: allow.iter().map(|s| s.to_string()).collect(),
            resources: resources(),
        })
    }

    fn filter(rules: &str, allow: &[&str]) -> ContentFilter {
        filter_with(vec![(1, rules)], allow)
    }

    #[test]
    fn network_rules() {
        let f = filter("||ads.example.com^\n||cdn.net/track.js$script,third-party\n@@||ads.example.com/ok.js", &[]);
        assert!(matches!(f.check("https://ads.example.com/x.js", "https://site.org/", "script", "GET"), Verdict::Block { .. }));
        assert!(matches!(f.check("https://ads.example.com/ok.js", "https://site.org/", "script", "GET"), Verdict::Allow));
        assert!(matches!(f.check("https://cdn.net/track.js", "https://site.org/", "script", "GET"), Verdict::Block { .. }));
        assert!(matches!(f.check("https://cdn.net/track.js", "https://cdn.net/", "script", "GET"), Verdict::Allow));
    }

    #[test]
    fn allowlist_disables_page_blocking() {
        let f = filter("||ads.example.com^\n##.ad", &["site.org"]);
        assert!(matches!(f.check("https://ads.example.com/x.js", "https://www.site.org/", "script", "GET"), Verdict::Allow));
        assert!(matches!(f.check("https://ads.example.com/x.js", "https://other.org/", "script", "GET"), Verdict::Block { .. }));
        assert!(f.cosmetics("https://site.org/", &["ad".to_string()].into(), &HashSet::new()).selectors.is_empty());
        assert_eq!(url_host("https://user@[::1]:8443/p"), "::1");
        assert_eq!(url_host("http://Example.com:80/x?y"), "Example.com");
    }

    #[test]
    fn removeparam_rewrites() {
        let f = filter("$removeparam=utm_source", &[]);
        match f.check("https://site.org/?utm_source=x&a=1", "https://site.org/", "document", "GET") {
            Verdict::Rewrite { url, .. } => assert_eq!(url, "https://site.org/?a=1"),
            _ => panic!("expected rewrite"),
        }
    }

    #[test]
    fn cosmetic_rules() {
        let f = filter("site.org##.banner\n##.ad-slot", &[]);
        let classes: HashSet<String> = ["ad-slot".to_string()].into();
        let c = f.cosmetics("https://site.org/", &classes, &HashSet::new());
        assert!(c.selectors.contains(&".banner".to_string()));
        assert!(c.selectors.contains(&".ad-slot".to_string()));
        assert_eq!(f.generic_selectors("https://site.org/", &["ad-slot"], &[]), vec![".ad-slot".to_string()]);
    }

    #[test]
    fn scriptlets_and_trust() {
        let f = filter_with(vec![(1, "site.org##+js(set, adsEnabled, false)\nsite.org##+js(trusted-set-cookie, a=1)"), (1001, "other.org##+js(trusted-set-cookie, a=1)")], &[]);
        let c = f.cosmetics("https://site.org/", &HashSet::new(), &HashSet::new());
        assert!(c.scriptlets.contains("setConstant(\"adsEnabled\", \"false\")"), "{}", c.scriptlets);
        assert!(c.scriptlets.contains("trustedSetCookie"), "built-in lists may use trusted scriptlets");
        let o = f.cosmetics("https://other.org/", &HashSet::new(), &HashSet::new());
        assert!(!o.scriptlets.contains("trustedSetCookie"), "custom lists must not use trusted scriptlets");
    }

    #[test]
    fn redirect_resources() {
        let f = filter("||ads.example.com/ad.js$script,redirect=noopjs", &[]);
        match f.check("https://ads.example.com/ad.js", "https://site.org/", "script", "GET") {
            Verdict::Block { redirect: Some(r), .. } => assert!(r.starts_with("data:application/javascript;base64,"), "{r}"),
            _ => panic!("expected a redirect"),
        }
    }

    #[test]
    fn csp_rules() {
        let f = filter("||site.org^$csp=script-src 'self'", &[]);
        assert_eq!(f.csp("https://site.org/", "https://site.org/", "document").as_deref(), Some("script-src 'self'"));
        assert!(f.csp("https://other.org/", "https://other.org/", "document").is_none());
    }

    #[test]
    fn adguard_syntax_reaches_both_engines() {
        let f = filter("site.org#%#//scriptlet('set-constant', 'adsOn', 'false')\nsite.org#$#.x { display: none !important; }", &[]);
        let c = f.cosmetics("https://site.org/", &HashSet::new(), &HashSet::new());
        assert!(c.scriptlets.contains("setConstant(\"adsOn\", \"false\")"), "{}", c.scriptlets);
        assert_eq!(f.extended.page("https://site.org/").css.len(), 1);
    }

    #[test]
    fn procedural_filters() {
        let f = filter("site.org##div.post:has-text(Sponsored)\nsite.org##.promo:remove()", &[]);
        let c = f.cosmetics("https://site.org/", &HashSet::new(), &HashSet::new());
        assert!(c.procedural.iter().any(|p| p.contains("has-text") && p.contains("Sponsored")), "{:?}", c.procedural);
        assert!(c.procedural.iter().any(|p| p.contains("\"remove\"")), "{:?}", c.procedural);
    }
}
