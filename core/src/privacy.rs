//! Tracking protection ("stealth mode"): request/response header rewriting, cookie lifetime
//! limits, tracking-parameter stripping and in-page browser API blocking.
use hyper::header::{HeaderMap, HeaderName, HeaderValue};

#[derive(Clone, Debug, Default)]
pub struct Privacy {
    pub hide_search_queries: bool,
    pub send_dnt: bool,
    pub remove_x_client_data: bool,
    pub strip_tracking_params: bool,
    /// None = untouched, Some(0) = blocked, Some(n) = expire after n minutes.
    pub third_party_cookie_minutes: Option<u64>,
    pub first_party_cookie_minutes: Option<u64>,
    pub hide_referrer: bool,
    pub custom_referrer: String,
    pub hide_user_agent: bool,
    pub custom_user_agent: String,
    pub mask_ip: bool,
    pub custom_ip: String,
    pub block_webrtc: bool,
    pub block_push_api: bool,
    pub block_location_api: bool,
    pub block_third_party_auth: bool,
    pub disable_third_party_cache: bool,
}

const GENERIC_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const HIGH_ENTROPY_HINTS: &[&str] = &[
    "sec-ch-ua-full-version", "sec-ch-ua-full-version-list", "sec-ch-ua-platform-version",
    "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-model", "sec-ch-ua-wow64", "sec-ch-ua-form-factors",
];
const SEARCH_ENGINES: &[&str] = &["google.", "bing.com", "duckduckgo.com", "yahoo.", "yandex.", "baidu.com", "ecosia.org", "startpage.com", "search.brave.com", "qwant.com"];

/// Query parameters that exist only to track clicks across sites.
const TRACKING_PARAMS: &[&str] = &[
    "fbclid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid", "msclkid", "yclid", "ysclid", "twclid", "ttclid",
    "mc_cid", "mc_eid", "_hsenc", "_hsmi", "__hssc", "__hstc", "__hsfp", "hsctatracking", "igshid", "igsh",
    "mkt_tok", "oly_anon_id", "oly_enc_id", "rb_clickid", "s_cid", "vero_conv", "vero_id", "wickedid",
    "_openstat", "epik", "srsltid", "pk_campaign", "pk_kwd", "pk_source", "pk_medium", "piwik_campaign",
    "piwik_kwd", "_gl", "trkcampaign",
];

/// Registrable domain ("eTLD+1"), e.g. news.bbc.co.uk → bbc.co.uk.
pub fn registrable(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&h).map(str::to_string).unwrap_or(h)
}

pub fn is_third_party(request_host: &str, page_host: &str) -> bool {
    !page_host.is_empty() && registrable(request_host) != registrable(page_host)
}

fn is_tracking_param(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.starts_with("utm_") || TRACKING_PARAMS.contains(&k.as_str())
}

/// Removes tracking parameters; returns the cleaned URL if anything changed.
pub fn strip_tracking_params(url: &str) -> Option<String> {
    let (main, fragment) = match url.split_once('#') {
        Some((m, f)) => (m, Some(f)),
        None => (url, None),
    };
    let (base, query) = main.split_once('?')?;
    let kept: Vec<&str> = query
        .split('&')
        .filter(|kv| !kv.is_empty() && !is_tracking_param(kv.split('=').next().unwrap_or("")))
        .collect();
    if kept.len() == query.split('&').filter(|kv| !kv.is_empty()).count() {
        return None;
    }
    let mut out = base.to_string();
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    Some(out)
}

fn header_host(value: &str) -> &str {
    crate::filter::url_host(value)
}

/// A stable random-looking public IPv4 address for "mask IP" when no custom value is set.
fn masked_ip() -> &'static str {
    static IP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    IP.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(std::process::id() as u64);
        let r = h.finish();
        // Avoid private/reserved ranges by picking from a few large public /8 blocks.
        let first = [23u8, 45, 62, 81, 91, 109, 151, 185, 193, 212][(r % 10) as usize];
        format!("{first}.{}.{}.{}", (r >> 8) as u8, (r >> 16) as u8, ((r >> 24) as u8).max(1))
    })
}

fn set(h: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        h.insert(HeaderName::from_static(name), v);
    }
}

impl Privacy {
    fn cookie_minutes(&self, third_party: bool) -> Option<u64> {
        if third_party { self.third_party_cookie_minutes } else { self.first_party_cookie_minutes }
    }

    pub fn apply_request(&self, h: &mut HeaderMap, request_host: &str, third_party: bool) {
        if self.send_dnt {
            set(h, "dnt", "1");
            set(h, "sec-gpc", "1");
        }
        if self.remove_x_client_data {
            h.remove("x-client-data");
        }
        let referer = h.get("referer").and_then(|v| v.to_str().ok()).map(str::to_string);
        if let Some(r) = referer {
            let rhost = header_host(&r).to_ascii_lowercase();
            let cross_site = registrable(&rhost) != registrable(request_host);
            if self.hide_search_queries && cross_site && SEARCH_ENGINES.iter().any(|s| rhost.contains(s)) {
                h.remove("referer");
            } else if self.hide_referrer && third_party {
                if self.custom_referrer.trim().is_empty() {
                    h.remove("referer");
                } else {
                    set(h, "referer", self.custom_referrer.trim());
                }
            }
        }
        if self.hide_user_agent {
            let ua = if self.custom_user_agent.trim().is_empty() { GENERIC_UA } else { self.custom_user_agent.trim() };
            set(h, "user-agent", ua);
            for name in HIGH_ENTROPY_HINTS {
                h.remove(*name);
            }
        }
        if self.mask_ip {
            let ip = if self.custom_ip.trim().is_empty() { masked_ip() } else { self.custom_ip.trim() };
            set(h, "x-forwarded-for", ip);
            set(h, "x-real-ip", ip);
        }
        if third_party && self.block_third_party_auth {
            h.remove("authorization");
        }
        if third_party && self.disable_third_party_cache {
            h.remove("if-none-match");
            h.remove("if-modified-since");
            set(h, "cache-control", "no-cache");
        }
        if self.cookie_minutes(third_party) == Some(0) {
            h.remove("cookie");
        }
    }

    pub fn apply_response(&self, h: &mut HeaderMap, third_party: bool) {
        match self.cookie_minutes(third_party) {
            Some(0) => {
                h.remove("set-cookie");
            }
            Some(minutes) => {
                let rewritten: Vec<HeaderValue> = h
                    .get_all("set-cookie")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .filter_map(|v| HeaderValue::from_str(&limit_cookie_lifetime(v, minutes * 60)).ok())
                    .collect();
                h.remove("set-cookie");
                for v in rewritten {
                    h.append("set-cookie", v);
                }
            }
            None => {}
        }
        if third_party && self.disable_third_party_cache {
            h.remove("etag");
            h.remove("last-modified");
            set(h, "cache-control", "no-store");
        }
    }

    /// JavaScript run first in every filtered page/frame to block browser APIs.
    pub fn page_script(&self) -> String {
        let mut js = String::new();
        if self.send_dnt {
            js.push_str("try{Object.defineProperty(Navigator.prototype,'doNotTrack',{get(){return '1'}});Object.defineProperty(Navigator.prototype,'globalPrivacyControl',{get(){return true}});}catch(e){}\n");
        }
        if self.block_webrtc {
            js.push_str("for(const n of ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','RTCSessionDescription','RTCIceCandidate']){try{Object.defineProperty(window,n,{value:undefined,writable:false,configurable:false});}catch(e){}}\n");
        }
        if self.block_push_api {
            js.push_str("try{Object.defineProperty(window,'PushManager',{value:undefined});if(window.ServiceWorkerRegistration)Object.defineProperty(ServiceWorkerRegistration.prototype,'pushManager',{get(){return undefined}});if(window.Notification){Object.defineProperty(Notification,'permission',{get(){return 'denied'}});Notification.requestPermission=()=>Promise.resolve('denied');}}catch(e){}\n");
        }
        if self.block_location_api {
            js.push_str("try{if(navigator.geolocation){const d=(s,e)=>{e&&setTimeout(()=>e({code:1,PERMISSION_DENIED:1,message:'User denied Geolocation'}),0);return 0};navigator.geolocation.getCurrentPosition=d;navigator.geolocation.watchPosition=d;}}catch(e){}\n");
        }
        js
    }
}

/// Replaces Expires/Max-Age with a Max-Age of at most `seconds`.
pub fn limit_cookie_lifetime(set_cookie: &str, seconds: u64) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for (i, part) in set_cookie.split(';').enumerate() {
        let name = part.trim().split('=').next().unwrap_or("").to_ascii_lowercase();
        if i > 0 && (name == "expires" || name == "max-age") {
            continue;
        }
        parts.push(part.trim());
    }
    format!("{}; Max-Age={seconds}", parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn third_party_by_registrable_domain() {
        assert_eq!(registrable("news.bbc.co.uk"), "bbc.co.uk");
        assert!(!is_third_party("static.bbc.co.uk", "www.bbc.co.uk"));
        assert!(is_third_party("www.google-analytics.com", "www.bbc.co.uk"));
    }

    #[test]
    fn strips_tracking_params() {
        assert_eq!(strip_tracking_params("https://a.com/p?utm_source=x&id=5&fbclid=y#top").as_deref(), Some("https://a.com/p?id=5#top"));
        assert_eq!(strip_tracking_params("https://a.com/p?gclid=1").as_deref(), Some("https://a.com/p"));
        assert_eq!(strip_tracking_params("https://a.com/p?id=5"), None);
    }

    #[test]
    fn cookie_lifetime() {
        assert_eq!(limit_cookie_lifetime("id=1; Path=/; Expires=Wed, 21 Oct 2099 07:28:00 GMT; HttpOnly", 600), "id=1; Path=/; HttpOnly; Max-Age=600");
    }

    #[test]
    fn request_rewriting() {
        let p = Privacy { send_dnt: true, remove_x_client_data: true, hide_search_queries: true, hide_referrer: true, block_third_party_auth: true, third_party_cookie_minutes: Some(0), ..Default::default() };
        let mut h = HeaderMap::new();
        h.insert("x-client-data", HeaderValue::from_static("abc"));
        h.insert("referer", HeaderValue::from_static("https://www.google.com/search?q=secret"));
        h.insert("cookie", HeaderValue::from_static("a=1"));
        h.insert("authorization", HeaderValue::from_static("Bearer x"));
        p.apply_request(&mut h, "tracker.net", true);
        assert_eq!(h.get("dnt").unwrap(), "1");
        assert!(h.get("x-client-data").is_none() && h.get("referer").is_none() && h.get("cookie").is_none() && h.get("authorization").is_none());

        let mut first = HeaderMap::new();
        first.insert("referer", HeaderValue::from_static("https://site.org/page"));
        first.insert("cookie", HeaderValue::from_static("a=1"));
        p.apply_request(&mut first, "cdn.site.org", false);
        assert!(first.get("referer").is_some() && first.get("cookie").is_some(), "first-party requests keep referer and cookies");
    }

    #[test]
    fn response_cookie_limits() {
        let p = Privacy { third_party_cookie_minutes: Some(10), disable_third_party_cache: true, ..Default::default() };
        let mut h = HeaderMap::new();
        h.append("set-cookie", HeaderValue::from_static("a=1; Max-Age=31536000"));
        h.append("set-cookie", HeaderValue::from_static("b=2"));
        h.insert("etag", HeaderValue::from_static("\"x\""));
        p.apply_response(&mut h, true);
        let cookies: Vec<_> = h.get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_string()).collect();
        assert_eq!(cookies, vec!["a=1; Max-Age=600", "b=2; Max-Age=600"]);
        assert!(h.get("etag").is_none());
    }
}
