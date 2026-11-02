//! Userscripts and userstyles managed by the Node service (<data>/userscripts): URL matching,
//! the GM API wrapper injected into pages, persisted GM values and GM_xmlhttpRequest checks.
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use regex::Regex;
use serde_json::{Map, Value};

use crate::filter::url_host;

enum Cond {
    Url(String),
    Prefix(String),
    Domain(String),
    Regexp(Regex),
}

struct Style {
    sections: Vec<(Vec<Cond>, String)>,
}

pub struct Script {
    pub id: String,
    pub name: String,
    version: String,
    namespace: String,
    description: String,
    include: Vec<Regex>,
    exclude: Vec<Regex>,
    run_at: String,
    noframes: bool,
    connects: Vec<String>,
    code: String,
}

#[derive(Default)]
pub struct UserScripts {
    scripts: Vec<Script>,
    styles: Vec<Style>,
    values: Mutex<HashMap<String, Map<String, Value>>>,
    dir: PathBuf,
    pub detect_install: bool,
    pub ui_port: u16,
}

fn escape_except_star(s: &str) -> String {
    s.split('*').map(regex::escape).collect::<Vec<_>>().join(".*")
}

/// Chrome-style match pattern (`*://*.example.com/path*`, `<all_urls>`) to a regex.
pub fn match_pattern(p: &str) -> Option<Regex> {
    if p == "<all_urls>" {
        return Regex::new(r"^(https?|file)://").ok();
    }
    let (scheme, rest) = p.split_once("://")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/*"),
    };
    let scheme = match scheme {
        "*" => "https?".to_string(),
        "http" | "https" | "file" => scheme.to_string(),
        _ => return None,
    };
    let host = if host == "*" {
        "[^/]*".to_string()
    } else if let Some(h) = host.strip_prefix("*.") {
        format!(r"(?:[^/]*\.)?{}", regex::escape(h))
    } else {
        regex::escape(host)
    };
    Regex::new(&format!("^{scheme}://{host}(?::\\d+)?{}$", escape_except_star(path))).ok()
}

/// Greasemonkey @include/@exclude: glob with `*`, or `/regex/`.
pub fn include_pattern(p: &str) -> Option<Regex> {
    if p.len() > 2 && p.starts_with('/') && p.ends_with('/') {
        return Regex::new(&format!("(?i){}", &p[1..p.len() - 1])).ok();
    }
    if p == "*" {
        return Regex::new("^.*$").ok();
    }
    Regex::new(&format!("(?i)^{}$", escape_except_star(p).replace(r"\.tld", r"\.[a-z.]{2,}"))).ok()
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()
}

fn is_private(host: &str) -> bool {
    match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified(),
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80,
        Err(_) => host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local"),
    }
}

impl UserScripts {
    pub fn load(data_dir: &Path) -> Self {
        let dir = data_dir.join("userscripts");
        let settings: Value = fs::read_to_string(data_dir.join("settings.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
        let ext = &settings["extensions"];
        let mut out = UserScripts {
            dir: dir.clone(),
            detect_install: ext["detectInstall"].as_bool().unwrap_or(true),
            ui_port: settings["api"]["port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(8899),
            ..Default::default()
        };
        if !ext["enabled"].as_bool().unwrap_or(true) {
            return out;
        }
        let index: Value = fs::read_to_string(dir.join("index.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
        for item in index["items"].as_array().into_iter().flatten() {
            if !item["enabled"].as_bool().unwrap_or(false) {
                continue;
            }
            let Some(id) = item["id"].as_str().filter(|i| i.chars().all(|c| c.is_ascii_alphanumeric())) else { continue };
            if item["type"].as_str() == Some("style") {
                let sections = item["sections"].as_array().into_iter().flatten().filter_map(|s| {
                    let conds = s["conditions"].as_array().into_iter().flatten().filter_map(|c| {
                        let v = c["value"].as_str()?.to_string();
                        Some(match c["type"].as_str()? {
                            "url" => Cond::Url(v),
                            "url-prefix" => Cond::Prefix(v),
                            "domain" => Cond::Domain(v.to_ascii_lowercase()),
                            "regexp" => Cond::Regexp(Regex::new(&format!("^(?:{v})$")).ok()?),
                            _ => return None,
                        })
                    }).collect();
                    Some((conds, s["css"].as_str()?.to_string()))
                }).collect();
                out.styles.push(Style { sections });
                continue;
            }
            let read = |kind: &str| fs::read_to_string(dir.join(format!("{id}.{kind}"))).unwrap_or_default();
            let mut include: Vec<Regex> = strs(&item["matches"]).iter().filter_map(|p| match_pattern(p)).collect();
            include.extend(strs(&item["includes"]).iter().filter_map(|p| include_pattern(p)));
            let mut exclude: Vec<Regex> = strs(&item["excludes"]).iter().filter_map(|p| include_pattern(p)).collect();
            exclude.extend(strs(&item["excludeMatches"]).iter().filter_map(|p| match_pattern(p)));
            let s = |k: &str| item[k].as_str().unwrap_or("").to_string();
            out.scripts.push(Script {
                id: id.to_string(),
                name: s("name"),
                version: s("version"),
                namespace: s("namespace"),
                description: s("description"),
                include,
                exclude,
                run_at: s("runAt"),
                noframes: item["noframes"].as_bool().unwrap_or(false),
                connects: strs(&item["connects"]).into_iter().map(|c| c.to_ascii_lowercase()).collect(),
                code: format!("{}\n;\n{}", read("require.js"), read("user.js")),
            });
            let values: Map<String, Value> = fs::read_to_string(dir.join("values").join(format!("{id}.json")))
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default();
            out.values.lock().unwrap().insert(id.to_string(), values);
        }
        out
    }

    pub fn count(&self) -> usize {
        self.scripts.len() + self.styles.len()
    }

    fn script_matches(s: &Script, url: &str) -> bool {
        s.include.iter().any(|r| r.is_match(url)) && !s.exclude.iter().any(|r| r.is_match(url))
    }

    pub fn styles_for(&self, url: &str) -> Vec<String> {
        let host = url_host(url).to_ascii_lowercase();
        let applies = |c: &Cond| match c {
            Cond::Url(u) => url == u,
            Cond::Prefix(p) => url.starts_with(p.as_str()),
            Cond::Domain(d) => host == *d || host.ends_with(&format!(".{d}")),
            Cond::Regexp(r) => r.is_match(url),
        };
        self.styles
            .iter()
            .flat_map(|s| s.sections.iter())
            .filter(|(conds, _)| conds.is_empty() || conds.iter().any(applies))
            .map(|(_, css)| css.clone())
            .collect()
    }

    /// Wrapped code for every enabled script matching `url`.
    pub fn scripts_for(&self, url: &str, top_frame: bool, nonce: &str) -> Vec<String> {
        self.scripts
            .iter()
            .filter(|s| (top_frame || !s.noframes) && Self::script_matches(s, url))
            .map(|s| self.wrap(s, nonce))
            .collect()
    }

    fn wrap(&self, s: &Script, nonce: &str) -> String {
        let values = self.values.lock().unwrap().get(&s.id).cloned().unwrap_or_default();
        let info = serde_json::json!({
            "script": { "name": s.name, "version": s.version, "namespace": s.namespace, "description": s.description },
            "scriptHandler": "AdHush", "version": env!("CARGO_PKG_VERSION"),
        });
        let run = match s.run_at.as_str() {
            "document-start" => "__run();",
            "document-end" | "document-body" => "if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',__run,{once:true});else __run();",
            _ => "if(document.readyState==='complete')setTimeout(__run,0);else window.addEventListener('load',()=>setTimeout(__run,0),{once:true});",
        };
        let mut out = String::with_capacity(s.code.len() + 4096);
        out.push_str("(function(){\n");
        out.push_str(&format!("const __id={};const __values={};const __nonce={};const GM_info={};\n",
            serde_json::json!(s.id), Value::Object(values), serde_json::json!(nonce), info));
        out.push_str(GM_API);
        out.push_str("const __run=()=>{try{\n");
        out.push_str(&s.code);
        out.push_str("\n}catch(e){console.error('[AdHush userscript '+GM_info.script.name+']',e)}};\n");
        out.push_str(run);
        out.push_str("\n})();");
        out
    }

    pub fn set_value(&self, id: &str, op: &str, key: &str, value: Value) -> bool {
        let mut all = self.values.lock().unwrap();
        let Some(values) = all.get_mut(id) else { return false };
        match op {
            "set" => {
                values.insert(key.to_string(), value);
            }
            "delete" => {
                values.remove(key);
            }
            _ => return false,
        }
        let dir = self.dir.join("values");
        let _ = fs::create_dir_all(&dir);
        let _ = fs::write(dir.join(format!("{id}.json")), Value::Object(values.clone()).to_string());
        true
    }

    /// Validates a GM_xmlhttpRequest: the script must run on `page_url` and be allowed to reach
    /// `target` (declared @connect host, or the page's own host), never private addresses.
    pub fn check_xhr(&self, id: &str, page_url: &str, target: &str) -> Result<(), String> {
        let s = self.scripts.iter().find(|s| s.id == id).ok_or("unknown or disabled script")?;
        if !Self::script_matches(s, page_url) {
            return Err("script does not run on this page".into());
        }
        if !(target.starts_with("http://") || target.starts_with("https://")) {
            return Err("only http(s) requests are allowed".into());
        }
        let host = url_host(target).to_ascii_lowercase();
        if host.is_empty() || is_private(&host) {
            return Err("requests to local or private addresses are not allowed".into());
        }
        let page_host = url_host(page_url).to_ascii_lowercase();
        let allowed = host == page_host
            || s.connects.iter().any(|c| c == "*" || (c == "self" && host == page_host) || host == *c || host.ends_with(&format!(".{c}")));
        if allowed { Ok(()) } else { Err(format!("{host} is not declared with @connect")) }
    }
}

/// GM_* / GM.* API available inside every userscript wrapper.
const GM_API: &str = r#"const __post=(p,b)=>fetch('/__adhush__/'+p+'/'+__id,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b),credentials:'omit'});
const GM_getValue=(k,d)=>Object.prototype.hasOwnProperty.call(__values,k)?__values[k]:d;
const GM_setValue=(k,v)=>{__values[k]=v;__post('gm',{op:'set',key:k,value:v}).catch(()=>{})};
const GM_deleteValue=k=>{delete __values[k];__post('gm',{op:'delete',key:k}).catch(()=>{})};
const GM_listValues=()=>Object.keys(__values);
const GM_addStyle=css=>{const s=document.createElement('style');s.setAttribute('nonce',__nonce);s.textContent=css;(document.head||document.documentElement).appendChild(s);return s};
const GM_xmlhttpRequest=d=>{const ctl={abort(){ctl.aborted=true}};const url=new URL(d.url,location.href).href;
__post('xhr',{page:location.href,url,method:d.method||'GET',headers:d.headers||{},data:typeof d.data==='string'?d.data:(d.data==null?null:JSON.stringify(d.data))})
.then(r=>r.json()).then(r=>{if(ctl.aborted)return;if(r.error){d.onerror&&d.onerror({error:r.error,status:0});return}
const resp={status:r.status,statusText:r.statusText,finalUrl:r.finalUrl,responseHeaders:r.responseHeaders,responseText:r.responseText,readyState:4,context:d.context};
if(d.responseType==='json'){try{resp.response=JSON.parse(r.responseText)}catch(e){resp.response=null}}else resp.response=r.responseText;
d.onreadystatechange&&d.onreadystatechange(resp);d.onload&&d.onload(resp);d.onloadend&&d.onloadend(resp)})
.catch(e=>{d.onerror&&d.onerror({error:String(e),status:0})});return ctl};
const GM_openInTab=u=>window.open(u,'_blank');
const GM_setClipboard=t=>{try{navigator.clipboard.writeText(String(t))}catch(e){}};
const GM_notification=t=>console.info('[userscript]',typeof t==='string'?t:(t&&t.text));
const GM_registerMenuCommand=()=>0,GM_unregisterMenuCommand=()=>{},GM_getResourceText=()=>null,GM_getResourceURL=()=>null,GM_log=console.log.bind(console);
const unsafeWindow=window;
const GM={info:GM_info,getValue:async(k,d)=>GM_getValue(k,d),setValue:async(k,v)=>GM_setValue(k,v),deleteValue:async k=>GM_deleteValue(k),listValues:async()=>GM_listValues(),addStyle:async c=>GM_addStyle(c),xmlHttpRequest:GM_xmlhttpRequest,openInTab:GM_openInTab,setClipboard:GM_setClipboard,notification:GM_notification,registerMenuCommand:GM_registerMenuCommand,getResourceUrl:async()=>null};
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_patterns() {
        let r = match_pattern("*://*.example.com/*").unwrap();
        assert!(r.is_match("https://www.example.com/a") && r.is_match("http://example.com/") && !r.is_match("https://evil.com/?example.com"));
        let p = match_pattern("https://site.org/watch*").unwrap();
        assert!(p.is_match("https://site.org/watch?v=1") && !p.is_match("https://site.org/home"));
        assert!(include_pattern("http*://*.google.tld/*").unwrap().is_match("https://www.google.co.uk/search"));
        assert!(include_pattern("/^https:\\/\\/a\\.com/").unwrap().is_match("https://a.com/x"));
    }

    fn fixture() -> (tempdir::Dir, UserScripts) {
        let dir = tempdir::Dir::new();
        let us = dir.path().join("userscripts");
        fs::create_dir_all(&us).unwrap();
        fs::write(us.join("abc123.user.js"), "window.hello = GM_getValue('k', 0);").unwrap();
        fs::write(us.join("abc123.require.js"), "").unwrap();
        fs::write(us.join("index.json"), serde_json::json!({"items": [
            {"id": "abc123", "type": "script", "enabled": true, "name": "Test", "matches": ["https://site.org/*"], "includes": [], "excludes": ["*://site.org/private*"], "excludeMatches": [], "runAt": "document-end", "connects": ["api.example.com"], "noframes": true},
            {"id": "sty1", "type": "style", "enabled": true, "name": "Dark", "sections": [{"conditions": [{"type": "domain", "value": "site.org"}], "css": "body{background:#000}"}, {"conditions": [], "css": "a{color:red}"}]},
            {"id": "off1", "type": "script", "enabled": false, "name": "Off", "matches": ["*://*/*"]}
        ]}).to_string()).unwrap();
        fs::write(dir.path().join("settings.json"), "{}").unwrap();
        let loaded = UserScripts::load(dir.path());
        (dir, loaded)
    }

    #[test]
    fn injection_selection() {
        let (_d, u) = fixture();
        assert_eq!(u.count(), 2);
        let js = u.scripts_for("https://site.org/page", true, "n1");
        assert_eq!(js.len(), 1);
        assert!(js[0].contains("window.hello = GM_getValue") && js[0].contains("DOMContentLoaded"));
        assert!(u.scripts_for("https://site.org/private/x", true, "n1").is_empty(), "excluded");
        assert!(u.scripts_for("https://site.org/page", false, "n1").is_empty(), "@noframes");
        assert_eq!(u.styles_for("https://www.site.org/"), vec!["body{background:#000}", "a{color:red}"]);
        assert_eq!(u.styles_for("https://other.org/"), vec!["a{color:red}"]);
    }

    #[test]
    fn values_and_xhr_rules() {
        let (_d, u) = fixture();
        assert!(u.set_value("abc123", "set", "k", serde_json::json!(5)));
        assert!(u.scripts_for("https://site.org/", true, "n")[0].contains("\"k\":5"));
        assert!(!u.set_value("nope", "set", "k", serde_json::json!(1)));
        assert!(u.check_xhr("abc123", "https://site.org/a", "https://api.example.com/v1").is_ok());
        assert!(u.check_xhr("abc123", "https://site.org/a", "https://site.org/data").is_ok(), "same host is always allowed");
        assert!(u.check_xhr("abc123", "https://site.org/a", "https://evil.com/").is_err());
        assert!(u.check_xhr("abc123", "https://site.org/a", "http://192.168.1.1/").is_err());
        assert!(u.check_xhr("abc123", "https://other.org/", "https://api.example.com/").is_err(), "page not matched");
    }

    /// Minimal self-cleaning temp dir (no extra dependency).
    mod tempdir {
        pub struct Dir(std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let p = std::env::temp_dir().join(format!("adhush-us-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
            pub fn path(&self) -> &std::path::Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
