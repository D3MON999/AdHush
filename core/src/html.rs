//! HTML response helpers: decompression, class/id harvesting for generic cosmetic rules,
//! <style>/<script> injection and Content-Security-Policy nonce patching.
use std::collections::HashSet;
use std::io::Read;

const MAX_DECODED: u64 = 32 * 1024 * 1024;

pub fn decode(encoding: &str, data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let enc = encoding.trim().to_ascii_lowercase();
    let ok = match enc.as_str() {
        "" | "identity" => {
            out.extend_from_slice(data);
            true
        }
        "gzip" | "x-gzip" => flate2::read::GzDecoder::new(data).take(MAX_DECODED).read_to_end(&mut out).is_ok(),
        "deflate" => {
            flate2::read::ZlibDecoder::new(data).take(MAX_DECODED).read_to_end(&mut out).is_ok() || {
                out.clear();
                flate2::read::DeflateDecoder::new(data).take(MAX_DECODED).read_to_end(&mut out).is_ok()
            }
        }
        "br" => brotli::Decompressor::new(data, 4096).take(MAX_DECODED).read_to_end(&mut out).is_ok(),
        _ => false, // zstd and others: leave the response untouched
    };
    ok.then_some(out)
}

fn find_ci(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| hay[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

/// Collects class names and ids from attributes (bounded; good enough for generic hiding).
pub fn harvest_classes_ids(html: &[u8]) -> (HashSet<String>, HashSet<String>) {
    let mut classes = HashSet::new();
    let mut ids = HashSet::new();
    let limit = html.len().min(2 * 1024 * 1024);
    let hay = &html[..limit];
    for (attr, is_class) in [(&b"class="[..], true), (&b" id="[..], false)] {
        let mut pos = 0;
        while let Some(i) = find_ci(hay, attr, pos) {
            let start = i + attr.len();
            pos = start;
            let Some(&q) = hay.get(start) else { break };
            if q != b'"' && q != b'\'' {
                continue;
            }
            let Some(len) = hay[start + 1..].iter().position(|&c| c == q) else { break };
            if let Ok(value) = std::str::from_utf8(&hay[start + 1..start + 1 + len]) {
                for token in value.split_ascii_whitespace() {
                    if token.len() < 64 {
                        if is_class { classes.insert(token.to_string()) } else { ids.insert(token.to_string()) };
                    }
                }
            }
            if classes.len() + ids.len() > 5000 {
                return (classes, ids);
            }
        }
    }
    (classes, ids)
}

const RUNTIME: &str = include_str!("inject.js");

fn script_safe(js: &str) -> String {
    js.replace("</script", "<\\/script").replace("<!--", "<\\!--")
}

/// Everything injected into one page or frame.
#[derive(Default)]
pub struct Snippet<'a> {
    /// Element-hiding selectors.
    pub selectors: &'a [String],
    /// Raw CSS rules (`#$#`).
    pub css: &'a [String],
    /// Scripts that must run before page scripts (privacy API blocking, `#%#` rules).
    pub early_js: &'a [String],
    pub scriptlets: &'a str,
    pub procedural: &'a [String],
    /// Same-origin URL the runtime asks for selectors of late-added elements.
    pub endpoint: Option<&'a str>,
    pub nonce: &'a str,
}

impl Snippet<'_> {
    pub fn has_script(&self) -> bool {
        !self.early_js.is_empty() || !self.scriptlets.trim().is_empty() || !self.procedural.is_empty() || self.endpoint.is_some()
    }
}

/// `<style>` with hiding rules, early scripts, scriptlets, and the in-page runtime.
pub fn build_snippet(sn: &Snippet) -> Vec<u8> {
    let nonce = sn.nonce;
    let mut s = String::new();
    if !sn.early_js.is_empty() {
        s.push_str(&format!("<script nonce=\"{nonce}\" data-adhush>"));
        for js in sn.early_js {
            s.push_str(&format!("try{{{}\n}}catch(e){{}}\n", script_safe(js)));
        }
        s.push_str("</script>");
    }
    if !sn.selectors.is_empty() || !sn.css.is_empty() {
        s.push_str(&format!("<style nonce=\"{nonce}\" data-adhush>"));
        // One rule per selector: an invalid selector must not void the others.
        for sel in sn.selectors {
            if !sel.contains('<') && !sel.contains('{') {
                s.push_str(sel);
                s.push_str("{display:none!important}");
            }
        }
        for rule in sn.css {
            if !rule.contains("</") {
                s.push_str(rule);
                s.push('\n');
            }
        }
        s.push_str("</style>");
    }
    let (scriptlets, procedural, endpoint) = (sn.scriptlets, sn.procedural, sn.endpoint);
    if !scriptlets.trim().is_empty() {
        // uBlock Origin scriptlets share state through `scriptletGlobals`.
        s.push_str(&format!(
            "<script nonce=\"{nonce}\" data-adhush>(function(){{try{{const scriptletGlobals={{}};\n{}\n}}catch(e){{}}}})();</script>",
            script_safe(scriptlets)
        ));
    }
    if !procedural.is_empty() || endpoint.is_some() {
        let procedural: Vec<serde_json::Value> = procedural.iter().filter_map(|p| serde_json::from_str(p).ok()).collect();
        let cfg = serde_json::json!({ "p": procedural, "e": endpoint, "n": nonce });
        s.push_str(&format!(
            "<script nonce=\"{nonce}\" data-adhush>{}</script>",
            script_safe(&RUNTIME.replace("})(CFG);", &format!("}})({cfg});")))
        ));
    }
    s.into_bytes()
}

/// Inserts `snippet` right after the opening <head> (or <html>) tag. Returns false if neither exists.
pub fn inject(html: &mut Vec<u8>, snippet: &[u8]) -> bool {
    let at = find_ci(html, b"<head", 0)
        .or_else(|| find_ci(html, b"<html", 0))
        .and_then(|i| html[i..].iter().position(|&c| c == b'>').map(|p| i + p + 1));
    match at {
        Some(at) => {
            html.splice(at..at, snippet.iter().copied());
            true
        }
        None => false,
    }
}

/// Adds `'nonce-…'` to the directives governing inline styles/scripts so our snippet is allowed.
/// A directive that relies on 'unsafe-inline' alone is left as is (adding a nonce would disable
/// it); if it already has a nonce, hash or 'strict-dynamic', 'unsafe-inline' is ignored by
/// browsers anyway, so we must add ours.
pub fn patch_csp(csp: &str, nonce: &str, with_script: bool) -> String {
    let mut directives: Vec<String> = csp.split(';').map(|d| d.trim().to_string()).filter(|d| !d.is_empty()).collect();
    let has = |dirs: &Vec<String>, name: &str| dirs.iter().any(|d| d.split_whitespace().next() == Some(name));
    let mut targets = vec![if has(&directives, "style-src") { "style-src" } else { "default-src" }];
    if with_script {
        targets.push(if has(&directives, "script-src") { "script-src" } else { "default-src" });
    }
    for d in directives.iter_mut() {
        let name = d.split_whitespace().next().unwrap_or("").to_string();
        let inline_ignored = ["'nonce-", "'sha256-", "'sha384-", "'sha512-", "'strict-dynamic'"].iter().any(|t| d.contains(t));
        let needs_nonce = !d.contains("'unsafe-inline'") || inline_ignored;
        if targets.contains(&name.as_str()) && needs_nonce && !d.contains(&format!("'nonce-{nonce}'")) {
            d.push_str(&format!(" 'nonce-{nonce}'"));
        }
    }
    directives.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_after_head() {
        let mut html = b"<!doctype html><HTML><Head lang=x><title>t</title>".to_vec();
        assert!(inject(&mut html, b"<style></style>"));
        assert_eq!(String::from_utf8(html).unwrap(), "<!doctype html><HTML><Head lang=x><style></style><title>t</title>");
    }

    #[test]
    fn harvests() {
        let (c, i) = harvest_classes_ids(br#"<div class="a b" id='main'><p class=x>"#);
        assert!(c.contains("a") && c.contains("b") && i.contains("main"));
    }

    #[test]
    fn csp() {
        assert_eq!(patch_csp("default-src 'self'; img-src *", "n1", false), "default-src 'self' 'nonce-n1'; img-src *");
        assert_eq!(patch_csp("style-src 'unsafe-inline'", "n1", false), "style-src 'unsafe-inline'");
        // YouTube-style: 'unsafe-inline' is ignored next to a nonce / strict-dynamic, so ours is needed.
        assert_eq!(
            patch_csp("script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'; object-src 'none'", "n1", true),
            "script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic' 'nonce-n1'; object-src 'none'"
        );
        // A policy without script-src falls back to default-src for scripts.
        assert_eq!(patch_csp("require-trusted-types-for 'script'", "n1", true), "require-trusted-types-for 'script'");
    }

    #[test]
    fn gzip_roundtrip() {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(b"hello").unwrap();
        assert_eq!(decode("gzip", &e.finish().unwrap()).unwrap(), b"hello");
    }
}
