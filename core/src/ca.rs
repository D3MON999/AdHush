//! Local certificate authority: a per-install root CA (created once, kept in `<data>/ca`)
//! and on-the-fly leaf certificates for intercepted hosts, cached as ready rustls configs.
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use lru::LruCache;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

pub struct CertAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    pub ca_pem: String,
    pub ca_path: PathBuf,
    leaf_key: KeyPair,
    cache: Mutex<LruCache<String, Arc<ServerConfig>>>,
}

/// Restricts a secret file to SYSTEM, Administrators and the current user (best effort).
fn restrict_acl(path: &Path) {
    let mut args = vec![
        path.display().to_string(),
        "/inheritance:r".into(),
        "/grant:r".into(),
        "*S-1-5-18:F".into(),
        "*S-1-5-32-544:F".into(),
    ];
    if let (Ok(domain), Ok(user)) = (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        if !user.ends_with('$') {
            args.push(format!("{domain}\\{user}:F"));
        }
    }
    match std::process::Command::new("icacls").args(&args).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => log::warn!("icacls on {} failed: {}", path.display(), String::from_utf8_lossy(&out.stdout)),
        Err(e) => log::warn!("could not run icacls: {e}"),
    }
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    decode_base64(body.trim()).context("invalid PEM body")
}

fn decode_base64(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, c) in ALPHABET.iter().enumerate() {
        lookup[*c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = lookup[c as usize];
        if v == 255 {
            return None;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    decode_base64(s)
}

impl CertAuthority {
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let cert_path = dir.join("adhush-ca.pem");
        let key_path = dir.join("adhush-ca.key");
        let (ca_pem, key) = if cert_path.exists() && key_path.exists() {
            let key = KeyPair::from_pem(&fs::read_to_string(&key_path)?).context("reading CA key")?;
            (fs::read_to_string(&cert_path)?, key)
        } else {
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "AdHush Personal CA");
            dn.push(DnType::OrganizationName, "AdHush (this computer only)");
            params.distinguished_name = dn;
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
            let now = OffsetDateTime::now_utc();
            params.not_before = now - Duration::days(1);
            params.not_after = now + Duration::days(3650);
            let cert = params.self_signed(&key)?;
            let pem = cert.pem();
            fs::write(&key_path, key.serialize_pem())?;
            restrict_acl(&key_path);
            fs::write(&cert_path, &pem)?;
            log::info!("created new root CA at {}", cert_path.display());
            (pem, key)
        };
        let ca_der = CertificateDer::from(pem_to_der(&ca_pem)?);
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, key).context("loading CA certificate")?;
        Ok(Self {
            issuer,
            ca_der,
            ca_pem,
            ca_path: cert_path,
            leaf_key: KeyPair::generate()?,
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(2000).unwrap())),
        })
    }

    /// A TLS server config presenting a certificate for `host`, signed by our CA.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        if let Some(cfg) = self.cache.lock().unwrap().get(host) {
            return Ok(cfg.clone());
        }
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // ECDSA leaf keys: key encipherment does not apply (only RSA key exchange uses it).
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(30);
        let cert = params.signed_by(&self.leaf_key, &self.issuer)?;
        let chain = vec![cert.der().clone(), self.ca_der.clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder().with_no_client_auth().with_single_cert(chain, key)?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.cache.lock().unwrap().put(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}
