//! Phase 2 fingerprinting probe (`ftw probe`) for authorized ranges only.
//!
//! Input is Phase 1 output ONLY: `scan_results` rows marked `open` in the
//! master database by a prior `ftw scan --db` run. Closed and filtered ports
//! are never re-probed, the original YAML targets file is never re-expanded,
//! and no port absent from the database is ever probed.
//!
//! One pass per open port, exactly the requests listed below — no 404
//! probing, no OPTIONS requests, no HEAD-vs-GET comparisons, no ETag
//! differentials, and no crawling of linked sitemap URLs:
//!
//! * Scheme is fixed by port: 443 → `https`, 80 → `http`, every other port
//!   defaults to `http`.
//! * A single `GET /` with the configured timeout; at most `body_cap` bytes
//!   (default 32 KiB) are read. Full pages are never downloaded.
//! * From that single response: final URL after redirects, HTTP status,
//!   `Server` header, `Set-Cookie` names only (values are never stored),
//!   `X-Generator`, `Via`, page `<title>`, `<meta name="generator">`, and
//!   script/style URLs whose paths indicate a stack (`wp-content`,
//!   `wp-includes`, theme/plugin paths, ...).
//! * TLS (https only): peer certificate CN, SAN list, issuer, and not-after
//!   date, captured from the handshake for the same host:port in the same
//!   pass. No separate TLS-only port probe is made.
//! * `GET /favicon.ico`: on a 200 response the SHA-256 hash of the bytes is
//!   stored; the binary itself is never stored.
//! * `GET /robots.txt` and `GET /sitemap.xml`, capped at 16 KiB each:
//!   presence, status, and truncated content. Sitemap URLs are not followed.
//! * Confidence is a simple count of independent agreeing signals — a single
//!   header is never presented as definitive proof of a stack.
//! * Patch status is NEVER inferred from a remote version string: any remote
//!   version is recorded as a hint only, and `patch_status` stays
//!   `unknown_from_remote` unless a [`HostCheckSummary`] merged from
//!   `ftw host-check` output says otherwise for the same host.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use tokio::sync::{Semaphore, mpsc};

use crate::fingerprint::classify_error;
use crate::output;

/// Default per-request timeout (2 s) when no `--timeout` is given.
pub const DEFAULT_TIMEOUT_SECS: f64 = 2.0;

/// Default cap for the `GET /` body: 32 KiB. Full pages are never fetched.
pub const DEFAULT_BODY_CAP: usize = 32 * 1024;

/// Cap for each of `/robots.txt` and `/sitemap.xml`: 16 KiB.
pub const AUX_BODY_CAP: usize = 16 * 1024;

/// Cap for `/favicon.ico` bytes before hashing: 256 KiB. Only the SHA-256
/// hex digest is stored, never the binary.
pub const FAVICON_CAP: usize = 256 * 1024;

/// Maximum redirects followed per probe request.
pub const MAX_REDIRECTS: usize = 5;

/// `patch_status` when no host-check record exists for the host: remote
/// version strings are hints only, never patch evidence.
pub const PATCH_UNKNOWN_FROM_REMOTE: &str = "unknown_from_remote";

/// `patch_status` when a `ftw host-check` record (authoritative on-host
/// package data) was merged for the same host.
pub const PATCH_AUTHORITATIVE_HOST_CHECK: &str = "authoritative_host_check";

const CHANNEL_CAPACITY: usize = 1024;

/// Runtime settings for a probe run.
#[derive(Debug, Clone, Copy)]
pub struct ProbeConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    pub insecure: bool,
    pub body_cap: usize,
}

/// Authoritative on-host patch data merged from `ftw host-check` JSONL by
/// host string. The full verbatim record lives in the host-check output;
/// only the fields needed to qualify `patch_status` travel with the probe.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostCheckSummary {
    pub host: String,
    pub php_version: Option<String>,
    pub package_count: usize,
}

/// One JSON-lines probe record: exactly one per open port probed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProbeRecord {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub status: Option<u16>,
    pub final_url: String,
    pub server: Option<String>,
    /// `Set-Cookie` cookie NAMES only, sorted and deduped. Values are never
    /// stored.
    pub cookie_names: Vec<String>,
    /// First `X-Generator` response header value, if any.
    pub x_generator: Option<String>,
    pub via: Option<String>,
    /// `<meta name="generator" content="...">`, if any.
    pub generator: Option<String>,
    pub title: Option<String>,
    /// Script/style URLs whose paths indicate a stack (`wp-content`, ...).
    pub asset_hints: Vec<String>,
    /// TLS peer certificate fields (https only; `None`/empty for http).
    pub tls_cn: Option<String>,
    pub tls_san: Vec<String>,
    pub tls_issuer: Option<String>,
    pub tls_not_after: Option<String>,
    /// SHA-256 hex of `/favicon.ico` bytes when it returned 200.
    pub favicon_sha256: Option<String>,
    pub robots_present: bool,
    pub robots_status: Option<u16>,
    pub robots_snippet: String,
    pub robots_truncated: bool,
    pub sitemap_present: bool,
    pub sitemap_status: Option<u16>,
    pub sitemap_snippet: String,
    pub sitemap_truncated: bool,
    /// `high` (3+ independent signals agree), `medium` (2), `low` (1), or
    /// `none` (0). A single header is never definitive.
    pub confidence: String,
    pub confidence_signals: Vec<String>,
    /// Best-guess stack from the agreeing signals, if any.
    pub stack_hint: Option<String>,
    /// A remote version string, if seen — a hint only, never patch evidence.
    pub remote_version_hint: Option<String>,
    pub patch_status: String,
    pub host_check: Option<HostCheckSummary>,
    /// `None` exactly when an HTTP status was received.
    pub error: Option<String>,
}

/// Aggregate counts for one probe run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProbeStats {
    pub total: usize,
    pub ok: usize,
    pub errors: usize,
    pub favicon_hashed: usize,
    pub robots_found: usize,
    pub sitemap_found: usize,
    pub authoritative_patch: usize,
}

impl ProbeStats {
    pub(crate) fn record(&mut self, record: &ProbeRecord) {
        self.total += 1;
        if record.error.is_none() {
            self.ok += 1;
        } else {
            self.errors += 1;
        }
        if record.favicon_sha256.is_some() {
            self.favicon_hashed += 1;
        }
        if record.robots_present {
            self.robots_found += 1;
        }
        if record.sitemap_present {
            self.sitemap_found += 1;
        }
        if record.patch_status == PATCH_AUTHORITATIVE_HOST_CHECK {
            self.authoritative_patch += 1;
        }
    }
}

/// One stderr summary line for a probe run. Kept as a function so tests can
/// assert the exact tokens without spawning the binary.
#[must_use]
pub fn format_summary(stats: &ProbeStats) -> String {
    format!(
        "ftw: probed {} open ports: {} ok, {} errors; favicon hashed on {}, robots.txt on {}, sitemap.xml on {}; authoritative patch status on {}",
        stats.total,
        stats.ok,
        stats.errors,
        stats.favicon_hashed,
        stats.robots_found,
        stats.sitemap_found,
        stats.authoritative_patch,
    )
}

/// Scheme for one open port: 443 uses https, 80 uses http, every other port
/// defaults to http.
#[must_use]
pub fn scheme_for_port(port: u16) -> &'static str {
    match port {
        443 => "https",
        80 => "http",
        _ => "http",
    }
}

/// `Set-Cookie` names only: the value before the first `=` of the
/// cookie-pair (text before the first `;`), trimmed. Values, attributes,
/// and empty names are dropped. Sorted and deduped.
#[must_use]
pub fn cookie_names(headers: &HeaderMap) -> Vec<String> {
    let mut names: Vec<String> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split('=').next())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// First response header value for `name`, if present and visible as text.
fn first_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// True when `text` contains a version-like token (`major.minor` with an
/// optional `.patch`): `8.2`, `8.2.0`, `6.5.2`. No regex crate needed.
fn contains_version(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let mut dots = 0;
            while j < bytes.len() && bytes[j] == b'.' {
                let mut k = j + 1;
                while k < bytes.len() && bytes[k].is_ascii_digit() {
                    k += 1;
                }
                if k == j + 1 {
                    break;
                }
                dots += 1;
                j = k;
            }
            if dots >= 1 {
                return true;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}

/// Remote version HINT: the first raw `X-Powered-By`, `Server`, or generator
/// value containing a version-like token. The raw string is kept so it is
/// obviously a hint, never patch evidence.
fn remote_version_hint(
    x_powered_by: Option<&str>,
    server: Option<&str>,
    generator: Option<&str>,
) -> Option<String> {
    [x_powered_by, server, generator]
        .into_iter()
        .flatten()
        .find(|value| contains_version(value))
        .map(str::to_owned)
}

/// Lowercased stack indicators matched against script/style URLs. Each entry
/// maps a path fragment to the stack it indicates.
const ASSET_STACKS: &[(&str, &str)] = &[
    ("wp-content", "wordpress"),
    ("wp-includes", "wordpress"),
    ("wp-json", "wordpress"),
    ("/themes/", "generic-theme"),
    ("/plugins/", "generic-plugin"),
    ("drupal", "drupal"),
    ("joomla", "joomla"),
    ("magento", "magento"),
    ("prestashop", "prestashop"),
    ("opencart", "opencart"),
    ("moodle", "moodle"),
    ("mediawiki", "mediawiki"),
    ("phpbb", "phpbb"),
    ("ghost", "ghost"),
    ("shopify", "shopify"),
    ("typo3", "typo3"),
    ("bitrix", "bitrix"),
];

/// Parsed HTML signals from the single `GET /` body preview: page title,
/// `<meta name="generator">` content, and stack-indicating asset URLs.
/// Never fetched separately — the preview is all this sees.
#[derive(Debug, Default)]
struct HtmlSignals {
    title: Option<String>,
    generator: Option<String>,
    asset_hints: Vec<String>,
    asset_stacks: Vec<&'static str>,
}

fn parse_html(preview: &str) -> HtmlSignals {
    use scraper::{Html, Selector};
    let mut out = HtmlSignals::default();
    if preview.trim().is_empty() {
        return out;
    }
    let doc = Html::parse_document(preview);
    if let Ok(sel) = Selector::parse("title") {
        if let Some(el) = doc.select(&sel).next() {
            let title: String = el.text().collect::<Vec<_>>().join(" ");
            let title = title.split_whitespace().collect::<Vec<_>>().join(" ");
            if !title.is_empty() {
                out.title = Some(title.chars().take(512).collect());
            }
        }
    }
    if let Ok(sel) = Selector::parse("meta") {
        for el in doc.select(&sel) {
            let is_generator = el.value().attr("name").is_some_and(|name| {
                name.trim().eq_ignore_ascii_case("generator")
            });
            if is_generator {
                if let Some(content) = el.value().attr("content") {
                    let content = content.trim();
                    if !content.is_empty() {
                        out.generator = Some(content.chars().take(256).collect());
                        break;
                    }
                }
            }
        }
    }
    let mut urls = Vec::new();
    if let Ok(sel) = Selector::parse("script[src]") {
        for el in doc.select(&sel) {
            if let Some(src) = el.value().attr("src") {
                urls.push(src.to_owned());
            }
        }
    }
    if let Ok(sel) = Selector::parse("link[href]") {
        for el in doc.select(&sel) {
            let rel = el.value().attr("rel").unwrap_or("");
            let is_style = rel.split_whitespace().any(|t| t.eq_ignore_ascii_case("stylesheet"));
            if is_style {
                if let Some(href) = el.value().attr("href") {
                    urls.push(href.to_owned());
                }
            }
        }
    }
    for url in urls {
        let lowered = url.to_lowercase();
        if let Some((_, stack)) = ASSET_STACKS.iter().find(|(frag, _)| lowered.contains(frag)) {
            out.asset_stacks.push(stack);
            if out.asset_hints.len() < 20 {
                out.asset_hints.push(url.chars().take(256).collect());
            }
        }
    }
    out
}

/// Best-effort stack vote from one cookie name. `None` means the cookie says
/// nothing about the stack.
fn stack_from_cookie(name: &str) -> Option<&'static str> {
    let lowered = name.to_lowercase();
    if lowered.contains("wordpress") || lowered.starts_with("wp-") || lowered.starts_with("wp_") {
        Some("wordpress")
    } else if lowered.contains("phpsessid") {
        Some("php")
    } else if lowered.contains("drupal") {
        Some("drupal")
    } else if lowered.contains("joomla") {
        Some("joomla")
    } else {
        None
    }
}

/// Best-effort stack vote from free text (Server / X-Powered-By /
/// X-Generator / generator meta). `None` means no named stack.
fn stack_from_text(text: &str) -> Option<&'static str> {
    let lowered = text.to_lowercase();
    if lowered.contains("wordpress") {
        Some("wordpress")
    } else if lowered.contains("drupal") {
        Some("drupal")
    } else if lowered.contains("joomla") {
        Some("joomla")
    } else if lowered.contains("magento") {
        Some("magento")
    } else if lowered.contains("php") {
        Some("php")
    } else {
        None
    }
}

/// Confidence from independent agreeing signals: `high` (3+ sources agree
/// on one stack), `medium` (2), `low` (1), `none` (0). Sources are the
/// header, cookie, meta, and asset channels — never one header alone.
fn confidence_for(
    server: Option<&str>,
    x_powered_by: Option<&str>,
    x_generator: Option<&str>,
    cookies: &[String],
    generator_meta: Option<&str>,
    asset_stacks: &[&'static str],
) -> (String, Vec<String>, Option<String>) {
    let mut votes: HashMap<&'static str, Vec<&'static str>> = HashMap::new();
    let mut vote = |stack: Option<&'static str>, source: &'static str| {
        if let Some(stack) = stack {
            votes.entry(stack).or_default().push(source);
        }
    };
    vote(server.and_then(stack_from_text), "server");
    vote(x_powered_by.and_then(stack_from_text), "x-powered-by");
    vote(x_generator.and_then(stack_from_text), "x-generator");
    vote(generator_meta.and_then(stack_from_text), "generator-meta");
    let mut cookie_stacks: HashSet<&'static str> = HashSet::new();
    for name in cookies {
        if let Some(stack) = stack_from_cookie(name) {
            cookie_stacks.insert(stack);
        }
    }
    for stack in cookie_stacks {
        vote(Some(stack), "cookies");
    }
    let mut asset_set: HashSet<&'static str> = HashSet::new();
    for stack in asset_stacks.iter().copied() {
        asset_set.insert(stack);
    }
    for stack in asset_set {
        vote(Some(stack), "asset-paths");
    }
    let Some((stack, sources)) = votes.iter().max_by_key(|(stack, sources)| (sources.len(), *stack)) else {
        return ("none".to_string(), Vec::new(), None);
    };
    let mut sources = sources.clone();
    sources.sort_unstable();
    let level = match sources.len() {
        0 => "none",
        1 => "low",
        2 => "medium",
        _ => "high",
    };
    (
        level.to_string(),
        sources.iter().map(ToString::to_string).collect(),
        Some((*stack).to_string()),
    )
}

/// Peer certificate fields captured from the TLS handshake for the same
/// host:port being probed over https. Never populated for http.
#[derive(Debug, Default, Clone)]
struct TlsFields {
    cn: Option<String>,
    san: Vec<String>,
    issuer: Option<String>,
    not_after: Option<String>,
}

/// A verifier that records the presented leaf certificate and always
/// accepts: this probe reports certificate metadata, it never judges trust.
#[derive(Debug)]
struct CaptureVerifier {
    captured: std::sync::Mutex<Option<Vec<u8>>>,
}

impl CaptureVerifier {
    fn new() -> Self {
        Self {
            captured: std::sync::Mutex::new(None),
        }
    }

    fn take(&self) -> Option<Vec<u8>> {
        self.captured.lock().ok()?.take()
    }
}

impl rustls::client::danger::ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Ok(mut slot) = self.captured.lock() {
            *slot = Some(end_entity.as_ref().to_vec());
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme;
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

/// Capture the peer leaf certificate from a TLS handshake to `addr` and
/// parse CN / SAN / issuer / not-after from it. Returns empty fields when
/// the handshake fails — the HTTP result still stands on its own.
async fn capture_tls(addr: SocketAddr, timeout: Duration) -> TlsFields {
    use std::sync::Arc;
    use tokio::net::TcpStream;

    let verifier = Arc::new(CaptureVerifier::new());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = match rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
    {
        Ok(builder) => builder
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth(),
        Err(_) => return TlsFields::default(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = match addr.ip() {
        IpAddr::V4(v4) => {
            rustls::pki_types::ServerName::IpAddress(rustls::pki_types::IpAddr::V4(v4.into()))
        }
        IpAddr::V6(v6) => {
            rustls::pki_types::ServerName::IpAddress(rustls::pki_types::IpAddr::V6(v6.into()))
        }
    };

    let handshake = async {
        let stream = TcpStream::connect(addr).await?;
        let _tls = connector.connect(server_name, stream).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    if tokio::time::timeout(timeout, handshake).await.is_err() {
        return TlsFields::default();
    }
    let Some(der) = verifier.take() else {
        return TlsFields::default();
    };
    parse_cert_der(&der).unwrap_or_default()
}

/// Parse CN / SAN / issuer / not-after out of one DER certificate.
fn parse_cert_der(der: &[u8]) -> Option<TlsFields> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::FromDer as _;
    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(der).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .map(|av| String::from_utf8_lossy(av.as_slice()).into_owned());
    let mut san = Vec::new();
    if let Ok(Some(names)) = cert.subject_alternative_name() {
        for name in &names.value.general_names {
            match name {
                GeneralName::DNSName(label) => san.push(label.to_string()),
                GeneralName::IPAddress(bytes) => {
                    let text = match bytes.len() {
                        4 => std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                            .to_string(),
                        16 => {
                            let mut groups = [0u16; 8];
                            for (i, g) in groups.iter_mut().enumerate() {
                                *g = u16::from_be_bytes([bytes[2 * i], bytes[2 * i + 1]]);
                            }
                            std::net::Ipv6Addr::from(groups).to_string()
                        }
                        _ => continue,
                    };
                    san.push(text);
                }
                _ => {}
            }
        }
    }
    san.sort();
    san.dedup();
    Some(TlsFields {
        cn,
        san,
        issuer: Some(cert.issuer().to_string()),
        not_after: Some(cert.validity().not_after.to_string()),
    })
}

/// Build the shared HTTP client: clear FTW User-Agent, per-request timeout,
/// and a small redirect limit so `final_url` reflects redirects.
fn build_client(config: &ProbeConfig) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .user_agent(format!(
            "FTW/{} (Authorized Security Scanner)",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(config.timeout)
        .redirect(Policy::limited(MAX_REDIRECTS));
    if config.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build()
}

/// Stream at most `cap` response body bytes, keeping the leading bytes as a
/// lossy string for parsing only. Larger pages are not fully fetched.
async fn collect_capped(mut response: reqwest::Response, cap: usize) -> (Vec<u8>, bool) {
    if cap == 0 {
        return (Vec::new(), true);
    }
    let mut kept = Vec::with_capacity(cap.min(8192));
    let mut truncated = response.content_length().is_some_and(|len| len > cap as u64);
    while kept.len() < cap {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = cap - kept.len();
                if chunk.len() > room {
                    kept.extend_from_slice(&chunk[..room]);
                    truncated = true;
                    break;
                }
                kept.extend_from_slice(&chunk);
            }
            _ => break,
        }
    }
    (kept, truncated)
}

/// Fetch one auxiliary path (`/favicon.ico`, `/robots.txt`, `/sitemap.xml`)
/// against `base`: returns status and up-to-`cap` raw bytes. Failures yield
/// `None` status and empty bytes — never an error for the whole record.
async fn fetch_aux(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    cap: usize,
) -> (Option<u16>, Vec<u8>, bool) {
    let url = format!("{base}{path}");
    let Ok(response) = client.get(&url).send().await else {
        return (None, Vec::new(), false);
    };
    let status = response.status().as_u16();
    let (bytes, truncated) = collect_capped(response, cap).await;
    (Some(status), bytes, truncated)
}

/// SHA-256 hex digest of `bytes`. Only the digest is stored, never the input.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Probe one open host:port in a single pass and build its record. The main
/// `GET /` decides `status`/`error`; every auxiliary fetch only fills its
/// own optional fields.
async fn probe_target(
    client: &reqwest::Client,
    config: &ProbeConfig,
    ip: IpAddr,
    port: u16,
    host_checks: &HashMap<String, HostCheckSummary>,
) -> ProbeRecord {
    let scheme = scheme_for_port(port);
    let base = format!("{scheme}://{}", SocketAddr::new(ip, port));
    let attempted_url = format!("{base}/");
    let mut record = ProbeRecord {
        host: ip.to_string(),
        port,
        scheme: scheme.to_string(),
        status: None,
        final_url: attempted_url.clone(),
        server: None,
        cookie_names: Vec::new(),
        x_generator: None,
        via: None,
        generator: None,
        title: None,
        asset_hints: Vec::new(),
        tls_cn: None,
        tls_san: Vec::new(),
        tls_issuer: None,
        tls_not_after: None,
        favicon_sha256: None,
        robots_present: false,
        robots_status: None,
        robots_snippet: String::new(),
        robots_truncated: false,
        sitemap_present: false,
        sitemap_status: None,
        sitemap_snippet: String::new(),
        sitemap_truncated: false,
        confidence: "none".to_string(),
        confidence_signals: Vec::new(),
        stack_hint: None,
        remote_version_hint: None,
        patch_status: PATCH_UNKNOWN_FROM_REMOTE.to_string(),
        host_check: None,
        error: None,
    };

    let main = client.get(&attempted_url).send().await;
    match main {
        Ok(response) => {
            let status = response.status().as_u16();
            record.status = Some(status);
            record.final_url = response.url().to_string();
            let headers = response.headers().clone();
            let (bytes, _) = collect_capped(response, config.body_cap).await;
            let preview = String::from_utf8_lossy(&bytes).into_owned();

            record.server = first_header(&headers, "server");
            record.cookie_names = cookie_names(&headers);
            let x_powered_by = first_header(&headers, "x-powered-by");
            record.x_generator = first_header(&headers, "x-generator");
            record.via = first_header(&headers, "via");

            let html = parse_html(&preview);
            record.generator = html.generator;
            record.title = html.title;
            record.asset_hints = html.asset_hints;

            let (confidence, signals, stack) = confidence_for(
                record.server.as_deref(),
                x_powered_by.as_deref(),
                record.x_generator.as_deref(),
                &record.cookie_names,
                record.generator.as_deref(),
                &html.asset_stacks,
            );
            record.confidence = confidence;
            record.confidence_signals = signals;
            record.stack_hint = stack;
            record.remote_version_hint = remote_version_hint(
                x_powered_by.as_deref(),
                record.server.as_deref(),
                record.generator.as_deref(),
            );

            if scheme == "https" {
                if let Ok(addr) = format!("{ip}:{port}").parse::<SocketAddr>() {
                    let tls = capture_tls(addr, config.timeout).await;
                    record.tls_cn = tls.cn;
                    record.tls_san = tls.san;
                    record.tls_issuer = tls.issuer;
                    record.tls_not_after = tls.not_after;
                }
            }

            let (favicon_status, favicon_bytes, _) =
                fetch_aux(client, &base, "/favicon.ico", FAVICON_CAP).await;
            if favicon_status == Some(200) && !favicon_bytes.is_empty() {
                record.favicon_sha256 = Some(sha256_hex(&favicon_bytes));
            }

            let (robots_status, robots_bytes, robots_truncated) =
                fetch_aux(client, &base, "/robots.txt", AUX_BODY_CAP).await;
            record.robots_status = robots_status;
            record.robots_present = robots_status == Some(200);
            record.robots_truncated = robots_truncated;
            record.robots_snippet = String::from_utf8_lossy(&robots_bytes).into_owned();

            let (sitemap_status, sitemap_bytes, sitemap_truncated) =
                fetch_aux(client, &base, "/sitemap.xml", AUX_BODY_CAP).await;
            record.sitemap_status = sitemap_status;
            record.sitemap_present = sitemap_status == Some(200);
            record.sitemap_truncated = sitemap_truncated;
            record.sitemap_snippet = String::from_utf8_lossy(&sitemap_bytes).into_owned();
        }
        Err(err) => {
            record.error = Some(classify_error(&err).to_string());
        }
    }

    if let Some(summary) = host_checks.get(&record.host) {
        record.patch_status = PATCH_AUTHORITATIVE_HOST_CHECK.to_string();
        record.host_check = Some(summary.clone());
    }
    record
}

/// Probe every open target recorded in the master database.
///
/// Mirrors the Phase 1 architecture: the semaphore permit is acquired in
/// this producer loop BEFORE `tokio::spawn`, results travel over a bounded
/// mpsc channel to a single writer task, and records stream out as they
/// arrive — the whole run is never buffered.
pub async fn run_with_options(
    config: &ProbeConfig,
    db_path: PathBuf,
    host_checks: &HashMap<String, HostCheckSummary>,
    options: output::OutputOptions,
) -> Result<ProbeStats, Box<dyn std::error::Error + Send + Sync>> {
    let conn = crate::db::open(&db_path)?;
    let targets = crate::db::open_ports(&conn)?;
    if targets.is_empty() {
        eprintln!("ftw: warning: no open ports found in database");
    }
    let client = build_client(config)?;
    eprintln!("ftw: probing {} open host:port targets", targets.len());
    let (tx, rx) = mpsc::channel::<ProbeRecord>(CHANNEL_CAPACITY);
    let writer =
        tokio::spawn(async move { output::run_probe_db_writer(rx, conn, options).await });
    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
    for (ip, port) in targets {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("probe semaphore never closes while probing");
        let tx = tx.clone();
        let client = client.clone();
        let config = *config;
        let host_checks = host_checks.clone();
        tokio::spawn(async move {
            let record = probe_target(&client, &config, ip, port, &host_checks).await;
            drop(permit);
            let _ = tx.send(record).await;
        });
    }
    drop(tx);
    let stats = writer.await??;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const FAVICON_BYTES: &[u8] = b"FTW-FAKE-FAVICON-BYTES";
    const FAVICON_SHA256: &str =
        "be8b3186fefcf7bc80e989b4b00b7b7098ad6e3bc71ef57dcce20a4fd0dfa0e3";
    const ROBOTS_BODY: &str = "User-agent: *\nDisallow: /admin\n";
    const SITEMAP_BODY: &str =
        "<?xml version=\"1.0\"?><urlset><url><loc>http://example.test/</loc></url></urlset>";
    const INDEX_BODY: &str = "<!doctype html><html><head><title>Test Page</title>\
        <meta name=\"generator\" content=\"WordPress 6.5.2\">\
        <link rel=\"stylesheet\" href=\"/wp-content/themes/t/style.css\">\
        </head><body><script src=\"/wp-includes/js/app.js\"></script></body></html>";

    fn temp_tag(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("ftw-probe-{prefix}-{nanos}-{}", std::process::id())
    }

    fn test_config() -> ProbeConfig {
        ProbeConfig {
            concurrency: 4,
            timeout: Duration::from_secs(5),
            insecure: false,
            body_cap: DEFAULT_BODY_CAP,
        }
    }

    /// Route-aware loopback HTTP server: `/` serves the WordPress-like page
    /// with the known headers, `/favicon.ico` the fixture bytes,
    /// `/robots.txt` and `/sitemap.xml` their bodies, anything else 404.
    async fn spawn_route_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("test server addr");
        let handle = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    let path = text
                        .lines()
                        .next()
                        .unwrap_or("")
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .to_string();
                    let path = path.split('?').next().unwrap_or("/").to_string();
                    let (status, headers, body): (&str, Vec<(&str, &str)>, Vec<u8>) = match path
                        .as_str()
                    {
                        "/" => (
                            "200 OK",
                            vec![
                                ("Server", "TestServer/2.5.1"),
                                ("X-Powered-By", "PHP/8.2.0"),
                                ("X-Generator", "WordPress"),
                                ("Via", "1.1 test-proxy"),
                                ("Content-Type", "text/html"),
                            ],
                            INDEX_BODY.as_bytes().to_vec(),
                        ),
                        "/favicon.ico" => (
                            "200 OK",
                            vec![("Content-Type", "image/x-icon")],
                            FAVICON_BYTES.to_vec(),
                        ),
                        "/robots.txt" => (
                            "200 OK",
                            vec![("Content-Type", "text/plain")],
                            ROBOTS_BODY.as_bytes().to_vec(),
                        ),
                        "/sitemap.xml" => (
                            "200 OK",
                            vec![("Content-Type", "application/xml")],
                            SITEMAP_BODY.as_bytes().to_vec(),
                        ),
                        _ => ("404 Not Found", vec![("Content-Type", "text/plain")], b"no".to_vec()),
                    };
                    let mut extra = String::new();
                    if path == "/" {
                        extra.push_str("Set-Cookie: PHPSESSID=abc123; Path=/\r\n");
                        extra.push_str("Set-Cookie: wordpress_logged_in_abc=xyz; Path=/\r\n");
                    }
                    let mut response = format!("HTTP/1.1 {status}\r\n{extra}");
                    for (name, value) in &headers {
                        response.push_str(&format!("{name}: {value}\r\n"));
                    }
                    response.push_str(&format!(
                        "Content-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    ));
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (addr, handle)
    }

    fn client_for_test() -> reqwest::Client {
        build_client(&test_config()).expect("test client")
    }

    #[test]
    fn scheme_is_fixed_by_port() {
        assert_eq!(scheme_for_port(443), "https");
        assert_eq!(scheme_for_port(80), "http");
        assert_eq!(scheme_for_port(8080), "http");
        assert_eq!(scheme_for_port(22), "http");
    }

    #[test]
    fn cookie_names_keep_names_only() {
        let mut headers = HeaderMap::new();
        headers.append(
            reqwest::header::SET_COOKIE,
            "PHPSESSID=abc123; Path=/; HttpOnly".parse().unwrap(),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            "wordpress_logged_in_abc=xyz; Path=/".parse().unwrap(),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            "PHPSESSID=second; Path=/".parse().unwrap(),
        );
        assert_eq!(
            cookie_names(&headers),
            vec!["PHPSESSID".to_string(), "wordpress_logged_in_abc".to_string()]
        );
    }

    #[test]
    fn version_hint_prefers_powered_by_then_server_then_generator() {
        assert_eq!(
            remote_version_hint(Some("PHP/8.2.0"), Some("TestServer/2.5.1"), None),
            Some("PHP/8.2.0".to_string())
        );
        assert_eq!(
            remote_version_hint(None, Some("TestServer/2.5.1"), Some("WordPress 6.5.2")),
            Some("TestServer/2.5.1".to_string())
        );
        assert_eq!(
            remote_version_hint(None, Some("plain"), Some("WordPress 6.5.2")),
            Some("WordPress 6.5.2".to_string())
        );
        assert_eq!(remote_version_hint(None, Some("plain"), None), None);
    }

    #[test]
    fn confidence_needs_independent_agreement() {
        // No signals at all.
        assert_eq!(
            confidence_for(None, None, None, &[], None, &[]).0,
            "none"
        );
        // A single header alone is only ever low, never definitive.
        let (level, signals, stack) =
            confidence_for(Some("TestServer/2.5.1 PHP/8.2.0"), None, None, &[], None, &[]);
        assert_eq!(level, "low");
        assert_eq!(signals, vec!["server".to_string()]);
        assert_eq!(stack.as_deref(), Some("php"));
        // Three independent channels agreeing is high (duplicate asset
        // paths count once — channels, not hits, are what agree).
        let (level, signals, stack) = confidence_for(
            None,
            Some("PHP/8.2.0"),
            None,
            &["wordpress_logged_in_abc".to_string()],
            Some("WordPress 6.5.2"),
            &["wordpress", "wordpress"],
        );
        assert_eq!(level, "high");
        assert_eq!(stack.as_deref(), Some("wordpress"));
        assert!(signals.contains(&"generator-meta".to_string()));
        assert!(signals.contains(&"asset-paths".to_string()));
    }

    /// Full loopback probe: every field of the streamed record is asserted
    /// against the known fixture server.
    #[tokio::test]
    async fn loopback_probe_records_every_field() {
        let (addr, server) = spawn_route_server().await;
        let client = client_for_test();
        let config = test_config();
        let record = probe_target(&client, &config, addr.ip(), addr.port(), &HashMap::new()).await;
        server.abort();

        assert_eq!(record.host, "127.0.0.1");
        assert_eq!(record.port, addr.port());
        assert_eq!(record.scheme, "http");
        assert_eq!(record.status, Some(200));
        assert_eq!(record.final_url, format!("http://127.0.0.1:{}/", addr.port()));
        assert_eq!(record.server.as_deref(), Some("TestServer/2.5.1"));
        assert_eq!(
            record.cookie_names,
            vec!["PHPSESSID".to_string(), "wordpress_logged_in_abc".to_string()]
        );
        assert_eq!(record.x_generator.as_deref(), Some("WordPress"));
        assert_eq!(record.via.as_deref(), Some("1.1 test-proxy"));
        assert_eq!(record.generator.as_deref(), Some("WordPress 6.5.2"));
        assert_eq!(record.title.as_deref(), Some("Test Page"));
        assert!(
            record.asset_hints.iter().any(|u| u.contains("wp-content")),
            "asset hints must keep wp-content URL: {:?}",
            record.asset_hints
        );
        assert!(
            record.asset_hints.iter().any(|u| u.contains("wp-includes")),
            "asset hints must keep wp-includes URL: {:?}",
            record.asset_hints
        );
        // Plain http: no TLS fields.
        assert_eq!(record.tls_cn, None);
        assert!(record.tls_san.is_empty());
        assert_eq!(record.tls_issuer, None);
        assert_eq!(record.tls_not_after, None);
        // Favicon: only the hash is stored, never the binary.
        assert_eq!(record.favicon_sha256.as_deref(), Some(FAVICON_SHA256));
        // Robots + sitemap: presence, status, and truncated content.
        assert!(record.robots_present);
        assert_eq!(record.robots_status, Some(200));
        assert!(record.robots_snippet.contains("Disallow: /admin"));
        assert!(!record.robots_truncated);
        assert!(record.sitemap_present);
        assert_eq!(record.sitemap_status, Some(200));
        assert!(record.sitemap_snippet.contains("<urlset"));
        assert!(!record.sitemap_truncated);
        // Confidence: generator-meta + asset-paths + cookies agree.
        assert_eq!(record.confidence, "high");
        assert_eq!(record.stack_hint.as_deref(), Some("wordpress"));
        // Remote versions stay hints; patch status stays unknown.
        assert_eq!(record.remote_version_hint.as_deref(), Some("PHP/8.2.0"));
        assert_eq!(record.patch_status, PATCH_UNKNOWN_FROM_REMOTE);
        assert_eq!(record.host_check, None);
        assert_eq!(record.error, None);
    }

    /// Closed ports are never probed: with one open and one closed seed, the
    /// pipeline emits exactly one record, for the open port.
    #[tokio::test]
    async fn pipeline_probes_only_open_ports() {
        let (addr, server) = spawn_route_server().await;
        let tag = temp_tag("only-open");
        let db_path: PathBuf = std::env::temp_dir().join(format!("{tag}.db"));
        {
            let conn = crate::db::open(&db_path).expect("open db");
            let open = crate::scanner::ScanResult {
                ip: addr.ip(),
                port: addr.port(),
                status: crate::scanner::PortStatus::Open,
                reason: "open",
            };
            crate::db::upsert_scan(&conn, &open).expect("seed open");
            let closed_port = {
                let tmp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp");
                tmp.local_addr().expect("temp addr").port()
            };
            let closed = crate::scanner::ScanResult {
                ip: addr.ip(),
                port: closed_port,
                status: crate::scanner::PortStatus::Closed,
                reason: "connection refused",
            };
            crate::db::upsert_scan(&conn, &closed).expect("seed closed");
        }
        let config = test_config();
        let stats = run_with_options(
            &config,
            db_path.clone(),
            &HashMap::new(),
            output::OutputOptions::new(false, true),
        )
        .await
        .expect("probe run");
        server.abort();
        assert_eq!(stats.total, 1, "only the open port may be probed");
        assert_eq!(stats.ok, 1);
        let check = rusqlite::Connection::open(&db_path).expect("reopen db");
        let count: i64 = check
            .query_row("SELECT COUNT(*) FROM probe_results", [], |row| row.get(0))
            .expect("count probe rows");
        assert_eq!(count, 1);
        std::fs::remove_file(&db_path).ok();
    }

    /// Host-check merge upgrades patch status for the matching host only.
    #[tokio::test]
    async fn host_check_merge_authorizes_patch_status() {
        let (addr, server) = spawn_route_server().await;
        let client = client_for_test();
        let config = test_config();
        let mut map = HashMap::new();
        map.insert(
            "127.0.0.1".to_string(),
            HostCheckSummary {
                host: "127.0.0.1".to_string(),
                php_version: Some("8.2.10".to_string()),
                package_count: 3,
            },
        );
        let record = probe_target(&client, &config, addr.ip(), addr.port(), &map).await;
        server.abort();
        assert_eq!(record.patch_status, PATCH_AUTHORITATIVE_HOST_CHECK);
        let summary = record.host_check.expect("merged summary");
        assert_eq!(summary.php_version.as_deref(), Some("8.2.10"));
        assert_eq!(summary.package_count, 3);
    }

    /// TLS capture against a closed port degrades to empty fields — the
    /// HTTP result still stands on its own.
    #[tokio::test]
    async fn tls_capture_failure_yields_empty_fields() {
        let port = {
            let tmp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp");
            tmp.local_addr().expect("temp addr").port()
        };
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let tls = capture_tls(addr, Duration::from_secs(2)).await;
        assert_eq!(tls.cn, None);
        assert!(tls.san.is_empty());
        assert_eq!(tls.issuer, None);
        assert_eq!(tls.not_after, None);
    }
}
