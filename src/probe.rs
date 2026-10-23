//! HTTP/HTTPS probe logic for Phase 2 (`ftw probe`).
//!
//! Input is a Phase 1 scan-output file ONLY: lines of `<ip>:<port> <status>`.
//! Only entries marked `open` are kept (deduplicated). Closed and filtered
//! ports are never re-probed, the original YAML targets file is never
//! re-expanded, and no port absent from the scan output is ever probed.
//!
//! Each open host:port is probed per scheme attempt with a clear FTW
//! User-Agent, redirects followed up to the configured limit, and at most
//! `--body-cap` response bytes read (never more than the 64 KiB tech preview
//! limit). The explicit `--fetch-mode` flag selects the request pattern:
//! `get` sends a single `GET /`; `head` sends a single `HEAD /` (no body, so
//! all HTML-derived signals are empty by definition); `both` sends `HEAD /`
//! then `GET /` always, in that order. Header signals from HEAD and GET are
//! unioned in `both` mode; the GET result supersedes HEAD for status and
//! final URL. PHP fingerprinting is passive only: response headers,
//! `Set-Cookie` headers, and the final URL. Technology fingerprinting
//! (`crate::tech`) additionally parses at most the first 65536 body bytes
//! kept in memory for parsing only — never written to the output, never
//! re-fetched, and never followed with extra requests.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use tokio::sync::{Semaphore, mpsc};

use crate::output;
use crate::tech;

const CHANNEL_CAPACITY: usize = 1024;

/// Which scheme(s) to probe with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Scheme {
    /// Try HTTPS first, then fall back to plain HTTP if HTTPS fails.
    #[default]
    Auto,
    /// Plain HTTP only.
    Http,
    /// HTTPS only.
    Https,
}

impl Scheme {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which HTTP method(s) to send per scheme attempt. The user — not the tool —
/// chooses the tradeoff at runtime: `head` is the fastest and lightest but
/// can only see headers, `both` is the most complete but always costs two
/// requests per port, and `get` is the previous behavior (the default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum FetchMode {
    /// Send a single `GET /` only (previous behavior).
    #[default]
    Get,
    /// Send a single `HEAD /` only. Never send GET, even if HEAD fails.
    Head,
    /// Send `HEAD /` first, then `GET /` always, in that order.
    Both,
}

impl FetchMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Head => "head",
            Self::Both => "both",
        }
    }
}

impl fmt::Display for FetchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Runtime settings for a probe run.
#[derive(Debug, Clone, Copy)]
pub struct ProbeConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    pub scheme: Scheme,
    pub insecure: bool,
    pub max_redirects: usize,
    pub body_cap: usize,
    pub fetch_mode: FetchMode,
}

/// One JSON-lines probe record.
///
/// `status`/`server` are `None` when no HTTP response was received; `error`
/// is `None` exactly when a response was received (`http` outcome).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProbeRecord {
    pub ip: String,
    pub port: u16,
    pub scheme: String,
    pub final_url: String,
    pub status: Option<u16>,
    pub server: Option<String>,
    pub tls: String,
    pub error: Option<String>,
    pub php_detected: bool,
    pub php_version: Option<String>,
    pub php_signals: Vec<String>,
    pub wordpress_detected: bool,
    pub wordpress_version: Option<String>,
    pub wordpress_signals: Vec<String>,
    pub php_apps: Vec<tech::PhpApp>,
    pub tailwind_detected: bool,
    pub tailwind_confidence: String,
    pub tailwind_signals: Vec<String>,
    /// How the response was obtained: `"get"`, `"head"`, `"both"`, or
    /// `"get-fallback"` (the last only in `both` mode when HEAD failed).
    pub fetch_method: String,
    /// The HEAD status code, or `None` when no HEAD request was sent or it
    /// produced no status (including `both`-mode HEAD 405/501 failures).
    pub head_status: Option<u16>,
}

/// Aggregate counts for one probe run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProbeStats {
    pub total: usize,
    pub http: usize,
    pub tls_errors: usize,
    pub connect_errors: usize,
    pub timeouts: usize,
    pub other_errors: usize,
    pub php_detected: usize,
    pub php_not_detected: usize,
}

impl ProbeStats {
    pub(crate) fn record(&mut self, result: &ProbeRecord) {
        self.total += 1;
        match result.error.as_deref() {
            None => self.http += 1,
            Some("tls_error") => self.tls_errors += 1,
            Some("connect_error") => self.connect_errors += 1,
            Some("timeout") => self.timeouts += 1,
            _ => self.other_errors += 1,
        }
        if result.php_detected {
            self.php_detected += 1;
        } else {
            self.php_not_detected += 1;
        }
    }
}

/// Failure to load or parse a scan-output file.
#[derive(Debug)]
pub enum ScanParseError {
    Io(std::io::Error),
    BadLine { line: usize, text: String },
}

impl fmt::Display for ScanParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "cannot read scan-output file: {err}"),
            Self::BadLine { line, text } => {
                write!(f, "invalid scan-output line {line}: {text:?}")
            }
        }
    }
}

impl std::error::Error for ScanParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::BadLine { .. } => None,
        }
    }
}

impl From<std::io::Error> for ScanParseError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Parse scan-output text: keep only entries marked `open`, deduplicated and
/// sorted. Every other status (closed, filtered, anything else) is skipped,
/// so those ports are never probed.
pub fn parse_scan_text(text: &str) -> Result<Vec<(IpAddr, u16)>, ScanParseError> {
    let mut open: HashSet<(IpAddr, u16)> = HashSet::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(addr_part), Some(status), None) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(ScanParseError::BadLine {
                line: index + 1,
                text: raw_line.to_string(),
            });
        };
        if status != "open" {
            continue;
        }
        let Some((ip_text, port_text)) = addr_part.rsplit_once(':') else {
            return Err(ScanParseError::BadLine {
                line: index + 1,
                text: raw_line.to_string(),
            });
        };
        let ip: IpAddr = ip_text.parse().map_err(|_| ScanParseError::BadLine {
            line: index + 1,
            text: raw_line.to_string(),
        })?;
        let port: u16 = port_text.parse().map_err(|_| ScanParseError::BadLine {
            line: index + 1,
            text: raw_line.to_string(),
        })?;
        open.insert((ip, port));
    }
    let mut targets: Vec<(IpAddr, u16)> = open.into_iter().collect();
    targets.sort_unstable();
    Ok(targets)
}

/// Load and parse a Phase 1 scan-output file.
pub fn parse_scan_output(path: &Path) -> Result<Vec<(IpAddr, u16)>, ScanParseError> {
    let text = std::fs::read_to_string(path)?;
    parse_scan_text(&text)
}

/// Build the shared HTTP client: clear FTW User-Agent, per-attempt timeout,
/// redirect limit, and opt-in acceptance of invalid certificates (only for
/// your own self-signed hosts).
fn build_client(config: &ProbeConfig) -> Result<reqwest::Client, reqwest::Error> {
    let policy = if config.max_redirects == 0 {
        Policy::none()
    } else {
        Policy::limited(config.max_redirects)
    };
    let mut builder = reqwest::Client::builder()
        .user_agent(format!(
            "FTW/{} (Authorized Security Scanner)",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(config.timeout)
        .redirect(policy);
    if config.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build()
}

/// Full Display + Debug + source-chain text of a request error, lowercased,
/// for transport classification.
fn error_text(err: &reqwest::Error) -> String {
    use std::error::Error as _;
    let mut text = format!("{err} {err:?}");
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(&format!(" {cause} {cause:?}"));
        source = cause.source();
    }
    text.to_lowercase()
}

/// True when the error text looks like a TLS failure (handshake breakdown,
/// certificate problem, or an HTTPS server speaking plain HTTP).
fn looks_like_tls_error(text: &str) -> bool {
    const MARKERS: &[&str] = &[
        "tls",
        "ssl",
        "rustls",
        "webpki",
        "certificate",
        "cert",
        "handshake",
        "unexpected message",
        "corrupt message",
        "invalid message",
        "alert",
        "bad record",
        "decrypt",
        "peer sent",
        "unknown issuer",
        "self-signed",
        "self signed",
        "expired",
        "not valid",
    ];
    MARKERS.iter().any(|marker| text.contains(marker))
}

/// True when the error text looks like a plain network/connect failure.
fn looks_like_connect_error(text: &str) -> bool {
    const MARKERS: &[&str] = &[
        "connection refused",
        "connection reset",
        "connection closed",
        "connection aborted",
        "network unreachable",
        "no route to host",
        "broken pipe",
        "dns",
        "resolve",
        "name or service not known",
        "econnrefused",
        "econnreset",
        "ehostunreach",
        "enetunreach",
    ];
    MARKERS.iter().any(|marker| text.contains(marker))
}

/// Classify a failed attempt. A TLS/certificate problem is always `tls_error`
/// — never a closed port or a connect failure.
fn classify_error(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        return "timeout";
    }
    let text = error_text(err);
    if looks_like_tls_error(&text) {
        return "tls_error";
    }
    if err.is_connect() || looks_like_connect_error(&text) {
        return "connect_error";
    }
    if err.is_redirect() {
        return "other";
    }
    if text.contains("timed out") || text.contains("deadline exceeded") {
        return "timeout";
    }
    "other"
}

/// Parse `PHP/<major>.<minor>.<patch>` out of an `X-Powered-By` value
/// (for example `PHP/8.2.0` gives `8.2.0`); anything else gives `None`.
/// Never invents a version.
fn parse_php_version(value: &str) -> Option<String> {
    let rest = value.split("PHP/").nth(1)?;
    let run: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let parts: Vec<&str> = run.split('.').collect();
    if parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    {
        Some(run)
    } else {
        None
    }
}

/// Passive PHP fingerprinting from the single GET response only: headers,
/// `Set-Cookie` headers, and the final URL. Never the body, never extra
/// requests. Returns `(detected, version, signals)`.
fn fingerprint(headers: &HeaderMap, final_url: &str) -> (bool, Option<String>, Vec<String>) {
    let powered_by: Vec<&str> = headers
        .get_all("x-powered-by")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    let set_cookies: Vec<&str> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();

    let mut signals = Vec::new();
    if powered_by.iter().any(|value| value.contains("PHP/")) {
        signals.push("x-powered-by".to_string());
    }
    let server_has_php = headers
        .get(reqwest::header::SERVER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_lowercase().contains("php"));
    if server_has_php {
        signals.push("server".to_string());
    }
    if set_cookies.iter().any(|value| value.contains("PHPSESSID")) {
        signals.push("phpsessid-cookie".to_string());
    }
    let redirect_to_php = reqwest::Url::parse(final_url)
        .map(|url| url.path().ends_with(".php"))
        .unwrap_or(false);
    if redirect_to_php {
        signals.push("redirect-to-php".to_string());
    }

    let version = powered_by.iter().find_map(|value| parse_php_version(value));
    (!signals.is_empty(), version, signals)
}

/// Stream at most `cap` response body bytes (and never more than the tech
/// preview limit), keeping the leading bytes as a lossy string for parsing
/// only. The preview is discarded after fingerprinting and never written to
/// the probe output file. Larger pages are not fully fetched: only the first
/// 65536 bytes are fingerprinted.
async fn collect_preview(mut response: reqwest::Response, cap: usize) -> String {
    let limit = cap.min(tech::MAX_PREVIEW_BYTES);
    if limit == 0 {
        return String::new();
    }
    let mut kept = Vec::with_capacity(limit.min(8192));
    let mut remaining = limit;
    while remaining > 0 {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let take = chunk.len().min(remaining);
                kept.extend_from_slice(&chunk[..take]);
                if chunk.len() >= remaining {
                    break;
                }
                remaining -= chunk.len();
            }
            _ => break,
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

/// Union two header sets with `primary` first, so single-value lookups
/// (`Server`, version parse order) prefer the primary response while
/// multi-value signals (`Set-Cookie`, `Link`, `X-Powered-By`) see both.
fn union_headers(primary: &HeaderMap, secondary: &HeaderMap) -> HeaderMap {
    let mut merged = primary.clone();
    for (name, value) in secondary {
        merged.append(name.clone(), value.clone());
    }
    merged
}

/// Send the single `GET /` for one scheme attempt: returns status, final
/// URL, headers, and the body preview for parsing.
async fn fetch_get(
    client: &reqwest::Client,
    url: &str,
    body_cap: usize,
) -> Result<(u16, String, HeaderMap, String), reqwest::Error> {
    let response = client.get(url).send().await?;
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let headers = response.headers().clone();
    // Observe the content length if the header is present; the body itself
    // is only streamed up to the cap (and the tech preview limit) and never
    // stored in the output record.
    let _content_length: Option<u64> = headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok());
    let preview = collect_preview(response, body_cap).await;
    Ok((status, final_url, headers, preview))
}

/// Fill a success record from one response: status and final URL from this
/// response, PHP + tech signals from `headers` (already unioned by the
/// caller) and `preview`. The body preview is never stored.
fn fill_success(
    record: &mut ProbeRecord,
    scheme: &str,
    status: u16,
    final_url: String,
    headers: &HeaderMap,
    preview: &str,
    fetch_method: &str,
) {
    record.final_url = final_url.clone();
    record.status = Some(status);
    record.server = headers
        .get(reqwest::header::SERVER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let (detected, version, signals) = fingerprint(headers, &final_url);
    record.tls = if scheme == "https" { "ok" } else { "n/a" }.to_string();
    record.php_detected = detected;
    record.php_version = version;
    record.php_signals = signals;
    let tech_fp = tech::fingerprint_tech(Some(status), headers, &final_url, preview);
    record.wordpress_detected = tech_fp.wordpress_detected;
    record.wordpress_version = tech_fp.wordpress_version;
    record.wordpress_signals = tech_fp.wordpress_signals;
    record.php_apps = tech_fp.php_apps;
    record.tailwind_detected = tech_fp.tailwind_detected;
    record.tailwind_confidence = tech_fp.tailwind_confidence;
    record.tailwind_signals = tech_fp.tailwind_signals;
    record.fetch_method = fetch_method.to_string();
}

/// Passive PHP fingerprinting for `head` mode: a HEAD response has no body,
/// so only `X-Powered-By` (containing `PHP/`) and a `PHPSESSID` cookie count.
/// `Server` and final-URL signals are ignored here by design — head mode can
/// only see headers, and PHP is reported only via these two header signals.
fn fingerprint_head(headers: &HeaderMap) -> (bool, Option<String>, Vec<String>) {
    let powered_by: Vec<&str> = headers
        .get_all("x-powered-by")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    let set_cookies: Vec<&str> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    let mut signals = Vec::new();
    if powered_by.iter().any(|value| value.contains("PHP/")) {
        signals.push("x-powered-by".to_string());
    }
    if set_cookies.iter().any(|value| value.contains("PHPSESSID")) {
        signals.push("phpsessid-cookie".to_string());
    }
    let version = powered_by.iter().find_map(|value| parse_php_version(value));
    (!signals.is_empty(), version, signals)
}

/// Fill a success record from a HEAD response: status and final URL from the
/// HEAD response, PHP signals from headers only, tech signals from headers
/// with an empty body preview (all HTML-derived signals are empty by
/// definition). The body is never fetched and never stored.
fn fill_head_success(
    record: &mut ProbeRecord,
    scheme: &str,
    status: u16,
    final_url: String,
    headers: &HeaderMap,
) {
    record.final_url = final_url.clone();
    record.status = Some(status);
    record.server = headers
        .get(reqwest::header::SERVER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let (detected, version, signals) = fingerprint_head(headers);
    record.tls = if scheme == "https" { "ok" } else { "n/a" }.to_string();
    record.php_detected = detected;
    record.php_version = version;
    record.php_signals = signals;
    let tech_fp = tech::fingerprint_tech(Some(status), headers, &final_url, "");
    record.wordpress_detected = tech_fp.wordpress_detected;
    record.wordpress_version = tech_fp.wordpress_version;
    record.wordpress_signals = tech_fp.wordpress_signals;
    record.php_apps = tech_fp.php_apps;
    record.tailwind_detected = tech_fp.tailwind_detected;
    record.tailwind_confidence = tech_fp.tailwind_confidence;
    record.tailwind_signals = tech_fp.tailwind_signals;
    record.fetch_method = "head".to_string();
}

/// True when the `Server` header contains `php` (case-insensitive).
fn server_has_php(headers: &HeaderMap) -> bool {
    headers
        .get(reqwest::header::SERVER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_lowercase().contains("php"))
}

/// Send the single `HEAD /` for one scheme attempt: returns status, final
/// URL, and headers. A HEAD response has no body, so nothing is read beyond
/// the headers.
async fn fetch_head(
    client: &reqwest::Client,
    url: &str,
) -> Result<(u16, String, HeaderMap), reqwest::Error> {
    let response = client.head(url).send().await?;
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let headers = response.headers().clone();
    Ok((status, final_url, headers))
}

/// True when a HEAD outcome counts as a failure for `both`-mode fallback:
/// a 405/501 status, or no status at all (network error / timeout).
fn head_failed_for_fallback(head: &Result<(u16, String, HeaderMap), reqwest::Error>) -> bool {
    match head {
        Ok((status, _, _)) => *status == 405 || *status == 501,
        Err(_) => true,
    }
}

/// Probe one host:port over `scheme` with the explicit fetch mode: `get`
/// sends a single `GET /`; `head` sends a single `HEAD /` (never a GET);
/// `both` sends `HEAD /` then `GET /` always, in that order. The same client
/// (same User-Agent, timeout, redirect limit, and TLS handling) is used for
/// every request, and the caller holds one semaphore permit for the whole
/// sequence. One record is produced regardless of mode.
async fn attempt(
    client: &reqwest::Client,
    scheme: &str,
    ip: IpAddr,
    port: u16,
    body_cap: usize,
    fetch_mode: FetchMode,
) -> ProbeRecord {
    let attempted_url = format!("{scheme}://{}/", SocketAddr::new(ip, port));
    let mut record = ProbeRecord {
        ip: ip.to_string(),
        port,
        scheme: scheme.to_string(),
        final_url: attempted_url.clone(),
        status: None,
        server: None,
        tls: if scheme == "https" { "error" } else { "n/a" }.to_string(),
        error: None,
        php_detected: false,
        php_version: None,
        php_signals: Vec::new(),
        wordpress_detected: false,
        wordpress_version: None,
        wordpress_signals: Vec::new(),
        php_apps: Vec::new(),
        tailwind_detected: false,
        tailwind_confidence: "none".to_string(),
        tailwind_signals: Vec::new(),
        fetch_method: fetch_mode.as_str().to_string(),
        head_status: None,
    };
    match fetch_mode {
        FetchMode::Get => {
            // Existing behavior: a single GET, never a HEAD.
            match fetch_get(client, &attempted_url, body_cap).await {
                Ok((status, final_url, headers, preview)) => {
                    fill_success(&mut record, scheme, status, final_url, &headers, &preview, "get");
                }
                Err(err) => {
                    record.error = Some(classify_error(&err).to_string());
                }
            }
        }
        FetchMode::Head => {
            // A single HEAD, never a GET — even on failure.
            match fetch_head(client, &attempted_url).await {
                Ok((status, final_url, headers)) => {
                    record.head_status = Some(status);
                    if status == 405 || status == 501 {
                        fill_head_success(&mut record, scheme, status, final_url, &headers);
                        record.error = Some("other".to_string());
                    } else {
                        fill_head_success(&mut record, scheme, status, final_url, &headers);
                    }
                }
                Err(err) => {
                    record.error = Some(classify_error(&err).to_string());
                }
            }
        }
        FetchMode::Both => {
            // HEAD first, then GET always, in that order — never skip the GET.
            let head = fetch_head(client, &attempted_url).await;
            let head_failed = head_failed_for_fallback(&head);
            let (head_headers, head_status) = match &head {
                Ok((status, _, headers)) => (Some(headers.clone()), Some(*status)),
                Err(_) => (None, None),
            };
            // A 405/501 or transport failure leaves no observable HEAD status:
            // the failure is signalled by `get-fallback` instead.
            if !head_failed {
                record.head_status = head_status;
            }
            match fetch_get(client, &attempted_url, body_cap).await {
                Ok((status, final_url, get_headers, preview)) => {
                    if head_failed {
                        fill_success(&mut record, scheme, status, final_url, &get_headers, &preview, "get-fallback");
                        record.head_status = None;
                    } else if let Some(head_headers) = head_headers {
                        let merged = union_headers(&get_headers, &head_headers);
                        fill_success(&mut record, scheme, status, final_url, &merged, &preview, "both");
                        // `Server` is single-valued, so a HEAD-only PHP marker
                        // would be shadowed by a GET `Server` without it: union
                        // the signal explicitly instead of overwriting it.
                        if server_has_php(&head_headers)
                            && !record.php_signals.contains(&"server".to_string())
                        {
                            record.php_detected = true;
                            record.php_signals.push("server".to_string());
                        }
                    } else {
                        fill_success(&mut record, scheme, status, final_url, &get_headers, &preview, "both");
                    }
                }
                Err(err) => {
                    // Both attempted (or HEAD failed and GET failed): the GET
                    // error decides the record.
                    record.error = Some(classify_error(&err).to_string());
                    if head_failed {
                        record.fetch_method = "get-fallback".to_string();
                        record.head_status = None;
                    } else {
                        record.fetch_method = "both".to_string();
                    }
                }
            }
        }
    }
    record
}

/// Probe one open host:port. `auto` tries HTTPS first and falls back to plain
/// HTTP only when HTTPS fails; `http`/`https` force that scheme alone.
pub async fn probe_target(
    client: &reqwest::Client,
    config: &ProbeConfig,
    ip: IpAddr,
    port: u16,
) -> ProbeRecord {
    match config.scheme {
        Scheme::Http => {
            attempt(client, "http", ip, port, config.body_cap, config.fetch_mode).await
        }
        Scheme::Https => {
            attempt(client, "https", ip, port, config.body_cap, config.fetch_mode).await
        }
        Scheme::Auto => {
            let https = attempt(client, "https", ip, port, config.body_cap, config.fetch_mode).await;
            if https.error.is_none() {
                https
            } else {
                attempt(client, "http", ip, port, config.body_cap, config.fetch_mode).await
            }
        }
    }
}

/// Probe every open target from the scan-output file.
///
/// Mirrors the Phase 1 architecture: the semaphore permit is acquired in this
/// producer loop BEFORE `tokio::spawn`, results travel over a bounded mpsc
/// channel to a single writer task, and records stream out as they arrive —
/// the whole run is never buffered.
pub async fn run(
    config: &ProbeConfig,
    scan_output: &Path,
    output_path: PathBuf,
) -> Result<ProbeStats, Box<dyn std::error::Error + Send + Sync>> {
    let targets = parse_scan_output(scan_output)?;
    if targets.is_empty() {
        eprintln!("ftw: warning: no open ports found in scan output");
    }
    let client = build_client(config)?;
    eprintln!("ftw: probing {} open host:port targets", targets.len());
    let (tx, rx) = mpsc::channel::<ProbeRecord>(CHANNEL_CAPACITY);
    let writer = tokio::spawn(output::run_probe_writer(rx, output_path));
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
        tokio::spawn(async move {
            let record = probe_target(&client, &config, ip, port).await;
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

    fn temp_tag(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("ftw-{prefix}-{nanos}-{}", std::process::id())
    }

    fn test_config(scheme: Scheme) -> ProbeConfig {
        ProbeConfig {
            concurrency: 4,
            timeout: Duration::from_secs(5),
            scheme,
            insecure: false,
            max_redirects: 5,
            body_cap: 8192,
            fetch_mode: FetchMode::Get,
        }
    }

    fn test_config_with_mode(scheme: Scheme, fetch_mode: FetchMode) -> ProbeConfig {
        ProbeConfig {
            fetch_mode,
            ..test_config(scheme)
        }
    }

    /// Minimal HTTP/1.1 origin server: one fixed 200 response (plus
    /// `Content-Length` and `Connection: close`) for every connection.
    /// Reads the request first so TLS ClientHello bytes do not cause a RST.
    async fn spawn_test_server(
        headers: Vec<(String, String)>,
        body: &'static str,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
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
                let headers = headers.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
                    let mut response = String::from("HTTP/1.1 200 OK\r\n");
                    for (name, value) in &headers {
                        response.push_str(&format!("{name}: {value}\r\n"));
                    }
                    response.push_str(&format!(
                        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ));
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (addr, handle)
    }

    /// A port nothing listens on (bind-then-drop, loopback only).
    async fn closed_port() -> u16 {
        let tmp = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind temp port");
        tmp.local_addr().expect("temp addr").port()
    }

    fn read_json_lines(path: &Path) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(path).expect("read probe output");
        text.lines()
            .map(|line| serde_json::from_str(line).expect("output line is JSON"))
            .collect()
    }

    #[test]
    fn scan_text_keeps_only_open_and_dedups() {
        let targets = parse_scan_text(
            "127.0.0.1:80 open\n127.0.0.1:80 open\n127.0.0.1:443 closed\n127.0.0.1:22 filtered\n\n",
        )
        .expect("parse scan text");
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0],
            ("127.0.0.1".parse().unwrap(), 80),
            "only the open entry survives, deduplicated"
        );
    }

    #[test]
    fn fingerprint_server_signal_and_redirect_to_php() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "MyPHPServer/1.0".parse().unwrap());
        let (detected, version, signals) =
            fingerprint(&headers, "http://127.0.0.1:80/index.php?x=1");
        assert!(detected);
        assert_eq!(version, None, "no X-Powered-By means no version is invented");
        assert_eq!(signals, vec!["server", "redirect-to-php"]);
    }

    #[test]
    fn fingerprint_rejects_unparseable_powered_by_version() {
        let mut headers = HeaderMap::new();
        headers.insert("x-powered-by", "PHP/8.2".parse().unwrap());
        let (detected, version, signals) =
            fingerprint(&headers, "http://127.0.0.1:80/");
        assert!(detected);
        assert_eq!(version, None, "PHP/8.2 is not major.minor.patch");
        assert_eq!(signals, vec!["x-powered-by"]);
    }

    /// End-to-end: fake scan output with one open port (plus a duplicate open
    /// line and one closed entry) yields exactly one record with status 200
    /// and the test Server header — closed entries are never probed.
    #[tokio::test]
    async fn probe_records_open_port_and_skips_closed() {
        let tag = temp_tag("probe-open");
        let dir = std::env::temp_dir();
        let scan_path = dir.join(format!("{tag}.scan"));
        let out_path = dir.join(format!("{tag}.out"));
        let (server_addr, server) =
            spawn_test_server(vec![("Server".into(), "TestServer/1.0".into())], "hello").await;
        let open_port = server_addr.port();
        let closed = closed_port().await;
        std::fs::write(
            &scan_path,
            format!(
                "127.0.0.1:{open_port} open\n127.0.0.1:{open_port} open\n127.0.0.1:{closed} closed\n"
            ),
        )
        .expect("write fake scan output");

        let stats = run(&test_config(Scheme::Http), &scan_path, out_path.clone())
            .await
            .expect("probe run");
        server.abort();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.http, 1);

        let records = read_json_lines(&out_path);
        assert_eq!(records.len(), 1, "exactly one record for the open port");
        let record = &records[0];
        assert_eq!(record["ip"], "127.0.0.1");
        assert_eq!(record["port"], open_port);
        assert_eq!(record["scheme"], "http");
        assert_eq!(record["status"], 200);
        assert_eq!(record["server"], "TestServer/1.0");
        assert_eq!(record["tls"], "n/a");
        assert!(record["error"].is_null());

        std::fs::remove_file(&scan_path).ok();
        std::fs::remove_file(&out_path).ok();
    }

    /// Probing a plain-HTTP server with `--scheme https` records a TLS error
    /// instead of crashing or reporting a connect failure.
    #[tokio::test]
    async fn probe_https_against_plain_http_records_tls_error() {
        let tag = temp_tag("probe-tls");
        let dir = std::env::temp_dir();
        let scan_path = dir.join(format!("{tag}.scan"));
        let out_path = dir.join(format!("{tag}.out"));
        let (server_addr, server) =
            spawn_test_server(vec![("Server".into(), "TestServer/1.0".into())], "hello").await;
        let open_port = server_addr.port();
        std::fs::write(&scan_path, format!("127.0.0.1:{open_port} open\n"))
            .expect("write fake scan output");

        let stats = run(&test_config(Scheme::Https), &scan_path, out_path.clone())
            .await
            .expect("probe run must not crash");
        server.abort();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.tls_errors, 1, "stats: {stats:?}");

        let records = read_json_lines(&out_path);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["scheme"], "https");
        assert!(record["status"].is_null());
        assert!(record["server"].is_null());
        assert_eq!(record["tls"], "error");
        assert_eq!(record["error"], "tls_error");

        std::fs::remove_file(&scan_path).ok();
        std::fs::remove_file(&out_path).ok();
    }

    /// `X-Powered-By: PHP/8.2.0` plus a `PHPSESSID` cookie fingerprints PHP
    /// with the parsed version — from the single GET response only.
    #[tokio::test]
    async fn probe_detects_php_from_headers_and_cookie() {
        let tag = temp_tag("probe-php");
        let dir = std::env::temp_dir();
        let scan_path = dir.join(format!("{tag}.scan"));
        let out_path = dir.join(format!("{tag}.out"));
        let (server_addr, server) = spawn_test_server(
            vec![
                ("Server".into(), "Apache".into()),
                ("X-Powered-By".into(), "PHP/8.2.0".into()),
                ("Set-Cookie".into(), "PHPSESSID=abc123; path=/".into()),
            ],
            "hello",
        )
        .await;
        std::fs::write(&scan_path, format!("127.0.0.1:{} open\n", server_addr.port()))
            .expect("write fake scan output");

        let stats = run(&test_config(Scheme::Http), &scan_path, out_path.clone())
            .await
            .expect("probe run");
        server.abort();
        assert_eq!(stats.php_detected, 1);

        let records = read_json_lines(&out_path);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["php_detected"], true);
        assert_eq!(record["php_version"], "8.2.0");
        assert_eq!(record["php_signals"], serde_json::json!(["x-powered-by", "phpsessid-cookie"]));

        std::fs::remove_file(&scan_path).ok();
        std::fs::remove_file(&out_path).ok();
    }

    /// No PHP headers or cookies means unconfirmed — never "not PHP", just
    /// `php_detected: false` with empty signals and no version.
    #[tokio::test]
    async fn probe_reports_no_php_without_signals() {
        let tag = temp_tag("probe-nophp");
        let dir = std::env::temp_dir();
        let scan_path = dir.join(format!("{tag}.scan"));
        let out_path = dir.join(format!("{tag}.out"));
        let (server_addr, server) =
            spawn_test_server(vec![("Server".into(), "TestServer/1.0".into())], "hello").await;
        std::fs::write(&scan_path, format!("127.0.0.1:{} open\n", server_addr.port()))
            .expect("write fake scan output");

        let stats = run(&test_config(Scheme::Http), &scan_path, out_path.clone())
            .await
            .expect("probe run");
        server.abort();
        assert_eq!(stats.php_not_detected, 1);

        let records = read_json_lines(&out_path);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["php_detected"], false);
        assert!(record["php_version"].is_null());
        assert_eq!(record["php_signals"], serde_json::json!([]));

        std::fs::remove_file(&scan_path).ok();
        std::fs::remove_file(&out_path).ok();
    }

    /// Test origin server that records every request path it sees, so tests
    /// can prove probe made no request beyond the single `GET /` per scheme
    /// attempt (never `/wp-admin`, `/wp-login.php`, `/phpinfo.php`, ...).
    async fn spawn_path_logging_server(
        body: &'static str,
    ) -> (
        SocketAddr,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind path-logging server");
        let addr = listener.local_addr().expect("path-logging addr");
        let paths = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen = paths.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if let Some(line) = text.lines().next() {
                        let mut parts = line.split_whitespace();
                        if let (Some(method), Some(path)) = (parts.next(), parts.next()) {
                            if method == "GET" {
                                seen.lock().expect("path log").push(path.to_string());
                            }
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (addr, paths, handle)
    }

    fn assert_only_root_request(paths: &std::sync::Mutex<Vec<String>>) {
        let logged = paths.lock().expect("path log").clone();
        assert_eq!(logged, vec!["/".to_string()], "only GET / is ever requested, got: {logged:?}");
        for forbidden in [
            "/wp-admin",
            "/wp-login.php",
            "/phpinfo.php",
            "/readme.html",
            "/xmlrpc.php",
        ] {
            assert!(
                !logged.iter().any(|path| path.contains(forbidden)),
                "forbidden path {forbidden} was requested: {logged:?}"
            );
        }
    }

    async fn run_single_tech_probe(
        tag: String,
        body: &'static str,
    ) -> (
        serde_json::Value,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        String,
    ) {
        let dir = std::env::temp_dir();
        let scan_path = dir.join(format!("{tag}.scan"));
        let out_path = dir.join(format!("{tag}.out"));
        let (addr, paths, server) = spawn_path_logging_server(body).await;
        std::fs::write(&scan_path, format!("127.0.0.1:{} open\n", addr.port()))
            .expect("write fake scan output");
        run(&test_config(Scheme::Http), &scan_path, out_path.clone())
            .await
            .expect("probe run");
        server.abort();
        let records = read_json_lines(&out_path);
        assert_eq!(records.len(), 1);
        let record = records.into_iter().next().expect("one record");
        let raw = std::fs::read_to_string(&out_path).expect("read raw output");
        std::fs::remove_file(&scan_path).ok();
        std::fs::remove_file(&out_path).ok();
        (record, paths, raw)
    }

    /// WordPress fixture: generator `WordPress 6.5.2` plus a `/wp-content/`
    /// script. No WooCommerce app entry is reported.
    #[tokio::test]
    async fn probe_detects_wordpress_with_version() {
        let body = "<html><head><meta name=\"generator\" content=\"WordPress 6.5.2\" /><script src=\"/wp-content/themes/t/app.js\"></script></head><body>hi</body></html>";
        let (record, paths, raw) = run_single_tech_probe(temp_tag("probe-wp"), body).await;
        assert_eq!(record["wordpress_detected"], true);
        assert_eq!(record["wordpress_version"], "6.5.2");
        let signals = record["wordpress_signals"].as_array().expect("signals array");
        assert!(signals.contains(&serde_json::json!("generator")));
        assert!(signals.contains(&serde_json::json!("wp-content")));
        assert_eq!(record["php_apps"], serde_json::json!([]));
        assert!(!raw.contains("/wp-content/themes"), "body must never be written to output");
        assert_only_root_request(&paths);
    }

    /// Joomla fixture produces the Joomla `php_apps` entry with its version.
    #[tokio::test]
    async fn probe_detects_joomla_app_with_version() {
        let body = "<html><head><meta name=\"generator\" content=\"Joomla! 4.2.5\" /><script src=\"/media/system/js/core.js\"></script></head><body>hi</body></html>";
        let (record, paths, _) = run_single_tech_probe(temp_tag("probe-joomla"), body).await;
        assert_eq!(record["wordpress_detected"], false);
        let apps = record["php_apps"].as_array().expect("php_apps array");
        let joomla = apps.iter().find(|app| app["name"] == "Joomla").expect("Joomla entry");
        assert_eq!(joomla["version"], "4.2.5");
        assert!(!joomla["signals"].as_array().expect("signals").is_empty());
        assert_only_root_request(&paths);
    }

    /// Drupal fixture produces the Drupal `php_apps` entry with its version.
    #[tokio::test]
    async fn probe_detects_drupal_app_with_version() {
        let body = "<html><head><meta name=\"generator\" content=\"Drupal 10\" /><script src=\"/sites/default/files/js/app.js\"></script></head><body>hi</body></html>";
        let (record, paths, _) = run_single_tech_probe(temp_tag("probe-drupal"), body).await;
        assert_eq!(record["wordpress_detected"], false);
        let apps = record["php_apps"].as_array().expect("php_apps array");
        let drupal = apps.iter().find(|app| app["name"] == "Drupal").expect("Drupal entry");
        assert_eq!(drupal["version"], "10");
        assert!(!drupal["signals"].as_array().expect("signals").is_empty());
        assert_only_root_request(&paths);
    }

    /// Plain HTML with no markers: no WordPress, no apps, Tailwind `"none"`.
    #[tokio::test]
    async fn probe_plain_html_has_no_tech_signals() {
        let body = "<html><head><title>Plain</title></head><body><p>hello</p></body></html>";
        let (record, paths, raw) = run_single_tech_probe(temp_tag("probe-plain"), body).await;
        assert_eq!(record["wordpress_detected"], false);
        assert!(record["wordpress_version"].is_null());
        assert_eq!(record["wordpress_signals"], serde_json::json!([]));
        assert_eq!(record["php_apps"], serde_json::json!([]));
        assert_eq!(record["tailwind_detected"], false);
        assert_eq!(record["tailwind_confidence"], "none");
        assert_eq!(record["tailwind_signals"], serde_json::json!([]));
        assert!(!raw.contains("<p>"), "body must never be written to output");
        assert_only_root_request(&paths);
    }

    /// Tailwind CDN script is a strong signal: detected with confidence strong.
    #[tokio::test]
    async fn probe_detects_tailwind_cdn_as_strong() {
        let body = "<html><head><script src=\"https://cdn.tailwindcss.com\"></script></head><body><div class=\"flex items-center justify-center\">hi</div></body></html>";
        let (record, paths, _) = run_single_tech_probe(temp_tag("probe-tw"), body).await;
        assert_eq!(record["tailwind_detected"], true);
        assert_eq!(record["tailwind_confidence"], "strong");
        let signals = record["tailwind_signals"].as_array().expect("signals array");
        assert!(signals.contains(&serde_json::json!("tailwind-cdn")));
        assert_only_root_request(&paths);
    }

    fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            405 => "Method Not Allowed",
            501 => "Not Implemented",
            _ => "Status",
        }
    }

    /// Origin server that routes by method and records every
    /// `(method, path)`: HEAD answers with a fixed status/headers and no
    /// body; any other method answers 200 with fixed headers/body. Proves
    /// the HEAD-first request pattern without extra paths.
    async fn spawn_method_server(
        head_status: u16,
        head_headers: Vec<(String, String)>,
        get_headers: Vec<(String, String)>,
        get_body: &'static str,
    ) -> (
        SocketAddr,
        std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind method server");
        let addr = listener.local_addr().expect("method server addr");
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let seen = log.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let seen = seen.clone();
                let head_headers = head_headers.clone();
                let get_headers = get_headers.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    let (method, path) = text
                        .lines()
                        .next()
                        .and_then(|line| {
                            let mut parts = line.split_whitespace();
                            Some((parts.next()?.to_string(), parts.next()?.to_string()))
                        })
                        .unwrap_or_default();
                    if !method.is_empty() {
                        seen.lock().expect("method log").push((method.clone(), path));
                    }
                    let response = if method == "HEAD" {
                        let mut response = format!(
                            "HTTP/1.1 {head_status} {}\r\n",
                            reason_phrase(head_status)
                        );
                        for (name, value) in &head_headers {
                            response.push_str(&format!("{name}: {value}\r\n"));
                        }
                        response.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
                        response
                    } else {
                        let mut response = String::from("HTTP/1.1 200 OK\r\n");
                        for (name, value) in &get_headers {
                            response.push_str(&format!("{name}: {value}\r\n"));
                        }
                        response.push_str(&format!(
                            "Content-Length: {}\r\nConnection: close\r\n\r\n{get_body}",
                            get_body.len()
                        ));
                        response
                    };
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (addr, log, handle)
    }

    async fn run_fetch_probe(
        tag: String,
        fetch_mode: FetchMode,
        head_status: u16,
        head_headers: Vec<(String, String)>,
        get_headers: Vec<(String, String)>,
        get_body: &'static str,
    ) -> (
        serde_json::Value,
        Vec<(String, String)>,
        String,
    ) {
        let dir = std::env::temp_dir();
        let scan_path = dir.join(format!("{tag}.scan"));
        let out_path = dir.join(format!("{tag}.out"));
        let (addr, log, server) =
            spawn_method_server(head_status, head_headers, get_headers, get_body).await;
        std::fs::write(&scan_path, format!("127.0.0.1:{} open\n", addr.port()))
            .expect("write fake scan output");
        run(
            &test_config_with_mode(Scheme::Http, fetch_mode),
            &scan_path,
            out_path.clone(),
        )
        .await
        .expect("probe run");
        server.abort();
        let records = read_json_lines(&out_path);
        assert_eq!(records.len(), 1);
        let record = records.into_iter().next().expect("one record");
        let raw = std::fs::read_to_string(&out_path).expect("read raw output");
        let logged = log.lock().expect("method log").clone();
        std::fs::remove_file(&scan_path).ok();
        std::fs::remove_file(&out_path).ok();
        (record, logged, raw)
    }

    fn assert_only_root_requests(log: &[(String, String)]) {
        assert!(!log.is_empty(), "expected at least one request");
        for (method, path) in log {
            assert!(
                method == "HEAD" || method == "GET",
                "unexpected method {method}"
            );
            assert_eq!(path, "/", "unexpected path {path}");
        }
        for forbidden in [
            "/wp-admin",
            "/wp-login.php",
            "/phpinfo.php",
            "/readme.html",
            "/xmlrpc.php",
        ] {
            assert!(
                !log.iter().any(|(_, path)| path.contains(forbidden)),
                "forbidden path {forbidden} requested in {log:?}"
            );
        }
    }

    /// An invalid `--fetch-mode` value is rejected by clap before any probing.
    #[test]
    fn invalid_fetch_mode_rejected_before_probing() {
        use clap::Parser as _;
        #[derive(Debug, clap::Parser)]
        struct ModeCli {
            #[arg(long, value_enum)]
            fetch_mode: FetchMode,
        }
        let result =
            ModeCli::try_parse_from(["mode-cli", "--fetch-mode", "bogus"]);
        assert!(result.is_err(), "bogus fetch mode must be rejected");
        let message = result.expect_err("rejected").to_string();
        assert!(
            message.contains("fetch-mode") || message.contains("bogus"),
            "usage error must name the flag or value, got: {message}"
        );
    }

    /// `FetchMode` defaults to `get`: the no-flag behavior sends one GET.
    #[test]
    fn fetch_mode_defaults_to_get() {
        assert_eq!(FetchMode::default(), FetchMode::Get);
        assert_eq!(FetchMode::Get.as_str(), "get");
        assert_eq!(test_config(Scheme::Http).fetch_mode, FetchMode::Get);
    }

    /// Default (`get`) mode sends exactly one GET to `/`: no HEAD is recorded
    /// and `head_status` stays null.
    #[tokio::test]
    async fn default_get_mode_sends_single_get() {
        let get_body = "<html><head><title>Plain</title></head><body><p>get-marker</p></body></html>";
        let (record, log, raw) = run_fetch_probe(
            temp_tag("probe-getdefault"),
            FetchMode::Get,
            200,
            Vec::new(),
            Vec::new(),
            get_body,
        )
        .await;
        assert_eq!(record["fetch_method"], "get");
        assert!(record["head_status"].is_null());
        assert_eq!(record["status"], 200);
        assert!(record["error"].is_null());
        assert_eq!(log, vec![("GET".to_string(), "/".to_string())]);
        assert!(!raw.contains("get-marker"), "body must never be written");
        assert_only_root_requests(&log);
    }

    /// `head` mode sends exactly one HEAD: the WordPress `Link` header fixture
    /// is detected from headers alone.
    #[tokio::test]
    async fn head_mode_detects_wordpress_link_header() {
        let head_headers = vec![(
            "Link".to_string(),
            "<https://example.com/wp-json/>; rel=\"https://api.w.org/\"".to_string(),
        )];
        let get_body = "<html><head><title>Never fetched</title></head><body><p>head-body-marker</p></body></html>";
        let (record, log, raw) = run_fetch_probe(
            temp_tag("probe-headwp"),
            FetchMode::Head,
            200,
            head_headers,
            Vec::new(),
            get_body,
        )
        .await;
        assert_eq!(record["fetch_method"], "head");
        assert_eq!(record["head_status"], 200);
        assert_eq!(record["status"], 200);
        assert!(record["error"].is_null());
        assert_eq!(record["wordpress_detected"], true);
        assert!(
            record["wordpress_signals"]
                .as_array()
                .expect("signals")
                .contains(&serde_json::json!("wp-json"))
        );
        assert_eq!(record["php_apps"], serde_json::json!([]));
        assert_eq!(log, vec![("HEAD".to_string(), "/".to_string())]);
        assert!(!raw.contains("head-body-marker"));
        assert_only_root_requests(&log);
    }

    /// `head` mode cannot see HTML signals: a WordPress-HTML-only fixture
    /// (no identifying headers) must NOT be detected.
    #[tokio::test]
    async fn head_mode_ignores_html_only_wordpress() {
        let get_body = "<html><head><meta name=\"generator\" content=\"WordPress 6.5.2\" /><script src=\"/wp-content/themes/t/app.js\"></script></head><body><p>head-body-marker</p></body></html>";
        let (record, log, raw) = run_fetch_probe(
            temp_tag("probe-headhtml"),
            FetchMode::Head,
            200,
            Vec::new(),
            Vec::new(),
            get_body,
        )
        .await;
        assert_eq!(record["fetch_method"], "head");
        assert_eq!(record["head_status"], 200);
        assert!(record["error"].is_null());
        assert_eq!(record["wordpress_detected"], false);
        assert_eq!(record["wordpress_signals"], serde_json::json!([]));
        assert!(record["wordpress_version"].is_null());
        assert_eq!(record["php_apps"], serde_json::json!([]));
        assert_eq!(record["tailwind_detected"], false);
        assert_eq!(record["tailwind_confidence"], "none");
        assert_eq!(record["tailwind_signals"], serde_json::json!([]));
        assert_eq!(log, vec![("HEAD".to_string(), "/".to_string())]);
        assert!(!raw.contains("head-body-marker"));
        assert_only_root_requests(&log);
    }

    /// `both` mode sends HEAD then GET and unions signals: the PHP header on
    /// HEAD plus the WordPress HTML on GET yield both detections.
    #[tokio::test]
    async fn both_mode_unions_php_head_and_wordpress_get() {
        let head_headers = vec![("X-Powered-By".to_string(), "PHP/8.2.0".to_string())];
        let get_body = "<html><head><meta name=\"generator\" content=\"WordPress 6.5.2\" /><script src=\"/wp-content/themes/t/app.js\"></script></head><body><p>both-marker</p></body></html>";
        let (record, log, raw) = run_fetch_probe(
            temp_tag("probe-bothunion"),
            FetchMode::Both,
            200,
            head_headers,
            Vec::new(),
            get_body,
        )
        .await;
        assert_eq!(record["fetch_method"], "both");
        assert_eq!(record["head_status"], 200);
        assert_eq!(record["status"], 200);
        assert!(record["error"].is_null());
        assert_eq!(record["php_detected"], true);
        assert_eq!(record["php_version"], "8.2.0");
        assert!(
            record["php_signals"]
                .as_array()
                .expect("signals")
                .contains(&serde_json::json!("x-powered-by"))
        );
        assert_eq!(record["wordpress_detected"], true);
        assert_eq!(record["wordpress_version"], "6.5.2");
        assert_eq!(
            log,
            vec![
                ("HEAD".to_string(), "/".to_string()),
                ("GET".to_string(), "/".to_string()),
            ]
        );
        assert!(!raw.contains("both-marker"), "body must never be written");
        assert_only_root_requests(&log);
    }

    /// `both` mode with HEAD 405 still runs the GET: `get-fallback` with a
    /// null `head_status` so the HEAD failure stays observable.
    #[tokio::test]
    async fn both_mode_head_405_still_gets_with_fallback() {
        let get_body = "<html><head><title>Plain</title></head><body><p>both-405-marker</p></body></html>";
        let (record, log, raw) = run_fetch_probe(
            temp_tag("probe-both405"),
            FetchMode::Both,
            405,
            Vec::new(),
            Vec::new(),
            get_body,
        )
        .await;
        assert_eq!(record["fetch_method"], "get-fallback");
        assert!(record["head_status"].is_null());
        assert_eq!(record["status"], 200);
        assert!(record["error"].is_null());
        assert_eq!(record["wordpress_detected"], false);
        assert_eq!(record["php_apps"], serde_json::json!([]));
        assert_eq!(
            log,
            vec![
                ("HEAD".to_string(), "/".to_string()),
                ("GET".to_string(), "/".to_string()),
            ]
        );
        assert!(!raw.contains("both-405-marker"));
        assert_only_root_requests(&log);
    }

    /// `head` mode with HEAD 405 records an error and never sends the GET.
    #[tokio::test]
    async fn head_mode_head_405_records_error_without_get() {
        let get_body = "<html><head><title>Plain</title></head><body><p>head-405-marker</p></body></html>";
        let (record, log, _) = run_fetch_probe(
            temp_tag("probe-head405"),
            FetchMode::Head,
            405,
            Vec::new(),
            Vec::new(),
            get_body,
        )
        .await;
        assert_eq!(record["fetch_method"], "head");
        assert_eq!(record["head_status"], 405);
        assert!(!record["error"].is_null(), "HEAD 405 must record an error");
        assert_eq!(log, vec![("HEAD".to_string(), "/".to_string())]);
        assert_only_root_requests(&log);
    }
}
