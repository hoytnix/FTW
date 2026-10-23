//! HTTP/HTTPS fingerprinting logic for Phase 2 (`ftw fingerprint`).
//!
//! Input is the master SQLite database ONLY: `scan_results` rows marked
//! `open` by `ftw scan`. Closed and filtered ports are never re-probed, the
//! original YAML targets file is never re-expanded, and no port absent from
//! the database is ever probed. Results are upserted back into the same
//! database (`fingerprint_results`) — there are no output files.
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
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use tokio::sync::{Semaphore, mpsc};

use crate::output;
use crate::tech;

const CHANNEL_CAPACITY: usize = 1024;

/// Which scheme(s) to try.
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

/// Runtime settings for a fingerprint run.
#[derive(Debug, Clone, Copy)]
pub struct FingerprintConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    pub scheme: Scheme,
    pub insecure: bool,
    pub max_redirects: usize,
    pub body_cap: usize,
    pub fetch_mode: FetchMode,
    /// Disable the prefer-HTTPS queue deduplication (`--no-prefer-https`):
    /// fingerprint every open port, with no 80/443 skipping and no fallback.
    pub no_prefer_https: bool,
}

/// One JSON-lines fingerprint record.
///
/// `status`/`server` are `None` when no HTTP response was received; `error`
/// is `None` exactly when a response was received (`http` outcome).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FingerprintRecord {
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

/// Aggregate counts for one fingerprint run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintStats {
    pub total: usize,
    pub http: usize,
    pub tls_errors: usize,
    pub connect_errors: usize,
    pub timeouts: usize,
    pub other_errors: usize,
    pub php_detected: usize,
    pub php_not_detected: usize,
    /// Open ports skipped by prefer-HTTPS deduplication (80s with a
    /// same-IP 443 also open). Skipped ports never produce a record.
    pub skipped_prefer_https: usize,
    /// Port-80 records fingerprinted only because the preferred 443 attempt
    /// failed outright (no HTTP status; timeout, TLS, or connect error).
    pub fallback_to_http: usize,
}

impl FingerprintStats {
    pub(crate) fn record(&mut self, result: &FingerprintRecord) {
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

/// One stderr summary line for a fingerprint run, including the prefer-HTTPS
/// deduplication counts. Kept as a function (instead of inline in the CLI
/// wiring) so tests can assert the exact tokens without spawning the binary.
#[must_use]
pub fn format_summary(stats: &FingerprintStats) -> String {
    format!(
        "ftw: fingerprinted {} targets: {} http, {} tls errors, {} connect errors, {} timeouts, {} other errors; php detected on {}, not detected on {}; skipped_prefer_https={}, fallback_to_http={}",
        stats.total,
        stats.http,
        stats.tls_errors,
        stats.connect_errors,
        stats.timeouts,
        stats.other_errors,
        stats.php_detected,
        stats.php_not_detected,
        stats.skipped_prefer_https,
        stats.fallback_to_http,
    )
}

/// Open `(ip, port)` targets in sorted queue order.
pub type OpenTargets = Vec<(IpAddr, u16)>;

/// Prefer-HTTPS queue deduplication: split open `(ip, port)` targets into
/// `(to_fingerprint, skipped)`.
///
/// When one IP has BOTH port 80 and port 443 open, only 443 is fingerprinted
/// and the port-80 entry is skipped (no record, no crawl seed; the
/// `scan_results` row is untouched). Nothing else is deduplicated: any other
/// port pair (8080/8443, 80/8080, 443/8443, ...) keeps both ports, lone 80s
/// and lone 443s are fingerprinted normally, and different IPs never share a
/// decision even when they resolve to the same hostname. Both lists are
/// sorted for a deterministic queue order.
#[must_use]
pub fn split_prefer_https_targets(targets: &[(IpAddr, u16)]) -> (OpenTargets, OpenTargets) {
    let open: HashSet<(IpAddr, u16)> = targets.iter().copied().collect();
    let mut primary = Vec::new();
    let mut skipped = Vec::new();
    let mut ordered: OpenTargets = targets.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    for (ip, port) in ordered {
        if port == 80 && open.contains(&(ip, 443)) {
            skipped.push((ip, port));
        } else {
            primary.push((ip, port));
        }
    }
    (primary, skipped)
}

/// True when the preferred-443 attempt failed outright and port 80 must be
/// fingerprinted once as a fallback: no HTTP status was recorded at all and
/// the error is a transport failure (`timeout`, `tls_error`, or
/// `connect_error`). ANY recorded status — including 400, 404, or 500 — is a
/// completed fingerprint and never falls back.
fn needs_http_fallback(record: &FingerprintRecord) -> bool {
    record.status.is_none()
        && matches!(
            record.error.as_deref(),
            Some("timeout") | Some("tls_error") | Some("connect_error")
        )
}

/// Build the shared HTTP client: clear FTW User-Agent, per-attempt timeout,
/// redirect limit, and opt-in acceptance of invalid certificates (only for
/// your own self-signed hosts).
fn build_client(config: &FingerprintConfig) -> Result<reqwest::Client, reqwest::Error> {
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
/// — never a closed port or a connect failure. Shared with the crawler and
/// the prober so all subcommands report the same error kinds.
pub fn classify_error(err: &reqwest::Error) -> &'static str {
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
/// the output record. Larger pages are not fully fetched: only the first
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
    record: &mut FingerprintRecord,
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
    record: &mut FingerprintRecord,
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

/// Fingerprint one host:port over `scheme` with the explicit fetch mode: `get`
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
) -> FingerprintRecord {
    let attempted_url = format!("{scheme}://{}/", SocketAddr::new(ip, port));
    let mut record = FingerprintRecord {
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

/// Fingerprint one open host:port. `auto` tries HTTPS first and falls back to plain
/// HTTP only when HTTPS fails; `http`/`https` force that scheme alone.
pub async fn fingerprint_target(
    client: &reqwest::Client,
    config: &FingerprintConfig,
    ip: IpAddr,
    port: u16,
) -> FingerprintRecord {
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

/// Fingerprint every open target recorded in the master database.
///
/// Mirrors the Phase 1 architecture: the semaphore permit is acquired in this
/// producer loop BEFORE `tokio::spawn`, results travel over a bounded mpsc
/// channel to a single writer task, and records stream out as they arrive —
/// the whole run is never buffered.
///
/// The database is opened once here, seeds are read, and the single
/// connection is moved into the writer task — the only task that writes.
/// Fingerprint workers never open connections or write directly.
#[allow(dead_code)]
pub async fn run(
    config: &FingerprintConfig,
    db_path: PathBuf,
) -> Result<FingerprintStats, Box<dyn std::error::Error + Send + Sync>> {
    run_with_options(config, db_path, output::OutputOptions::default()).await
}

/// Same as [`run`], with live-output options for the single writer task.
/// The writer remains the only place that prints per-event output; fingerprint
/// tasks never print directly.
///
/// Prefer-HTTPS deduplication applies unless the run opts out with
/// `no_prefer_https` or forces plain HTTP with `Scheme::Http`: an IP with
/// both 80 and 443 open fingerprints only 443 (over HTTPS — never a
/// plain-HTTP request to port 443), the skipped port 80 produces no record,
/// and a 443 transport failure falls back to port 80 exactly once.
pub async fn run_with_options(
    config: &FingerprintConfig,
    db_path: PathBuf,
    options: output::OutputOptions,
) -> Result<FingerprintStats, Box<dyn std::error::Error + Send + Sync>> {
    let conn = crate::db::open(&db_path)?;
    let targets = crate::db::open_ports(&conn)?;
    if targets.is_empty() {
        eprintln!("ftw: warning: no open ports found in database");
    }
    // An explicit `--scheme http` run disables prefer-HTTPS entirely: the
    // user asked for plain HTTP on every port, so both 80 and 443 are
    // fingerprinted as requested with no skipping and no fallback.
    let prefer = !config.no_prefer_https && config.scheme != Scheme::Http;
    let (primary, skipped) = if prefer {
        split_prefer_https_targets(&targets)
    } else {
        (targets, Vec::new())
    };
    // Skipped ports are reported here, up front, so they are obvious from
    // verbose output alone even though they never produce a record. Skipped
    // ports never reach the database: only actually fingerprinted ports
    // (including fallback attempts) are sent to the writer.
    if options.verbose {
        for (ip, port) in &skipped {
            eprintln!("skipped {ip}:{port} (prefer 443)");
        }
    }
    let skipped_ips: HashSet<IpAddr> = skipped.iter().map(|(ip, _)| *ip).collect();
    let fallbacks = Arc::new(AtomicUsize::new(0));
    let client = build_client(config)?;
    eprintln!("ftw: fingerprinting {} open host:port targets", primary.len());
    let (tx, rx) = mpsc::channel::<FingerprintRecord>(CHANNEL_CAPACITY);
    let writer =
        tokio::spawn(async move { output::run_fingerprint_db_writer(rx, conn, options).await });
    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
    for (ip, port) in primary {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("fingerprint semaphore never closes while fingerprinting");
        let tx = tx.clone();
        let client = client.clone();
        let config = *config;
        let preferred = prefer && port == 443 && skipped_ips.contains(&ip);
        let fallbacks = fallbacks.clone();
        tokio::spawn(async move {
            if preferred {
                // The deduped port: HTTPS only, so a plain-HTTP request is
                // never sent to port 443. One permit covers the whole
                // sequence, and the port-80 fallback runs at most once.
                let record =
                    attempt(&client, "https", ip, port, config.body_cap, config.fetch_mode).await;
                let fallback = needs_http_fallback(&record);
                drop(permit);
                let _ = tx.send(record).await;
                if fallback {
                    let http_record = fingerprint_target(&client, &config, ip, 80).await;
                    fallbacks.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.send(http_record).await;
                }
            } else {
                let record = fingerprint_target(&client, &config, ip, port).await;
                drop(permit);
                let _ = tx.send(record).await;
            }
        });
    }
    drop(tx);
    let mut stats = writer.await??;
    stats.skipped_prefer_https = skipped.len();
    stats.fallback_to_http = fallbacks.load(Ordering::Relaxed);
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
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

    fn test_config(scheme: Scheme) -> FingerprintConfig {
        FingerprintConfig {
            concurrency: 4,
            timeout: Duration::from_secs(5),
            scheme,
            insecure: false,
            max_redirects: 5,
            body_cap: 8192,
            fetch_mode: FetchMode::Get,
            no_prefer_https: false,
        }
    }

    fn test_config_with_mode(scheme: Scheme, fetch_mode: FetchMode) -> FingerprintConfig {
        FingerprintConfig {
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

    fn db_path_for(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{tag}.db"))
    }

    /// Remove a temp database and its WAL sidecars (best effort).
    fn remove_db(db_path: &Path) {
        std::fs::remove_file(db_path).ok();
        std::fs::remove_file(db_path.with_extension("db-wal")).ok();
        std::fs::remove_file(db_path.with_extension("db-shm")).ok();
    }

    /// Seed `scan_results` the way a prior `ftw scan --db` run would.
    fn seed_scan(db_path: &Path, entries: &[(IpAddr, u16, crate::scanner::PortStatus)]) {
        let conn = crate::db::open(db_path).expect("open db");
        for (ip, port, status) in entries {
            crate::db::upsert_scan(
                &conn,
                &crate::scanner::ScanResult {
                    ip: *ip,
                    port: *port,
                    status: *status,
                    reason: status.as_str(),
                },
            )
            .expect("seed scan row");
        }
    }

    /// Read fingerprint rows back as JSON shaped like the old JSON-lines
    /// records, so the detection assertions below are unchanged.
    fn read_fingerprint_records(db_path: &Path) -> Vec<serde_json::Value> {
        let conn = rusqlite::Connection::open(db_path).expect("open db");
        let mut stmt = conn
            .prepare(
                "SELECT ip, port, scheme, final_url, status, server, tls, error,
                        php_detected, php_version, php_signals,
                        wordpress_detected, wordpress_version, wordpress_signals,
                        php_apps, tailwind_detected, tailwind_confidence,
                        tailwind_signals, fetch_method, head_status
                 FROM fingerprint_results ORDER BY port, scheme",
            )
            .expect("prepare query");
        let rows = stmt
            .query_map([], |row| {
                let signals = |index: usize| -> Result<serde_json::Value, rusqlite::Error> {
                    let raw: String = row.get(index)?;
                    Ok(serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null))
                };
                Ok(serde_json::json!({
                    "ip": row.get::<_, String>(0)?,
                    "port": row.get::<_, u16>(1)?,
                    "scheme": row.get::<_, String>(2)?,
                    "final_url": row.get::<_, String>(3)?,
                    "status": row.get::<_, Option<u16>>(4)?,
                    "server": row.get::<_, Option<String>>(5)?,
                    "tls": row.get::<_, String>(6)?,
                    "error": row.get::<_, Option<String>>(7)?,
                    "php_detected": row.get::<_, bool>(8)?,
                    "php_version": row.get::<_, Option<String>>(9)?,
                    "php_signals": signals(10)?,
                    "wordpress_detected": row.get::<_, bool>(11)?,
                    "wordpress_version": row.get::<_, Option<String>>(12)?,
                    "wordpress_signals": signals(13)?,
                    "php_apps": signals(14)?,
                    "tailwind_detected": row.get::<_, bool>(15)?,
                    "tailwind_confidence": row.get::<_, String>(16)?,
                    "tailwind_signals": signals(17)?,
                    "fetch_method": row.get::<_, String>(18)?,
                    "head_status": row.get::<_, Option<u16>>(19)?,
                }))
            })
            .expect("map rows");
        rows.collect::<Result<_, _>>().expect("collect rows")
    }

    /// An empty database fingerprints nothing and stores nothing: seeds come
    /// from the database only, never from a scan-output file.
    #[tokio::test]
    async fn fingerprint_empty_database_fingerprints_nothing() {
        let db_path = db_path_for(&temp_tag("fingerprint-empty"));
        let stats = run(&test_config(Scheme::Http), db_path.clone())
            .await
            .expect("fingerprint run");
        assert_eq!(stats.total, 0);
        assert!(read_fingerprint_records(&db_path).is_empty());
        remove_db(&db_path);
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
    async fn fingerprint_records_open_port_and_skips_closed() {
        let tag = temp_tag("fingerprint-open");
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("{tag}.db"));
        let (server_addr, server) =
            spawn_test_server(vec![("Server".into(), "TestServer/1.0".into())], "hello").await;
        let open_port = server_addr.port();
        let closed = closed_port().await;
        seed_scan(
            &db_path,
            &[
                ("127.0.0.1".parse().unwrap(), open_port, crate::scanner::PortStatus::Open),
                ("127.0.0.1".parse().unwrap(), open_port, crate::scanner::PortStatus::Open),
                ("127.0.0.1".parse().unwrap(), closed, crate::scanner::PortStatus::Closed),
            ],
        );

        let stats = run(&test_config(Scheme::Http), db_path.clone())
            .await
            .expect("fingerprint run");
        server.abort();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.http, 1);

        let records = read_fingerprint_records(&db_path);
        assert_eq!(records.len(), 1, "exactly one record for the open port");
        let record = &records[0];
        assert_eq!(record["ip"], "127.0.0.1");
        assert_eq!(record["port"], open_port);
        assert_eq!(record["scheme"], "http");
        assert_eq!(record["status"], 200);
        assert_eq!(record["server"], "TestServer/1.0");
        assert_eq!(record["tls"], "n/a");
        assert!(record["error"].is_null());

        remove_db(&db_path);
    }

    /// Probing a plain-HTTP server with `--scheme https` records a TLS error
    /// instead of crashing or reporting a connect failure.
    #[tokio::test]
    async fn fingerprint_https_against_plain_http_records_tls_error() {
        let tag = temp_tag("fingerprint-tls");
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("{tag}.db"));
        let (server_addr, server) =
            spawn_test_server(vec![("Server".into(), "TestServer/1.0".into())], "hello").await;
        let open_port = server_addr.port();
        seed_scan(
            &db_path,
            &[("127.0.0.1".parse().unwrap(), open_port, crate::scanner::PortStatus::Open)],
        );

        let stats = run(&test_config(Scheme::Https), db_path.clone())
            .await
            .expect("fingerprint run must not crash");
        server.abort();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.tls_errors, 1, "stats: {stats:?}");

        let records = read_fingerprint_records(&db_path);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["scheme"], "https");
        assert!(record["status"].is_null());
        assert!(record["server"].is_null());
        assert_eq!(record["tls"], "error");
        assert_eq!(record["error"], "tls_error");

        remove_db(&db_path);
    }

    /// `X-Powered-By: PHP/8.2.0` plus a `PHPSESSID` cookie fingerprints PHP
    /// with the parsed version — from the single GET response only.
    #[tokio::test]
    async fn fingerprint_detects_php_from_headers_and_cookie() {
        let tag = temp_tag("fingerprint-php");
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("{tag}.db"));
        let (server_addr, server) = spawn_test_server(
            vec![
                ("Server".into(), "Apache".into()),
                ("X-Powered-By".into(), "PHP/8.2.0".into()),
                ("Set-Cookie".into(), "PHPSESSID=abc123; path=/".into()),
            ],
            "hello",
        )
        .await;
        seed_scan(
            &db_path,
            &[(
                "127.0.0.1".parse().unwrap(),
                server_addr.port(),
                crate::scanner::PortStatus::Open,
            )],
        );

        let stats = run(&test_config(Scheme::Http), db_path.clone())
            .await
            .expect("fingerprint run");
        server.abort();
        assert_eq!(stats.php_detected, 1);

        let records = read_fingerprint_records(&db_path);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["php_detected"], true);
        assert_eq!(record["php_version"], "8.2.0");
        assert_eq!(record["php_signals"], serde_json::json!(["x-powered-by", "phpsessid-cookie"]));

        remove_db(&db_path);
    }

    /// No PHP headers or cookies means unconfirmed — never "not PHP", just
    /// `php_detected: false` with empty signals and no version.
    #[tokio::test]
    async fn fingerprint_reports_no_php_without_signals() {
        let tag = temp_tag("fingerprint-nophp");
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("{tag}.db"));
        let (server_addr, server) =
            spawn_test_server(vec![("Server".into(), "TestServer/1.0".into())], "hello").await;
        seed_scan(
            &db_path,
            &[(
                "127.0.0.1".parse().unwrap(),
                server_addr.port(),
                crate::scanner::PortStatus::Open,
            )],
        );

        let stats = run(&test_config(Scheme::Http), db_path.clone())
            .await
            .expect("fingerprint run");
        server.abort();
        assert_eq!(stats.php_not_detected, 1);

        let records = read_fingerprint_records(&db_path);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["php_detected"], false);
        assert!(record["php_version"].is_null());
        assert_eq!(record["php_signals"], serde_json::json!([]));

        remove_db(&db_path);
    }

    /// Test origin server that records every request path it sees, so tests
    /// can prove fingerprint made no request beyond the single `GET /` per scheme
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

    async fn run_single_tech_fingerprint(
        tag: String,
        body: &'static str,
    ) -> (
        serde_json::Value,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        String,
    ) {
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("{tag}.db"));
        let (addr, paths, server) = spawn_path_logging_server(body).await;
        seed_scan(
            &db_path,
            &[(
                "127.0.0.1".parse().unwrap(),
                addr.port(),
                crate::scanner::PortStatus::Open,
            )],
        );
        run(&test_config(Scheme::Http), db_path.clone())
            .await
            .expect("fingerprint run");
        server.abort();
        let records = read_fingerprint_records(&db_path);
        assert_eq!(records.len(), 1);
        let record = records.into_iter().next().expect("one record");
        let raw = serde_json::to_string(&record).expect("dump record");
        remove_db(&db_path);
        (record, paths, raw)
    }

    /// WordPress fixture: generator `WordPress 6.5.2` plus a `/wp-content/`
    /// script. No WooCommerce app entry is reported.
    #[tokio::test]
    async fn fingerprint_detects_wordpress_with_version() {
        let body = "<html><head><meta name=\"generator\" content=\"WordPress 6.5.2\" /><script src=\"/wp-content/themes/t/app.js\"></script></head><body>hi</body></html>";
        let (record, paths, raw) = run_single_tech_fingerprint(temp_tag("fingerprint-wp"), body).await;
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
    async fn fingerprint_detects_joomla_app_with_version() {
        let body = "<html><head><meta name=\"generator\" content=\"Joomla! 4.2.5\" /><script src=\"/media/system/js/core.js\"></script></head><body>hi</body></html>";
        let (record, paths, _) = run_single_tech_fingerprint(temp_tag("fingerprint-joomla"), body).await;
        assert_eq!(record["wordpress_detected"], false);
        let apps = record["php_apps"].as_array().expect("php_apps array");
        let joomla = apps.iter().find(|app| app["name"] == "Joomla").expect("Joomla entry");
        assert_eq!(joomla["version"], "4.2.5");
        assert!(!joomla["signals"].as_array().expect("signals").is_empty());
        assert_only_root_request(&paths);
    }

    /// Drupal fixture produces the Drupal `php_apps` entry with its version.
    #[tokio::test]
    async fn fingerprint_detects_drupal_app_with_version() {
        let body = "<html><head><meta name=\"generator\" content=\"Drupal 10\" /><script src=\"/sites/default/files/js/app.js\"></script></head><body>hi</body></html>";
        let (record, paths, _) = run_single_tech_fingerprint(temp_tag("fingerprint-drupal"), body).await;
        assert_eq!(record["wordpress_detected"], false);
        let apps = record["php_apps"].as_array().expect("php_apps array");
        let drupal = apps.iter().find(|app| app["name"] == "Drupal").expect("Drupal entry");
        assert_eq!(drupal["version"], "10");
        assert!(!drupal["signals"].as_array().expect("signals").is_empty());
        assert_only_root_request(&paths);
    }

    /// Plain HTML with no markers: no WordPress, no apps, Tailwind `"none"`.
    #[tokio::test]
    async fn fingerprint_plain_html_has_no_tech_signals() {
        let body = "<html><head><title>Plain</title></head><body><p>hello</p></body></html>";
        let (record, paths, raw) = run_single_tech_fingerprint(temp_tag("fingerprint-plain"), body).await;
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
    async fn fingerprint_detects_tailwind_cdn_as_strong() {
        let body = "<html><head><script src=\"https://cdn.tailwindcss.com\"></script></head><body><div class=\"flex items-center justify-center\">hi</div></body></html>";
        let (record, paths, _) = run_single_tech_fingerprint(temp_tag("fingerprint-tw"), body).await;
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

    async fn run_fetch_fingerprint(
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
        let db_path = dir.join(format!("{tag}.db"));
        let (addr, log, server) =
            spawn_method_server(head_status, head_headers, get_headers, get_body).await;
        seed_scan(
            &db_path,
            &[(
                "127.0.0.1".parse().unwrap(),
                addr.port(),
                crate::scanner::PortStatus::Open,
            )],
        );
        run(
            &test_config_with_mode(Scheme::Http, fetch_mode),
            db_path.clone(),
        )
        .await
        .expect("fingerprint run");
        server.abort();
        let records = read_fingerprint_records(&db_path);
        assert_eq!(records.len(), 1);
        let record = records.into_iter().next().expect("one record");
        let raw = serde_json::to_string(&record).expect("dump record");
        let logged = log.lock().expect("method log").clone();
        remove_db(&db_path);
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
        let (record, log, raw) = run_fetch_fingerprint(
            temp_tag("fingerprint-getdefault"),
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
        let (record, log, raw) = run_fetch_fingerprint(
            temp_tag("fingerprint-headwp"),
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
        let (record, log, raw) = run_fetch_fingerprint(
            temp_tag("fingerprint-headhtml"),
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
        let (record, log, raw) = run_fetch_fingerprint(
            temp_tag("fingerprint-bothunion"),
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
        let (record, log, raw) = run_fetch_fingerprint(
            temp_tag("fingerprint-both405"),
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
        let (record, log, _) = run_fetch_fingerprint(
            temp_tag("fingerprint-head405"),
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

    fn prefer_target(ip: &str, port: u16) -> (IpAddr, u16) {
        (ip.parse().expect("test ip"), port)
    }

    /// Grouping logic: only the 80/443 pair on a single IP collapses to 443.
    /// Lone ports, other pairs, and other IPs are never deduplicated.
    #[test]
    fn prefer_https_grouping_only_skips_dual_port_80() {
        // (ip,80)+(ip,443) yields only 443.
        let (primary, skipped) = split_prefer_https_targets(&[
            prefer_target("127.0.0.1", 80),
            prefer_target("127.0.0.1", 443),
        ]);
        assert_eq!(primary, vec![prefer_target("127.0.0.1", 443)]);
        assert_eq!(skipped, vec![prefer_target("127.0.0.1", 80)]);

        // (ip,80) alone yields 80; (ip,443) alone yields 443.
        let (primary, skipped) = split_prefer_https_targets(&[prefer_target("127.0.0.1", 80)]);
        assert_eq!(primary, vec![prefer_target("127.0.0.1", 80)]);
        assert!(skipped.is_empty());
        let (primary, skipped) = split_prefer_https_targets(&[prefer_target("127.0.0.1", 443)]);
        assert_eq!(primary, vec![prefer_target("127.0.0.1", 443)]);
        assert!(skipped.is_empty());

        // (ip,8080)+(ip,8443) yields both — no other pair is deduplicated.
        let (primary, skipped) = split_prefer_https_targets(&[
            prefer_target("127.0.0.1", 8080),
            prefer_target("127.0.0.1", 8443),
        ]);
        assert_eq!(
            primary,
            vec![
                prefer_target("127.0.0.1", 8080),
                prefer_target("127.0.0.1", 8443),
            ]
        );
        assert!(skipped.is_empty());

        // 80/8080 and 443/8443 pairs also keep both ports.
        let (primary, skipped) = split_prefer_https_targets(&[
            prefer_target("127.0.0.1", 80),
            prefer_target("127.0.0.1", 8080),
        ]);
        assert_eq!(primary.len(), 2);
        assert!(skipped.is_empty());
        let (primary, skipped) = split_prefer_https_targets(&[
            prefer_target("127.0.0.1", 443),
            prefer_target("127.0.0.1", 8443),
        ]);
        assert_eq!(primary.len(), 2);
        assert!(skipped.is_empty());

        // Two different IPs with 80/443 each yield 443 for each IP: no
        // cross-IP deduplication even for the same port pair.
        let (primary, skipped) = split_prefer_https_targets(&[
            prefer_target("127.0.0.1", 80),
            prefer_target("127.0.0.1", 443),
            prefer_target("192.168.1.1", 80),
            prefer_target("192.168.1.1", 443),
        ]);
        assert_eq!(
            primary,
            vec![
                prefer_target("127.0.0.1", 443),
                prefer_target("192.168.1.1", 443),
            ]
        );
        assert_eq!(
            skipped,
            vec![
                prefer_target("127.0.0.1", 80),
                prefer_target("192.168.1.1", 80),
            ]
        );

        // An 80 without a same-IP 443 is kept even when another IP has 443.
        let (primary, skipped) = split_prefer_https_targets(&[
            prefer_target("127.0.0.1", 80),
            prefer_target("192.168.1.1", 443),
        ]);
        assert_eq!(primary.len(), 2);
        assert!(skipped.is_empty());

        // IPv6 pairs collapse exactly like IPv4 pairs.
        let (primary, skipped) =
            split_prefer_https_targets(&[prefer_target("::1", 80), prefer_target("::1", 443)]);
        assert_eq!(primary, vec![prefer_target("::1", 443)]);
        assert_eq!(skipped, vec![prefer_target("::1", 80)]);

        // A third port on a dual-port host is unaffected: 80+443+8080
        // fingerprints 443 and 8080, skipping only 80.
        let (primary, skipped) = split_prefer_https_targets(&[
            prefer_target("127.0.0.1", 80),
            prefer_target("127.0.0.1", 443),
            prefer_target("127.0.0.1", 8080),
        ]);
        assert_eq!(
            primary,
            vec![
                prefer_target("127.0.0.1", 443),
                prefer_target("127.0.0.1", 8080),
            ]
        );
        assert_eq!(skipped, vec![prefer_target("127.0.0.1", 80)]);
    }

    fn fallback_record(status: Option<u16>, error: Option<&str>) -> FingerprintRecord {
        FingerprintRecord {
            ip: "127.0.0.1".to_string(),
            port: 443,
            scheme: "https".to_string(),
            final_url: "https://127.0.0.1:443/".to_string(),
            status,
            server: None,
            tls: "error".to_string(),
            error: error.map(str::to_string),
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
            fetch_method: "get".to_string(),
            head_status: None,
        }
    }

    /// Fallback condition: only an outright transport failure (no HTTP status
    /// plus timeout/tls_error/connect_error) falls back. ANY recorded status —
    /// including 400, 404, and 500 — is a completed fingerprint.
    #[test]
    fn http_fallback_only_on_outright_transport_failure() {
        for error in ["timeout", "tls_error", "connect_error"] {
            assert!(
                needs_http_fallback(&fallback_record(None, Some(error))),
                "{error} without a status must fall back"
            );
        }
        for status in [200u16, 301, 400, 404, 500] {
            assert!(
                !needs_http_fallback(&fallback_record(Some(status), None)),
                "status {status} must never fall back"
            );
        }
        assert!(
            !needs_http_fallback(&fallback_record(None, Some("other"))),
            "an unclassified error must not fall back"
        );
        assert!(
            !needs_http_fallback(&fallback_record(None, None)),
            "no error at all must not fall back"
        );
    }

    /// The stderr summary carries the exact prefer-HTTPS count tokens.
    #[test]
    fn summary_reports_skip_and_fallback_counts() {
        let stats = FingerprintStats {
            total: 2,
            http: 1,
            connect_errors: 1,
            php_detected: 1,
            php_not_detected: 1,
            skipped_prefer_https: 1,
            fallback_to_http: 1,
            ..Default::default()
        };
        let line = format_summary(&stats);
        assert!(
            line.starts_with("ftw: fingerprinted 2 targets"),
            "summary keeps its existing shape: {line}"
        );
        assert!(
            line.contains("skipped_prefer_https=1"),
            "summary reports the skipped count: {line}"
        );
        assert!(
            line.contains("fallback_to_http=1"),
            "summary reports the fallback count: {line}"
        );
        let zero = format_summary(&FingerprintStats::default());
        assert!(
            zero.contains("skipped_prefer_https=0") && zero.contains("fallback_to_http=0"),
            "a run with no deduplication reports zeros: {zero}"
        );
    }

    /// An HTTPS attempt against a plain-HTTP server fails as a TLS error and
    /// — critically — the server never sees a plaintext HTTP request line, so
    /// no plain-HTTP request is ever sent to a TLS port in prefer-HTTPS mode.
    #[tokio::test]
    async fn https_attempt_sends_no_plaintext_http() {
        let (addr, log, server) =
            spawn_method_server(200, Vec::new(), Vec::new(), "hello").await;
        let config = test_config(Scheme::Https);
        let client = build_client(&config).expect("build client");
        let record = attempt(
            &client,
            "https",
            addr.ip(),
            addr.port(),
            config.body_cap,
            FetchMode::Get,
        )
        .await;
        server.abort();
        assert_eq!(record.scheme, "https");
        assert!(
            record.status.is_none(),
            "the TLS handshake must fail: {record:?}"
        );
        assert_eq!(record.error.as_deref(), Some("tls_error"));
        assert_eq!(record.tls, "error");
        assert!(
            record.final_url.starts_with("https://"),
            "the preferred port is always requested over HTTPS: {}",
            record.final_url
        );
        assert!(
            needs_http_fallback(&record),
            "a TLS error with no status must fall back"
        );
        let seen = log.lock().expect("method log").clone();
        assert!(
            !seen
                .iter()
                .any(|(method, _)| method == "GET" || method == "HEAD"),
            "no plaintext HTTP request may reach a TLS port, got: {seen:?}"
        );
    }

    /// A real TLS server (`openssl s_server`) answering 200 proves the
    /// preferred-port happy path: an HTTPS attempt records a status, so no
    /// fallback is needed and the skipped port 80 stays untouched.
    #[tokio::test]
    async fn https_attempt_succeeds_against_tls_server() {
        let dir = std::env::temp_dir().join(temp_tag("prefer-tls"));
        std::fs::create_dir_all(&dir).expect("tls staging dir");
        let key = dir.join("key.pem");
        let cert = dir.join("cert.pem");
        let mint = tokio::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                &key.to_string_lossy(),
                "-out",
                &cert.to_string_lossy(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
            ])
            .output()
            .await
            .expect("mint test certificate");
        assert!(
            mint.status.success(),
            "openssl must mint the test certificate: {}",
            String::from_utf8_lossy(&mint.stderr)
        );
        let port = {
            let tmp = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind temp port");
            tmp.local_addr().expect("temp addr").port()
        };
        let mut child = tokio::process::Command::new("openssl")
            .args([
                "s_server",
                "-accept",
                &port.to_string(),
                "-cert",
                &cert.to_string_lossy(),
                "-key",
                &key.to_string_lossy(),
                "-www",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("start s_server");
        let start = std::time::Instant::now();
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "s_server never came up on 127.0.0.1:{port}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut config = test_config(Scheme::Https);
        config.insecure = true;
        let client = build_client(&config).expect("build client");
        let record = attempt(
            &client,
            "https",
            "127.0.0.1".parse().expect("test ip"),
            port,
            config.body_cap,
            FetchMode::Get,
        )
        .await;
        let _ = child.kill().await;
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(record.status, Some(200), "TLS 200: {record:?}");
        assert!(record.error.is_none());
        assert_eq!(record.scheme, "https");
        assert_eq!(record.tls, "ok");
        assert!(
            !needs_http_fallback(&record),
            "a completed fingerprint never falls back"
        );
    }

    fn fingerprint_ports(db_path: &Path) -> Vec<u16> {
        let conn = rusqlite::Connection::open(db_path).expect("open db");
        let mut stmt = conn
            .prepare("SELECT port FROM fingerprint_results ORDER BY port")
            .expect("prepare query");
        stmt.query_map([], |row| row.get(0))
            .expect("map rows")
            .collect::<Result<_, _>>()
            .expect("collect rows")
    }

    fn scan_status(db_path: &Path, port: u16) -> String {
        let conn = rusqlite::Connection::open(db_path).expect("open db");
        conn.query_row(
            "SELECT status FROM scan_results WHERE ip = '127.0.0.1' AND port = ?1",
            rusqlite::params![port],
            |row| row.get(0),
        )
        .expect("read scan status")
    }

    /// Fallback end to end: with 80+443 seeded open and nothing listening on
    /// 443, the preferred HTTPS attempt fails outright (connect error, no
    /// status), so port 80 is fingerprinted exactly once. The scan rows stay
    /// open and the stats report 1 skipped + 1 fallback.
    #[tokio::test]
    async fn prefer_https_falls_back_to_80_once_when_443_refused() {
        let db_path = db_path_for(&temp_tag("prefer-fallback"));
        seed_scan(
            &db_path,
            &[
                ("127.0.0.1".parse().unwrap(), 80, crate::scanner::PortStatus::Open),
                ("127.0.0.1".parse().unwrap(), 443, crate::scanner::PortStatus::Open),
            ],
        );
        let config = FingerprintConfig {
            timeout: Duration::from_secs(3),
            ..test_config(Scheme::Auto)
        };
        let stats = run(&config, db_path.clone())
            .await
            .expect("fingerprint run");
        assert_eq!(stats.total, 2, "443 plus exactly one fallback 80: {stats:?}");
        assert_eq!(stats.skipped_prefer_https, 1, "one 80 skipped: {stats:?}");
        assert_eq!(stats.fallback_to_http, 1, "one fallback 80: {stats:?}");
        assert_eq!(
            fingerprint_ports(&db_path),
            vec![80, 443],
            "only the 443 row plus a single fallback 80 row exist"
        );
        assert_eq!(
            scan_status(&db_path, 80),
            "open",
            "the scan row for the skipped port stays untouched"
        );
        assert_eq!(scan_status(&db_path, 443), "open");
        remove_db(&db_path);
    }

    /// Opt-out end to end: with `--no-prefer-https` (and, separately, with an
    /// explicit `--scheme http` and no flag) both seeded ports are
    /// fingerprinted, with no skipping and no fallback.
    #[tokio::test]
    async fn no_prefer_https_fingerprints_both_ports() {
        for (scheme, no_prefer_https) in [(Scheme::Auto, true), (Scheme::Http, false)] {
            let db_path = db_path_for(&temp_tag("prefer-optout"));
            seed_scan(
                &db_path,
                &[
                    ("127.0.0.1".parse().unwrap(), 80, crate::scanner::PortStatus::Open),
                    ("127.0.0.1".parse().unwrap(), 443, crate::scanner::PortStatus::Open),
                ],
            );
            let config = FingerprintConfig {
                timeout: Duration::from_secs(3),
                no_prefer_https,
                ..test_config(scheme)
            };
            let stats = run(&config, db_path.clone())
                .await
                .expect("fingerprint run");
            assert_eq!(
                stats.total, 2,
                "scheme={scheme} no_prefer_https={no_prefer_https}: both ports: {stats:?}"
            );
            assert_eq!(stats.skipped_prefer_https, 0, "nothing skipped");
            assert_eq!(stats.fallback_to_http, 0, "no fallback without deduplication");
            assert_eq!(
                fingerprint_ports(&db_path),
                vec![80, 443],
                "both ports have rows when deduplication is off"
            );
            remove_db(&db_path);
        }
    }
}
