//! Event-driven async crawler (`ftw crawl`).
//!
//! Seeds come ONLY from the master database: fingerprint records with a
//! non-null `final_url` and a 2xx/3xx status. No seed URLs from files or the
//! command line in this version.
//!
//! Architecture mirrors scan/fingerprint: a coordinator owns the visited set
//! and the frontier queue, semaphore-gated workers fetch one URL each (the
//! permit is acquired in the coordinator loop BEFORE `tokio::spawn`, so the
//! frontier never queues unbounded tasks), and the single writer task is the
//! only task writing to `crawl_pages`/`crawl_links`. Workers hold two bounded
//! mpsc senders — page/link records to the writer, discovered URLs back to
//! the coordinator — and never decide visitedness themselves or touch the
//! database.
//!
//! Fetching is GET-only (never POST, never forms, never credentials).
//! Redirects are followed up to the configured limit and the final URL is
//! recorded; a redirect that leaves the seed host is recorded without link
//! extraction. Only `text/html` responses are parsed (`<a href>` only);
//! non-HTML bodies are recorded by status and content type and never
//! downloaded beyond headers. Full bodies are never stored — only metadata
//! and links. URLs whose path looks administrative or whose query looks like
//! an action are never enqueued.

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reqwest::redirect::Policy;
use scraper::{Html, Selector};
use tokio::sync::{Semaphore, mpsc};

use crate::{db, output, rate_limit};

const CHANNEL_CAPACITY: usize = 1024;

/// Runtime settings for a crawl run.
#[derive(Debug, Clone, Copy)]
pub struct CrawlConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    pub max_depth: usize,
    pub max_pages: usize,
    pub body_cap: usize,
    pub max_redirects: usize,
    pub insecure: bool,
    /// Maximum requests per minute per canonical domain (`0` = unlimited,
    /// which preserves the old unthrottled behavior exactly).
    pub requests_per_minute: u64,
    /// Sliding-window length for the rate limiter (60 seconds in
    /// production; tests pass shorter windows).
    pub rate_window: Duration,
}

/// One crawled page. `url` is the normalized URL (dedupe key);
/// `body_truncated` is stats-only and is NOT persisted — the response body
/// itself is never stored in the database.
#[derive(Debug, Clone)]
pub struct CrawlPageRecord {
    pub url: String,
    pub final_url: Option<String>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub title: Option<String>,
    pub depth: usize,
    pub parent_url: Option<String>,
    pub error: Option<String>,
    pub links_found: usize,
    pub body_truncated: bool,
}

/// Events the crawl workers send to the single writer task: visited pages
/// and every extracted link (including external links that are never
/// fetched and action-looking URLs that are never enqueued).
#[derive(Debug)]
pub enum CrawlEvent {
    Page(CrawlPageRecord),
    Link {
        from_url: String,
        to_url: String,
        external: bool,
    },
}

/// Aggregate counts for one crawl run (counted by the writer task).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CrawlStats {
    pub visited: usize,
    pub links_discovered: usize,
    pub links_external: usize,
    pub timeouts: usize,
    pub tls_errors: usize,
    pub connect_errors: usize,
    pub other_errors: usize,
    pub body_cap_hits: usize,
    /// Acquires that blocked on a domain rate limit at least once. Filled in
    /// by the coordinator after the writer finishes (the writer only sees
    /// pages and links).
    pub rate_limit_waits: usize,
    /// Longest single acquire's total rate-limit wait.
    pub longest_rate_wait: Duration,
}

impl CrawlStats {
    pub(crate) fn record_page(&mut self, page: &CrawlPageRecord) {
        self.visited += 1;
        match page.error.as_deref() {
            None => {}
            Some("timeout") => self.timeouts += 1,
            Some("tls_error") => self.tls_errors += 1,
            Some("connect_error") => self.connect_errors += 1,
            _ => self.other_errors += 1,
        }
        if page.body_truncated {
            self.body_cap_hits += 1;
        }
    }

    pub(crate) fn record_link(&mut self, external: bool) {
        self.links_discovered += 1;
        if external {
            self.links_external += 1;
        }
    }
}

/// One stderr summary line for a crawl run, including the rate-limit
/// setting and its observed waits. Kept as a function (instead of inline in
/// the CLI wiring) so tests can assert the exact tokens without spawning
/// the binary.
#[must_use]
pub fn format_summary(stats: &CrawlStats, requests_per_minute: u64) -> String {
    let limit = if requests_per_minute == 0 {
        "unlimited".to_string()
    } else {
        format!("{requests_per_minute}/min")
    };
    format!(
        "ftw: crawled {} pages, {} links discovered ({} external skipped); errors: {} timeout, {} tls, {} connect, {} other; {} pages hit the body cap; rate limit {}, {} waits, longest wait {:.2}s",
        stats.visited,
        stats.links_discovered,
        stats.links_external,
        stats.timeouts,
        stats.tls_errors,
        stats.connect_errors,
        stats.other_errors,
        stats.body_cap_hits,
        limit,
        stats.rate_limit_waits,
        stats.longest_rate_wait.as_secs_f64(),
    )
}

/// The seed host a crawled URL came from. In-scope means the same host, and
/// — for IP seeds — the same port. Hostname seeds ignore ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedScope {
    host: String,
    port: u16,
    host_is_ip: bool,
}

impl SeedScope {
    fn from_url(url: &reqwest::Url) -> Option<Self> {
        let host = url.host_str()?.to_string();
        let port = url.port_or_known_default()?;
        let host_is_ip = host.parse::<IpAddr>().is_ok();
        Some(Self { host, port, host_is_ip })
    }

    fn contains(&self, url: &reqwest::Url) -> bool {
        if url.host_str() != Some(self.host.as_str()) {
            return false;
        }
        if self.host_is_ip && url.port_or_known_default() != Some(self.port) {
            return false;
        }
        true
    }
}

/// Normalize a URL into its dedupe key: lowercase host (done by the parser
/// for http/https), no fragment, no default ports, collapsed duplicate
/// slashes in the path. Returns `None` when the URL does not parse.
#[must_use]
pub fn normalize_url(raw: &str) -> Option<String> {
    let mut url = reqwest::Url::parse(raw).ok()?;
    url.set_fragment(None);
    let is_default_port = match url.scheme() {
        "http" => url.port() == Some(80),
        "https" => url.port() == Some(443),
        _ => false,
    };
    if is_default_port {
        let _ = url.set_port(None);
    }
    let path = url.path().to_string();
    if path.contains("//") {
        let mut collapsed = String::with_capacity(path.len());
        let mut prev_slash = false;
        for ch in path.chars() {
            if ch == '/' {
                if !prev_slash {
                    collapsed.push(ch);
                }
                prev_slash = true;
            } else {
                collapsed.push(ch);
                prev_slash = false;
            }
        }
        url.set_path(&collapsed);
    }
    Some(url.to_string())
}

/// True when a URL must never be enqueued: an administrative-looking path
/// (`/wp-admin`, `/wp-login`, `logout`, `delete`) or an action-looking query
/// (`action=delete`, `action=logout`). Matching is case-insensitive.
fn should_skip(url: &reqwest::Url) -> bool {
    const PATH_MARKERS: &[&str] = &["/wp-admin", "/wp-login", "logout", "delete"];
    let path = url.path().to_lowercase();
    if PATH_MARKERS.iter().any(|marker| path.contains(marker)) {
        return true;
    }
    url.query().unwrap_or_default().to_lowercase().split('&').any(|pair| {
        let mut parts = pair.splitn(2, '=');
        parts.next() == Some("action")
            && matches!(parts.next(), Some("delete") | Some("logout"))
    })
}

/// One frontier entry: the normalized URL, its depth (seeds are 0), its
/// parent, and the seed scope it must stay inside.
struct CrawlJob {
    url: String,
    depth: usize,
    parent: Option<String>,
    scope: SeedScope,
}

/// One extracted link with its scope verdict (computed by the worker so the
/// writer can count external links; the coordinator re-checks scope itself
/// before enqueueing).
struct DiscoveredLink {
    url: String,
    external: bool,
}

/// What a worker reports back to the coordinator after fetching one job.
struct CrawlOutcome {
    job: CrawlJob,
    links: Vec<DiscoveredLink>,
}

/// Build the shared HTTP client: clear FTW User-Agent, per-request timeout,
/// redirect limit, and opt-in acceptance of invalid certificates (only for
/// your own self-signed hosts).
fn build_client(config: &CrawlConfig) -> Result<reqwest::Client, reqwest::Error> {
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

/// MIME essence of a response (`text/html`), or `None` when absent.
fn content_type_of(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get(reqwest::header::CONTENT_TYPE)?
        .to_str()
        .ok()
        .map(|value| value.split(';').next().unwrap_or("").trim().to_lowercase())
        .filter(|mime| !mime.is_empty())
}

/// Text of the first `<title>` element, trimmed and capped, or `None`.
fn page_title(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("title").ok()?;
    let title: String = document
        .select(&selector)
        .next()
        .map(|element| element.text().collect::<String>())?;
    let title = title.trim();
    if title.is_empty() {
        return None;
    }
    Some(title.chars().take(512).collect())
}

/// Every `<a href>` on the page, resolved against `base` and normalized.
/// Only http/https links are kept; unparseable and non-web links are dropped.
fn extract_links(base: &reqwest::Url, html: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let Ok(selector) = Selector::parse("a") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for element in document.select(&selector) {
        let Some(href) = element.value().attr("href") else {
            continue;
        };
        let href = href.trim();
        if href.is_empty() {
            continue;
        }
        let Ok(joined) = base.join(href) else {
            continue;
        };
        if !matches!(joined.scheme(), "http" | "https") {
            continue;
        }
        if let Some(normalized) = normalize_url(joined.as_str()) {
            if seen.insert(normalized.clone()) {
                out.push(normalized);
            }
        }
    }
    out
}

/// Stream at most `cap` response body bytes as a lossy string for parsing
/// only. Returns the preview and whether the body hit the cap (more bytes
/// remained). The preview is discarded after parsing and never stored.
async fn collect_capped(mut response: reqwest::Response, cap: usize) -> (String, bool) {
    let mut kept = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        let room = cap.saturating_sub(kept.len());
        if room == 0 {
            return (String::from_utf8_lossy(&kept).into_owned(), true);
        }
        let take = chunk.len().min(room);
        kept.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            return (String::from_utf8_lossy(&kept).into_owned(), true);
        }
    }
    (String::from_utf8_lossy(&kept).into_owned(), false)
}

/// Fetch one job: GET only, record the page, extract links when the final
/// response is same-host HTML. Never POSTs, never submits forms, never sends
/// credentials.
async fn fetch_page(
    client: &reqwest::Client,
    job: &CrawlJob,
    config: &CrawlConfig,
) -> (CrawlPageRecord, Vec<DiscoveredLink>) {
    let mut page = CrawlPageRecord {
        url: job.url.clone(),
        final_url: None,
        status: None,
        content_type: None,
        title: None,
        depth: job.depth,
        parent_url: job.parent.clone(),
        error: None,
        links_found: 0,
        body_truncated: false,
    };
    let response = match client.get(&job.url).send().await {
        Ok(response) => response,
        Err(err) => {
            page.error = Some(crate::fingerprint::classify_error(&err).to_string());
            return (page, Vec::new());
        }
    };
    page.status = Some(response.status().as_u16());
    let final_url = response.url().to_string();
    page.final_url = Some(final_url.clone());
    let headers = response.headers().clone();
    page.content_type = content_type_of(&headers);

    // A redirect that leaves the seed host is recorded but never parsed.
    let same_host = reqwest::Url::parse(&final_url).is_ok_and(|url| job.scope.contains(&url));
    if !same_host {
        return (page, Vec::new());
    }
    // Non-HTML bodies are recorded by status and content type and never
    // downloaded beyond headers.
    if page.content_type.as_deref() != Some("text/html") {
        return (page, Vec::new());
    }
    let (preview, truncated) = collect_capped(response, config.body_cap).await;
    page.body_truncated = truncated;
    page.title = page_title(&preview);
    let Ok(base) = reqwest::Url::parse(&final_url) else {
        return (page, Vec::new());
    };
    let links = extract_links(&base, &preview);
    page.links_found = links.len();
    let discovered = links
        .into_iter()
        .map(|url| {
            let external = !reqwest::Url::parse(&url).is_ok_and(|parsed| job.scope.contains(&parsed));
            DiscoveredLink { url, external }
        })
        .collect();
    (page, discovered)
}

/// Crawl seeds from the master database with default live-output options.
#[allow(dead_code)]
pub async fn run(
    config: &CrawlConfig,
    db_path: PathBuf,
) -> Result<CrawlStats, Box<dyn std::error::Error + Send + Sync>> {
    run_with_options(config, db_path, output::OutputOptions::default()).await
}

/// Crawl seeds from the master database.
///
/// The database is opened once here, seeds are read, and the single
/// connection is moved into the writer task — the only task that writes.
/// Workers never open connections or write directly.
///
/// Polite crawling: every worker shares one [`rate_limit::RateLimiter`]
/// (per canonical domain, across all threads combined). Each fetch waits
/// out its domain's rate limit FIRST with no concurrency permit held, then
/// takes a semaphore permit, then fetches — so a worker stalled on one
/// domain's limit never occupies a fetch slot needed by other domains. The
/// coordinator therefore spawns one task per frontier job without gating:
/// waiting tasks hold nothing, and total tasks stay bounded by `max_pages`.
pub async fn run_with_options(
    config: &CrawlConfig,
    db_path: PathBuf,
    options: output::OutputOptions,
) -> Result<CrawlStats, Box<dyn std::error::Error + Send + Sync>> {
    let conn = db::open(&db_path)?;
    let seeds = db::crawl_seeds(&conn)?;
    if seeds.is_empty() {
        eprintln!("ftw: warning: no crawlable seeds in database");
    }
    let client = build_client(config)?;
    eprintln!("ftw: crawling {} seed pages", seeds.len());
    let limiter = Arc::new(rate_limit::RateLimiter::new(
        config.requests_per_minute,
        config.rate_window,
    ));
    let verbose = options.verbose;
    let (db_tx, db_rx) = mpsc::channel::<CrawlEvent>(CHANNEL_CAPACITY);
    let writer =
        tokio::spawn(async move { output::run_crawl_db_writer(db_rx, conn, options).await });
    let (coord_tx, mut coord_rx) = mpsc::channel::<CrawlOutcome>(CHANNEL_CAPACITY);
    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));

    let mut visited: HashSet<String> = HashSet::new();
    let mut frontier: VecDeque<CrawlJob> = VecDeque::new();
    for seed in &seeds {
        let Some(normalized) = normalize_url(seed) else {
            continue;
        };
        let Ok(seed_url) = reqwest::Url::parse(&normalized) else {
            continue;
        };
        let Some(scope) = SeedScope::from_url(&seed_url) else {
            continue;
        };
        if visited.insert(normalized.clone()) {
            frontier.push_back(CrawlJob {
                url: normalized,
                depth: 0,
                parent: None,
                scope,
            });
        }
    }

    let mut in_flight = 0usize;
    while !frontier.is_empty() || in_flight > 0 {
        // Spawn one task per frontier job with no permit held: the worker
        // rate-waits first (holding nothing), then takes a fetch permit.
        // Waiting tasks therefore never starve other domains' fetches.
        while visited.len() < config.max_pages && !frontier.is_empty() {
            let Some(job) = frontier.pop_front() else {
                break;
            };
            in_flight += 1;
            let job_url = job.url.clone();
            let db_tx = db_tx.clone();
            let coord_tx = coord_tx.clone();
            let client = client.clone();
            let config = *config;
            let limiter = limiter.clone();
            let semaphore = semaphore.clone();
            tokio::spawn(async move {
                let outcome_job_url = job_url.clone();
                let domain = rate_limit::canonical_domain(&job.url);
                let waited = limiter.acquire(&domain).await;
                if verbose && !waited.is_zero() {
                    eprintln!("{}", rate_limit::format_rate_wait(&domain, waited));
                }
                let permit = semaphore
                    .acquire_owned()
                    .await
                    .expect("crawl semaphore never closes while crawling");
                let (page, links) = fetch_page(&client, &job, &config).await;
                drop(permit);
                let _ = db_tx.send(CrawlEvent::Page(page)).await;
                for link in &links {
                    let _ = db_tx
                        .send(CrawlEvent::Link {
                            from_url: outcome_job_url.clone(),
                            to_url: link.url.clone(),
                            external: link.external,
                        })
                        .await;
                }
                let _ = coord_tx.send(CrawlOutcome { job, links }).await;
            });
        }
        if in_flight == 0 {
            break;
        }
        let Some(outcome) = coord_rx.recv().await else {
            break;
        };
        in_flight -= 1;
        if visited.len() >= config.max_pages {
            continue;
        }
        // The coordinator alone decides visitedness, depth, scope, skips,
        // and the page budget — workers never enqueue themselves.
        for link in outcome.links {
            if visited.len() >= config.max_pages {
                break;
            }
            let depth = outcome.job.depth + 1;
            if depth > config.max_depth {
                continue;
            }
            if link.external {
                continue;
            }
            let Ok(url) = reqwest::Url::parse(&link.url) else {
                continue;
            };
            if !outcome.job.scope.contains(&url) {
                continue;
            }
            if should_skip(&url) {
                continue;
            }
            if visited.insert(link.url.clone()) {
                frontier.push_back(CrawlJob {
                    url: link.url,
                    depth,
                    parent: Some(outcome.job.url.clone()),
                    scope: outcome.job.scope.clone(),
                });
            }
        }
    }
    drop(db_tx);
    drop(coord_tx);
    let mut stats = writer.await??;
    stats.rate_limit_waits = limiter.waits();
    stats.longest_rate_wait = limiter.longest_wait();
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_config(max_depth: usize, max_pages: usize) -> CrawlConfig {
        CrawlConfig {
            concurrency: 8,
            timeout: Duration::from_secs(5),
            max_depth,
            max_pages,
            body_cap: 262144,
            max_redirects: 5,
            insecure: false,
            requests_per_minute: 0,
            rate_window: Duration::from_secs(60),
        }
    }

    fn temp_db(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("ftw-crawltest-{tag}-{nanos}-{}.db", std::process::id()))
    }

    fn remove_db(db_path: &std::path::Path) {
        std::fs::remove_file(db_path).ok();
        std::fs::remove_file(db_path.with_extension("db-wal")).ok();
        std::fs::remove_file(db_path.with_extension("db-shm")).ok();
    }

    fn seed_record(port: u16, final_url: String, status: Option<u16>) -> crate::fingerprint::FingerprintRecord {
        crate::fingerprint::FingerprintRecord {
            ip: "127.0.0.1".to_string(),
            port,
            scheme: "http".to_string(),
            final_url,
            status,
            server: Some("TestServer/1.0".to_string()),
            tls: "n/a".to_string(),
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
            fetch_method: "get".to_string(),
            head_status: None,
        }
    }

    /// Seed one crawlable fingerprint row the way `ftw fingerprint --db`
    /// would have stored it.
    fn seed_fingerprint(db_path: &std::path::Path, port: u16, final_url: &str, status: u16) {
        let conn = db::open(db_path).expect("open db");
        db::upsert_fingerprint(&conn, &seed_record(port, final_url.to_string(), Some(status)))
            .expect("seed fingerprint row");
    }

    fn page_urls(db_path: &std::path::Path) -> Vec<String> {
        let conn = rusqlite::Connection::open(db_path).expect("open db");
        let mut stmt = conn
            .prepare("SELECT url FROM crawl_pages ORDER BY url")
            .expect("prepare pages");
        stmt.query_map([], |row| row.get(0))
            .expect("map pages")
            .collect::<Result<_, _>>()
            .expect("collect pages")
    }

    fn link_pairs(db_path: &std::path::Path) -> Vec<(String, String)> {
        let conn = rusqlite::Connection::open(db_path).expect("open db");
        let mut stmt = conn
            .prepare("SELECT from_url, to_url FROM crawl_links ORDER BY from_url, to_url")
            .expect("prepare links");
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("map links")
            .collect::<Result<_, _>>()
            .expect("collect links")
    }

    /// Test origin route: fixed HTML, raw body, or redirect. Bodies are
    /// owned so routes can embed the bound port.
    #[derive(Debug, Clone)]
    enum TestRoute {
        Html(String),
        Raw {
            content_type: &'static str,
            body: &'static str,
        },
        Redirect(String),
    }

    /// Render one test response for a routed path key.
    fn respond(routes: &HashMap<String, TestRoute>, key: &str) -> String {
        match routes.get(key) {
            Some(TestRoute::Html(body)) => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
            Some(TestRoute::Raw { content_type, body }) => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
            Some(TestRoute::Redirect(location)) => format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
        }
    }

    /// Read one request and return its routed path key (query stripped).
    async fn request_key(sock: &mut tokio::net::TcpStream) -> String {
        let mut buf = [0u8; 8192];
        let _ = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let path = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/");
        path.split('?').next().unwrap_or("/").to_string()
    }

    /// Route-serving test server: matches the request path (query stripped)
    /// against `routes`, 404 otherwise. Reads the request first so every
    /// method behaves. The routes are built with the bound address, so pages
    /// can link to the server's own port.
    async fn spawn_route_server_with(
        build: impl FnOnce(std::net::SocketAddr) -> HashMap<String, TestRoute>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind route server");
        let addr = listener.local_addr().expect("route server addr");
        let routes = build(addr);
        let handle = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let key = request_key(&mut sock).await;
                    let response = respond(&routes, &key);
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (addr, handle)
    }

    /// Timestamp-logging route server bound to an explicit loopback IP, so
    /// two servers can live on different canonical domains (ports are
    /// ignored by the rate limiter). Records one `Instant` per accepted
    /// connection — the fetch arrival order — alongside serving routes.
    async fn spawn_timestamp_server(
        bind_ip: &str,
        build: impl FnOnce(std::net::SocketAddr) -> HashMap<String, TestRoute>,
    ) -> (
        std::net::SocketAddr,
        Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind(format!("{bind_ip}:0"))
            .await
            .expect("bind timestamp server");
        let addr = listener.local_addr().expect("timestamp server addr");
        let routes = build(addr);
        let stamps = Arc::new(std::sync::Mutex::new(Vec::<std::time::Instant>::new()));
        let seen = stamps.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                seen.lock().expect("stamp log").push(std::time::Instant::now());
                let routes = routes.clone();
                tokio::spawn(async move {
                    let key = request_key(&mut sock).await;
                    let response = respond(&routes, &key);
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (addr, stamps, handle)
    }

    /// A port nothing listens on (bind-then-drop, loopback only).
    async fn closed_port() -> u16 {
        let tmp = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind temp port");
        tmp.local_addr().expect("temp addr").port()
    }

    #[test]
    fn normalize_url_keys_on_host_path_and_port() {
        assert_eq!(
            normalize_url("http://Example.COM/a").as_deref(),
            Some("http://example.com/a")
        );
        assert_eq!(
            normalize_url("http://example.com:80/a").as_deref(),
            Some("http://example.com/a"),
            "default HTTP port is dropped"
        );
        assert_eq!(
            normalize_url("https://example.com:443/a").as_deref(),
            Some("https://example.com/a"),
            "default HTTPS port is dropped"
        );
        assert_eq!(
            normalize_url("http://example.com:8080/a").as_deref(),
            Some("http://example.com:8080/a"),
            "non-default ports are kept"
        );
        assert_eq!(
            normalize_url("http://example.com/a#frag").as_deref(),
            Some("http://example.com/a"),
            "fragments do not create new pages"
        );
        assert_eq!(
            normalize_url("http://example.com//a///b").as_deref(),
            Some("http://example.com/a/b"),
            "duplicate slashes collapse"
        );
        assert!(normalize_url("not a url").is_none());
    }

    #[test]
    fn seed_scope_matches_host_and_ip_port() {
        let host_seed = SeedScope::from_url(
            &reqwest::Url::parse("http://example.com:8080/").expect("seed url"),
        )
        .expect("seed scope");
        assert!(host_seed.contains(
            &reqwest::Url::parse("http://example.com:9999/other").expect("url")
        ), "hostname seeds ignore ports");
        assert!(!host_seed.contains(
            &reqwest::Url::parse("http://other.com:8080/").expect("url")
        ));

        let ip_seed = SeedScope::from_url(
            &reqwest::Url::parse("http://127.0.0.1:8000/").expect("seed url"),
        )
        .expect("seed scope");
        assert!(ip_seed.contains(
            &reqwest::Url::parse("http://127.0.0.1:8000/x").expect("url")
        ));
        assert!(!ip_seed.contains(
            &reqwest::Url::parse("http://127.0.0.1:8001/x").expect("url")
        ), "IP seeds require the same port");
    }

    #[test]
    fn should_skip_blocks_admin_paths_and_action_queries() {
        for raw in [
            "http://h/wp-admin/x",
            "http://h/wp-login.php",
            "http://h/a/logout/b",
            "http://h/a/delete/b",
            "http://h/view?action=delete",
            "http://h/view?action=logout",
        ] {
            assert!(
                should_skip(&reqwest::Url::parse(raw).expect("url")),
                "must skip {raw}"
            );
        }
        for raw in [
            "http://h/about",
            "http://h/view?action=show",
            "http://h/some-page",
        ] {
            assert!(
                !should_skip(&reqwest::Url::parse(raw).expect("url")),
                "must not skip {raw}"
            );
        }
    }

    fn html_page(title: &str, links: &[String]) -> TestRoute {
        let mut body = format!("<html><head><title>{title}</title></head><body>");
        for link in links {
            body.push_str(&format!("<a href=\"{link}\">x</a>"));
        }
        body.push_str("</body></html>");
        TestRoute::Html(body)
    }

    fn page_detail(
        db_path: &std::path::Path,
        url: &str,
    ) -> (
        Option<u16>,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    ) {
        let conn = rusqlite::Connection::open(db_path).expect("open db");
        conn.query_row(
            "SELECT status, final_url, content_type, title, links_found FROM crawl_pages WHERE url = ?1",
            [url],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("page row")
    }

    /// Chain A→B→C with a cycle C→A plus an external link: exactly 3 visited
    /// pages, no duplicate URLs, the external link recorded but never
    /// visited.
    #[tokio::test]
    async fn crawl_visits_chain_with_cycle_and_ignores_external() {
        let db_path = temp_db("chain");
        let dead = closed_port().await;
        let (addr, server) = spawn_route_server_with(|addr| {
            let base = format!("http://{addr}");
            let mut routes = HashMap::new();
            routes.insert("/a".to_string(), html_page("A", &[format!("{base}/b")]));
            routes.insert("/b".to_string(), html_page("B", &[format!("{base}/c")]));
            routes.insert(
                "/c".to_string(),
                html_page(
                    "C",
                    &[format!("{base}/a"), format!("http://127.0.0.1:{dead}/x")],
                ),
            );
            routes
        })
        .await;
        let base = format!("http://{addr}");
        seed_fingerprint(&db_path, addr.port(), &format!("{base}/a"), 200);
        let stats = run_with_options(
            &test_config(10, 100),
            db_path.clone(),
            output::OutputOptions::default(),
        )
        .await
        .expect("crawl run");
        server.abort();

        assert_eq!(stats.visited, 3);
        let mut urls = page_urls(&db_path);
        urls.sort_unstable();
        assert_eq!(
            urls,
            vec![
                format!("{base}/a"),
                format!("{base}/b"),
                format!("{base}/c"),
            ],
            "exactly A, B, C visited once each despite the cycle"
        );
        let links = link_pairs(&db_path);
        for pair in [
            (format!("{base}/a"), format!("{base}/b")),
            (format!("{base}/b"), format!("{base}/c")),
            (format!("{base}/c"), format!("{base}/a")),
            (
                format!("{base}/c"),
                format!("http://127.0.0.1:{dead}/x"),
            ),
        ] {
            assert!(links.contains(&pair), "missing link {pair:?} in {links:?}");
        }
        assert!(
            !urls.contains(&format!("http://127.0.0.1:{dead}/x")),
            "the external link must be recorded but never visited"
        );
        assert_eq!(stats.links_external, 1);
        remove_db(&db_path);
    }

    /// `--max-depth 1` visits only the seed and its direct children.
    #[tokio::test]
    async fn crawl_respects_max_depth_one() {
        let db_path = temp_db("depth");
        let (addr, server) = spawn_route_server_with(|addr| {
            let base = format!("http://{addr}");
            let mut routes = HashMap::new();
            routes.insert("/a".to_string(), html_page("A", &[format!("{base}/b")]));
            routes.insert("/b".to_string(), html_page("B", &[format!("{base}/c")]));
            routes.insert("/c".to_string(), html_page("C", &[]));
            routes
        })
        .await;
        let base = format!("http://{addr}");
        seed_fingerprint(&db_path, addr.port(), &format!("{base}/a"), 200);
        let stats = run_with_options(
            &test_config(1, 100),
            db_path.clone(),
            output::OutputOptions::default(),
        )
        .await
        .expect("crawl run");
        server.abort();

        assert_eq!(stats.visited, 2);
        let mut urls = page_urls(&db_path);
        urls.sort_unstable();
        assert_eq!(urls, vec![format!("{base}/a"), format!("{base}/b")]);
        // B→C was extracted (recorded) but is too deep to visit.
        assert!(
            link_pairs(&db_path).contains(&(format!("{base}/b"), format!("{base}/c"))),
            "over-depth links are recorded even though they are never visited"
        );
        remove_db(&db_path);
    }

    /// Non-HTML bodies record status and content type with no link extraction
    /// and no body download beyond headers.
    #[tokio::test]
    async fn crawl_records_non_html_without_links() {
        let db_path = temp_db("nonhtml");
        let (addr, server) = spawn_route_server_with(|_| {
            let mut routes = HashMap::new();
            routes.insert(
                "/file".to_string(),
                TestRoute::Raw {
                    content_type: "application/octet-stream",
                    body: "binary-data",
                },
            );
            routes
        })
        .await;
        let url = format!("http://{addr}/file");
        seed_fingerprint(&db_path, addr.port(), &url, 200);
        let stats = run_with_options(
            &test_config(2, 100),
            db_path.clone(),
            output::OutputOptions::default(),
        )
        .await
        .expect("crawl run");
        server.abort();

        assert_eq!(stats.visited, 1);
        let (status, final_url, content_type, title, links_found) = page_detail(&db_path, &url);
        assert_eq!(status, Some(200));
        assert_eq!(final_url.as_deref(), Some(url.as_str()));
        assert_eq!(content_type.as_deref(), Some("application/octet-stream"));
        assert_eq!(title, None);
        assert_eq!(links_found, 0);
        assert!(link_pairs(&db_path).is_empty());
        remove_db(&db_path);
    }

    /// Same-host redirects are followed: the page records the final URL and
    /// links are extracted from the landing page.
    #[tokio::test]
    async fn crawl_follows_same_host_redirect_and_extracts_links() {
        let db_path = temp_db("redir");
        let (addr, server) = spawn_route_server_with(|addr| {
            let base = format!("http://{addr}");
            let mut routes = HashMap::new();
            routes.insert("/old".to_string(), TestRoute::Redirect("/new".to_string()));
            routes.insert("/new".to_string(), html_page("New", &[format!("{base}/deep")]));
            routes.insert("/deep".to_string(), html_page("Deep", &[]));
            routes
        })
        .await;
        let base = format!("http://{addr}");
        seed_fingerprint(&db_path, addr.port(), &format!("{base}/old"), 200);
        let stats = run_with_options(
            &test_config(2, 100),
            db_path.clone(),
            output::OutputOptions::default(),
        )
        .await
        .expect("crawl run");
        server.abort();

        // Only /old and /deep are visited: /new is the redirect landing
        // page, recorded as /old's final_url rather than fetched itself.
        assert_eq!(stats.visited, 2);
        let (status, final_url, _, _, links_found) = page_detail(&db_path, &format!("{base}/old"));
        assert_eq!(status, Some(200));
        assert_eq!(final_url.as_deref(), Some(format!("{base}/new").as_str()));
        assert_eq!(links_found, 1, "links come from the redirect landing page");
        assert!(page_urls(&db_path).contains(&format!("{base}/deep")));
        remove_db(&db_path);
    }

    /// A redirect that leaves the seed host is recorded but never parsed:
    /// the off-host page is not visited and yields no links.
    #[tokio::test]
    async fn crawl_records_off_host_redirect_without_following_links() {
        let db_path = temp_db("offhost");
        let (other_addr, other_server) = spawn_route_server_with(|_| {
            let mut routes = HashMap::new();
            routes.insert("/".to_string(), html_page("Other", &[]));
            routes
        })
        .await;
        let (addr, server) = spawn_route_server_with(|_| {
            let mut routes = HashMap::new();
            routes.insert(
                "/away".to_string(),
                TestRoute::Redirect(format!("http://{other_addr}/")),
            );
            routes
        })
        .await;
        let base = format!("http://{addr}");
        seed_fingerprint(&db_path, addr.port(), &format!("{base}/away"), 200);
        let stats = run_with_options(
            &test_config(2, 100),
            db_path.clone(),
            output::OutputOptions::default(),
        )
        .await
        .expect("crawl run");
        server.abort();
        other_server.abort();

        assert_eq!(stats.visited, 1);
        assert_eq!(page_urls(&db_path), vec![format!("{base}/away")]);
        let (_, final_url, _, _, links_found) =
            page_detail(&db_path, &format!("{base}/away"));
        assert_eq!(
            final_url.as_deref(),
            Some(format!("http://{other_addr}/").as_str())
        );
        assert_eq!(links_found, 0, "off-host landing pages yield no links");
        assert!(link_pairs(&db_path).is_empty());
        remove_db(&db_path);
    }

    /// Administrative paths and action-looking queries are recorded as
    /// discovered links but never enqueued or visited.
    #[tokio::test]
    async fn crawl_skips_admin_paths_and_action_queries() {
        let db_path = temp_db("skip");
        let (addr, server) = spawn_route_server_with(|addr| {
            let base = format!("http://{addr}");
            let mut routes = HashMap::new();
            routes.insert(
                "/s".to_string(),
                html_page(
                    "S",
                    &[
                        format!("{base}/ok"),
                        format!("{base}/gone?action=delete"),
                        format!("{base}/wp-admin/x"),
                    ],
                ),
            );
            routes.insert("/ok".to_string(), html_page("Ok", &[]));
            routes
        })
        .await;
        let base = format!("http://{addr}");
        seed_fingerprint(&db_path, addr.port(), &format!("{base}/s"), 200);
        let stats = run_with_options(
            &test_config(2, 100),
            db_path.clone(),
            output::OutputOptions::default(),
        )
        .await
        .expect("crawl run");
        server.abort();

        assert_eq!(stats.visited, 2);
        let mut urls = page_urls(&db_path);
        urls.sort_unstable();
        assert_eq!(urls, vec![format!("{base}/ok"), format!("{base}/s")]);
        let links = link_pairs(&db_path);
        for skipped in [format!("{base}/gone?action=delete"), format!("{base}/wp-admin/x")] {
            assert!(
                links.iter().any(|(_, to)| to == &skipped),
                "skipped URLs are still recorded as discovered links: {links:?}"
            );
            assert!(!urls.contains(&skipped), "skipped URLs are never visited");
        }
        remove_db(&db_path);
    }

    /// Unreachable seeds are recorded with a connect error and counted by
    /// kind instead of failing the run.
    #[tokio::test]
    async fn crawl_records_connect_errors_by_kind() {
        let db_path = temp_db("connerr");
        let dead = closed_port().await;
        let url = format!("http://127.0.0.1:{dead}/");
        seed_fingerprint(&db_path, dead, &url, 200);
        let stats = run_with_options(
            &test_config(2, 100),
            db_path.clone(),
            output::OutputOptions::default(),
        )
        .await
        .expect("crawl run");

        assert_eq!(stats.visited, 1);
        assert_eq!(stats.connect_errors, 1);
        let (status, _, _, _, links_found) = page_detail(&db_path, &url);
        assert_eq!(status, None);
        assert_eq!(links_found, 0);
        remove_db(&db_path);
    }

    /// The stderr summary carries the rate-limit setting and its waits.
    #[test]
    fn crawl_summary_reports_rate_limit_setting_and_waits() {
        let stats = CrawlStats {
            visited: 3,
            links_discovered: 2,
            rate_limit_waits: 2,
            longest_rate_wait: Duration::from_millis(500),
            ..Default::default()
        };
        let line = format_summary(&stats, 60);
        assert!(
            line.starts_with("ftw: crawled 3 pages"),
            "summary keeps its existing shape: {line}"
        );
        assert!(line.contains("60/min"), "summary names the setting: {line}");
        assert!(line.contains("2 waits"), "summary counts the waits: {line}");
        assert!(
            line.contains("longest wait"),
            "summary names the longest wait: {line}"
        );
        let unlimited = format_summary(&CrawlStats::default(), 0);
        assert!(
            unlimited.contains("unlimited"),
            "a zero limit reports unlimited: {unlimited}"
        );
        assert!(
            unlimited.contains("0 waits"),
            "an unthrottled run reports zero waits: {unlimited}"
        );
    }

    /// Rate limiting end to end with a 500 ms test window at 1 request per
    /// window: three pages on 127.0.0.1 arrive one window apart (two waits),
    /// while the 127.0.0.2 seed — a different canonical domain — arrives
    /// promptly instead of queueing behind the first domain's limit.
    #[tokio::test]
    async fn crawl_throttles_one_domain_without_blocking_another() {
        let db_path = temp_db("ratelimit");
        let (addr_a, stamps_a, server_a) = spawn_timestamp_server("127.0.0.1", |addr| {
            let base = format!("http://{addr}");
            let mut routes = HashMap::new();
            routes.insert(
                "/seed".to_string(),
                html_page("Seed", &[format!("{base}/a1"), format!("{base}/a2")]),
            );
            routes.insert("/a1".to_string(), html_page("A1", &[]));
            routes.insert("/a2".to_string(), html_page("A2", &[]));
            routes
        })
        .await;
        let (addr_b, stamps_b, server_b) = spawn_timestamp_server("127.0.0.2", |_| {
            let mut routes = HashMap::new();
            routes.insert("/seed".to_string(), html_page("Seed", &[]));
            routes
        })
        .await;
        seed_fingerprint(&db_path, addr_a.port(), &format!("http://{addr_a}/seed"), 200);
        seed_fingerprint(&db_path, addr_b.port(), &format!("http://{addr_b}/seed"), 200);
        let config = CrawlConfig {
            requests_per_minute: 1,
            rate_window: Duration::from_millis(500),
            ..test_config(2, 100)
        };
        let start = std::time::Instant::now();
        let stats = run_with_options(&config, db_path.clone(), output::OutputOptions::default())
            .await
            .expect("crawl run");
        server_a.abort();
        server_b.abort();

        assert_eq!(stats.visited, 4, "all seeds and children visited");
        assert_eq!(
            stats.rate_limit_waits, 2,
            "exactly the two over-limit fetches waited: {stats:?}"
        );
        assert!(
            stats.longest_rate_wait >= Duration::from_millis(400),
            "the longest wait spans a full window: {:?}",
            stats.longest_rate_wait
        );

        let mut arrivals_a = stamps_a.lock().expect("stamp log").clone();
        arrivals_a.sort_unstable();
        assert_eq!(arrivals_a.len(), 3, "three fetches hit 127.0.0.1");
        assert!(
            arrivals_a[1] - arrivals_a[0] >= Duration::from_millis(400),
            "second fetch waits out a window: {:?}",
            arrivals_a
        );
        assert!(
            arrivals_a[2] - arrivals_a[0] >= Duration::from_millis(900),
            "third fetch waits out two windows: {:?}",
            arrivals_a
        );

        let arrivals_b = stamps_b.lock().expect("stamp log").clone();
        assert_eq!(arrivals_b.len(), 1, "one fetch hit 127.0.0.2");
        assert!(
            arrivals_b[0] - start < Duration::from_millis(400),
            "the other domain proceeds without waiting: {:?}",
            arrivals_b[0] - start
        );
        remove_db(&db_path);
    }

    /// A zero limit crawls with no throttling: all pages visited, no waits,
    /// no longest wait — unlimited is never "0 requests allowed".
    #[tokio::test]
    async fn crawl_unlimited_records_no_waits() {
        let db_path = temp_db("unlimited");
        let (addr, server) = spawn_route_server_with(|addr| {
            let base = format!("http://{addr}");
            let mut routes = HashMap::new();
            routes.insert(
                "/seed".to_string(),
                html_page("Seed", &[format!("{base}/a1"), format!("{base}/a2")]),
            );
            routes.insert("/a1".to_string(), html_page("A1", &[]));
            routes.insert("/a2".to_string(), html_page("A2", &[]));
            routes
        })
        .await;
        let base = format!("http://{addr}");
        seed_fingerprint(&db_path, addr.port(), &format!("{base}/seed"), 200);
        let stats = run_with_options(
            &test_config(2, 100),
            db_path.clone(),
            output::OutputOptions::default(),
        )
        .await
        .expect("crawl run");
        server.abort();

        assert_eq!(stats.visited, 3);
        assert_eq!(stats.rate_limit_waits, 0);
        assert_eq!(stats.longest_rate_wait, Duration::ZERO);
        remove_db(&db_path);
    }
}
