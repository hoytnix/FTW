//! Per-canonical-domain sliding-window rate limiter for `ftw crawl`.
//!
//! One [`RateLimiter`] is shared by every crawl worker through an `Arc`:
//! workers must never own or clone limiter state per thread, or each thread
//! would get its own allowance and a domain would receive
//! threads-times-the-limit. The limiter holds a mutex-guarded map from
//! canonical domain to that domain's request timestamps; the mutex is only
//! ever held for microseconds and never across an `.await`.
//!
//! Each domain gets a burst of up to N requests per window, then throttles:
//! a request is allowed only when fewer than N requests to that domain
//! started in the last `window`. Otherwise the caller asynchronously sleeps
//! until the oldest request in the window expires and then re-checks (a
//! woken worker can still lose the freed slot to another worker, so the
//! check loops). This is a sliding window, not a fixed-interval spacer, and
//! it is per domain, not global. A limit of 0 means unlimited: `acquire`
//! returns immediately without recording anything, so 0 is never treated as
//! "0 requests allowed".
//!
//! The window is a constructor parameter (60 seconds in production via
//! [`DEFAULT_WINDOW`]) so tests can use millisecond windows instead of
//! waiting out a real minute. Limiter state lives only in memory for one
//! crawl run and is discarded on exit — nothing is stored in the database.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Production sliding-window length: 60 seconds.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// Normalize one host exactly as the limiter sees it: lowercase, one pair
/// of IPv6 brackets stripped, one leading `www.` stripped.
fn normalize_host(host: &str) -> String {
    let lower = host.to_lowercase();
    // IPv6 literals parse with brackets (`[::1]`); the canonical domain is
    // the IP string itself, without them.
    let bare = lower
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(&lower);
    bare.strip_prefix("www.")
        .map(str::to_string)
        .unwrap_or_else(|| bare.to_string())
}

/// Canonical domain of one fetched URL: the lowercase host with a single
/// leading `www.` stripped. Scheme and port are ignored (http and https to
/// the same host share one limiter, as do different ports), IP hosts stay
/// as-is, and subdomains other than `www.` stay distinct — there is no
/// registrable-domain logic in this version. Unparseable input maps to
/// itself so it still gets a (harmless, per-URL) bucket.
#[must_use]
pub fn canonical_domain(raw_url: &str) -> String {
    reqwest::Url::parse(raw_url)
        .ok()
        .and_then(|url| url.host_str().map(normalize_host))
        .unwrap_or_else(|| raw_url.to_string())
}

/// Canonicalize a per-domain config key through the same normalization, so
/// config keys and runtime URLs meet: bare hosts, `host:port`, and full
/// URLs all reduce identically (`www.wordpress.org` in config is
/// `wordpress.org` at runtime).
#[must_use]
pub fn canonical_host(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(url) = reqwest::Url::parse(trimmed) {
        if let Some(host) = url.host_str() {
            return normalize_host(host);
        }
    }
    if let Ok(url) = reqwest::Url::parse(&format!("http://{trimmed}")) {
        if let Some(host) = url.host_str() {
            return normalize_host(host);
        }
    }
    normalize_host(trimmed)
}

/// One stderr line per rate-limit wait, printed live by the worker when its
/// acquire actually blocked: `rate-limit wait <domain> <seconds>s`.
#[must_use]
pub fn format_rate_wait(domain: &str, waited: Duration) -> String {
    format!("rate-limit wait {domain} {:.2}s", waited.as_secs_f64())
}

#[derive(Debug, Default)]
struct DomainState {
    /// Request start times inside the current window, oldest first.
    hits: VecDeque<Instant>,
}

#[derive(Debug, Default)]
struct LimiterState {
    domains: HashMap<String, DomainState>,
    waits: usize,
    longest_wait: Duration,
}

/// Shared sliding-window limiter: at most `limit` requests per `window` per
/// canonical domain, across all workers holding an `Arc` clone combined. A
/// per-domain override (from `[crawl.rate_limits]`) replaces the default
/// for that domain only.
#[derive(Debug)]
pub struct RateLimiter {
    limit: u64,
    window: Duration,
    overrides: HashMap<String, u64>,
    state: std::sync::Mutex<LimiterState>,
}

impl RateLimiter {
    /// Build a limiter allowing `limit` requests per `window` per canonical
    /// domain. A `limit` of 0 means unlimited.
    #[must_use]
    pub fn new(limit: u64, window: Duration) -> Self {
        Self {
            limit,
            window,
            overrides: HashMap::new(),
            state: std::sync::Mutex::new(LimiterState::default()),
        }
    }

    /// Attach per-domain limits keyed by canonical domain. Keys are
    /// canonicalized on the way in, so raw config spellings
    /// (`www.wordpress.org`, `https://wordpress.org:443/`) land on the same
    /// bucket the runtime lookup uses.
    #[must_use]
    pub fn with_overrides(mut self, overrides: HashMap<String, u64>) -> Self {
        self.overrides = overrides
            .into_iter()
            .map(|(domain, limit)| (canonical_host(&domain), limit))
            .collect();
        self
    }

    /// Wait until a request to `domain` may start, record it, and return the
    /// total time spent waiting (`Duration::ZERO` when no sleep was needed).
    /// Recording happens here, at fetch-start time, so failed fetches still
    /// count — they still hit the server. Redirects followed internally by
    /// the HTTP client are not separate acquires.
    pub async fn acquire(&self, domain: &str) -> Duration {
        let effective = self.overrides.get(domain).copied().unwrap_or(self.limit);
        if effective == 0 {
            return Duration::ZERO;
        }
        let start = Instant::now();
        let mut slept = false;
        loop {
            // Decide under the lock, sleep outside it: the guard is dropped
            // before any `.await` below.
            let wake = {
                let mut state = self.state.lock().expect("rate limiter lock");
                let hits = &mut state
                    .domains
                    .entry(domain.to_string())
                    .or_default()
                    .hits;
                let cutoff = Instant::now() - self.window;
                while hits.front().is_some_and(|hit| *hit <= cutoff) {
                    hits.pop_front();
                }
                if (hits.len() as u64) < effective {
                    hits.push_back(Instant::now());
                    let waited = if slept { start.elapsed() } else { Duration::ZERO };
                    if slept {
                        state.waits += 1;
                        state.longest_wait = state.longest_wait.max(waited);
                    }
                    return waited;
                }
                // The window is full: the oldest hit decides when a slot
                // frees. It is always present here (`effective` ≥ 1).
                hits[0] + self.window
            };
            tokio::time::sleep_until(wake.into()).await;
            slept = true;
        }
    }

    /// How many acquires blocked at least once.
    #[must_use]
    pub fn waits(&self) -> usize {
        self.state.lock().expect("rate limiter lock").waits
    }

    /// The longest single acquire's total wait (`Duration::ZERO` when nothing
    /// ever blocked).
    #[must_use]
    pub fn longest_wait(&self) -> Duration {
        self.state.lock().expect("rate limiter lock").longest_wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> String {
        raw.to_string()
    }

    /// Canonical domains: scheme and port are ignored, one `www.` is
    /// stripped, other subdomains and IPs stay as-is.
    #[test]
    fn canonical_domain_strips_one_www_and_ignores_scheme_and_port() {
        assert_eq!(
            canonical_domain(&url("https://www.wordpress.org/docs/")),
            "wordpress.org"
        );
        assert_eq!(
            canonical_domain(&url("http://wordpress.org/about/")),
            "wordpress.org"
        );
        assert_eq!(
            canonical_domain(&url("https://wordpress.org:443/")),
            "wordpress.org"
        );
        assert_eq!(
            canonical_domain(&url("http://wordpress.org:8080/x")),
            "wordpress.org",
            "ports never join the canonical domain"
        );
        assert_eq!(
            canonical_domain(&url("https://blog.wordpress.org/")),
            "blog.wordpress.org",
            "non-www subdomains stay distinct"
        );
        assert_eq!(
            canonical_domain(&url("http://66.6.42.252/")),
            "66.6.42.252",
            "IP hosts stay as-is"
        );
        assert_eq!(
            canonical_domain(&url("HTTP://WWW.Example.COM/")),
            "example.com",
            "hosts lowercase before stripping"
        );
        assert_eq!(
            canonical_domain(&url("http://[::1]:8080/")),
            "::1",
            "IPv6 hosts stay as-is"
        );
    }

    /// Config keys canonicalize exactly like runtime URLs: bare hosts,
    /// `host:port`, and full URLs all meet on the same bucket.
    #[test]
    fn canonical_host_matches_runtime_domains() {
        assert_eq!(canonical_host("wordpress.org"), "wordpress.org");
        assert_eq!(canonical_host("www.wordpress.org"), "wordpress.org");
        assert_eq!(canonical_host("WWW.WordPress.Org"), "wordpress.org");
        assert_eq!(
            canonical_host("https://www.wordpress.org:443/docs/"),
            "wordpress.org"
        );
        assert_eq!(canonical_host("wordpress.org:8080"), "wordpress.org");
        assert_eq!(canonical_host("blog.wordpress.org"), "blog.wordpress.org");
        assert_eq!(canonical_host("66.6.42.252"), "66.6.42.252");
        assert_eq!(
            canonical_domain("https://wordpress.org/about/"),
            canonical_host("www.wordpress.org"),
            "config key and runtime URL share one bucket"
        );
    }

    /// A per-domain override replaces the global default for that domain
    /// only; other domains keep the default.
    #[tokio::test]
    async fn per_domain_override_throttles_one_domain_only() {
        let overrides = HashMap::from([("WWW.Example.COM".to_string(), 1)]);
        let limiter = RateLimiter::new(60, Duration::from_millis(100)).with_overrides(overrides);
        assert_eq!(limiter.acquire("example.com").await, Duration::ZERO);
        let waited = limiter.acquire("example.com").await;
        assert!(
            waited >= Duration::from_millis(80),
            "overridden domain throttles at 1/window, waited {waited:?}"
        );
        assert_eq!(limiter.waits(), 1);
        for _ in 0..5 {
            assert_eq!(limiter.acquire("other.test").await, Duration::ZERO);
        }
        assert_eq!(limiter.waits(), 1, "other domains keep the loose default");
    }

    /// The limiter allows a burst of N, then the (N+1)th blocks until the
    /// window expires; afterwards the window is reusable.
    #[tokio::test]
    async fn limiter_bursts_then_blocks_until_window_expires() {
        let limiter = RateLimiter::new(2, Duration::from_millis(100));
        assert_eq!(limiter.acquire("example.com").await, Duration::ZERO);
        assert_eq!(limiter.acquire("example.com").await, Duration::ZERO);
        let waited = limiter.acquire("example.com").await;
        assert!(
            waited >= Duration::from_millis(80),
            "the third request must wait out the window, waited {waited:?}"
        );
        assert_eq!(limiter.waits(), 1);
        assert!(limiter.longest_wait() >= Duration::from_millis(80));
        // The window has since expired, so requests flow immediately again.
        assert_eq!(limiter.acquire("example.com").await, Duration::ZERO);
        assert_eq!(limiter.waits(), 1, "immediate acquires are not waits");
    }

    /// Two workers sharing one limiter do NOT each get N: with a limit of 1
    /// exactly one of two simultaneous acquires proceeds immediately.
    #[tokio::test]
    async fn shared_limiter_grants_one_allowance_to_two_workers() {
        let limiter = std::sync::Arc::new(RateLimiter::new(1, Duration::from_millis(100)));
        let gate = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let limiter = limiter.clone();
            let gate = gate.clone();
            handles.push(tokio::spawn(async move {
                gate.wait().await;
                limiter.acquire("shared.test").await
            }));
        }
        let mut waited = Vec::new();
        for handle in handles {
            waited.push(handle.await.expect("worker task"));
        }
        waited.sort();
        assert_eq!(waited.len(), 2);
        assert_eq!(waited[0], Duration::ZERO, "one worker proceeds at once");
        assert!(
            waited[1] >= Duration::from_millis(80),
            "the other worker waits out the window, waited {:?}",
            waited[1]
        );
        assert_eq!(limiter.waits(), 1);
    }

    /// A limit of 0 is unlimited, never "0 requests allowed": rapid acquires
    /// never block and record nothing.
    #[tokio::test]
    async fn unlimited_never_blocks_or_counts() {
        let limiter = RateLimiter::new(0, Duration::from_millis(10));
        for _ in 0..5 {
            assert_eq!(limiter.acquire("example.com").await, Duration::ZERO);
        }
        assert_eq!(limiter.waits(), 0);
        assert_eq!(limiter.longest_wait(), Duration::ZERO);
    }

    /// The verbose wait line has the exact required form.
    #[test]
    fn rate_wait_line_format() {
        assert_eq!(
            format_rate_wait("wordpress.org", Duration::from_millis(1500)),
            "rate-limit wait wordpress.org 1.50s"
        );
    }
}
