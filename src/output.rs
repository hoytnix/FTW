//! Streaming result writer: one task owns the database connection and writes
//! each result to the master SQLite database as it arrives over a bounded
//! channel.
//!
//! The writer task is the ONLY place that writes to the database and the only
//! place that prints live terminal output, so event order is preserved and
//! lines never interleave. For every event it upserts the record into the
//! database, writes the exact same line/record to stdout immediately (unless
//! quiet), then flushes stdout before taking the next event — never waiting
//! for the buffer to fill or the channel to close. Flushing per event is
//! slower than bulk buffering on very large scans; that is the intended
//! tradeoff: live visibility over throughput.
//!
//! A second FTW process opening the same database file is NOT silently
//! absorbed: its writes wait up to the busy timeout and then fail with
//! `SQLITE_BUSY`, which is returned here as an I/O error so the run exits
//! non-zero instead of retrying forever.
//!
//! Final summaries are printed by the caller to stderr only, after the
//! channel closes and the writer finishes, so stdout stays parseable.

use std::io;
use std::io::Write as _;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use tokio::sync::mpsc;

use crate::crawl::{CrawlEvent, CrawlStats};
use crate::db;
use crate::fingerprint::{FingerprintRecord, FingerprintStats};
use crate::scanner::ScanResult;

/// Live-output options shared by all subcommands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutputOptions {
    /// Print one human-readable stderr line per event (elapsed + detail).
    pub verbose: bool,
    /// Suppress all terminal output during the run (database still written,
    /// still flushed per event). Errors and the final summary still go to
    /// stderr.
    pub quiet: bool,
}

impl OutputOptions {
    #[must_use]
    pub fn new(verbose: bool, quiet: bool) -> Self {
        Self { verbose, quiet }
    }
}

/// Aggregate counts for one scan run (counted by the writer task).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanStats {
    pub open: usize,
    pub closed: usize,
    pub filtered: usize,
}

impl ScanStats {
    #[allow(dead_code)]
    #[must_use]
    pub fn total(self) -> usize {
        self.open + self.closed + self.filtered
    }

    fn record(&mut self, result: &ScanResult) {
        use crate::scanner::PortStatus;
        match result.status {
            PortStatus::Open => self.open += 1,
            PortStatus::Closed => self.closed += 1,
            PortStatus::Filtered => self.filtered += 1,
        }
    }
}

/// One output line: `<ip>:<port> <status>`.
#[must_use]
pub fn format_result(result: &ScanResult) -> String {
    format!("{}:{} {}\n", result.ip, result.port, result.status)
}

/// One verbose stderr line per scan event: elapsed time plus the
/// classification reason. For filtered results the reason is the underlying
/// error kind (timeout, host/network unreachable, permission denied, or
/// other) — never just the word "filtered".
#[must_use]
pub fn format_scan_verbose(elapsed: Duration, result: &ScanResult) -> String {
    format!(
        "[+{:.2}s] {}:{} {} ({})\n",
        elapsed.as_secs_f64(),
        result.ip,
        result.port,
        result.status,
        result.reason,
    )
}

/// One verbose stderr line per fingerprint event: `ip:port`, the scheme
/// actually used, fetch method and head status, HTTP status (or error), final
/// URL, Server header when present, and detected technologies. The JSON
/// record on stdout stays the machine-readable source of truth; this line is
/// only for watching, and it always names both scheme and final URL so a
/// scheme mismatch (for example a plain-HTTP request to a TLS port returning
/// 400) is obvious from this line alone.
#[must_use]
pub fn format_fingerprint_verbose(elapsed: Duration, record: &FingerprintRecord) -> String {
    let head = record
        .head_status
        .map(|status| status.to_string())
        .unwrap_or_else(|| "-".to_string());
    let outcome = match record.status {
        Some(status) => status.to_string(),
        None => format!(
            "error:{}",
            record.error.as_deref().unwrap_or("other")
        ),
    };
    let mut line = format!(
        "[+{:.2}s] {}:{} via {} {}(head_status={}) -> {} {}",
        elapsed.as_secs_f64(),
        record.ip,
        record.port,
        record.scheme,
        record.fetch_method,
        head,
        outcome,
        record.final_url,
    );
    if let Some(server) = record.server.as_deref().filter(|s| !s.is_empty()) {
        line.push_str(&format!(" server=\"{server}\""));
    }
    if record.php_detected {
        match record.php_version.as_deref() {
            Some(version) => line.push_str(&format!(" php={version}")),
            None => line.push_str(" php=yes"),
        }
        if !record.php_signals.is_empty() {
            line.push_str(&format!("({})", record.php_signals.join(",")));
        }
    }
    if record.wordpress_detected {
        match record.wordpress_version.as_deref() {
            Some(version) => line.push_str(&format!(" wp={version}")),
            None => line.push_str(" wp=yes"),
        }
        if !record.wordpress_signals.is_empty() {
            line.push_str(&format!("({})", record.wordpress_signals.join(",")));
        }
    }
    if !record.php_apps.is_empty() {
        let apps: Vec<String> = record
            .php_apps
            .iter()
            .map(|app| match app.version.as_deref() {
                Some(version) => format!("{}:{version}", app.name),
                None => app.name.clone(),
            })
            .collect();
        line.push_str(&format!(" apps=[{}]", apps.join(",")));
    }
    if record.tailwind_confidence != "none" {
        line.push_str(&format!(" tailwind={}", record.tailwind_confidence));
        if !record.tailwind_signals.is_empty() {
            line.push_str(&format!("({})", record.tailwind_signals.join(",")));
        }
    }
    line.push('\n');
    line
}

/// One stdout line per crawled page: `<url> <status-or-error>`.
#[must_use]
pub fn format_crawl_page(url: &str, status: Option<u16>, error: Option<&str>) -> String {
    match status {
        Some(status) => format!("{url} {status}\n"),
        None => format!("{url} error:{}\n", error.unwrap_or("other")),
    }
}

/// One verbose stderr line per crawled page: elapsed time, depth, URL, final
/// URL, outcome, and how many links the page yielded.
#[must_use]
pub fn format_crawl_verbose(
    elapsed: Duration,
    url: &str,
    final_url: Option<&str>,
    status: Option<u16>,
    error: Option<&str>,
    depth: usize,
    links_found: usize,
) -> String {
    let outcome = match status {
        Some(status) => status.to_string(),
        None => format!("error:{}", error.unwrap_or("other")),
    };
    format!(
        "[+{:.2}s] depth={depth} {url} -> {} {outcome} links={links_found}\n",
        final_url.unwrap_or("-"),
        elapsed.as_secs_f64(),
    )
}

/// Write one result line to the locked stdout and flush it. Stdout carries
/// parseable results only, never diagnostics.
fn emit_stdout(line: &str) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let _ = handle.write_all(line.as_bytes());
    let _ = handle.flush();
}

fn db_error(err: rusqlite::Error) -> io::Error {
    io::Error::other(format!("ftw: database write failed: {err}"))
}

/// Drain scan results: upsert each `<ip>:<port> <status>` result into the
/// master database, duplicate it to stdout (unless quiet), print a verbose
/// stderr line per event when requested, and flush stdout after every event.
/// Returns per-run counts. Ends when all senders drop, then checkpoints WAL.
pub async fn run_scan_db_writer(
    mut rx: mpsc::Receiver<ScanResult>,
    conn: Connection,
    options: OutputOptions,
) -> io::Result<ScanStats> {
    let start = Instant::now();
    let mut stats = ScanStats::default();
    while let Some(result) = rx.recv().await {
        stats.record(&result);
        db::upsert_scan(&conn, &result).map_err(db_error)?;
        let line = format_result(&result);
        if !options.quiet {
            emit_stdout(&line);
        }
        if options.verbose {
            eprint!("{}", format_scan_verbose(start.elapsed(), &result));
        }
        if !options.quiet {
            io::stdout().flush()?;
        }
    }
    db::checkpoint(&conn);
    Ok(stats)
}

/// Drain fingerprint records: upsert each record into the master database as
/// well as duplicating it to stdout as one JSON object per line (unless
/// quiet), with a verbose stderr line per event when requested. Flushes
/// stdout after every event. Returns per-run counts. Ends when all senders
/// drop, then checkpoints WAL.
pub async fn run_fingerprint_db_writer(
    mut rx: mpsc::Receiver<FingerprintRecord>,
    conn: Connection,
    options: OutputOptions,
) -> io::Result<FingerprintStats> {
    let start = Instant::now();
    let mut stats = FingerprintStats::default();
    while let Some(record) = rx.recv().await {
        stats.record(&record);
        db::upsert_fingerprint(&conn, &record).map_err(db_error)?;
        let mut line =
            serde_json::to_string(&record).map_err(|err| io::Error::other(err.to_string()))?;
        line.push('\n');
        if !options.quiet {
            emit_stdout(&line);
        }
        if options.verbose {
            eprint!("{}", format_fingerprint_verbose(start.elapsed(), &record));
        }
        if !options.quiet {
            io::stdout().flush()?;
        }
    }
    db::checkpoint(&conn);
    Ok(stats)
}

/// Drain crawl events: upsert each visited page and record each extracted
/// link in the master database, print one stdout line per visited page
/// (unless quiet), and print a verbose stderr line per page when requested.
/// Flushes stdout after every event. Returns per-run counts. Ends when all
/// senders drop, then checkpoints WAL.
pub async fn run_crawl_db_writer(
    mut rx: mpsc::Receiver<CrawlEvent>,
    conn: Connection,
    options: OutputOptions,
) -> io::Result<CrawlStats> {
    let start = Instant::now();
    let mut stats = CrawlStats::default();
    while let Some(event) = rx.recv().await {
        match event {
            CrawlEvent::Page(page) => {
                stats.record_page(&page);
                db::upsert_crawl_page(&conn, &page).map_err(db_error)?;
                let line = format_crawl_page(&page.url, page.status, page.error.as_deref());
                if !options.quiet {
                    emit_stdout(&line);
                }
                if options.verbose {
                    eprint!(
                        "{}",
                        format_crawl_verbose(
                            start.elapsed(),
                            &page.url,
                            page.final_url.as_deref(),
                            page.status,
                            page.error.as_deref(),
                            page.depth,
                            page.links_found,
                        )
                    );
                }
                if !options.quiet {
                    io::stdout().flush()?;
                }
            }
            CrawlEvent::Link { from_url, to_url, external } => {
                stats.record_link(external);
                db::insert_crawl_link(&conn, &from_url, &to_url).map_err(db_error)?;
            }
        }
    }
    db::checkpoint(&conn);
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("ftw-outtest-{tag}-{nanos}-{}.db", std::process::id()))
    }

    fn scan_result(ip: &str, port: u16, status: crate::scanner::PortStatus) -> ScanResult {
        ScanResult {
            ip: ip.parse().expect("test ip"),
            port,
            status,
            reason: status.as_str(),
        }
    }

    fn fingerprint_record(port: u16) -> FingerprintRecord {
        FingerprintRecord {
            ip: "127.0.0.1".to_string(),
            port,
            scheme: "http".to_string(),
            final_url: format!("http://127.0.0.1:{port}/"),
            status: Some(200),
            server: None,
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

    /// The scan writer persists every event to the database (no result
    /// files): three events, one per port, with a rerun upserting in place.
    #[tokio::test]
    async fn scan_writer_persists_events_to_database() {
        let path = temp_db("scan");
        let conn = db::open(&path).expect("open db");
        let (tx, rx) = mpsc::channel(8);
        let options = OutputOptions::new(false, true);
        let task = tokio::spawn(run_scan_db_writer(rx, conn, options));
        for port in [80u16, 443, 22] {
            tx.send(scan_result(
                "127.0.0.1",
                port,
                crate::scanner::PortStatus::Open,
            ))
            .await
            .expect("send scan result");
        }
        drop(tx);
        let stats = task.await.expect("writer task").expect("writer ok");
        assert_eq!(stats.total(), 3);

        let check = db::open(&path).expect("reopen db");
        let count: i64 = check
            .query_row("SELECT COUNT(*) FROM scan_results", [], |row| row.get(0))
            .expect("count rows");
        assert_eq!(count, 3, "every event must land in the database");
        std::fs::remove_file(&path).ok();
    }

    /// The fingerprint writer persists every record to the database with its
    /// signal arrays stored as JSON text.
    #[tokio::test]
    async fn fingerprint_writer_persists_records_to_database() {
        let path = temp_db("fingerprint");
        let conn = db::open(&path).expect("open db");
        let (tx, rx) = mpsc::channel(8);
        let options = OutputOptions::new(false, true);
        let task = tokio::spawn(run_fingerprint_db_writer(rx, conn, options));
        for port in [80u16, 443] {
            tx.send(fingerprint_record(port)).await.expect("send record");
        }
        drop(tx);
        let stats = task.await.expect("writer task").expect("writer ok");
        assert_eq!(stats.total, 2);

        let check = db::open(&path).expect("reopen db");
        let count: i64 = check
            .query_row("SELECT COUNT(*) FROM fingerprint_results", [], |row| row.get(0))
            .expect("count rows");
        assert_eq!(count, 2, "every record must land in the database");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn scan_verbose_names_filtered_reason_not_just_filtered() {
        use std::net::IpAddr;
        let result = ScanResult {
            ip: "127.0.0.1".parse::<IpAddr>().expect("ip"),
            port: 9,
            status: crate::scanner::PortStatus::Filtered,
            reason: "timeout",
        };
        let line = format_scan_verbose(Duration::from_millis(120), &result);
        assert!(line.contains("127.0.0.1:9"), "line names the target: {line}");
        assert!(line.contains("filtered"), "line names the status: {line}");
        assert!(line.contains("timeout"), "line names the reason: {line}");
    }

    #[test]
    fn fingerprint_verbose_names_scheme_and_final_url() {
        let mut record = fingerprint_record(443);
        record.scheme = "http".to_string();
        record.status = Some(400);
        record.final_url = "http://127.0.0.1:443/".to_string();
        record.fetch_method = "get".to_string();
        let line = format_fingerprint_verbose(Duration::from_millis(50), &record);
        assert!(line.contains("http"), "scheme visible: {line}");
        assert!(
            line.contains("http://127.0.0.1:443/"),
            "final_url visible: {line}"
        );
        assert!(line.contains("400"), "status visible: {line}");
    }
}
