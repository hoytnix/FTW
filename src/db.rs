//! Master SQLite database: one file, one writer, no result files.
//!
//! Scan, fingerprint, and crawl results all live in a single database file
//! (default `ftw.db`). The database is opened once per run with WAL mode, a
//! 5 s busy timeout, and `synchronous=NORMAL`, the schema is created with
//! `CREATE TABLE IF NOT EXISTS`, and the resulting connection is moved into
//! the single writer task — the only task that ever executes INSERT/UPSERT
//! statements. Scanner, fingerprint, and crawl workers only hold bounded
//! `tokio::sync::mpsc` senders and never open a connection or write directly.
//!
//! Concurrent-process note: SQLite WAL does NOT make concurrent writers lock
//! free. If a second FTW process opens the same database file, its writes
//! wait up to `busy_timeout` (5 s) and then fail with `SQLITE_BUSY`, which
//! the writer reports as an error and exits non-zero — it is never retried
//! forever in a loop.

use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

/// Milliseconds a blocked writer waits on a locked database before failing.
pub const BUSY_TIMEOUT_MS: i32 = 5000;

/// Full schema: created with `CREATE TABLE IF NOT EXISTS` on every open so
/// reruns against an existing database are safe.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scan_results (
  ip           TEXT NOT NULL,
  port         INTEGER NOT NULL,
  status       TEXT NOT NULL,
  scanned_at   TEXT NOT NULL,
  PRIMARY KEY (ip, port)
);
CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);
CREATE TABLE IF NOT EXISTS fingerprint_results (
  ip                  TEXT NOT NULL,
  port                INTEGER NOT NULL,
  scheme              TEXT NOT NULL,
  final_url           TEXT NOT NULL,
  status              INTEGER,
  server              TEXT,
  tls                 TEXT NOT NULL,
  error               TEXT,
  php_detected        INTEGER NOT NULL,
  php_version         TEXT,
  php_signals         TEXT NOT NULL,
  wordpress_detected  INTEGER NOT NULL,
  wordpress_version   TEXT,
  wordpress_signals   TEXT NOT NULL,
  php_apps            TEXT NOT NULL,
  tailwind_detected   INTEGER NOT NULL,
  tailwind_confidence TEXT NOT NULL,
  tailwind_signals    TEXT NOT NULL,
  fetch_method        TEXT NOT NULL,
  head_status         INTEGER,
  fingerprinted_at    TEXT NOT NULL,
  PRIMARY KEY (ip, port, scheme)
);
CREATE INDEX IF NOT EXISTS idx_fingerprint_results_status ON fingerprint_results(status);
CREATE TABLE IF NOT EXISTS crawl_pages (
  url          TEXT PRIMARY KEY,
  final_url    TEXT,
  status       INTEGER,
  content_type TEXT,
  title        TEXT,
  depth        INTEGER NOT NULL,
  parent_url   TEXT,
  error        TEXT,
  fetched_at   TEXT NOT NULL,
  links_found  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS crawl_links (
  from_url TEXT NOT NULL,
  to_url   TEXT NOT NULL,
  PRIMARY KEY (from_url, to_url)
);
CREATE TABLE IF NOT EXISTS probe_results (
  host          TEXT NOT NULL,
  port          INTEGER NOT NULL,
  scheme        TEXT NOT NULL,
  final_url     TEXT NOT NULL,
  status        INTEGER,
  server        TEXT,
  patch_status  TEXT NOT NULL,
  record_json   TEXT NOT NULL,
  probed_at     TEXT NOT NULL,
  PRIMARY KEY (host, port)
);
CREATE TABLE IF NOT EXISTS host_check_results (
  host          TEXT PRIMARY KEY,
  php_version   TEXT,
  php_raw       TEXT NOT NULL,
  packages_json TEXT NOT NULL,
  checked_at    TEXT NOT NULL
);
";

/// Open (or create) the master database, configure WAL mode, a 5 s busy
/// timeout, and `synchronous=NORMAL`, and ensure the schema exists.
pub fn open<P: AsRef<Path>>(path: P) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS)?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Best-effort WAL checkpoint on exit so the `-wal` file does not linger.
/// Failures are ignored: the data is already durable in the WAL.
pub fn checkpoint(conn: &Connection) {
    let _ = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)", []);
}

/// Format a Unix timestamp as ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
fn iso8601_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let mut y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mut m = mp as i64 + 3;
    if m > 12 {
        y += 1;
        m -= 12;
    }
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    )
}

/// Current UTC time as ISO 8601, for the `*_at` columns.
#[must_use]
pub fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| -> i64 { d.as_secs().try_into().unwrap_or(i64::MAX) })
        .unwrap_or(0);
    iso8601_from_unix(secs)
}

/// Insert or update one scan result. Reruns overwrite the status and
/// timestamp for the same `(ip, port)` instead of duplicating rows.
pub fn upsert_scan(
    conn: &Connection,
    result: &crate::scanner::ScanResult,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO scan_results (ip, port, status, scanned_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (ip, port) DO UPDATE
         SET status = excluded.status, scanned_at = excluded.scanned_at",
        params![
            result.ip.to_string(),
            result.port,
            result.status.as_str(),
            now_iso8601(),
        ],
    )?;
    Ok(())
}

/// Distinct host IPs with at least one `open` port — the host-check seed
/// set. Hosts are SSHed directly, so only the IP string is needed.
/// Unparseable rows are skipped (the writer only stores valid `IpAddr`s,
/// so this is purely defensive).
pub fn host_check_seeds(conn: &Connection) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT DISTINCT ip FROM scan_results WHERE status = 'open'")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        let ip = row?;
        if ip.parse::<IpAddr>().is_ok() {
            out.push(ip);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Every `(ip, port)` currently marked `open` — the fingerprint seed set.
/// Rows with unparseable addresses are skipped (the writer only stores
/// valid `IpAddr`s, so this is purely defensive).
pub fn open_ports(conn: &Connection) -> Result<Vec<(IpAddr, u16)>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT ip, port FROM scan_results WHERE status = 'open'")?;
    let rows = stmt.query_map([], |row| {
        let ip: String = row.get(0)?;
        let port: u16 = row.get(1)?;
        Ok((ip, port))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (ip_text, port) = row?;
        if let Ok(ip) = ip_text.parse::<IpAddr>() {
            out.push((ip, port));
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Signal lists are stored as JSON text; serialization cannot fail for
/// these plain string shapes, so fall back to `[]` instead of erroring.
fn signals_json(values: &[String]) -> String {
    serde_json::to_string(values).unwrap_or_else(|_| "[]".to_string())
}

fn apps_json(apps: &[crate::tech::PhpApp]) -> String {
    serde_json::to_string(apps).unwrap_or_else(|_| "[]".to_string())
}

/// Insert or update one fingerprint record, keyed by `(ip, port, scheme)`.
/// Signal arrays are stored as JSON text inside their columns.
pub fn upsert_fingerprint(
    conn: &Connection,
    record: &crate::fingerprint::FingerprintRecord,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO fingerprint_results
         (ip, port, scheme, final_url, status, server, tls, error,
          php_detected, php_version, php_signals,
          wordpress_detected, wordpress_version, wordpress_signals, php_apps,
          tailwind_detected, tailwind_confidence, tailwind_signals,
          fetch_method, head_status, fingerprinted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21)
         ON CONFLICT (ip, port, scheme) DO UPDATE SET
           final_url = excluded.final_url, status = excluded.status,
           server = excluded.server, tls = excluded.tls, error = excluded.error,
           php_detected = excluded.php_detected, php_version = excluded.php_version,
           php_signals = excluded.php_signals,
           wordpress_detected = excluded.wordpress_detected,
           wordpress_version = excluded.wordpress_version,
           wordpress_signals = excluded.wordpress_signals,
           php_apps = excluded.php_apps,
           tailwind_detected = excluded.tailwind_detected,
           tailwind_confidence = excluded.tailwind_confidence,
           tailwind_signals = excluded.tailwind_signals,
           fetch_method = excluded.fetch_method,
           head_status = excluded.head_status,
           fingerprinted_at = excluded.fingerprinted_at",
        params![
            record.ip,
            record.port,
            record.scheme,
            record.final_url,
            record.status,
            record.server,
            record.tls,
            record.error,
            record.php_detected,
            record.php_version,
            signals_json(&record.php_signals),
            record.wordpress_detected,
            record.wordpress_version,
            signals_json(&record.wordpress_signals),
            apps_json(&record.php_apps),
            record.tailwind_detected,
            record.tailwind_confidence,
            signals_json(&record.tailwind_signals),
            record.fetch_method,
            record.head_status,
            now_iso8601(),
        ],
    )?;
    Ok(())
}

/// Crawl seeds: fingerprint records with a non-null, non-empty `final_url`
/// and a 2xx or 3xx status. Timeouts, TLS errors, and connect errors are
/// never seeds.
pub fn crawl_seeds(conn: &Connection) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT final_url FROM fingerprint_results
         WHERE final_url IS NOT NULL AND final_url != ''
           AND status >= 200 AND status < 400",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Insert or update one crawled page, keyed by its normalized URL.
pub fn upsert_crawl_page(
    conn: &Connection,
    page: &crate::crawl::CrawlPageRecord,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO crawl_pages
         (url, final_url, status, content_type, title, depth, parent_url,
          error, fetched_at, links_found)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT (url) DO UPDATE SET
           final_url = excluded.final_url, status = excluded.status,
           content_type = excluded.content_type, title = excluded.title,
           depth = excluded.depth, parent_url = excluded.parent_url,
           error = excluded.error, fetched_at = excluded.fetched_at,
           links_found = excluded.links_found",
        params![
            page.url,
            page.final_url,
            page.status,
            page.content_type,
            page.title,
            page.depth as i64,
            page.parent_url,
            page.error,
            now_iso8601(),
            page.links_found as i64,
        ],
    )?;
    Ok(())
}

/// Insert or update one probe record, keyed by `(host, port)`. The full
/// record travels as JSON text; the column subset keeps seed-style queries
/// possible without parsing JSON.
pub fn upsert_probe(
    conn: &Connection,
    record: &crate::probe::ProbeRecord,
) -> Result<(), rusqlite::Error> {
    let json = serde_json::to_string(record).unwrap_or_else(|_| "{}".to_string());
    conn.execute(
        "INSERT INTO probe_results
         (host, port, scheme, final_url, status, server, patch_status,
          record_json, probed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT (host, port) DO UPDATE SET
           scheme = excluded.scheme, final_url = excluded.final_url,
           status = excluded.status, server = excluded.server,
           patch_status = excluded.patch_status,
           record_json = excluded.record_json,
           probed_at = excluded.probed_at",
        params![
            record.host,
            record.port,
            record.scheme,
            record.final_url,
            record.status,
            record.server,
            record.patch_status,
            json,
            now_iso8601(),
        ],
    )?;
    Ok(())
}

/// Insert or update one host-check record, keyed by host. The verbatim
/// `php -v` output is stored in full; packages travel as JSON text.
pub fn upsert_host_check(
    conn: &Connection,
    record: &crate::host_check::HostCheckRecord,
) -> Result<(), rusqlite::Error> {
    let json = serde_json::to_string(&record.packages).unwrap_or_else(|_| "[]".to_string());
    conn.execute(
        "INSERT INTO host_check_results
         (host, php_version, php_raw, packages_json, checked_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (host) DO UPDATE SET
           php_version = excluded.php_version, php_raw = excluded.php_raw,
           packages_json = excluded.packages_json,
           checked_at = excluded.checked_at",
        params![
            record.host,
            record.php_version,
            record.php_raw,
            json,
            now_iso8601(),
        ],
    )?;
    Ok(())
}

/// Record one extracted link, including external links that are never
/// fetched. Repeats are ignored, so cycles cannot duplicate rows.
pub fn insert_crawl_link(
    conn: &Connection,
    from_url: &str,
    to_url: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT OR IGNORE INTO crawl_links (from_url, to_url) VALUES (?1, ?2)",
        params![from_url, to_url],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("ftw-dbtest-{tag}-{nanos}-{}.db", std::process::id()))
    }

    fn row_count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("count rows")
    }

    #[test]
    fn iso8601_formats_known_timestamps() {
        assert_eq!(iso8601_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_from_unix(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601_from_unix(86_400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn open_creates_all_tables_and_indexes() {
        let path = temp_db("schema");
        let conn = open(&path).expect("open db");
        for table in [
            "scan_results",
            "fingerprint_results",
            "crawl_pages",
            "crawl_links",
            "probe_results",
            "host_check_results",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get(0),
                )
                .expect("schema lookup");
            assert_eq!(count, 1, "table {table} must exist");
        }
        // Reopen must be idempotent (CREATE TABLE IF NOT EXISTS).
        drop(conn);
        let _ = open(&path).expect("reopen db");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(path.with_extension("db-wal")).ok();
        std::fs::remove_file(path.with_extension("db-shm")).ok();
    }

    fn scan_result(ip: &str, port: u16, status: crate::scanner::PortStatus) -> crate::scanner::ScanResult {
        crate::scanner::ScanResult {
            ip: ip.parse().expect("test ip"),
            port,
            status,
            reason: status.as_str(),
        }
    }

    #[test]
    fn scan_reruns_upsert_instead_of_duplicating() {
        let path = temp_db("scan-upsert");
        let conn = open(&path).expect("open db");
        upsert_scan(&conn, &scan_result("127.0.0.1", 80, crate::scanner::PortStatus::Closed))
            .expect("first insert");
        upsert_scan(&conn, &scan_result("127.0.0.1", 80, crate::scanner::PortStatus::Open))
            .expect("rerun upsert");
        assert_eq!(row_count(&conn, "scan_results"), 1, "rerun must not duplicate rows");
        let status: String = conn
            .query_row(
                "SELECT status FROM scan_results WHERE ip = '127.0.0.1' AND port = 80",
                [],
                |row| row.get(0),
            )
            .expect("read status");
        assert_eq!(status, "open", "rerun must overwrite the status");
        let seeds = open_ports(&conn).expect("seed query");
        assert_eq!(seeds.len(), 1, "only open rows seed fingerprinting");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn open_ports_skips_closed_and_filtered() {
        let path = temp_db("seeds");
        let conn = open(&path).expect("open db");
        for (port, status) in [
            (80u16, crate::scanner::PortStatus::Open),
            (443u16, crate::scanner::PortStatus::Closed),
            (22u16, crate::scanner::PortStatus::Filtered),
        ] {
            upsert_scan(&conn, &scan_result("127.0.0.1", port, status)).expect("insert");
        }
        let seeds = open_ports(&conn).expect("seed query");
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].1, 80);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn host_check_seeds_are_distinct_open_ips_only() {
        let path = temp_db("hc-seeds");
        let conn = open(&path).expect("open db");
        for (ip, port, status) in [
            ("127.0.0.1", 80u16, crate::scanner::PortStatus::Open),
            ("127.0.0.1", 443u16, crate::scanner::PortStatus::Open),
            ("127.0.0.2", 80u16, crate::scanner::PortStatus::Closed),
            ("127.0.0.3", 22u16, crate::scanner::PortStatus::Filtered),
            ("127.0.0.4", 443u16, crate::scanner::PortStatus::Open),
        ] {
            upsert_scan(&conn, &scan_result(ip, port, status)).expect("insert");
        }
        let seeds = host_check_seeds(&conn).expect("seed query");
        assert_eq!(
            seeds,
            vec!["127.0.0.1".to_string(), "127.0.0.4".to_string()],
            "one row per open host, closed/filtered excluded"
        );
        std::fs::remove_file(&path).ok();
    }

    fn fingerprint_record(port: u16, status: Option<u16>, error: Option<&str>) -> crate::fingerprint::FingerprintRecord {
        crate::fingerprint::FingerprintRecord {
            ip: "127.0.0.1".to_string(),
            port,
            scheme: "http".to_string(),
            final_url: format!("http://127.0.0.1:{port}/"),
            status,
            server: Some("TestServer/1.0".to_string()),
            tls: "n/a".to_string(),
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

    #[test]
    fn fingerprint_upsert_round_trips_signals_as_json() {
        let path = temp_db("fp-upsert");
        let conn = open(&path).expect("open db");
        let mut record = fingerprint_record(80, Some(200), None);
        record.php_detected = true;
        record.php_version = Some("8.2.0".to_string());
        record.php_signals = vec!["x-powered-by".to_string()];
        upsert_fingerprint(&conn, &record).expect("insert");
        upsert_fingerprint(&conn, &record).expect("rerun");
        assert_eq!(row_count(&conn, "fingerprint_results"), 1, "rerun must upsert, not duplicate");
        let signals: String = conn
            .query_row(
                "SELECT php_signals FROM fingerprint_results WHERE port = 80",
                [],
                |row| row.get(0),
            )
            .expect("read signals");
        let parsed: Vec<String> = serde_json::from_str(&signals).expect("signals are JSON");
        assert_eq!(parsed, vec!["x-powered-by".to_string()]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn crawl_seeds_only_2xx_and_3xx_with_final_url() {
        let path = temp_db("crawl-seeds");
        let conn = open(&path).expect("open db");
        upsert_fingerprint(&conn, &fingerprint_record(80, Some(200), None)).expect("2xx seed");
        let mut redirect = fingerprint_record(443, Some(301), None);
        redirect.final_url = "http://127.0.0.1:443/landing".to_string();
        upsert_fingerprint(&conn, &redirect).expect("3xx seed");
        upsert_fingerprint(&conn, &fingerprint_record(22, Some(404), None)).expect("4xx not a seed");
        upsert_fingerprint(&conn, &fingerprint_record(23, None, Some("timeout"))).expect("error not a seed");
        let seeds = crawl_seeds(&conn).expect("seed query");
        assert_eq!(seeds.len(), 2, "only 2xx/3xx with a final_url seed the crawl, got: {seeds:?}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn crawl_links_dedupe_and_pages_upsert() {
        let path = temp_db("crawl");
        let conn = open(&path).expect("open db");
        let page = crate::crawl::CrawlPageRecord {
            url: "http://127.0.0.1:80/a".to_string(),
            final_url: Some("http://127.0.0.1:80/a".to_string()),
            status: Some(200),
            content_type: Some("text/html".to_string()),
            title: Some("A".to_string()),
            depth: 0,
            parent_url: None,
            error: None,
            links_found: 1,
            body_truncated: false,
        };
        upsert_crawl_page(&conn, &page).expect("insert page");
        upsert_crawl_page(&conn, &page).expect("rerun");
        assert_eq!(row_count(&conn, "crawl_pages"), 1);
        insert_crawl_link(&conn, &page.url, "http://127.0.0.1:80/b").expect("insert link");
        insert_crawl_link(&conn, &page.url, "http://127.0.0.1:80/b").expect("repeat link");
        assert_eq!(row_count(&conn, "crawl_links"), 1, "cycles must not duplicate links");
        std::fs::remove_file(&path).ok();
    }

    /// Structural proof of the single-writer design, scoped to production
    /// code (test modules below `#[cfg(test)]` may open read connections to
    /// assert on): the only module that executes SQL statements is `db.rs`
    /// itself. Scanner, fingerprint, crawl, probe, and host-check workers
    /// never touch rusqlite at all, and the writer (`output.rs`) only calls
    /// `db::upsert_*` / `insert_*` helpers over the one connection it owns —
    /// it never executes statements directly.
    #[test]
    fn only_the_single_writer_path_executes_database_writes() {
        fn production(source: &str) -> &str {
            source.split("#[cfg(test)]").next().unwrap_or(source)
        }
        for worker in [
            ("scanner.rs", production(include_str!("scanner.rs"))),
            ("crawl.rs", production(include_str!("crawl.rs"))),
            ("fingerprint.rs", production(include_str!("fingerprint.rs"))),
            ("probe.rs", production(include_str!("probe.rs"))),
            ("host_check.rs", production(include_str!("host_check.rs"))),
        ] {
            assert!(
                !worker.1.contains("rusqlite"),
                "{} must never open a database connection or write directly",
                worker.0
            );
        }
        for module in [
            ("output.rs", production(include_str!("output.rs"))),
            ("fingerprint.rs", production(include_str!("fingerprint.rs"))),
            ("probe.rs", production(include_str!("probe.rs"))),
            ("host_check.rs", production(include_str!("host_check.rs"))),
        ] {
            assert!(
                !module.1.contains(".execute"),
                "{} must only call db helpers, never execute statements",
                module.0
            );
        }
    }
}
