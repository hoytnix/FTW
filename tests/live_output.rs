//! Live-output CLI tests: default stdout duplication, `--verbose` stderr
//! lines, `--quiet` suppression, the `--verbose`/`--quiet` conflict, legacy
//! file-flag rejection, and the scan→fingerprint→crawl database chain.
//!
//! These run the built `ftw` binary end to end on loopback targets. Scan and
//! fingerprint results live in the master SQLite database (`--db`) — there
//! are no result files — while stdout still carries the same parseable lines
//! as before.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn ftw_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ftw"))
}

fn temp_tag(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("ftw-live-{prefix}-{nanos}-{}", std::process::id())
}

fn temp_path(tag: &str, ext: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{tag}.{ext}"))
}

fn remove_db(db_path: &std::path::Path) {
    std::fs::remove_file(db_path).ok();
    std::fs::remove_file(db_path.with_extension("db-wal")).ok();
    std::fs::remove_file(db_path.with_extension("db-shm")).ok();
}

fn db_text_rows(db_path: &std::path::Path, sql: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(db_path).expect("open db");
    let mut stmt = conn.prepare(sql).expect("prepare query");
    stmt.query_map([], |row| row.get(0))
        .expect("map rows")
        .collect::<Result<_, _>>()
        .expect("collect rows")
}

fn db_int_rows(db_path: &std::path::Path, sql: &str) -> Vec<i64> {
    let conn = rusqlite::Connection::open(db_path).expect("open db");
    let mut stmt = conn.prepare(sql).expect("prepare query");
    stmt.query_map([], |row| row.get(0))
        .expect("map rows")
        .collect::<Result<_, _>>()
        .expect("collect rows")
}

fn db_count(db_path: &std::path::Path, table: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open db");
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
        .expect("count rows")
}

/// Seed `scan_results` with open rows exactly as a prior `ftw scan --db` run
/// would have left them (fingerprint's own `db::open` completes the schema).
fn seed_open_ports(db_path: &std::path::Path, ports: &[u16]) {
    let conn = rusqlite::Connection::open(db_path).expect("open db");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scan_results (
           ip           TEXT NOT NULL,
           port         INTEGER NOT NULL,
           status       TEXT NOT NULL,
           scanned_at   TEXT NOT NULL,
           PRIMARY KEY (ip, port)
        );",
    )
    .expect("create scan table");
    for port in ports {
        conn.execute(
            "INSERT OR REPLACE INTO scan_results (ip, port, status, scanned_at)
             VALUES ('127.0.0.1', ?1, 'open', '2026-01-01T00:00:00Z')",
            rusqlite::params![port],
        )
        .expect("seed open row");
    }
}

/// A port nothing listens on (bind-then-drop, loopback only).
fn closed_port() -> u16 {
    let sock = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp port");
    sock.local_addr().expect("temp addr").port()
}

/// Hold an open loopback port for the duration of a scan. The kernel
/// completes TCP handshakes from the backlog even before `accept`, so the
/// socket only needs to stay bound.
fn hold_open_port() -> (std::net::TcpListener, u16) {
    let sock = std::net::TcpListener::bind("127.0.0.1:0").expect("bind open port");
    let port = sock.local_addr().expect("open addr").port();
    (sock, port)
}

/// Minimal blocking HTTP server: routes the request path (query stripped) to
/// a fixed HTML body, 404 otherwise. Returns the port; the thread exits
/// after `max_connections` connections.
fn spawn_route_server(
    routes: std::collections::HashMap<String, String>,
    max_connections: usize,
) -> (u16, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http server");
    let port = listener.local_addr().expect("http addr").port();
    let handle = std::thread::spawn(move || {
        for _ in 0..max_connections {
            let Ok((mut sock, _)) = listener.accept() else {
                break;
            };
            let routes = routes.clone();
            std::thread::spawn(move || {
                let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut buf = [0u8; 8192];
                let _ = sock.read(&mut buf);
                let text = String::from_utf8_lossy(&buf).into_owned();
                let path = text
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                let key = path.split('?').next().unwrap_or("/");
                let (status, body) = match routes.get(key) {
                    Some(body) => ("200 OK", body.clone()),
                    None => ("404 Not Found", String::new()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nServer: TestServer/1.0\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes());
            });
        }
    });
    (port, handle)
}

fn sorted_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    lines.sort_unstable();
    lines
}

/// Default flags: stdout must contain exactly the `<ip>:<port> <status>`
/// lines stored in the database (no result file is created).
#[test]
fn scan_default_stdout_matches_database() {
    let tag = temp_tag("scan-live");
    let yaml_path = temp_path(&tag, "yml");
    let db_path = temp_path(&tag, "db");
    let (_open_sock, open_port) = hold_open_port();
    let closed = closed_port();
    std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write yaml");

    let output = Command::new(ftw_bin())
        .args([
            "scan",
            "--input",
            &yaml_path.to_string_lossy(),
            "--ports",
            &format!("{open_port},{closed}"),
            "--db",
            &db_path.to_string_lossy(),
        ])
        .output()
        .expect("run ftw scan");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let open_line = format!("127.0.0.1:{open_port} open");
    let closed_line = format!("127.0.0.1:{closed} closed");
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert_eq!(
        sorted_lines(&stdout),
        sorted_lines(&format!("{open_line}\n{closed_line}\n")),
        "stdout must carry one line per scanned port"
    );

    // The same results must be in the database; no result file may exist.
    let mut rows = db_text_rows(
        &db_path,
        "SELECT ip || ':' || port || ' ' || status FROM scan_results",
    );
    rows.sort_unstable();
    assert_eq!(
        rows,
        sorted_lines(&stdout),
        "database rows must match the stdout lines"
    );
    assert!(
        !std::path::Path::new(&temp_path(&tag, "out")).exists(),
        "no result file may be created"
    );

    std::fs::remove_file(&yaml_path).ok();
    remove_db(&db_path);
}

/// `fingerprint --db` reads open ports from the database with no
/// scan-output file involved, and stores one row per port.
#[test]
fn fingerprint_reads_seeds_from_database_only() {
    let tag = temp_tag("fp-db");
    let yaml_path = temp_path(&tag, "yml");
    let db_path = temp_path(&tag, "db");
    std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write yaml");
    let mut routes = std::collections::HashMap::new();
    routes.insert(
        "/".to_string(),
        "<html><head><title>Hi</title></head><body>hi</body></html>".to_string(),
    );
    let (http_port, _server) = spawn_route_server(routes, 8);
    let closed = closed_port();

    let scan = Command::new(ftw_bin())
        .args([
            "scan",
            "--input",
            &yaml_path.to_string_lossy(),
            "--ports",
            &format!("{http_port},{closed}"),
            "--db",
            &db_path.to_string_lossy(),
            "--quiet",
        ])
        .output()
        .expect("run ftw scan");
    assert!(
        scan.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );

    // No scan-output file exists anywhere near this run; fingerprint must
    // still find the open port via --db alone.
    let scan_file = temp_path(&tag, "scan");
    assert!(!scan_file.exists());
    let output = Command::new(ftw_bin())
        .args([
            "fingerprint",
            "--db",
            &db_path.to_string_lossy(),
            "--scheme",
            "http",
        ])
        .output()
        .expect("run ftw fingerprint");
    assert!(
        output.status.success(),
        "fingerprint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let rows = db_text_rows(
        &db_path,
        "SELECT ip || ':' || port || ':' || scheme FROM fingerprint_results",
    );
    assert_eq!(
        rows,
        vec![format!("127.0.0.1:{http_port}:http")],
        "exactly the open port is fingerprinted, the closed port never"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let record: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout line is JSON");
    assert_eq!(record["status"], 200);

    std::fs::remove_file(&yaml_path).ok();
    remove_db(&db_path);
}

/// `--verbose` fingerprint: stderr must contain one per-event line for each
/// record, naming its scheme and final_url.
#[test]
fn fingerprint_verbose_stderr_names_scheme_and_final_url() {
    let tag = temp_tag("fingerprint-verbose");
    let yaml_path = temp_path(&tag, "yml");
    let db_path = temp_path(&tag, "db");
    std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write yaml");
    let mut routes = std::collections::HashMap::new();
    routes.insert(
        "/".to_string(),
        "<html><head><title>Hi</title></head><body>hi</body></html>".to_string(),
    );
    let (http_port, _server) = spawn_route_server(routes, 8);

    let scan = Command::new(ftw_bin())
        .args([
            "scan",
            "--input",
            &yaml_path.to_string_lossy(),
            "--ports",
            &http_port.to_string(),
            "--db",
            &db_path.to_string_lossy(),
            "--quiet",
        ])
        .output()
        .expect("run ftw scan");
    assert!(scan.status.success());

    let output = Command::new(ftw_bin())
        .args([
            "fingerprint",
            "--db",
            &db_path.to_string_lossy(),
            "--scheme",
            "http",
            "--verbose",
        ])
        .output()
        .expect("run ftw fingerprint");
    assert!(
        output.status.success(),
        "fingerprint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let rows = db_text_rows(&db_path, "SELECT scheme || ' ' || final_url FROM fingerprint_results");
    assert_eq!(rows.len(), 1, "expected one fingerprint row");
    let (scheme, final_url) = rows[0].split_once(' ').expect("scheme + url");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains(scheme),
        "verbose stderr must name the scheme {scheme}: {stderr}"
    );
    assert!(
        stderr.contains(final_url),
        "verbose stderr must name the final_url {final_url}: {stderr}"
    );

    std::fs::remove_file(&yaml_path).ok();
    remove_db(&db_path);
}

/// `--quiet` scan: stdout stays empty while the database is complete.
#[test]
fn scan_quiet_suppresses_stdout_but_writes_db() {
    let tag = temp_tag("scan-quiet");
    let yaml_path = temp_path(&tag, "yml");
    let db_path = temp_path(&tag, "db");
    let (_open_sock, open_port) = hold_open_port();
    let closed = closed_port();
    std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write yaml");

    let output = Command::new(ftw_bin())
        .args([
            "scan",
            "--input",
            &yaml_path.to_string_lossy(),
            "--ports",
            &format!("{open_port},{closed}"),
            "--db",
            &db_path.to_string_lossy(),
            "--quiet",
        ])
        .output()
        .expect("run ftw scan --quiet");
    assert!(
        output.status.success(),
        "quiet scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "quiet stdout must be empty, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    assert_eq!(
        db_count(&db_path, "scan_results"),
        2,
        "database must still be complete"
    );

    // The final summary still goes to stderr in quiet mode.
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("scanned"), "summary stays on stderr: {stderr}");

    std::fs::remove_file(&yaml_path).ok();
    remove_db(&db_path);
}

/// `--quiet` fingerprint: stdout stays empty while the database row lands.
#[test]
fn fingerprint_quiet_suppresses_stdout_but_writes_db() {
    let tag = temp_tag("fingerprint-quiet");
    let yaml_path = temp_path(&tag, "yml");
    let db_path = temp_path(&tag, "db");
    std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write yaml");
    let mut routes = std::collections::HashMap::new();
    routes.insert(
        "/".to_string(),
        "<html><head><title>Hi</title></head><body>hi</body></html>".to_string(),
    );
    let (http_port, _server) = spawn_route_server(routes, 8);

    let scan = Command::new(ftw_bin())
        .args([
            "scan",
            "--input",
            &yaml_path.to_string_lossy(),
            "--ports",
            &http_port.to_string(),
            "--db",
            &db_path.to_string_lossy(),
            "--quiet",
        ])
        .output()
        .expect("run ftw scan");
    assert!(scan.status.success());

    let output = Command::new(ftw_bin())
        .args([
            "fingerprint",
            "--db",
            &db_path.to_string_lossy(),
            "--scheme",
            "http",
            "--quiet",
        ])
        .output()
        .expect("run ftw fingerprint --quiet");
    assert!(
        output.status.success(),
        "quiet fingerprint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "quiet stdout must be empty, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        db_count(&db_path, "fingerprint_results"),
        1,
        "database must still be complete"
    );

    std::fs::remove_file(&yaml_path).ok();
    remove_db(&db_path);
}

/// `--verbose` and `--quiet` together are rejected by clap for all five
/// subcommands.
#[test]
fn verbose_and_quiet_conflict_on_all_subcommands() {
    let tag = temp_tag("conflict");
    let yaml_path = temp_path(&tag, "yml");
    let db_path = temp_path(&tag, "db");
    std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write yaml");

    let scan = Command::new(ftw_bin())
        .args([
            "scan",
            "--input",
            &yaml_path.to_string_lossy(),
            "--ports",
            "80",
            "--db",
            &db_path.to_string_lossy(),
            "--verbose",
            "--quiet",
        ])
        .output()
        .expect("run conflicting scan");
    assert!(
        !scan.status.success(),
        "--verbose + --quiet must be rejected for scan"
    );

    let fingerprint = Command::new(ftw_bin())
        .args([
            "fingerprint",
            "--db",
            &db_path.to_string_lossy(),
            "--verbose",
            "--quiet",
        ])
        .output()
        .expect("run conflicting fingerprint");
    assert!(
        !fingerprint.status.success(),
        "--verbose + --quiet must be rejected for fingerprint"
    );

    let crawl = Command::new(ftw_bin())
        .args([
            "crawl",
            "--db",
            &db_path.to_string_lossy(),
            "--verbose",
            "--quiet",
        ])
        .output()
        .expect("run conflicting crawl");
    assert!(
        !crawl.status.success(),
        "--verbose + --quiet must be rejected for crawl"
    );

    let probe = Command::new(ftw_bin())
        .args([
            "probe",
            "--db",
            &db_path.to_string_lossy(),
            "--verbose",
            "--quiet",
        ])
        .output()
        .expect("run conflicting probe");
    assert!(
        !probe.status.success(),
        "--verbose + --quiet must be rejected for probe"
    );

    let host_check = Command::new(ftw_bin())
        .args([
            "host-check",
            "--db",
            &db_path.to_string_lossy(),
            "--verbose",
            "--quiet",
        ])
        .output()
        .expect("run conflicting host-check");
    assert!(
        !host_check.status.success(),
        "--verbose + --quiet must be rejected for host-check"
    );

    std::fs::remove_file(&yaml_path).ok();
    remove_db(&db_path);
}

/// The removed file flags are rejected with an error saying results now live
/// in `--db`.
#[test]
fn removed_file_flags_are_rejected() {
    let tag = temp_tag("legacy-flags");
    let yaml_path = temp_path(&tag, "yml");
    let db_path = temp_path(&tag, "db");
    let legacy = temp_path(&tag, "legacy");
    std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write yaml");

    let scan = Command::new(ftw_bin())
        .args([
            "scan",
            "--input",
            &yaml_path.to_string_lossy(),
            "--ports",
            "80",
            "--db",
            &db_path.to_string_lossy(),
            "--output",
            &legacy.to_string_lossy(),
        ])
        .output()
        .expect("run scan with --output");
    assert!(!scan.status.success(), "--output must be rejected for scan");
    assert!(
        String::from_utf8_lossy(&scan.stderr).contains("--db"),
        "rejection must point at --db: {}",
        String::from_utf8_lossy(&scan.stderr)
    );

    let fingerprint_output = Command::new(ftw_bin())
        .args([
            "fingerprint",
            "--db",
            &db_path.to_string_lossy(),
            "--output",
            &legacy.to_string_lossy(),
        ])
        .output()
        .expect("run fingerprint with --output");
    assert!(
        !fingerprint_output.status.success(),
        "--output must be rejected for fingerprint"
    );
    assert!(
        String::from_utf8_lossy(&fingerprint_output.stderr).contains("--db"),
        "rejection must point at --db: {}",
        String::from_utf8_lossy(&fingerprint_output.stderr)
    );

    let fingerprint_scan = Command::new(ftw_bin())
        .args([
            "fingerprint",
            "--db",
            &db_path.to_string_lossy(),
            "--scan-output",
            &legacy.to_string_lossy(),
        ])
        .output()
        .expect("run fingerprint with --scan-output");
    assert!(
        !fingerprint_scan.status.success(),
        "--scan-output must be rejected for fingerprint"
    );
    assert!(
        String::from_utf8_lossy(&fingerprint_scan.stderr).contains("--db"),
        "rejection must point at --db: {}",
        String::from_utf8_lossy(&fingerprint_scan.stderr)
    );

    let host_check_inventory = Command::new(ftw_bin())
        .args([
            "host-check",
            "--db",
            &db_path.to_string_lossy(),
            "--inventory",
            &legacy.to_string_lossy(),
        ])
        .output()
        .expect("run host-check with --inventory");
    assert!(
        !host_check_inventory.status.success(),
        "--inventory must be rejected for host-check"
    );
    assert!(
        String::from_utf8_lossy(&host_check_inventory.stderr).contains("--db"),
        "rejection must point at --db: {}",
        String::from_utf8_lossy(&host_check_inventory.stderr)
    );

    std::fs::remove_file(&yaml_path).ok();
    remove_db(&db_path);
}

/// `--max-depth 0` and values below -1 are rejected as CLI errors; -1 and
/// values >= 1 are accepted.
#[test]
fn crawl_rejects_invalid_max_depth() {
    let tag = temp_tag("max-depth");
    let db_path = temp_path(&tag, "db");
    for bad in ["0", "-2", "-100"] {
        let output = Command::new(ftw_bin())
            .args([
                "crawl",
                "--db",
                &db_path.to_string_lossy(),
                "--max-depth",
                bad,
            ])
            .output()
            .expect("run ftw crawl with bad max-depth");
        assert!(
            !output.status.success(),
            "--max-depth {bad} must be rejected"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("max_depth"),
            "rejection names the key: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for good in ["-1", "1", "5"] {
        let output = Command::new(ftw_bin())
            .args([
                "crawl",
                "--db",
                &db_path.to_string_lossy(),
                "--max-depth",
                good,
            ])
            .output()
            .expect("run ftw crawl with good max-depth");
        assert!(
            output.status.success(),
            "--max-depth {good} must be accepted: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    remove_db(&db_path);
}

/// End-to-end chain: scan → fingerprint → crawl against a 3-page site
/// (root links to /b, /b links to /c, /c links back to root plus an external
/// link). Crawl must visit exactly the 3 local pages, record the external
/// link, and never visit it.
#[test]
fn crawl_end_to_end_visits_chain_and_skips_external() {
    let tag = temp_tag("crawl-e2e");
    let yaml_path = temp_path(&tag, "yml");
    let db_path = temp_path(&tag, "db");
    std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write yaml");

    let dead = closed_port();
    let mut routes = std::collections::HashMap::new();
    routes.insert(
        "/".to_string(),
        "<html><head><title>Root</title></head><body><a href=\"/b\">b</a></body></html>".to_string(),
    );
    routes.insert(
        "/b".to_string(),
        "<html><head><title>B</title></head><body><a href=\"/c\">c</a></body></html>".to_string(),
    );
    let (http_port, _server) = spawn_route_server(
        {
            routes.insert(
                "/c".to_string(),
                format!(
                    "<html><head><title>C</title></head><body><a href=\"/\">root</a><a href=\"http://127.0.0.1:{dead}/x\">ext</a></body></html>"
                ),
            );
            routes
        },
        16,
    );

    for args in [
        vec![
            "scan",
            "--input",
            &yaml_path.to_string_lossy(),
            "--ports",
            &http_port.to_string(),
            "--db",
            &db_path.to_string_lossy(),
            "--quiet",
        ],
        vec![
            "fingerprint",
            "--db",
            &db_path.to_string_lossy(),
            "--scheme",
            "http",
            "--quiet",
        ],
    ] {
        let step = Command::new(ftw_bin())
            .args(&args)
            .output()
            .unwrap_or_else(|_| panic!("run ftw {}", args[0]));
        assert!(
            step.status.success(),
            "{} failed: {}",
            args[0],
            String::from_utf8_lossy(&step.stderr)
        );
    }

    let crawl = Command::new(ftw_bin())
        .args([
            "crawl",
            "--db",
            &db_path.to_string_lossy(),
            "--max-depth",
            "5",
            "--quiet",
        ])
        .output()
        .expect("run ftw crawl");
    assert!(
        crawl.status.success(),
        "crawl failed: {}",
        String::from_utf8_lossy(&crawl.stderr)
    );
    let stderr = String::from_utf8(crawl.stderr).expect("stderr utf8");
    assert!(stderr.contains("crawled 3 pages"), "summary reports 3 pages: {stderr}");
    assert!(
        stderr.contains("unlimited"),
        "default runs report an unlimited rate limit: {stderr}"
    );

    let base = format!("http://127.0.0.1:{http_port}");
    let mut pages = db_text_rows(&db_path, "SELECT url FROM crawl_pages");
    pages.sort_unstable();
    assert_eq!(
        pages,
        vec![
            format!("{base}/"),
            format!("{base}/b"),
            format!("{base}/c"),
        ],
        "exactly the 3 local pages are visited"
    );
    let links = db_text_rows(&db_path, "SELECT from_url || ' -> ' || to_url FROM crawl_links");
    assert!(
        links.iter().any(|link| link.ends_with(&format!("http://127.0.0.1:{dead}/x"))),
        "the external link is recorded: {links:?}"
    );
    assert!(
        !pages.contains(&format!("http://127.0.0.1:{dead}/x")),
        "the external link is never visited"
    );

    std::fs::remove_file(&yaml_path).ok();
    remove_db(&db_path);
}

/// Prefer-HTTPS end to end: with 80+443 seeded open and nothing listening on
/// 443, `--verbose` prints `skipped 127.0.0.1:80 (prefer 443)`, the 443
/// failure falls back to port 80 exactly once, the summary reports
/// `skipped_prefer_https=1` + `fallback_to_http=1`, and the scan rows stay
/// open.
#[test]
fn fingerprint_prefer_https_skips_80_verbose_and_falls_back() {
    let tag = temp_tag("prefer-https");
    let db_path = temp_path(&tag, "db");
    seed_open_ports(&db_path, &[80, 443]);

    let output = Command::new(ftw_bin())
        .args([
            "fingerprint",
            "--db",
            &db_path.to_string_lossy(),
            "--verbose",
        ])
        .output()
        .expect("run ftw fingerprint");
    assert!(
        output.status.success(),
        "fingerprint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("skipped 127.0.0.1:80 (prefer 443)"),
        "verbose stderr names the skipped port: {stderr}"
    );
    assert!(
        stderr.contains("skipped_prefer_https=1"),
        "summary reports 1 skipped: {stderr}"
    );
    assert!(
        stderr.contains("fallback_to_http=1"),
        "summary reports 1 fallback: {stderr}"
    );

    // Only the 443 row plus a single fallback 80 row exist; the skipped port
    // gets no row of its own beyond the fallback attempt.
    let ports = db_int_rows(&db_path, "SELECT port FROM fingerprint_results ORDER BY port");
    assert_eq!(ports, vec![80, 443]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert_eq!(
        stdout.lines().count(),
        2,
        "stdout carries one live JSON line per fingerprinted port"
    );

    // The scan rows are untouched: both ports still read open.
    let scan = db_text_rows(
        &db_path,
        "SELECT port || ' ' || status FROM scan_results WHERE ip = '127.0.0.1' ORDER BY port",
    );
    assert_eq!(scan, vec!["80 open".to_string(), "443 open".to_string()]);

    remove_db(&db_path);
}

/// `--no-prefer-https` end to end: both seeded ports are fingerprinted with
/// no skipping and no fallback, and the summary reports zeros.
#[test]
fn fingerprint_no_prefer_https_fingerprints_both() {
    let tag = temp_tag("no-prefer-https");
    let db_path = temp_path(&tag, "db");
    seed_open_ports(&db_path, &[80, 443]);

    let output = Command::new(ftw_bin())
        .args([
            "fingerprint",
            "--db",
            &db_path.to_string_lossy(),
            "--no-prefer-https",
            "--quiet",
        ])
        .output()
        .expect("run ftw fingerprint");
    assert!(
        output.status.success(),
        "fingerprint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ports = db_int_rows(&db_path, "SELECT port FROM fingerprint_results ORDER BY port");
    assert_eq!(
        ports,
        vec![80, 443],
        "both ports are fingerprinted with deduplication off"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("skipped_prefer_https=0"),
        "summary reports 0 skipped: {stderr}"
    );
    assert!(
        stderr.contains("fallback_to_http=0"),
        "summary reports 0 fallback: {stderr}"
    );
    assert!(
        !stderr.contains("skipped 127.0.0.1:80"),
        "no skip line is printed with deduplication off: {stderr}"
    );

    remove_db(&db_path);
}

/// Hermetic directory for config discovery tests: the child runs with its
/// working directory and `$HOME` pointed here, so neither `./ftw.toml` nor
/// `$HOME/.config/ftw/config.toml` can leak in from the real environment.
fn config_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(tag);
    std::fs::create_dir_all(&dir).expect("config test dir");
    dir
}

fn write_config(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write config");
    path
}

/// Config precedence end to end on empty databases (no seeds, so runs are
/// instant): config-only shows `(config)` values and the config summary,
/// CLI overrides show `(cli)`, and no config shows `(default)` + unlimited.
/// A config setting only some options leaves the rest at built-in defaults.
#[test]
fn crawl_config_precedence_cli_over_config_over_default() {
    let tag = temp_tag("cfg-precedence");
    let dir = config_dir(&tag);
    let db_path = dir.join("t.db");
    let cfg_path = write_config(
        &dir,
        "ftw.toml",
        "[crawl]\nrequests_per_minute = 5\nmax_pages = 7\ntimeout = 9\n",
    );

    // Config only: values and summary come from the file; untouched options
    // stay at built-in defaults instead of resetting to zero.
    let output = Command::new(ftw_bin())
        .current_dir(&dir)
        .env("HOME", &dir)
        .args([
            "crawl",
            "--db",
            &db_path.to_string_lossy(),
            "--config",
            &cfg_path.to_string_lossy(),
            "--verbose",
        ])
        .output()
        .expect("run ftw crawl with config");
    assert!(
        output.status.success(),
        "config-only crawl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("config: crawl.requests_per_minute = 5 (config)"),
        "config value with source: {stderr}"
    );
    assert!(
        stderr.contains("config: crawl.max_pages = 7 (config)"),
        "second config value: {stderr}"
    );
    assert!(
        stderr.contains("config: crawl.timeout = 9 (config)"),
        "third config value: {stderr}"
    );
    assert!(
        stderr.contains("config: crawl.concurrency = 100 (default)"),
        "unset options keep built-in defaults: {stderr}"
    );
    assert!(stderr.contains("5/min"), "summary uses the config value: {stderr}");

    // CLI overrides: the same options report `(cli)` and the summary follows.
    let output = Command::new(ftw_bin())
        .current_dir(&dir)
        .env("HOME", &dir)
        .args([
            "crawl",
            "--db",
            &db_path.to_string_lossy(),
            "--config",
            &cfg_path.to_string_lossy(),
            "--requests-per-minute",
            "10",
            "--max-pages",
            "11",
            "--verbose",
        ])
        .output()
        .expect("run ftw crawl with overrides");
    assert!(
        output.status.success(),
        "override crawl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("config: crawl.requests_per_minute = 10 (cli)"),
        "CLI beats config: {stderr}"
    );
    assert!(
        stderr.contains("config: crawl.max_pages = 11 (cli)"),
        "CLI beats config for pages: {stderr}"
    );
    assert!(
        stderr.contains("config: crawl.timeout = 9 (config)"),
        "unflagged options still come from config: {stderr}"
    );
    assert!(stderr.contains("10/min"), "summary uses the CLI value: {stderr}");

    // No config anywhere: built-in defaults, unlimited, still successful.
    // A fresh directory (the first one holds ftw.toml, which discovery
    // would otherwise pick up).
    let bare = config_dir(&format!("{tag}-bare"));
    let output = Command::new(ftw_bin())
        .current_dir(&bare)
        .env("HOME", &bare)
        .args([
            "crawl",
            "--db",
            &bare.join("plain.db").to_string_lossy(),
            "--verbose",
        ])
        .output()
        .expect("run ftw crawl without config");
    assert!(
        output.status.success(),
        "default crawl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("config: crawl.requests_per_minute = 0 (default)"),
        "built-in default with source: {stderr}"
    );
    assert!(stderr.contains("unlimited"), "default summary: {stderr}");

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&bare).ok();
}

/// An explicit `--config` path that does not exist fails before any work,
/// naming the path.
#[test]
fn explicit_config_missing_path_fails_before_work() {
    let tag = temp_tag("cfg-missing");
    let dir = config_dir(&tag);
    let missing = dir.join("no-such.toml");
    let output = Command::new(ftw_bin())
        .current_dir(&dir)
        .env("HOME", &dir)
        .args([
            "crawl",
            "--db",
            &dir.join("t.db").to_string_lossy(),
            "--config",
            &missing.to_string_lossy(),
        ])
        .output()
        .expect("run ftw crawl with missing config");
    assert!(
        !output.status.success(),
        "missing explicit config must fail"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains(&missing.to_string_lossy().to_string()),
        "error names the path: {stderr}"
    );
    assert!(
        !dir.join("t.db").exists(),
        "no database may be created before the config error"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A typo'd config key fails naming the key and the file; a negative
/// crawl rate limit and a bogus fingerprint scheme fail the same way.
#[test]
fn invalid_config_fails_with_key_and_path() {
    let tag = temp_tag("cfg-invalid");
    let dir = config_dir(&tag);
    let db = dir.join("t.db").to_string_lossy().to_string();

    let typo = write_config(&dir, "typo.toml", "[crawl]\nconcurrnecy = 5\n");
    let output = Command::new(ftw_bin())
        .current_dir(&dir)
        .env("HOME", &dir)
        .args(["crawl", "--db", &db, "--config", &typo.to_string_lossy()])
        .output()
        .expect("run with typo config");
    assert!(!output.status.success(), "typo key must fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("concurrnecy"), "names the key: {stderr}");
    assert!(
        stderr.contains(&typo.to_string_lossy().to_string()),
        "names the path: {stderr}"
    );

    let negative = write_config(&dir, "neg.toml", "[crawl]\nrequests_per_minute = -5\n");
    let output = Command::new(ftw_bin())
        .current_dir(&dir)
        .env("HOME", &dir)
        .args(["crawl", "--db", &db, "--config", &negative.to_string_lossy()])
        .output()
        .expect("run with negative limit");
    assert!(!output.status.success(), "negative limit must fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("requests_per_minute"), "names the key: {stderr}");
    assert!(
        stderr.contains(&negative.to_string_lossy().to_string()),
        "names the path: {stderr}"
    );

    let scheme = write_config(&dir, "scheme.toml", "[fingerprint]\nscheme = \"bogus\"\n");
    let output = Command::new(ftw_bin())
        .current_dir(&dir)
        .env("HOME", &dir)
        .args([
            "fingerprint",
            "--db",
            &db,
            "--config",
            &scheme.to_string_lossy(),
        ])
        .output()
        .expect("run with bogus scheme");
    assert!(!output.status.success(), "bogus scheme must fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("scheme"), "names the key: {stderr}");

    std::fs::remove_dir_all(&dir).ok();
}

/// A negative `--requests-per-minute` is rejected by clap before any
/// crawling: both the `--flag=value` form (invalid value) and the separate
/// form must fail.
#[test]
fn crawl_rejects_negative_requests_per_minute() {
    let tag = temp_tag("rate-limit-flag");
    let db_path = temp_path(&tag, "db");

    for args in [
        vec![
            "crawl",
            "--db",
            &db_path.to_string_lossy(),
            "--requests-per-minute=-1",
        ],
        vec![
            "crawl",
            "--db",
            &db_path.to_string_lossy(),
            "--requests-per-minute",
            "-1",
        ],
    ] {
        let output = Command::new(ftw_bin())
            .args(&args)
            .output()
            .expect("run ftw crawl with negative limit");
        assert!(
            !output.status.success(),
            "negative --requests-per-minute must be rejected: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    remove_db(&db_path);
}

/// Prefer-HTTPS happy path end to end: with 80+443 seeded open and a real
/// TLS server answering on 443, the pipeline fingerprints ONLY the 443 row
/// (HTTPS 200, no fallback), the scan rows stay open, verbose prints the
/// skip line, and the summary reports `skipped_prefer_https=1` with
/// `fallback_to_http=0`.
///
/// Fixture mechanics: literal port 443 is unbindable without privileges, so
/// `tests/shim_443.c` (built here with `cc`, the same kind of external-tool
/// fixture dependency as the `openssl` server in the unit tests)
/// transparently remaps port 443 to a free high port for both the
/// `openssl s_server` fixture and the `ftw` binary. The pipeline itself is
/// unmodified — it asks for literal 443 over HTTPS — so a recorded
/// `scheme: https` + `status: 200` row proves the real HTTPS code path ran.
#[test]
fn fingerprint_prefer_https_happy_path_fingerprints_only_443() {
    let tag = temp_tag("prefer-happy");
    let dir = std::env::temp_dir();
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let shim_src = manifest.join("tests").join("shim_443.c");
    let shim = dir.join(format!("{tag}-shim.so"));
    let key = dir.join(format!("{tag}-key.pem"));
    let cert = dir.join(format!("{tag}-cert.pem"));
    let db_path = temp_path(&tag, "db");
    let shim_text = shim.to_string_lossy().into_owned();

    // Free high port standing in for 443 via the shim.
    let shadow = {
        let sock = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp port");
        sock.local_addr().expect("temp addr").port()
    };
    let shadow_text = shadow.to_string();

    let cc = Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            "-O2",
            "-o",
            shim_text.as_str(),
            shim_src.to_string_lossy().as_ref(),
            "-ldl",
        ])
        .output()
        .expect("build port-443 shim (needs cc)");
    assert!(
        cc.status.success(),
        "cc must build the shim: {}",
        String::from_utf8_lossy(&cc.stderr)
    );

    let mint = Command::new("openssl")
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
        .expect("mint test certificate");
    assert!(
        mint.status.success(),
        "openssl must mint the test certificate: {}",
        String::from_utf8_lossy(&mint.stderr)
    );

    seed_open_ports(&db_path, &[80, 443]);

    let mut server = Command::new("openssl")
        .env("LD_PRELOAD", &shim_text)
        .env("FTW_SHADOW_PORT", &shadow_text)
        .args([
            "s_server",
            "-accept",
            "443",
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

    let mut ready = false;
    for _ in 0..200 {
        let probe = Command::new("curl")
            .env("LD_PRELOAD", &shim_text)
            .env("FTW_SHADOW_PORT", &shadow_text)
            .args([
                "-sk",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "https://127.0.0.1:443/",
            ])
            .output();
        if let Ok(probe) = probe {
            if probe.status.success()
                && String::from_utf8_lossy(&probe.stdout).trim() == "200"
            {
                ready = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !ready {
        let _ = server.kill();
        let _ = server.wait();
        panic!("s_server never came up on shadow port {shadow}");
    }

    let output = Command::new(ftw_bin())
        .env("LD_PRELOAD", &shim_text)
        .env("FTW_SHADOW_PORT", &shadow_text)
        .args([
            "fingerprint",
            "--db",
            &db_path.to_string_lossy(),
            "--verbose",
            "--insecure",
        ])
        .output()
        .expect("run ftw fingerprint");
    let _ = server.kill();
    let _ = server.wait();
    assert!(
        output.status.success(),
        "fingerprint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("skipped 127.0.0.1:80 (prefer 443)"),
        "verbose stderr names the skipped port: {stderr}"
    );
    assert!(
        stderr.contains("skipped_prefer_https=1"),
        "summary reports 1 skipped: {stderr}"
    );
    assert!(
        stderr.contains("fallback_to_http=0"),
        "summary reports 0 fallback: {stderr}"
    );

    // Exactly one fingerprint row exists, and it is the HTTPS 200 on 443:
    // the skipped port 80 leaves no row.
    assert_eq!(
        db_int_rows(&db_path, "SELECT port FROM fingerprint_results ORDER BY port"),
        vec![443]
    );
    assert_eq!(
        db_text_rows(&db_path, "SELECT scheme FROM fingerprint_results"),
        vec!["https".to_string()]
    );
    assert_eq!(
        db_int_rows(&db_path, "SELECT status FROM fingerprint_results"),
        vec![200]
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert_eq!(
        stdout.lines().count(),
        1,
        "stdout carries one live JSON line for the single fingerprinted port"
    );
    let record: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout line is JSON");
    assert_eq!(record["port"], 443);
    assert_eq!(record["scheme"], "https");
    assert_eq!(record["status"], 200);

    // The scan rows are untouched: both ports still read open.
    assert_eq!(
        db_text_rows(
            &db_path,
            "SELECT port || ' ' || status FROM scan_results WHERE ip = '127.0.0.1' ORDER BY port"
        ),
        vec!["80 open".to_string(), "443 open".to_string()]
    );

    std::fs::remove_file(&shim).ok();
    std::fs::remove_file(&key).ok();
    std::fs::remove_file(&cert).ok();
    remove_db(&db_path);
}

/// `ftw probe` against a live TLS fixture on port 443 (via the same
/// LD_PRELOAD shim): the HTTPS pass records status 200 plus the peer
/// certificate CN/issuer/not-after captured in the same pass — no separate
/// TLS-only probe, no plaintext HTTP to 443.
#[test]
fn probe_https_records_tls_fields_from_same_pass() {
    let tag = temp_tag("probe-tls");
    let dir = std::env::temp_dir();
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let shim_src = manifest.join("tests").join("shim_443.c");
    let shim = dir.join(format!("{tag}-shim.so"));
    let key = dir.join(format!("{tag}-key.pem"));
    let cert = dir.join(format!("{tag}-cert.pem"));
    let db_path = temp_path(&tag, "db");
    let shim_text = shim.to_string_lossy().into_owned();

    let shadow = {
        let sock = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp port");
        sock.local_addr().expect("temp addr").port()
    };
    let shadow_text = shadow.to_string();

    let cc = Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            "-O2",
            "-o",
            shim_text.as_str(),
            shim_src.to_string_lossy().as_ref(),
            "-ldl",
        ])
        .output()
        .expect("build port-443 shim (needs cc)");
    assert!(
        cc.status.success(),
        "cc must build the shim: {}",
        String::from_utf8_lossy(&cc.stderr)
    );

    let mint = Command::new("openssl")
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
        .expect("mint test certificate");
    assert!(
        mint.status.success(),
        "openssl must mint the test certificate: {}",
        String::from_utf8_lossy(&mint.stderr)
    );

    seed_open_ports(&db_path, &[443]);

    let mut server = Command::new("openssl")
        .env("LD_PRELOAD", &shim_text)
        .env("FTW_SHADOW_PORT", &shadow_text)
        .args([
            "s_server",
            "-accept",
            "443",
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

    let mut ready = false;
    for _ in 0..200 {
        let probe = Command::new("curl")
            .env("LD_PRELOAD", &shim_text)
            .env("FTW_SHADOW_PORT", &shadow_text)
            .args([
                "-sk",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "https://127.0.0.1:443/",
            ])
            .output();
        if let Ok(probe) = probe {
            if probe.status.success()
                && String::from_utf8_lossy(&probe.stdout).trim() == "200"
            {
                ready = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !ready {
        let _ = server.kill();
        let _ = server.wait();
        panic!("s_server never came up on shadow port {shadow}");
    }

    let output = Command::new(ftw_bin())
        .env("LD_PRELOAD", &shim_text)
        .env("FTW_SHADOW_PORT", &shadow_text)
        .args([
            "probe",
            "--db",
            &db_path.to_string_lossy(),
            "--verbose",
            "--insecure",
        ])
        .output()
        .expect("run ftw probe");
    let _ = server.kill();
    let _ = server.wait();
    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert_eq!(
        stdout.lines().count(),
        1,
        "stdout carries one live JSON line for the single probed port"
    );
    let record: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout line is JSON");
    assert_eq!(record["host"], "127.0.0.1");
    assert_eq!(record["port"], 443);
    assert_eq!(record["scheme"], "https");
    assert_eq!(record["status"], 200);
    assert_eq!(record["tls_cn"], "127.0.0.1");
    assert!(
        record["tls_issuer"].as_str().is_some_and(|s| s.contains("127.0.0.1")),
        "issuer names the test CN: {}",
        record["tls_issuer"]
    );
    assert!(
        record["tls_not_after"].as_str().is_some_and(|s| !s.is_empty()),
        "not-after is recorded"
    );
    assert_eq!(record["patch_status"], "unknown_from_remote");
    assert!(
        record["confidence"].as_str().is_some(),
        "confidence is always present"
    );

    assert_eq!(
        db_text_rows(&db_path, "SELECT scheme FROM probe_results"),
        vec!["https".to_string()]
    );
    assert_eq!(
        db_text_rows(&db_path, "SELECT patch_status FROM probe_results"),
        vec!["unknown_from_remote".to_string()]
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("probed"),
        "summary reports the probe run: {stderr}"
    );

    std::fs::remove_file(&shim).ok();
    std::fs::remove_file(&key).ok();
    std::fs::remove_file(&cert).ok();
    remove_db(&db_path);
}
