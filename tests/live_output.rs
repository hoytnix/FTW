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

fn db_count(db_path: &std::path::Path, table: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open db");
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
        .expect("count rows")
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

/// `--verbose` and `--quiet` together are rejected by clap for all three
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

    std::fs::remove_file(&yaml_path).ok();
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
