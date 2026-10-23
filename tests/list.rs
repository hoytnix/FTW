//! CLI tests for `ftw list`: offline reporting from a fixture SQLite
//! database only — no live network, no live SSH. The fixture database is
//! seeded with raw SQL mirroring the writer schema in `src/db.rs`.

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
    format!("ftw-list-{prefix}-{nanos}-{}", std::process::id())
}

fn temp_path(tag: &str, ext: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{tag}.{ext}"))
}

fn remove_db(db_path: &std::path::Path) {
    std::fs::remove_file(db_path).ok();
    std::fs::remove_file(db_path.with_extension("db-wal")).ok();
    std::fs::remove_file(db_path.with_extension("db-shm")).ok();
}

/// Seed a fixture database with raw SQL (same column layout the writers in
/// `src/db.rs` use): A is PHP+vulnerable, B is app+PHP patched, C is a
/// static host in no list, D is host-check-only PHP+vulnerable.
fn seed_fixture_db(db_path: &std::path::Path) {
    let conn = rusqlite::Connection::open(db_path).expect("open fixture db");
    conn.execute_batch(
        "CREATE TABLE fingerprint_results (
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
        CREATE TABLE host_check_results (
          host          TEXT PRIMARY KEY,
          php_version   TEXT,
          php_raw       TEXT NOT NULL,
          packages_json TEXT NOT NULL,
          checked_at    TEXT NOT NULL
        );",
    )
    .expect("create fixture tables");
    let insert_fp = "INSERT INTO fingerprint_results
        (ip, port, scheme, final_url, status, server, tls, error,
         php_detected, php_version, php_signals,
         wordpress_detected, wordpress_version, wordpress_signals, php_apps,
         tailwind_detected, tailwind_confidence, tailwind_signals,
         fetch_method, head_status, fingerprinted_at)
        VALUES (?1, ?2, ?3, ?4, 200, ?5, 'ok', NULL,
         ?6, ?7, ?8, ?9, NULL, ?10, ?11, 0, 'none', '[]', 'get', NULL, '2026-01-01T00:00:00Z')";
    // A: PHP + vulnerable (8.2.10 below fixed 8.2.35).
    conn.execute(
        insert_fp,
        rusqlite::params![
            "10.8.0.1", 443, "https", "https://10.8.0.1:443/",
            "nginx/1.24.0", 1, "8.2.10", "[\"x-powered-by\"]",
            0, "[]", "[]",
        ],
    )
    .expect("seed A");
    // B: app + PHP, patched (8.4.27 is exactly the fixed version).
    conn.execute(
        insert_fp,
        rusqlite::params![
            "10.8.0.2", 443, "https", "https://10.8.0.2:443/",
            "Apache/2.4.58", 1, "8.4.27", "[\"x-powered-by\"]",
            1, "[\"generator\"]", "[]",
        ],
    )
    .expect("seed B");
    // C: static host, in no list.
    conn.execute(
        insert_fp,
        rusqlite::params![
            "10.8.0.3", 80, "http", "http://10.8.0.3:80/",
            "nginx/1.24.0", 0, Option::<String>::None, "[]",
            0, "[]", "[]",
        ],
    )
    .expect("seed C");
    // D: host-check only, PHP + vulnerable.
    conn.execute(
        "INSERT INTO host_check_results (host, php_version, php_raw, packages_json, checked_at)
         VALUES ('10.8.0.4', '8.2.10', 'PHP 8.2.10 (cli) (built: Aug 30 2024) ( NTS )',
                 '[{\"name\":\"php8.2-cli\",\"version\":\"8.2.10-2ubuntu1\"}]', '2026-01-01T00:00:00Z')",
        [],
    )
    .expect("seed D");
}

fn run_list(db_path: &std::path::Path, extra: &[&str]) -> std::process::Output {
    let mut args = vec!["list", "--db"];
    let db = db_path.to_string_lossy().to_string();
    args.push(&db);
    args.extend(extra.iter().copied());
    Command::new(ftw_bin()).args(&args).output().expect("run ftw list")
}

/// `ftw list` reports all three lists with counts plus the overlap summary.
#[test]
fn list_table_reports_all_three_lists_with_counts() {
    let tag = temp_tag("table");
    let db_path = temp_path(&tag, "db");
    seed_fixture_db(&db_path);

    let output = run_list(&db_path, &[]);
    assert!(
        output.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let php_at = stdout.find("## Running PHP (3)").expect("PHP section with count");
    let app_at = stdout
        .find("## Running a fingerprinted application (1)")
        .expect("app section with count");
    let vuln_at = stdout
        .find("## PHP2Shell vulnerable (2)")
        .expect("vuln section with count");
    let summary_at = stdout.find("## Summary").expect("summary section");
    assert!(php_at < app_at && app_at < vuln_at && vuln_at < summary_at, "sections in order:\n{stdout}");
    assert!(stdout.contains("host=10.8.0.4 "), "host-check-only host listed");
    assert!(stdout.contains("distinct_hosts=4 php=3 app=1 vuln=2"), "summary counts:\n{stdout}");
    assert!(stdout.contains("lists overlap"), "overlap note:\n{stdout}");
    assert!(!stdout.contains("host=10.8.0.3 "), "static host in no list");

    remove_db(&db_path);
}

/// `--type` shows only the selected section; the summary stays global.
#[test]
fn list_type_filters_to_one_section() {
    let tag = temp_tag("filter");
    let db_path = temp_path(&tag, "db");
    seed_fixture_db(&db_path);

    for (filter, want, count, dropped) in [
        ("php", "## Running PHP (3)", 3, "## Running a fingerprinted application"),
        ("app", "## Running a fingerprinted application (1)", 1, "## PHP2Shell vulnerable"),
        ("vuln", "## PHP2Shell vulnerable (2)", 2, "## Running PHP"),
    ] {
        let output = run_list(&db_path, &["--type", filter]);
        assert!(output.status.success(), "--type {filter} failed");
        let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
        assert!(stdout.contains(want), "{want} present:\n{stdout}");
        assert!(!stdout.contains(dropped), "{dropped} hidden:\n{stdout}");
        assert_eq!(stdout.matches("host=10.8.0.").count(), count, "section entry count for {filter}");
        assert!(stdout.contains("distinct_hosts=4 php=3 app=1 vuln=2"), "summary stays global for {filter}");
    }

    remove_db(&db_path);
}

/// `--format json` parses as JSONL and carries the same hosts and counts as
/// the table output; stdout stays pure JSONL.
#[test]
fn list_json_matches_table_hosts_and_counts() {
    let tag = temp_tag("json");
    let db_path = temp_path(&tag, "db");
    seed_fixture_db(&db_path);

    let table = run_list(&db_path, &[]);
    assert!(table.status.success());
    let table_out = String::from_utf8(table.stdout).expect("table utf8");

    let json = run_list(&db_path, &["--format", "json"]);
    assert!(json.status.success(), "json failed: {}", String::from_utf8_lossy(&json.stderr));
    let stdout = String::from_utf8(json.stdout).expect("stdout utf8");
    let mut counts = std::collections::HashMap::new();
    for line in stdout.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("stdout is JSONL");
        let category = value["category"].as_str().expect("category field");
        *counts.entry(category.to_string()).or_insert(0) += 1;
        let host = value["host"].as_str().expect("host field");
        assert!(table_out.contains(&format!("host={host} ")), "{host} also in table output");
    }
    assert_eq!(counts.get("php"), Some(&3));
    assert_eq!(counts.get("app"), Some(&1));
    assert_eq!(counts.get("vuln"), Some(&2));
    let stderr = String::from_utf8(json.stderr).expect("stderr utf8");
    assert!(stderr.contains("distinct_hosts=4 php=3 app=1 vuln=2"), "summary on stderr:\n{stderr}");

    remove_db(&db_path);
}

/// `--cve` verdicts decide the vulnerable list in both directions, ignore
/// hosts absent from the database, and tolerate a bad line with a warning.
#[test]
fn list_cve_file_overrides_the_vuln_list() {
    let tag = temp_tag("cve");
    let db_path = temp_path(&tag, "db");
    let cve_path = temp_path(&tag, "jsonl");
    seed_fixture_db(&db_path);
    std::fs::write(
        &cve_path,
        concat!(
            "{\"host\":\"10.8.0.1\",\"verdict\":\"patched\",\"reason\":\"8.2.35 >= fixed 8.2.35\",\"cve_ids\":[\"CVE-2026-109618\",\"CVE-2026-109619\"]}\n",
            "not json\n",
            "{\"host\":\"10.8.0.3\",\"verdict\":\"vulnerable\",\"reason\":\"file verdict\",\"cve_ids\":[\"CVE-2026-109618\"]}\n",
            "{\"host\":\"10.8.9.9\",\"verdict\":\"vulnerable\",\"reason\":\"unknown host\",\"cve_ids\":[]}\n",
        ),
    )
    .expect("write cve fixture");

    let output = run_list(&db_path, &["--cve", &cve_path.to_string_lossy(), "--type", "vuln"]);
    assert!(output.status.success(), "list --cve failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(!stdout.contains("host=10.8.0.1 "), "file-patched host leaves the vuln list");
    assert!(stdout.contains("host=10.8.0.3 "), "file-vulnerable host joins the vuln list");
    assert!(stdout.contains("reason=file verdict"), "file reason shown");
    assert!(!stdout.contains("10.8.9.9"), "hosts outside the database are ignored");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("skipping invalid JSON on line 2"), "bad line warned:\n{stderr}");

    remove_db(&db_path);
    std::fs::remove_file(&cve_path).ok();
}

/// `--output` writes the report to a file instead of stdout.
#[test]
fn list_output_writes_file_not_stdout() {
    let tag = temp_tag("output");
    let db_path = temp_path(&tag, "db");
    let out_path = temp_path(&tag, "out");
    seed_fixture_db(&db_path);

    let output = run_list(
        &db_path,
        &["--format", "json", "--output", &out_path.to_string_lossy()],
    );
    assert!(output.status.success(), "list --output failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.is_empty(), "stdout stays empty with --output");
    let text = std::fs::read_to_string(&out_path).expect("read output file");
    assert_eq!(text.lines().count(), 6, "file carries one JSON object per entry");
    for line in text.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("file is JSONL");
    }

    remove_db(&db_path);
    std::fs::remove_file(&out_path).ok();
}

/// An empty database succeeds with zeroed sections and a stderr warning.
#[test]
fn list_empty_db_warns_and_reports_zeroes() {
    let tag = temp_tag("empty");
    let db_path = temp_path(&tag, "db");

    let output = run_list(&db_path, &[]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("## Running PHP (0)"));
    assert!(stdout.contains("distinct_hosts=0 php=0 app=0 vuln=0"));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("no sites found"), "empty warning:\n{stderr}");

    remove_db(&db_path);
}

/// `--verbose` prints effective-config lines; `--verbose --quiet` conflicts.
#[test]
fn list_verbose_and_quiet_behave() {
    let tag = temp_tag("flags");
    let db_path = temp_path(&tag, "db");
    seed_fixture_db(&db_path);

    let output = run_list(&db_path, &["--verbose", "--type", "php"]);
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("config: list.type = php (cli)"), "verbose names type:\n{stderr}");
    assert!(stderr.contains("config: list.format = table (default)"), "verbose names format:\n{stderr}");

    let output = run_list(&db_path, &["--quiet"]);
    assert!(output.status.success());
    assert!(!String::from_utf8(output.stdout).expect("stdout utf8").is_empty(), "quiet keeps the report");

    let output = run_list(&db_path, &["--verbose", "--quiet"]);
    assert!(!output.status.success(), "verbose+quiet must conflict");

    remove_db(&db_path);
}

/// Help documents the chosen name, the JSON shape, and the key flags.
#[test]
fn list_help_documents_name_format_and_flags() {
    let output = Command::new(ftw_bin())
        .args(["list", "--help"])
        .output()
        .expect("run ftw list --help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("help utf8");
    for token in ["--type", "--format", "--cve", "--db", "--output", "JSONL", "category", "offline"] {
        assert!(help.contains(token), "help documents {token}:\n{help}");
    }
}
