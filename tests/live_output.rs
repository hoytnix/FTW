//! Live-output CLI tests: default stdout duplication, `--verbose` stderr
//! lines, `--quiet` suppression, and the `--verbose`/`--quiet` conflict.
//!
//! These run the built `ftw` binary end to end on loopback targets.

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

/// Minimal blocking HTTP origin server: fixed 200 + `Server` header for
/// every connection. Returns the port; the thread exits after a few
/// connections.
fn spawn_http_server() -> (u16, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http server");
    let port = listener.local_addr().expect("http addr").port();
    let handle = std::thread::spawn(move || {
        for _ in 0..8 {
            let Ok((mut sock, _)) = listener.accept() else {
                break;
            };
            let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = [0u8; 8192];
            let _ = sock.read(&mut buf);
            let body = "hello-live";
            let response = format!(
                "HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(response.as_bytes());
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
/// lines written to the output file.
#[test]
fn scan_default_stdout_matches_output_file() {
    let tag = temp_tag("scan-live");
    let yaml_path = temp_path(&tag, "yml");
    let out_path = temp_path(&tag, "out");
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
            "--output",
            &out_path.to_string_lossy(),
        ])
        .output()
        .expect("run ftw scan");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let file_text = std::fs::read_to_string(&out_path).expect("read output file");
    assert_eq!(
        sorted_lines(&stdout),
        sorted_lines(&file_text),
        "stdout must carry the same result lines as the file"
    );
    let open_line = format!("127.0.0.1:{open_port} open");
    let closed_line = format!("127.0.0.1:{closed} closed");
    assert!(stdout.contains(&open_line), "missing open line: {stdout}");
    assert!(stdout.contains(&closed_line), "missing closed line: {stdout}");

    std::fs::remove_file(&yaml_path).ok();
    std::fs::remove_file(&out_path).ok();
}

/// `--verbose` probe: stderr must contain one per-event line for each probe
/// record, naming its scheme and final_url.
#[test]
fn probe_verbose_stderr_names_scheme_and_final_url() {
    let tag = temp_tag("probe-verbose");
    let scan_path = temp_path(&tag, "scan");
    let out_path = temp_path(&tag, "out");
    let (http_port, _server) = spawn_http_server();
    std::fs::write(&scan_path, format!("127.0.0.1:{http_port} open\n")).expect("write scan");

    let output = Command::new(ftw_bin())
        .args([
            "probe",
            "--scan-output",
            &scan_path.to_string_lossy(),
            "--output",
            &out_path.to_string_lossy(),
            "--scheme",
            "http",
            "--verbose",
        ])
        .output()
        .expect("run ftw probe");
    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let file_text = std::fs::read_to_string(&out_path).expect("read probe output");
    let records: Vec<serde_json::Value> = file_text
        .lines()
        .map(|line| serde_json::from_str(line).expect("output line is JSON"))
        .collect();
    assert_eq!(records.len(), 1, "expected one probe record");
    let scheme = records[0]["scheme"].as_str().expect("scheme str");
    let final_url = records[0]["final_url"].as_str().expect("final_url str");

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains(scheme),
        "verbose stderr must name the scheme {scheme}: {stderr}"
    );
    assert!(
        stderr.contains(final_url),
        "verbose stderr must name the final_url {final_url}: {stderr}"
    );

    std::fs::remove_file(&scan_path).ok();
    std::fs::remove_file(&out_path).ok();
}

/// `--quiet` scan: stdout stays empty while the output file is complete.
#[test]
fn scan_quiet_suppresses_stdout_but_writes_file() {
    let tag = temp_tag("scan-quiet");
    let yaml_path = temp_path(&tag, "yml");
    let out_path = temp_path(&tag, "out");
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
            "--output",
            &out_path.to_string_lossy(),
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

    let file_text = std::fs::read_to_string(&out_path).expect("read output file");
    let lines = sorted_lines(&file_text);
    assert_eq!(lines.len(), 2, "file must still be complete: {file_text}");
    assert!(file_text.contains(&format!("127.0.0.1:{open_port} open")));
    assert!(file_text.contains(&format!("127.0.0.1:{closed} closed")));

    // The final summary still goes to stderr in quiet mode.
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("scanned"), "summary stays on stderr: {stderr}");

    std::fs::remove_file(&yaml_path).ok();
    std::fs::remove_file(&out_path).ok();
}

/// `--quiet` probe: stdout stays empty while the JSON-lines file is complete.
#[test]
fn probe_quiet_suppresses_stdout_but_writes_file() {
    let tag = temp_tag("probe-quiet");
    let scan_path = temp_path(&tag, "scan");
    let out_path = temp_path(&tag, "out");
    let (http_port, _server) = spawn_http_server();
    std::fs::write(&scan_path, format!("127.0.0.1:{http_port} open\n")).expect("write scan");

    let output = Command::new(ftw_bin())
        .args([
            "probe",
            "--scan-output",
            &scan_path.to_string_lossy(),
            "--output",
            &out_path.to_string_lossy(),
            "--scheme",
            "http",
            "--quiet",
        ])
        .output()
        .expect("run ftw probe --quiet");
    assert!(
        output.status.success(),
        "quiet probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "quiet stdout must be empty, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let file_text = std::fs::read_to_string(&out_path).expect("read probe output");
    let records: Vec<serde_json::Value> = file_text
        .lines()
        .map(|line| serde_json::from_str(line).expect("output line is JSON"))
        .collect();
    assert_eq!(records.len(), 1, "file must still be complete");

    std::fs::remove_file(&scan_path).ok();
    std::fs::remove_file(&out_path).ok();
}

/// `--verbose` and `--quiet` together are rejected by clap for both
/// subcommands.
#[test]
fn verbose_and_quiet_conflict_on_both_subcommands() {
    let tag = temp_tag("conflict");
    let yaml_path = temp_path(&tag, "yml");
    let out_path = temp_path(&tag, "out");
    std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write yaml");

    let scan = Command::new(ftw_bin())
        .args([
            "scan",
            "--input",
            &yaml_path.to_string_lossy(),
            "--ports",
            "80",
            "--output",
            &out_path.to_string_lossy(),
            "--verbose",
            "--quiet",
        ])
        .output()
        .expect("run conflicting scan");
    assert!(
        !scan.status.success(),
        "--verbose + --quiet must be rejected for scan"
    );

    let scan_path = temp_path(&tag, "scan");
    std::fs::write(&scan_path, "127.0.0.1:80 open\n").expect("write scan");
    let probe = Command::new(ftw_bin())
        .args([
            "probe",
            "--scan-output",
            &scan_path.to_string_lossy(),
            "--output",
            &out_path.to_string_lossy(),
            "--verbose",
            "--quiet",
        ])
        .output()
        .expect("run conflicting probe");
    assert!(
        !probe.status.success(),
        "--verbose + --quiet must be rejected for probe"
    );

    std::fs::remove_file(&yaml_path).ok();
    std::fs::remove_file(&scan_path).ok();
    std::fs::remove_file(&out_path).ok();
}
