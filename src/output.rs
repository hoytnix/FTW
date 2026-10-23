//! Streaming result writer: one task owns a `BufWriter` and writes each
//! result to the output file as it arrives over a bounded channel.
//!
//! The writer task is the ONLY place that writes live terminal output, so
//! event order is preserved and lines never interleave. For every event it
//! writes the exact same line/record to stdout immediately (unless quiet),
//! then flushes stdout AND the file writer before taking the next event —
//! never waiting for the buffer to fill or the channel to close. Flushing
//! per event is slower than bulk buffering on very large scans; that is the
//! intended tradeoff: live visibility over throughput. No batching delay,
//! no progress throttle, no flush-every-N optimization.
//!
//! Final summaries are printed by the caller to stderr only, after the
//! channel closes and the writer finishes, so stdout stays parseable.

use std::io;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokio::fs::File;
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

use crate::probe::{ProbeRecord, ProbeStats};
use crate::scanner::ScanResult;

/// Live-output options shared by both subcommands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutputOptions {
    /// Print one human-readable stderr line per event (elapsed + detail).
    pub verbose: bool,
    /// Suppress all terminal output during the run (file still written,
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

/// One verbose stderr line per probe event: `ip:port`, the scheme actually
/// used, fetch method and head status, HTTP status (or error), final URL,
/// Server header when present, and detected technologies. The JSON record on
/// stdout stays the machine-readable source of truth; this line is only for
/// watching, and it always names both scheme and final URL so a scheme
/// mismatch (for example a plain-HTTP request to a TLS port returning 400)
/// is obvious from this line alone.
#[must_use]
pub fn format_probe_verbose(elapsed: Duration, record: &ProbeRecord) -> String {
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

/// Write one result line to the locked stdout and flush it. Stdout carries
/// parseable results only, never diagnostics.
fn emit_stdout(line: &str) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let _ = handle.write_all(line.as_bytes());
    let _ = handle.flush();
}

/// Drain scan results: write each `<ip>:<port> <status>` line to `file`,
/// duplicate it to stdout (unless quiet), print a verbose stderr line per
/// event when requested, and flush stdout AND the file after every event.
/// Returns per-run counts. Ends when all senders drop.
pub async fn run_scan_stream<W>(
    mut rx: mpsc::Receiver<ScanResult>,
    file: W,
    options: OutputOptions,
) -> io::Result<ScanStats>
where
    W: AsyncWrite + Unpin,
{
    let start = Instant::now();
    let mut writer = BufWriter::new(file);
    let mut stats = ScanStats::default();
    while let Some(result) = rx.recv().await {
        stats.record(&result);
        let line = format_result(&result);
        writer.write_all(line.as_bytes()).await?;
        if !options.quiet {
            emit_stdout(&line);
        }
        if options.verbose {
            eprint!("{}", format_scan_verbose(start.elapsed(), &result));
        }
        if !options.quiet {
            // Flush the terminal copy before the file copy so a watcher
            // never sees the file advance without the terminal matching it.
            io::stdout().flush()?;
        }
        writer.flush().await?;
    }
    Ok(stats)
}

/// Drain probe records to `file` as one JSON object per line, duplicating
/// each record to stdout (unless quiet) and printing a verbose stderr line
/// per event when requested. Flushes stdout AND the file after every event.
/// Returns per-run counts. Ends when all senders drop.
pub async fn run_probe_stream<W>(
    mut rx: mpsc::Receiver<ProbeRecord>,
    file: W,
    options: OutputOptions,
) -> io::Result<ProbeStats>
where
    W: AsyncWrite + Unpin,
{
    let start = Instant::now();
    let mut writer = BufWriter::new(file);
    let mut stats = ProbeStats::default();
    while let Some(record) = rx.recv().await {
        stats.record(&record);
        let mut line =
            serde_json::to_string(&record).map_err(|err| io::Error::other(err.to_string()))?;
        line.push('\n');
        writer.write_all(line.as_bytes()).await?;
        if !options.quiet {
            emit_stdout(&line);
        }
        if options.verbose {
            eprint!("{}", format_probe_verbose(start.elapsed(), &record));
        }
        if !options.quiet {
            io::stdout().flush()?;
        }
        writer.flush().await?;
    }
    Ok(stats)
}

/// Drain `rx` to `path` with live stdout duplication (unless quiet) and an
/// optional per-event verbose line to stderr. Returns per-run counts.
pub async fn run_writer_with_options(
    rx: mpsc::Receiver<ScanResult>,
    path: PathBuf,
    options: OutputOptions,
) -> io::Result<ScanStats> {
    let file = File::create(&path).await?;
    run_scan_stream(rx, file, options).await
}

/// Drain `rx` to `path`. Returns when all senders drop. Live stdout
/// duplication is on by default (matching the CLI default).
#[allow(dead_code)]
pub async fn run_writer(
    rx: mpsc::Receiver<ScanResult>,
    path: PathBuf,
) -> io::Result<()> {
    run_writer_with_options(rx, path, OutputOptions::default()).await?;
    Ok(())
}

/// Drain probe records to `path` as one JSON object per line with live
/// stdout duplication (unless quiet) and an optional per-event verbose line
/// to stderr. Returns per-run counts. Returns when all senders drop.
pub async fn run_probe_writer_with_options(
    rx: mpsc::Receiver<ProbeRecord>,
    path: PathBuf,
    options: OutputOptions,
) -> io::Result<ProbeStats> {
    let file = File::create(&path).await?;
    run_probe_stream(rx, file, options).await
}

/// Drain probe records to `path` as one JSON object per line. Returns
/// per-run counts. Returns when all senders drop. Live stdout duplication
/// is on by default (matching the CLI default).
#[allow(dead_code)]
pub async fn run_probe_writer(
    rx: mpsc::Receiver<ProbeRecord>,
    path: PathBuf,
) -> io::Result<ProbeStats> {
    run_probe_writer_with_options(rx, path, OutputOptions::default()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    /// Shared in-memory async sink that counts flushes, proving
    /// flush-per-event. `Clone` shares the same counters so the writer task
    /// can own one handle while the test observes the other.
    #[derive(Debug, Clone, Default)]
    struct SharedMock {
        inner: Arc<Mutex<MockInner>>,
    }

    #[derive(Debug, Default)]
    struct MockInner {
        written: Vec<u8>,
        flushes: usize,
    }

    impl SharedMock {
        fn flushes(&self) -> usize {
            self.inner.lock().expect("mock lock").flushes
        }
    }

    impl AsyncWrite for SharedMock {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.inner
                .lock()
                .expect("mock lock")
                .written
                .extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.inner.lock().expect("mock lock").flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn scan_result(ip: &str, port: u16, status: crate::scanner::PortStatus) -> ScanResult {
        ScanResult {
            ip: ip.parse().expect("test ip"),
            port,
            status,
            reason: status.as_str(),
        }
    }

    fn probe_record(port: u16) -> ProbeRecord {
        ProbeRecord {
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

    /// Three scan events through the channel must flush the file writer three
    /// times (once per event), not once at close.
    #[tokio::test]
    async fn scan_stream_flushes_once_per_event() {
        let (tx, rx) = mpsc::channel(8);
        let options = OutputOptions::new(false, true);
        let mock = SharedMock::default();
        let task = tokio::spawn(run_scan_stream(rx, mock.clone(), options));
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
        assert_eq!(
            mock.flushes(),
            3,
            "mock writer must see one flush per record, not one flush at close"
        );
    }

    /// Three probe records through the channel must flush three times.
    #[tokio::test]
    async fn probe_stream_flushes_once_per_event() {
        let (tx, rx) = mpsc::channel(8);
        let options = OutputOptions::new(false, true);
        let mock = SharedMock::default();
        let task = tokio::spawn(run_probe_stream(rx, mock.clone(), options));
        for port in [80u16, 443, 22] {
            tx.send(probe_record(port)).await.expect("send record");
        }
        drop(tx);
        let stats = task.await.expect("writer task").expect("writer ok");
        assert_eq!(stats.total, 3);
        assert_eq!(
            mock.flushes(),
            3,
            "mock writer must see one flush per record, not one flush at close"
        );
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
    fn probe_verbose_names_scheme_and_final_url() {
        let mut record = probe_record(443);
        record.scheme = "http".to_string();
        record.status = Some(400);
        record.final_url = "http://127.0.0.1:443/".to_string();
        record.fetch_method = "get".to_string();
        let line = format_probe_verbose(Duration::from_millis(50), &record);
        assert!(line.contains("http"), "scheme visible: {line}");
        assert!(
            line.contains("http://127.0.0.1:443/"),
            "final_url visible: {line}"
        );
        assert!(line.contains("400"), "status visible: {line}");
    }
}
