//! Streaming result writer: one task owns a `BufWriter` and writes each
//! result to the output file as it arrives over a bounded channel.

use std::io;
use std::path::PathBuf;

use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

use crate::probe::{ProbeRecord, ProbeStats};
use crate::scanner::ScanResult;

/// One output line: `<ip>:<port> <status>`.
#[must_use]
pub fn format_result(result: &ScanResult) -> String {
    format!("{}:{} {}\n", result.ip, result.port, result.status)
}

/// Drain `rx` to `path`, flushing at the end. Returns when all senders drop.
pub async fn run_writer(
    mut rx: mpsc::Receiver<ScanResult>,
    path: PathBuf,
) -> io::Result<()> {
    let file = File::create(&path).await?;
    let mut writer = BufWriter::new(file);
    while let Some(result) = rx.recv().await {
        writer.write_all(format_result(&result).as_bytes()).await?;
    }
    writer.flush().await
}

/// Drain probe records to `path` as one JSON object per line, flushing at the
/// end. Returns per-run counts. Returns when all senders drop.
pub async fn run_probe_writer(
    mut rx: mpsc::Receiver<ProbeRecord>,
    path: PathBuf,
) -> io::Result<ProbeStats> {
    let file = File::create(&path).await?;
    let mut writer = BufWriter::new(file);
    let mut stats = ProbeStats::default();
    while let Some(record) = rx.recv().await {
        stats.record(&record);
        let mut line =
            serde_json::to_string(&record).map_err(|err| io::Error::other(err.to_string()))?;
        line.push('\n');
        writer.write_all(line.as_bytes()).await?;
    }
    writer.flush().await?;
    Ok(stats)
}
