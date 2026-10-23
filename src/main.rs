mod output;
mod probe;
mod scanner;
mod targets;
mod tech;

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use tokio::sync::mpsc;

use probe::Scheme;
use scanner::ScanResult;

#[derive(Debug, Parser)]
#[command(
    name = "FTW",
    about = "Fuck Teh World (FTW) — Authorized Async TCP Port Scanner",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the Phase 1 authorized TCP port scan.
    Scan(ScanArgs),
    /// Probe open ports from a scan-output file over HTTP/HTTPS.
    Probe(ProbeArgs),
}

/// Phase 1 scan flags (unchanged apart from moving under `scan`).
#[derive(Debug, Args)]
struct ScanArgs {
    /// YAML file listing authorized target CIDRs or single IPs
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    /// TCP ports to probe (comma-separated)
    #[arg(short, long, value_delimiter = ',', default_values_t = [80, 443])]
    ports: Vec<u16>,

    /// Maximum number of probes in flight at once
    #[arg(short, long, default_value_t = 500)]
    concurrency: usize,

    /// Per-probe timeout in seconds
    #[arg(short, long, value_name = "SECS", default_value_t = 2.0)]
    timeout: f64,

    /// File to stream results to
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,
}

/// Phase 2 probe flags.
#[derive(Debug, Args)]
struct ProbeArgs {
    /// Phase 1 scan-output file to read open ports from
    #[arg(long, value_name = "FILE")]
    scan_output: PathBuf,

    /// File to stream JSON-lines probe results to
    #[arg(long, value_name = "FILE")]
    output: PathBuf,

    /// Maximum number of probes in flight at once
    #[arg(long, default_value_t = 100)]
    concurrency: usize,

    /// Per-probe timeout in seconds
    #[arg(long, value_name = "SECS", default_value_t = 5.0)]
    timeout: f64,

    /// Which scheme(s) to probe with
    #[arg(long, value_enum, default_value_t = Scheme::Auto)]
    scheme: Scheme,

    /// Accept invalid TLS certificates (only for your own self-signed hosts)
    #[arg(long)]
    insecure: bool,

    /// Maximum HTTP redirects to follow per scheme attempt
    #[arg(long, default_value_t = 5)]
    max_redirects: usize,

    /// Maximum response body bytes to read per scheme attempt
    #[arg(long, value_name = "BYTES", default_value_t = 8192)]
    body_cap: usize,
}

const CHANNEL_CAPACITY: usize = 1024;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Scan(args) => run_scan(args).await,
        Commands::Probe(args) => run_probe(args).await,
    };
    if let Err(err) = result {
        eprintln!("ftw: error: {err}");
        std::process::exit(1);
    }
}

async fn run_scan(cli: ScanArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !cli.timeout.is_finite() || cli.timeout <= 0.0 {
        return Err("timeout must be a positive number of seconds".into());
    }
    let targets = targets::load_targets(&cli.input)?;
    if targets.is_empty() {
        eprintln!("ftw: warning: no targets to scan");
    }
    eprintln!(
        "ftw: scanning {} addresses across {} networks × {} ports",
        targets.address_count(),
        targets.net_count(),
        cli.ports.len()
    );
    let (tx, rx) = mpsc::channel::<ScanResult>(CHANNEL_CAPACITY);
    let writer = tokio::spawn(async move { output::run_writer(rx, cli.output).await });
    scanner::scan(
        &targets,
        &cli.ports,
        cli.concurrency,
        Duration::from_secs_f64(cli.timeout),
        tx,
    )
    .await;
    // `scan` returns after spawning every probe; each task holds a `tx`
    // clone, so the writer finishes only after all results are delivered.
    writer.await??;
    Ok(())
}

async fn run_probe(cli: ProbeArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !cli.timeout.is_finite() || cli.timeout <= 0.0 {
        return Err("timeout must be a positive number of seconds".into());
    }
    let config = probe::ProbeConfig {
        concurrency: cli.concurrency,
        timeout: Duration::from_secs_f64(cli.timeout),
        scheme: cli.scheme,
        insecure: cli.insecure,
        max_redirects: cli.max_redirects,
        body_cap: cli.body_cap,
    };
    let stats = probe::run(&config, &cli.scan_output, cli.output).await?;
    eprintln!(
        "ftw: probed {} targets: {} http, {} tls errors, {} connect errors, {} timeouts, {} other errors; php detected on {}, not detected on {}",
        stats.total,
        stats.http,
        stats.tls_errors,
        stats.connect_errors,
        stats.timeouts,
        stats.other_errors,
        stats.php_detected,
        stats.php_not_detected,
    );
    Ok(())
}

#[cfg(test)]
mod loopback_tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use crate::{output, scanner, targets};

    fn temp_tag() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("ftw-loopback-{}-{nanos}", std::process::id())
    }

    /// End-to-end loopback check: parse a sample YAML target file, scan one
    /// open port (ephemeral listener) plus one unbound closed port, and
    /// verify the streamed output file.
    #[tokio::test]
    async fn loopback_scan_streams_open_and_closed_results() {
        let tag = temp_tag();
        let dir = std::env::temp_dir();
        let yaml_path = dir.join(format!("{tag}.yml"));
        let out_path = dir.join(format!("{tag}.out"));
        std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write sample YAML");

        // Ephemeral listener: its port stays open for the whole scan.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind open port");
        let open_port = listener.local_addr().expect("open addr").port();

        // Bind-then-drop: nothing listens here, so probes are refused.
        let closed_port = {
            let tmp = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind temp port");
            tmp.local_addr().expect("temp addr").port()
        };

        let targets = targets::load_targets(&yaml_path).expect("parse sample YAML");
        assert_eq!(targets.address_count(), 1);

        let (tx, rx) = mpsc::channel(16);
        let writer = tokio::spawn(output::run_writer(rx, out_path.clone()));
        scanner::scan(
            &targets,
            &[open_port, closed_port],
            4,
            Duration::from_secs(2),
            tx,
        )
        .await;
        writer.await.expect("writer task").expect("writer io");
        drop(listener);

        let text = std::fs::read_to_string(&out_path).expect("read output");
        let mut lines: Vec<&str> = text.lines().collect();
        lines.sort_unstable();
        let open_line = format!("127.0.0.1:{open_port} open");
        let closed_line = format!("127.0.0.1:{closed_port} closed");
        assert_eq!(lines.len(), 2, "expected one line per probed port, got:\n{text}");
        assert!(lines.contains(&open_line.as_str()), "missing open line:\n{text}");
        assert!(
            lines.contains(&closed_line.as_str()),
            "missing closed line:\n{text}"
        );

        std::fs::remove_file(&yaml_path).ok();
        std::fs::remove_file(&out_path).ok();
    }
}
