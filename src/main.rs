mod crawl;
mod db;
mod fingerprint;
mod output;
mod scanner;
mod targets;
mod tech;

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, CommandFactory, Parser, Subcommand};
use tokio::sync::mpsc;

use fingerprint::Scheme;
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
    /// Fingerprint open ports from the master database over HTTP/HTTPS.
    Fingerprint(FingerprintArgs),
    /// Crawl seed pages from the master database (same-host only).
    Crawl(CrawlArgs),
}

/// Phase 1 scan flags. Results live in the master database (`--db`); there
/// are no result files.
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

    /// Master SQLite database file holding all scan/fingerprint/crawl results
    #[arg(long, value_name = "FILE", default_value = "ftw.db")]
    db: PathBuf,

    /// Print one human-readable stderr line per event (elapsed + detail)
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,

    /// Print nothing to the terminal during the run except errors and the
    /// final summary to stderr (database still written, flushed per event)
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,

    /// Removed: scan results now live in `--db`, not in a file.
    #[arg(short, long, value_name = "FILE", hide = true)]
    output: Option<PathBuf>,
}

/// Fingerprint flags. Seeds are read from the master database (`--db`) and
/// results are upserted back into it; there are no scan-output or result
/// files.
#[derive(Debug, Args)]
struct FingerprintArgs {
    /// Maximum number of fingerprint requests in flight at once
    #[arg(long, default_value_t = 100)]
    concurrency: usize,

    /// Per-target timeout in seconds
    #[arg(long, value_name = "SECS", default_value_t = 5.0)]
    timeout: f64,

    /// Which scheme(s) to try
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

    /// Which HTTP method(s) to send per scheme attempt
    #[arg(long, value_enum, default_value_t = fingerprint::FetchMode::Get)]
    fetch_mode: fingerprint::FetchMode,

    /// Fingerprint every open port, disabling the default prefer-HTTPS
    /// deduplication (which skips port 80 when the same IP also has 443 open)
    #[arg(long)]
    no_prefer_https: bool,

    /// Master SQLite database file holding all scan/fingerprint/crawl results
    #[arg(long, value_name = "FILE", default_value = "ftw.db")]
    db: PathBuf,

    /// Print one human-readable stderr line per event (elapsed + detail)
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,

    /// Print nothing to the terminal during the run except errors and the
    /// final summary to stderr (database still written, flushed per event)
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,

    /// Removed: fingerprint results now live in `--db`, not in a file.
    #[arg(long, value_name = "FILE", hide = true)]
    output: Option<PathBuf>,

    /// Removed: seeds are read from `--db`, not from a scan-output file.
    #[arg(long, value_name = "FILE", hide = true)]
    scan_output: Option<PathBuf>,
}

/// Crawl flags. Seeds are read from the master database (`--db`) and results
/// are upserted back into it; there are no seed files and no result files.
#[derive(Debug, Args)]
struct CrawlArgs {
    /// Master SQLite database file holding all scan/fingerprint/crawl results
    #[arg(long, value_name = "FILE", default_value = "ftw.db")]
    db: PathBuf,

    /// Maximum number of fetches in flight at once
    #[arg(long, default_value_t = 100)]
    concurrency: usize,

    /// Per-fetch timeout in seconds
    #[arg(long, value_name = "SECS", default_value_t = 5.0)]
    timeout: f64,

    /// Maximum link depth to fetch (depth 0 is the seed page)
    #[arg(long, default_value_t = 2)]
    max_depth: usize,

    /// Maximum pages to visit in total
    #[arg(long, default_value_t = 1000)]
    max_pages: usize,

    /// Maximum response body bytes to read per page
    #[arg(long, value_name = "BYTES", default_value_t = 262144)]
    body_cap: usize,

    /// Maximum HTTP redirects to follow per page
    #[arg(long, default_value_t = 5)]
    max_redirects: usize,

    /// Accept invalid TLS certificates (only for your own self-signed hosts)
    #[arg(long)]
    insecure: bool,

    /// Print one human-readable stderr line per event (elapsed + detail)
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,

    /// Print nothing to the terminal during the run except errors and the
    /// final summary to stderr (database still written, flushed per event)
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,
}

const CHANNEL_CAPACITY: usize = 1024;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Scan(args) => run_scan(args).await,
        Commands::Fingerprint(args) => run_fingerprint(args).await,
        Commands::Crawl(args) => run_crawl(args).await,
    };
    if let Err(err) = result {
        eprintln!("ftw: error: {err}");
        std::process::exit(1);
    }
}

/// Reject a removed file flag with a clap usage error: results now live in
/// `--db`, and the old flags are not accepted as a parallel option.
fn reject_removed_file_flag(flag: &str) -> ! {
    Cli::command()
        .error(
            clap::error::ErrorKind::UnknownArgument,
            format!(
                "{flag} is no longer supported: results now live in --db (default ftw.db); \
                 run `ftw scan --db <FILE>` first and pass the same --db file here"
            ),
        )
        .exit()
}

fn check_timeout(timeout: f64) -> Result<Duration, String> {
    if !timeout.is_finite() || timeout <= 0.0 {
        return Err("timeout must be a positive number of seconds".to_string());
    }
    Ok(Duration::from_secs_f64(timeout))
}

async fn run_scan(cli: ScanArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if cli.output.is_some() {
        reject_removed_file_flag("--output");
    }
    let timeout = check_timeout(cli.timeout)?;
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
    // Opened once here and moved into the writer task — the only task that
    // writes. Scanner workers only hold channel senders.
    let conn = db::open(&cli.db)?;
    let options = output::OutputOptions::new(cli.verbose, cli.quiet);
    let (tx, rx) = mpsc::channel::<ScanResult>(CHANNEL_CAPACITY);
    let writer = tokio::spawn(async move { output::run_scan_db_writer(rx, conn, options).await });
    scanner::scan(
        &targets,
        &cli.ports,
        cli.concurrency,
        timeout,
        tx,
    )
    .await;
    // `scan` returns after spawning every probe; each task holds a `tx`
    // clone, so the writer finishes only after all results are delivered.
    let stats = writer.await??;
    eprintln!(
        "ftw: scanned {} addresses across {} networks × {} ports: {} open, {} closed, {} filtered",
        targets.address_count(),
        targets.net_count(),
        cli.ports.len(),
        stats.open,
        stats.closed,
        stats.filtered,
    );
    Ok(())
}

async fn run_fingerprint(cli: FingerprintArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if cli.output.is_some() {
        reject_removed_file_flag("--output");
    }
    if cli.scan_output.is_some() {
        reject_removed_file_flag("--scan-output");
    }
    let config = fingerprint::FingerprintConfig {
        concurrency: cli.concurrency,
        timeout: check_timeout(cli.timeout)?,
        scheme: cli.scheme,
        insecure: cli.insecure,
        max_redirects: cli.max_redirects,
        body_cap: cli.body_cap,
        fetch_mode: cli.fetch_mode,
        no_prefer_https: cli.no_prefer_https,
    };
    let options = output::OutputOptions::new(cli.verbose, cli.quiet);
    let stats =
        fingerprint::run_with_options(&config, cli.db, options).await?;
    eprintln!("{}", fingerprint::format_summary(&stats));
    Ok(())
}

async fn run_crawl(cli: CrawlArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = crawl::CrawlConfig {
        concurrency: cli.concurrency,
        timeout: check_timeout(cli.timeout)?,
        max_depth: cli.max_depth,
        max_pages: cli.max_pages,
        body_cap: cli.body_cap,
        max_redirects: cli.max_redirects,
        insecure: cli.insecure,
    };
    let options = output::OutputOptions::new(cli.verbose, cli.quiet);
    let stats = crawl::run_with_options(&config, cli.db, options).await?;
    eprintln!(
        "ftw: crawled {} pages, {} links discovered ({} external skipped); errors: {} timeout, {} tls, {} connect, {} other; {} pages hit the body cap",
        stats.visited,
        stats.links_discovered,
        stats.links_external,
        stats.timeouts,
        stats.tls_errors,
        stats.connect_errors,
        stats.other_errors,
        stats.body_cap_hits,
    );
    Ok(())
}

#[cfg(test)]
mod loopback_tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use crate::{db, output, scanner, targets};

    fn temp_tag() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("ftw-loopback-{nanos}-{}", std::process::id())
    }

    /// End-to-end loopback check: parse a sample YAML target file, scan one
    /// open port (ephemeral listener) plus one unbound closed port, and
    /// verify the results land in the master database (no result files).
    #[tokio::test]
    async fn loopback_scan_streams_open_and_closed_results() {
        let tag = temp_tag();
        let dir = std::env::temp_dir();
        let yaml_path = dir.join(format!("{tag}.yml"));
        let db_path = dir.join(format!("{tag}.db"));
        std::fs::write(&yaml_path, "targets:\n  - 127.0.0.1/32\n").expect("write sample YAML");

        // Ephemeral listener: its port stays open for the whole scan.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind open port");
        let open_port = listener.local_addr().expect("open addr").port();

        // Bind-then-drop: nothing listens here, so connections are refused.
        let closed_port = {
            let tmp = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind temp port");
            tmp.local_addr().expect("temp addr").port()
        };

        let targets = targets::load_targets(&yaml_path).expect("parse sample YAML");
        assert_eq!(targets.address_count(), 1);

        let conn = db::open(&db_path).expect("open db");
        let (tx, rx) = mpsc::channel(16);
        let writer = tokio::spawn(output::run_scan_db_writer(
            rx,
            conn,
            output::OutputOptions::default(),
        ));
        scanner::scan(
            &targets,
            &[open_port, closed_port],
            4,
            std::time::Duration::from_secs(2),
            tx,
        )
        .await;
        let stats = writer.await.expect("writer task").expect("writer io");
        drop(listener);
        assert_eq!(stats.total(), 2);

        let check = db::open(&db_path).expect("reopen db");
        let mut stmt = check
            .prepare("SELECT port, status FROM scan_results WHERE ip = '127.0.0.1'")
            .expect("query scan results");
        let mut rows: Vec<(u16, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("map rows")
            .collect::<Result<_, _>>()
            .expect("collect rows");
        rows.sort_unstable();
        let mut expected = vec![
            (open_port, "open".to_string()),
            (closed_port, "closed".to_string()),
        ];
        expected.sort_unstable();
        assert_eq!(
            rows, expected,
            "expected one open and one closed row in the database"
        );

        std::fs::remove_file(&yaml_path).ok();
        std::fs::remove_file(&db_path).ok();
    }
}
