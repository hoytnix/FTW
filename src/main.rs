mod config;
mod crawl;
mod db;
mod fingerprint;
mod output;
mod rate_limit;
mod scanner;
mod targets;
mod tech;

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, CommandFactory, Parser, Subcommand};
use tokio::sync::mpsc;

use config::Source;
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
/// are no result files. Defaults may be set in the config file; see
/// `--config`.
#[derive(Debug, Args)]
struct ScanArgs {
    /// YAML file listing authorized target CIDRs or single IPs
    #[arg(short, long, value_name = "FILE")]
    input: Option<PathBuf>,

    /// TCP ports to probe (comma-separated) (default 80,443)
    #[arg(short, long, value_delimiter = ',')]
    ports: Option<Vec<u16>>,

    /// Maximum number of probes in flight at once (default 500)
    #[arg(short, long)]
    concurrency: Option<usize>,

    /// Per-probe timeout in seconds (default 2)
    #[arg(short, long, value_name = "SECS")]
    timeout: Option<f64>,

    /// Master SQLite database file holding all scan/fingerprint/crawl results
    /// (default ftw.db)
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,

    /// Config file with persistent defaults (discovery order when omitted:
    /// ./ftw.toml, then $HOME/.config/ftw/config.toml)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

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
/// files. Defaults may be set in the config file; see `--config`.
#[derive(Debug, Args)]
struct FingerprintArgs {
    /// Maximum number of fingerprint requests in flight at once (default 100)
    #[arg(long)]
    concurrency: Option<usize>,

    /// Per-target timeout in seconds (default 5)
    #[arg(long, value_name = "SECS")]
    timeout: Option<f64>,

    /// Which scheme(s) to try (default auto)
    #[arg(long, value_enum)]
    scheme: Option<Scheme>,

    /// Accept invalid TLS certificates (only for your own self-signed hosts)
    #[arg(long)]
    insecure: bool,

    /// Maximum HTTP redirects to follow per scheme attempt (default 5)
    #[arg(long)]
    max_redirects: Option<usize>,

    /// Maximum response body bytes to read per scheme attempt (default 8192)
    #[arg(long, value_name = "BYTES")]
    body_cap: Option<usize>,

    /// Which HTTP method(s) to send per scheme attempt (default get)
    #[arg(long, value_enum)]
    fetch_mode: Option<fingerprint::FetchMode>,

    /// Fingerprint every open port, disabling the default prefer-HTTPS
    /// deduplication (which skips port 80 when the same IP also has 443 open)
    #[arg(long)]
    no_prefer_https: bool,

    /// Master SQLite database file holding all scan/fingerprint/crawl results
    /// (default ftw.db)
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,

    /// Config file with persistent defaults (discovery order when omitted:
    /// ./ftw.toml, then $HOME/.config/ftw/config.toml)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

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
/// Defaults may be set in the config file; see `--config`.
#[derive(Debug, Args)]
struct CrawlArgs {
    /// Master SQLite database file holding all scan/fingerprint/crawl results
    /// (default ftw.db)
    #[arg(long, value_name = "FILE")]
    db: Option<PathBuf>,

    /// Maximum number of fetches in flight at once (default 100)
    #[arg(long)]
    concurrency: Option<usize>,

    /// Per-fetch timeout in seconds (default 5)
    #[arg(long, value_name = "SECS")]
    timeout: Option<f64>,

    /// Maximum link depth to fetch (depth 0 is the seed page) (default 2)
    #[arg(long)]
    max_depth: Option<usize>,

    /// Maximum pages to visit in total (default 1000)
    #[arg(long)]
    max_pages: Option<usize>,

    /// Maximum response body bytes to read per page (default 262144)
    #[arg(long, value_name = "BYTES")]
    body_cap: Option<usize>,

    /// Maximum HTTP redirects to follow per page (default 5)
    #[arg(long)]
    max_redirects: Option<usize>,

    /// Accept invalid TLS certificates (only for your own self-signed hosts)
    #[arg(long)]
    insecure: bool,

    /// Maximum requests per minute per canonical domain (0 = unlimited)
    /// (default 0)
    #[arg(long, value_name = "N")]
    requests_per_minute: Option<u64>,

    /// Config file with persistent defaults (discovery order when omitted:
    /// ./ftw.toml, then $HOME/.config/ftw/config.toml)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

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
    let cfg_path = config::discover(cli.config.as_deref())?;
    let file = match &cfg_path {
        Some(path) => config::load(path)?,
        None => config::FileConfig::default(),
    };
    let cfg = &file.scan;
    let (input, input_src) = match (cli.input, cfg.input.clone()) {
        (Some(value), _) => (Some(value), Source::Cli),
        (None, Some(value)) => (Some(value), Source::Config),
        (None, None) => (None, Source::Default),
    };
    let Some(input) = input else {
        return Err(
            "no scan input: pass --input <FILE> or set scan.input in the config file".to_string().into(),
        );
    };
    let (ports, ports_src) = config::resolve(cli.ports, cfg.ports.clone(), vec![80, 443]);
    let (concurrency, concurrency_src) = config::resolve(cli.concurrency, cfg.concurrency, 500);
    let (timeout_secs, timeout_src) =
        config::resolve(cli.timeout, cfg.timeout.map(|t| t.0), 2.0);
    let (db, db_src) = config::resolve(
        cli.db,
        file.global.db.clone(),
        PathBuf::from("ftw.db"),
    );
    let (verbose, _) = config::resolve_flag(cli.verbose, cfg.verbose, false);
    let (quiet, _) = config::resolve_flag(cli.quiet, cfg.quiet, false);
    if verbose && quiet {
        return Err("verbose and quiet conflict: enable only one".to_string().into());
    }
    let cfg_ref = cfg_path.as_deref();
    config::require_at_least_one("scan", "concurrency", concurrency, concurrency_src, cfg_ref)?;
    config::require_positive_seconds("scan", "timeout", timeout_secs, timeout_src, cfg_ref)?;
    let timeout = check_timeout(timeout_secs)?;
    if verbose {
        eprintln!("{}", config::line("scan", "input", &input.display().to_string(), input_src));
        eprintln!("{}", config::line("scan", "ports", &format!("{ports:?}"), ports_src));
        eprintln!("{}", config::line("scan", "concurrency", &concurrency.to_string(), concurrency_src));
        eprintln!("{}", config::line("scan", "timeout", &timeout_secs.to_string(), timeout_src));
        let db_section = if db_src == Source::Config { "global" } else { "scan" };
        eprintln!("{}", config::line(db_section, "db", &db.display().to_string(), db_src));
    }
    let targets = targets::load_targets(&input)?;
    if targets.is_empty() {
        eprintln!("ftw: warning: no targets to scan");
    }
    eprintln!(
        "ftw: scanning {} addresses across {} networks × {} ports",
        targets.address_count(),
        targets.net_count(),
        ports.len()
    );
    // Opened once here and moved into the writer task — the only task that
    // writes. Scanner workers only hold channel senders.
    let conn = db::open(&db)?;
    let options = output::OutputOptions::new(verbose, quiet);
    let (tx, rx) = mpsc::channel::<ScanResult>(CHANNEL_CAPACITY);
    let writer = tokio::spawn(async move { output::run_scan_db_writer(rx, conn, options).await });
    scanner::scan(
        &targets,
        &ports,
        concurrency,
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
        ports.len(),
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
    let cfg_path = config::discover(cli.config.as_deref())?;
    let file = match &cfg_path {
        Some(path) => config::load(path)?,
        None => config::FileConfig::default(),
    };
    let cfg = &file.fingerprint;
    let (concurrency, concurrency_src) = config::resolve(cli.concurrency, cfg.concurrency, 100);
    let (timeout_secs, timeout_src) =
        config::resolve(cli.timeout, cfg.timeout.map(|t| t.0), 5.0);
    let (scheme_raw, scheme_src) = config::resolve(
        cli.scheme.map(|s| s.as_str().to_string()),
        cfg.scheme.clone(),
        "auto".to_string(),
    );
    let scheme = match scheme_raw.as_str() {
        "auto" => Scheme::Auto,
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        _ => {
            let where_from = match (scheme_src, cfg_path.as_deref()) {
                (Source::Config, Some(path)) => format!("{}: ", path.display()),
                _ => String::new(),
            };
            return Err(format!(
                "{where_from}[fingerprint] scheme must be auto, http, or https, got {scheme_raw:?}"
            )
            .into());
        }
    };
    let (insecure, insecure_src) = config::resolve_flag(cli.insecure, cfg.insecure, false);
    let (max_redirects, max_redirects_src) =
        config::resolve(cli.max_redirects, cfg.max_redirects, 5);
    let (body_cap, body_cap_src) = config::resolve(cli.body_cap, cfg.body_cap, 8192);
    let (fetch_mode_raw, fetch_mode_src) = config::resolve(
        cli.fetch_mode.map(|m| m.as_str().to_string()),
        cfg.fetch_mode.clone(),
        "get".to_string(),
    );
    let fetch_mode = match fetch_mode_raw.as_str() {
        "get" => fingerprint::FetchMode::Get,
        "head" => fingerprint::FetchMode::Head,
        "both" => fingerprint::FetchMode::Both,
        _ => {
            let where_from = match (fetch_mode_src, cfg_path.as_deref()) {
                (Source::Config, Some(path)) => format!("{}: ", path.display()),
                _ => String::new(),
            };
            return Err(format!(
                "{where_from}[fingerprint] fetch_mode must be get, head, or both, got {fetch_mode_raw:?}"
            )
            .into());
        }
    };
    let (prefer_https, prefer_src) =
        config::resolve_prefer_https(cli.no_prefer_https, cfg.prefer_https);
    let (db, db_src) = config::resolve(
        cli.db,
        file.global.db.clone(),
        PathBuf::from("ftw.db"),
    );
    let (verbose, _) = config::resolve_flag(cli.verbose, cfg.verbose, false);
    let (quiet, _) = config::resolve_flag(cli.quiet, cfg.quiet, false);
    if verbose && quiet {
        return Err("verbose and quiet conflict: enable only one".to_string().into());
    }
    let cfg_ref = cfg_path.as_deref();
    config::require_at_least_one(
        "fingerprint",
        "concurrency",
        concurrency,
        concurrency_src,
        cfg_ref,
    )?;
    config::require_positive_seconds("fingerprint", "timeout", timeout_secs, timeout_src, cfg_ref)?;
    let timeout = check_timeout(timeout_secs)?;
    if verbose {
        eprintln!("{}", config::line("fingerprint", "concurrency", &concurrency.to_string(), concurrency_src));
        eprintln!("{}", config::line("fingerprint", "timeout", &timeout_secs.to_string(), timeout_src));
        eprintln!("{}", config::line("fingerprint", "scheme", &scheme_raw, scheme_src));
        eprintln!("{}", config::line("fingerprint", "insecure", &insecure.to_string(), insecure_src));
        eprintln!("{}", config::line("fingerprint", "max_redirects", &max_redirects.to_string(), max_redirects_src));
        eprintln!("{}", config::line("fingerprint", "body_cap", &body_cap.to_string(), body_cap_src));
        eprintln!("{}", config::line("fingerprint", "fetch_mode", &fetch_mode_raw, fetch_mode_src));
        eprintln!("{}", config::line("fingerprint", "prefer_https", &prefer_https.to_string(), prefer_src));
        let db_section = if db_src == Source::Config { "global" } else { "fingerprint" };
        eprintln!("{}", config::line(db_section, "db", &db.display().to_string(), db_src));
    }
    let config = fingerprint::FingerprintConfig {
        concurrency,
        timeout,
        scheme,
        insecure,
        max_redirects,
        body_cap,
        fetch_mode,
        no_prefer_https: !prefer_https,
    };
    let options = output::OutputOptions::new(verbose, quiet);
    let stats =
        fingerprint::run_with_options(&config, db, options).await?;
    eprintln!("{}", fingerprint::format_summary(&stats));
    Ok(())
}

async fn run_crawl(cli: CrawlArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg_path = config::discover(cli.config.as_deref())?;
    let file = match &cfg_path {
        Some(path) => config::load(path)?,
        None => config::FileConfig::default(),
    };
    let cfg = &file.crawl;
    let (concurrency, concurrency_src) = config::resolve(cli.concurrency, cfg.concurrency, 100);
    let (timeout_secs, timeout_src) =
        config::resolve(cli.timeout, cfg.timeout.map(|t| t.0), 5.0);
    let (max_depth, max_depth_src) = config::resolve(cli.max_depth, cfg.max_depth, 2);
    let (max_pages, max_pages_src) = config::resolve(cli.max_pages, cfg.max_pages, 1000);
    let (body_cap, body_cap_src) = config::resolve(cli.body_cap, cfg.body_cap, 262144);
    let (max_redirects, max_redirects_src) =
        config::resolve(cli.max_redirects, cfg.max_redirects, 5);
    let (insecure, insecure_src) = config::resolve_flag(cli.insecure, cfg.insecure, false);
    let (requests_per_minute, rpm_src) =
        config::resolve(cli.requests_per_minute, cfg.requests_per_minute, 0);
    let rate_overrides = cfg.rate_limits.clone().unwrap_or_default();
    let overrides_src = if cfg.rate_limits.is_some() {
        Source::Config
    } else {
        Source::Default
    };
    let (db, db_src) = config::resolve(
        cli.db,
        file.global.db.clone(),
        PathBuf::from("ftw.db"),
    );
    let (verbose, _) = config::resolve_flag(cli.verbose, cfg.verbose, false);
    let (quiet, _) = config::resolve_flag(cli.quiet, cfg.quiet, false);
    if verbose && quiet {
        return Err("verbose and quiet conflict: enable only one".to_string().into());
    }
    let cfg_ref = cfg_path.as_deref();
    config::require_at_least_one("crawl", "concurrency", concurrency, concurrency_src, cfg_ref)?;
    config::require_positive_seconds("crawl", "timeout", timeout_secs, timeout_src, cfg_ref)?;
    config::require_at_least_one("crawl", "max_pages", max_pages, max_pages_src, cfg_ref)?;
    let timeout = check_timeout(timeout_secs)?;
    if verbose {
        eprintln!("{}", config::line("crawl", "concurrency", &concurrency.to_string(), concurrency_src));
        eprintln!("{}", config::line("crawl", "timeout", &timeout_secs.to_string(), timeout_src));
        eprintln!("{}", config::line("crawl", "max_depth", &max_depth.to_string(), max_depth_src));
        eprintln!("{}", config::line("crawl", "max_pages", &max_pages.to_string(), max_pages_src));
        eprintln!("{}", config::line("crawl", "body_cap", &body_cap.to_string(), body_cap_src));
        eprintln!("{}", config::line("crawl", "max_redirects", &max_redirects.to_string(), max_redirects_src));
        eprintln!("{}", config::line("crawl", "insecure", &insecure.to_string(), insecure_src));
        eprintln!("{}", config::line("crawl", "requests_per_minute", &requests_per_minute.to_string(), rpm_src));
        eprintln!("{}", config::line("crawl", "rate_limits", &format!("{} domains", rate_overrides.len()), overrides_src));
        let db_section = if db_src == Source::Config { "global" } else { "crawl" };
        eprintln!("{}", config::line(db_section, "db", &db.display().to_string(), db_src));
    }
    let config = crawl::CrawlConfig {
        concurrency,
        timeout,
        max_depth,
        max_pages,
        body_cap,
        max_redirects,
        insecure,
        requests_per_minute,
        rate_window: rate_limit::DEFAULT_WINDOW,
        rate_overrides,
    };
    let options = output::OutputOptions::new(verbose, quiet);
    let stats = crawl::run_with_options(&config, db, options).await?;
    eprintln!(
        "{}",
        crawl::format_summary(&stats, requests_per_minute)
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
