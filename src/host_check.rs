//! Authoritative on-host patch records (`ftw host-check`) for authorized
//! ranges only.
//!
//! Reads a host inventory file and, using the user's EXISTING SSH config and
//! agent only, runs `php -v` plus the distro PHP package query on each host.
//! SSH credentials are never embedded, accepted, or stored anywhere: not in
//! code, not in config, not in output. Authentication uses
//! `ssh -o BatchMode=yes` (no password prompts, no fallback to keyboard
//! input) so only hosts already reachable via the user's own keys, agent,
//! and `~/.ssh/config` are checked; anything else is recorded as an error.
//!
//! For each host the raw `php -v` output and the raw package-query output
//! are recorded VERBATIM. That verbatim record is the authoritative patch
//! record — probe-side version strings stay hints only. [`HostCheckRecord`]
//! also carries small parsed conveniences (`php_version`, `packages`) for
//! merging; the raw text is always the source of truth.
//!
//! [`summaries_from_jsonl`] loads one `ftw host-check` JSONL output file
//! into the `host → summary` map that [`crate::probe`] merges into probe
//! records by host where available.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc};

use crate::output;
use crate::probe::HostCheckSummary;

const CHANNEL_CAPACITY: usize = 1024;

/// Marker separating `php -v` output from the package query in one SSH run.
pub const PACKAGES_MARKER: &str = "__FTW_PACKAGES__";

/// Single remote command: `php -v`, then the distro package query. `dpkg`
/// first, `rpm` as fallback, silence when neither exists. Passed as ONE ssh
/// argument so the REMOTE shell parses the quoting — the local shell never
/// sees it.
const REMOTE_COMMAND: &str = "php -v 2>&1; echo __FTW_PACKAGES__; dpkg-query -W -f='${Package} ${Version}\n' '*php*' 2>/dev/null || rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' '*php*' 2>/dev/null || true";

/// Runtime settings for a host-check run.
#[derive(Debug, Clone, Copy)]
pub struct HostCheckConfig {
    pub concurrency: usize,
    pub timeout: Duration,
}

/// One installed package (name + version), parsed for convenience. The
/// authoritative data is the verbatim query output in [`HostCheckRecord`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PhpPackage {
    pub name: String,
    pub version: String,
}

/// One JSON-lines host-check record: exactly one per inventory host.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostCheckRecord {
    pub host: String,
    /// Verbatim `php -v` stdout (the authoritative PHP record).
    pub php_raw: String,
    /// Parsed `major.minor.patch` from the first `php -v` line, if any.
    pub php_version: Option<String>,
    /// Verbatim distro package-query stdout.
    pub packages_raw: String,
    /// Parsed package list for convenience; raw text stays authoritative.
    pub packages: Vec<PhpPackage>,
    /// `None` exactly when the SSH run completed (even if PHP is absent on
    /// the host — that is data, recorded verbatim, not an error).
    pub error: Option<String>,
}

/// Aggregate counts for one host-check run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HostCheckStats {
    pub total: usize,
    pub ok: usize,
    pub errors: usize,
    pub with_php: usize,
}

impl HostCheckStats {
    pub(crate) fn record(&mut self, record: &HostCheckRecord) {
        self.total += 1;
        if record.error.is_none() {
            self.ok += 1;
        } else {
            self.errors += 1;
        }
        if record.php_version.is_some() {
            self.with_php += 1;
        }
    }
}

/// One stderr summary line for a host-check run.
#[must_use]
pub fn format_summary(stats: &HostCheckStats) -> String {
    format!(
        "ftw: host-checked {} hosts: {} ok, {} errors; php present on {}",
        stats.total, stats.ok, stats.errors, stats.with_php,
    )
}

/// Failure to load or parse a host inventory file.
#[derive(Debug)]
pub enum InventoryError {
    Io(std::io::Error),
    Yaml(String),
    Entry(String),
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "cannot read host inventory file: {err}"),
            Self::Yaml(err) => write!(f, "invalid YAML host inventory file: {err}"),
            Self::Entry(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for InventoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Yaml(_) | Self::Entry(_) => None,
        }
    }
}

impl From<std::io::Error> for InventoryError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// On-disk shape: `{ hosts: [...] }` or a top-level sequence. Entries are
/// plain host strings (`host.example.com`, `192.0.2.5`) or `{ host, port? }`
/// maps. Any credential-looking key (`password`, `passphrase`, `secret`,
/// ...) is refused outright: this tool never accepts SSH credentials.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum InventoryDoc {
    Map { hosts: Vec<InventoryEntry> },
    Seq(Vec<InventoryEntry>),
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum InventoryEntry {
    Host(String),
    Detailed {
        host: String,
        #[allow(dead_code)]
        port: Option<u16>,
    },
}

/// Credential-looking YAML keys. Their presence in ANY entry is a hard
/// error — credentials are never accepted, let alone stored.
const FORBIDDEN_KEYS: &[&str] = &[
    "password",
    "passphrase",
    "pass",
    "secret",
    "private_key",
    "privatekey",
    "identity_file",
    "key",
];

/// Load, parse, and validate a host inventory file.
pub fn load_inventory(path: &Path) -> Result<Vec<String>, InventoryError> {
    let text = std::fs::read_to_string(path)?;
    parse_inventory(&text)
}

/// Parse and validate inventory YAML text.
pub fn parse_inventory(text: &str) -> Result<Vec<String>, InventoryError> {
    reject_forbidden_keys(text)?;
    let doc: InventoryDoc =
        serde_yml::from_str(text).map_err(|err| InventoryError::Yaml(err.to_string()))?;
    let entries = match doc {
        InventoryDoc::Map { hosts } => hosts,
        InventoryDoc::Seq(entries) => entries,
    };
    let mut hosts = Vec::with_capacity(entries.len());
    for entry in &entries {
        let host = match entry {
            InventoryEntry::Host(host) => host.clone(),
            InventoryEntry::Detailed { host, .. } => host.clone(),
        };
        let host = host.trim().to_owned();
        if host.is_empty() {
            return Err(InventoryError::Entry(
                "host inventory entry must not be empty".to_string(),
            ));
        }
        if host.contains(char::is_whitespace) || host.contains('@') || host.contains(':') {
            // `user@host`, embedded credentials/ports, and multi-word
            // entries are refused: the entry must be a bare hostname or IP.
            // (Bare IPv6 literals contain ':' — use their unbracketed form
            // only via scan targets, not here.)
            if host.parse::<SocketAddr>().is_err() && host.parse::<std::net::IpAddr>().is_ok() {
                hosts.push(host);
                continue;
            }
            return Err(InventoryError::Entry(format!(
                "invalid host entry {host:?}: use a bare hostname or IP (no user@, no embedded credentials)"
            )));
        }
        hosts.push(host);
    }
    hosts.sort();
    hosts.dedup();
    Ok(hosts)
}

/// Refuse credential-looking keys before deserialization drops them: scan
/// the raw mapping keys so a `password:` entry can never slip through as an
/// ignored field.
fn reject_forbidden_keys(text: &str) -> Result<(), InventoryError> {
    let value: serde_yml::Value =
        serde_yml::from_str(text).map_err(|err| InventoryError::Yaml(err.to_string()))?;
    let mut found = Vec::new();
    fn walk(value: &serde_yml::Value, found: &mut Vec<String>) {
        if let Some(map) = value.as_mapping() {
            for (key, val) in map {
                if FORBIDDEN_KEYS.iter().any(|bad| key.eq_ignore_ascii_case(bad)) {
                    found.push(key.clone());
                }
                walk(val, found);
            }
        } else if let Some(seq) = value.as_sequence() {
            for item in seq {
                walk(item, found);
            }
        }
    }
    walk(&value, &mut found);
    if found.is_empty() {
        Ok(())
    } else {
        found.sort();
        found.dedup();
        Err(InventoryError::Entry(format!(
            "host inventory must not contain credentials (found key(s): {}); \
             ftw host-check uses your existing SSH config and agent only",
            found.join(", ")
        )))
    }
}

/// Parse `major.minor.patch` out of `php -v` output: the token after `PHP`
/// on the first line starting with `PHP ` (for example
/// `PHP 8.2.10-2ubuntu1 (cli)` gives `8.2.10`).
#[must_use]
pub fn parse_php_version(output: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        let rest = line.strip_prefix("PHP ").unwrap_or(line);
        let token = rest.split_whitespace().next()?;
        let run: String = token
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let parts: Vec<&str> = run.split('.').collect();
        if parts.len() >= 2
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
        {
            return Some(run);
        }
    }
    None
}

/// Parse `name version` lines from the distro package query into pairs.
/// Lines without at least two tokens are skipped; the raw text stays the
/// authoritative record regardless.
#[must_use]
pub fn parse_packages(output: &str) -> Vec<PhpPackage> {
    let mut out = Vec::new();
    for line in output.lines() {
        let mut tokens = line.split_whitespace();
        if let (Some(name), Some(first)) = (tokens.next(), tokens.next()) {
            let mut version = first.to_owned();
            for rest in tokens {
                version.push(' ');
                version.push_str(rest);
            }
            out.push(PhpPackage {
                name: name.to_owned(),
                version,
            });
        }
    }
    out
}

/// Split one SSH run's stdout at the marker into `(php_raw, packages_raw)`.
fn split_remote_output(output: &str) -> (String, String) {
    match output.split_once(PACKAGES_MARKER) {
        Some((php, packages)) => (php.trim().to_owned(), packages.trim().to_owned()),
        None => (output.trim().to_owned(), String::new()),
    }
}

/// Check one host over SSH using the user's existing config and agent only:
/// `BatchMode=yes` disables every interactive credential prompt, and
/// `ConnectTimeout` bounds dialing; the whole run is additionally bounded by
/// the configured timeout.
async fn check_host(config: &HostCheckConfig, host: &str) -> HostCheckRecord {
    let connect_secs = config.timeout.as_secs().max(1).to_string();
    let run = async {
        tokio::process::Command::new("ssh")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg(format!("ConnectTimeout={connect_secs}"))
            .arg(host)
            .arg(REMOTE_COMMAND)
            .output()
            .await
    };
    let output = match tokio::time::timeout(config.timeout, run).await {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => {
            return HostCheckRecord {
                host: host.to_owned(),
                php_raw: String::new(),
                php_version: None,
                packages_raw: String::new(),
                packages: Vec::new(),
                error: Some(format!("ssh failed: {err}")),
            };
        }
        Err(_) => {
            return HostCheckRecord {
                host: host.to_owned(),
                php_raw: String::new(),
                php_version: None,
                packages_raw: String::new(),
                packages: Vec::new(),
                error: Some("timeout".to_string()),
            };
        }
    };
    if !output.status.success() {
        return HostCheckRecord {
            host: host.to_owned(),
            php_raw: String::new(),
            php_version: None,
            packages_raw: String::new(),
            packages: Vec::new(),
            error: Some(format!(
                "ssh exited with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )),
        };
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let (php_raw, packages_raw) = split_remote_output(&stdout);
    HostCheckRecord {
        host: host.to_owned(),
        php_version: parse_php_version(&php_raw),
        php_raw,
        packages: parse_packages(&packages_raw),
        packages_raw,
        error: None,
    }
}

/// Load one `ftw host-check` JSONL output file into the `host → summary`
/// map merged into probe records. Malformed lines name their line number.
pub fn summaries_from_jsonl(path: &Path) -> Result<HashMap<String, HostCheckSummary>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read host-check file {}: {err}", path.display()))?;
    let mut map = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: HostCheckRecord = serde_json::from_str(line).map_err(|err| {
            format!(
                "invalid host-check JSON on line {} of {}: {err}",
                index + 1,
                path.display()
            )
        })?;
        map.insert(
            record.host.clone(),
            HostCheckSummary {
                host: record.host,
                php_version: record.php_version,
                package_count: record.packages.len(),
            },
        );
    }
    Ok(map)
}

/// Check every inventory host, streaming one JSON record per host as it
/// arrives — the whole run is never buffered.
pub async fn run_with_options(
    config: &HostCheckConfig,
    inventory: Vec<String>,
    db_path: PathBuf,
    options: output::OutputOptions,
) -> Result<HostCheckStats, Box<dyn std::error::Error + Send + Sync>> {
    let conn = crate::db::open(&db_path)?;
    eprintln!("ftw: host-checking {} hosts", inventory.len());
    let (tx, rx) = mpsc::channel::<HostCheckRecord>(CHANNEL_CAPACITY);
    let writer =
        tokio::spawn(async move { output::run_host_check_db_writer(rx, conn, options).await });
    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
    for host in inventory {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("host-check semaphore never closes while checking");
        let tx = tx.clone();
        let config = *config;
        tokio::spawn(async move {
            let record = check_host(&config, &host).await;
            drop(permit);
            let _ = tx.send(record).await;
        });
    }
    drop(tx);
    let stats = writer.await??;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample Ubuntu `php -v` output: version parses, raw text untouched.
    const PHP_V_UBUNTU: &str = "PHP 8.2.10-2ubuntu1 (cli) (built: Aug 30 2024 16:55:15) ( NTS )\n\
        Copyright (c) The PHP Group\n\
        Zend Engine v4.2.10, Copyright (c) Zend Technologies\n";

    /// Sample Remi `php -v` output: same parser, different distro suffix.
    const PHP_V_REMI: &str = "PHP 8.1.27 (cli) (built: Dec 19 2023 20:35:55) ( NTS gcc x86_64 )\n\
        Copyright (c) The PHP Group\n";

    /// `php -v` when PHP is absent: no version, but the raw text is kept.
    const PHP_V_MISSING: &str = "sh: 1: php: not found\n";

    /// Sample `dpkg-query` output for installed PHP packages.
    const DPKG_PACKAGES: &str = "php8.2-cli 8.2.10-2ubuntu1\nphp8.2-common 8.2.10-2ubuntu1\n";

    /// Sample `rpm -qa` output for installed PHP packages.
    const RPM_PACKAGES: &str = "php-cli 8.1.27-1.el9.remi\nphp-common 8.1.27-1.el9.remi\n";

    #[test]
    fn parses_php_v_variants_verbatim() {
        assert_eq!(parse_php_version(PHP_V_UBUNTU), Some("8.2.10".to_string()));
        assert_eq!(parse_php_version(PHP_V_REMI), Some("8.1.27".to_string()));
        assert_eq!(parse_php_version(PHP_V_MISSING), None);
        assert_eq!(parse_php_version(""), None);
    }

    #[test]
    fn parses_dpkg_and_rpm_package_lines() {
        let dpkg = parse_packages(DPKG_PACKAGES);
        assert_eq!(dpkg.len(), 2);
        assert_eq!(dpkg[0].name, "php8.2-cli");
        assert_eq!(dpkg[0].version, "8.2.10-2ubuntu1");
        let rpm = parse_packages(RPM_PACKAGES);
        assert_eq!(rpm.len(), 2);
        assert_eq!(rpm[0].name, "php-cli");
        assert_eq!(rpm[0].version, "8.1.27-1.el9.remi");
        // Blank and single-token lines are skipped, never invented.
        assert!(parse_packages("\n   \nlone\n").is_empty());
    }

    #[test]
    fn splits_remote_output_at_marker() {
        let combined = format!("{PHP_V_UBUNTU}\n{PACKAGES_MARKER}\n{DPKG_PACKAGES}");
        let (php, packages) = split_remote_output(&combined);
        assert!(php.contains("PHP 8.2.10"), "php side keeps php -v: {php}");
        assert!(packages.contains("php8.2-cli"), "package side keeps dpkg: {packages}");
        let (php, packages) = split_remote_output("no marker here");
        assert_eq!(php, "no marker here");
        assert!(packages.is_empty());
    }

    #[test]
    fn inventory_parses_map_and_sequence_shapes() {
        let hosts = parse_inventory("hosts:\n  - web1.example.com\n  - 192.0.2.5\n")
            .expect("map shape");
        assert_eq!(hosts, vec!["192.0.2.5".to_string(), "web1.example.com".to_string()]);
        let hosts = parse_inventory("- web1.example.com\n- host: db1.example.com\n")
            .expect("sequence shape with detailed entry");
        assert_eq!(hosts, vec!["db1.example.com".to_string(), "web1.example.com".to_string()]);
        // Duplicates collapse.
        let hosts = parse_inventory("- a.example.com\n- a.example.com\n").expect("dedup");
        assert_eq!(hosts, vec!["a.example.com".to_string()]);
    }

    #[test]
    fn inventory_refuses_credentials_and_user_at_hosts() {
        let err = parse_inventory("hosts:\n  - host: web1.example.com\n    password: s3cret\n")
            .expect_err("password key must be refused");
        assert!(err.to_string().contains("credentials"), "names the reason: {err}");
        let err = parse_inventory("- deploy@web1.example.com\n")
            .expect_err("user@host must be refused");
        assert!(err.to_string().contains("user@"), "names the reason: {err}");
        assert!(parse_inventory("hosts:\n  - \"\"\n").is_err(), "empty host refused");
    }

    #[test]
    fn summaries_load_from_jsonl() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "ftw-hc-{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let record = HostCheckRecord {
            host: "web1.example.com".to_string(),
            php_raw: PHP_V_UBUNTU.to_string(),
            php_version: Some("8.2.10".to_string()),
            packages_raw: DPKG_PACKAGES.to_string(),
            packages: parse_packages(DPKG_PACKAGES),
            error: None,
        };
        std::fs::write(&path, format!("{}\n", serde_json::to_string(&record).unwrap()))
            .expect("write jsonl");
        let map = summaries_from_jsonl(&path).expect("load summaries");
        std::fs::remove_file(&path).ok();
        let summary = map.get("web1.example.com").expect("host present");
        assert_eq!(summary.php_version.as_deref(), Some("8.2.10"));
        assert_eq!(summary.package_count, 2);
    }

    #[test]
    fn summaries_reject_malformed_lines_naming_the_line() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "ftw-hc-bad-{}.jsonl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(
            &path,
            "{\"host\":\"a\",\"php_raw\":\"\",\"php_version\":null,\"packages_raw\":\"\",\"packages\":[],\"error\":null}\nnot json\n",
        )
        .expect("write jsonl");
        let err = summaries_from_jsonl(&path).expect_err("bad json must fail");
        assert!(err.contains("line 2"), "names the line: {err}");
        std::fs::remove_file(&path).ok();
    }
}
