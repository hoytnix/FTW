//! Offline site listing (`ftw list`) for authorized ranges only.
//!
//! A reporting command only: it reads the master SQLite database (`scan`,
//! `fingerprint`, `probe`, and `host-check` results) plus an optional
//! `ftw cve-check` JSONL file. It never sends HTTP requests, never runs SSH,
//! never probes ports, and never attempts any exploit test.
//!
//! Three overlapping lists, in this order:
//!
//! 1. Running PHP: the host is verified to run PHP by the same gate
//!    `ftw cve-check` uses (host-check PHP version, `X-Powered-By` with PHP,
//!    `Server` with PHP, a PHPSESSID cookie, `php_detected`, or a PHP app
//!    signal). Reused verbatim via [`crate::cve_check::assess`], never
//!    reimplemented here.
//! 2. Running a fingerprinted application: fingerprint reports
//!    `wordpress_detected` or a non-empty `php_apps` list, or probe reports a
//!    generator/meta signal naming a PHP application. Frontend CSS alone
//!    (including Tailwind) is never an application.
//! 3. PHP2Shell vulnerable: the CVE verdict is `vulnerable` for
//!    CVE-2026-109618 / CVE-2026-109619 — either from `--cve` verdicts or
//!    from [`crate::cve_check::assess`] against versions already stored in
//!    the database (fixed table 8.2.35, 8.3.36, 8.4.27, 8.5.12, reused, not
//!    forked). `unknown_assume_vulnerable` and `patched` are never listed.
//!
//! Categories overlap on purpose: a WordPress host on unpatched PHP belongs
//! in all three lists. Hosts are deduplicated by host/IP (one entry per list
//! at most); when both port 80 and 443 rows exist, the 443 record is
//! preferred for the displayed port, mirroring the fingerprint prefer-HTTPS
//! choice. Each list is sorted by host, then IP.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

/// Which site list(s) to show. `all` (the default) prints every list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ListType {
    /// Only the Running PHP list.
    Php,
    /// Only the Running a fingerprinted application list.
    App,
    /// Only the PHP2Shell vulnerable list.
    Vuln,
    /// All three lists in order (default).
    #[default]
    All,
}

impl ListType {
    /// CLI spelling of this list selector.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Php => "php",
            Self::App => "app",
            Self::Vuln => "vuln",
            Self::All => "all",
        }
    }

    /// True when an entry of `category` (`"php"`, `"app"`, or `"vuln"`)
    /// belongs in this filtered view.
    #[must_use]
    pub fn includes(self, category: &str) -> bool {
        match self {
            Self::All => true,
            Self::Php => category == "php",
            Self::App => category == "app",
            Self::Vuln => category == "vuln",
        }
    }
}

/// Output shape. `table` (the default) is human-readable sections plus a
/// summary; `json` streams one JSON object per list entry (JSONL, matching
/// the existing FTW JSONL convention: one object per line on stdout, or in
/// `--output` when given; the summary goes to stderr so stdout stays
/// parseable). Each JSON object carries `category` (`"php"`, `"app"`, or
/// `"vuln"`) plus `host`, `ip`, `port`, `scheme`, `php_version`,
/// `applications`, `cve_ids`, `verdict`, and `reason` (nulls where unknown;
/// `cve_ids` is empty and `verdict`/`reason` come from the same source as
/// the vulnerable list for that host).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ListFormat {
    /// Human-readable sections with counts, then a summary (default).
    #[default]
    Table,
    /// One JSON object per list entry (JSONL).
    Json,
}

impl ListFormat {
    /// CLI spelling of this output format.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Json => "json",
        }
    }
}

/// One entry in one list. A host in all three lists yields three entries
/// (one per category) so per-list counts match the table sections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SiteEntry {
    /// Which list this entry belongs to: `"php"`, `"app"`, or `"vuln"`.
    pub category: String,
    /// Display host: a hostname label when one was seen, else the IP.
    pub host: String,
    /// The IP address when one is known.
    pub ip: Option<String>,
    /// The preferred port (443 preferred, mirroring prefer-HTTPS).
    pub port: Option<u16>,
    /// The scheme of the preferred record (`"http"`/`"https"`).
    pub scheme: Option<String>,
    /// Raw PHP version as stored (host-check wins over remote headers),
    /// never invented; `None` when no version is known.
    pub php_version: Option<String>,
    /// Application display names (`WordPress`, `Joomla`, ...), sorted.
    pub applications: Vec<String>,
    /// CVE ids for this host (empty when PHP is not verified).
    pub cve_ids: Vec<String>,
    /// CVE verdict from the same source as the vulnerable list.
    pub verdict: String,
    /// Human-readable reason for the verdict.
    pub reason: String,
}

/// The full offline report: three overlapping lists plus the distinct-host
/// total (hosts seen across fingerprint, probe, and host-check tables).
#[derive(Debug, Default)]
pub struct SiteReport {
    /// Every site in the Running PHP list, sorted by host, then IP.
    pub php: Vec<SiteEntry>,
    /// Every site in the application list, sorted by host, then IP.
    pub app: Vec<SiteEntry>,
    /// Every site in the PHP2Shell vulnerable list, sorted by host, then IP.
    pub vuln: Vec<SiteEntry>,
    /// Distinct hosts seen across all three tables (counted once each even
    /// when they appear in several lists).
    pub distinct_hosts: usize,
}

/// A `--cve` file verdict for one host: it replaces the database assessment
/// for the vulnerable list (and for the entry's verdict fields) wherever the
/// file names the host. Hosts missing from the file are never listed as
/// vulnerable.
#[derive(Debug, Clone)]
pub struct CveOverride {
    pub verdict: String,
    pub reason: String,
    pub cve_ids: Vec<String>,
}

/// Display name for a probe stack hint, if it names a fingerprinted PHP
/// application. `php` alone is not an application, and neither are non-PHP
/// stacks (`ghost`, `shopify`, `generic-theme`, ...) or frontend CSS
/// (Tailwind): they return `None` here, matching the cve-check PHP gate
/// minus the generic `php`.
fn display_app(stack: &str) -> Option<&'static str> {
    match stack {
        "wordpress" => Some("WordPress"),
        "drupal" => Some("Drupal"),
        "joomla" => Some("Joomla"),
        "magento" => Some("Magento"),
        "phpbb" => Some("phpBB"),
        "mediawiki" => Some("MediaWiki"),
        "prestashop" => Some("PrestaShop"),
        "opencart" => Some("OpenCart"),
        "moodle" => Some("Moodle"),
        _ => None,
    }
}

/// Canonical merge key for one host/IP label: trimmed and lowercased
/// (hostnames are case-insensitive; IP text is unaffected). `None` for
/// blank labels, which contribute no site.
pub(crate) fn site_key(label: &str) -> Option<String> {
    let key = label.trim().to_lowercase();
    if key.is_empty() { None } else { Some(key) }
}

/// True when the label parses as an IP address (a host identity, not a
/// display hostname).
fn is_ip(label: &str) -> bool {
    label.parse::<std::net::IpAddr>().is_ok()
}

/// Per-site accumulation across the three tables before assessment.
#[derive(Default)]
struct SiteBits<'a> {
    fingerprint: Vec<&'a crate::db::ListFingerprintRow>,
    probe: Vec<&'a crate::probe::ProbeRecord>,
    host_check: Option<&'a crate::db::ListHostCheckRow>,
    ip_hint: Option<String>,
    name_hint: Option<String>,
}

impl<'a> SiteBits<'a> {
    fn note_label(&mut self, label: &str) {
        if is_ip(label) {
            self.ip_hint.get_or_insert_with(|| label.to_string());
        } else {
            self.name_hint.get_or_insert_with(|| label.to_string());
        }
    }
}

/// Build the full report from already-read database rows. `overrides` is
/// the parsed `--cve` file (`None` means no file: the database assessment
/// decides the vulnerable list). Pure offline grouping and formatting — no
/// I/O beyond the rows handed in.
#[must_use]
pub fn build_report(
    fingerprint: &[crate::db::ListFingerprintRow],
    probe: &[crate::probe::ProbeRecord],
    host_checks: &[crate::db::ListHostCheckRow],
    overrides: Option<&HashMap<String, CveOverride>>,
) -> SiteReport {
    let mut sites: BTreeMap<String, SiteBits<'_>> = BTreeMap::new();
    for row in fingerprint {
        let Some(key) = site_key(&row.ip) else { continue };
        let bits = sites.entry(key).or_default();
        bits.ip_hint.get_or_insert_with(|| row.ip.clone());
        bits.fingerprint.push(row);
    }
    for record in probe {
        let Some(key) = site_key(&record.host) else { continue };
        let bits = sites.entry(key).or_default();
        bits.note_label(&record.host);
        bits.probe.push(record);
    }
    for row in host_checks {
        let Some(key) = site_key(&row.host) else { continue };
        let bits = sites.entry(key).or_default();
        bits.note_label(&row.host);
        bits.host_check.get_or_insert(row);
    }

    let mut report = SiteReport {
        distinct_hosts: sites.len(),
        ..SiteReport::default()
    };
    for (key, bits) in &sites {
        let Some(assessed) = assess_site(key, bits) else { continue };
        let (verdict, reason, cve_ids) = match overrides.and_then(|map| map.get(key)) {
            Some(file) => (file.verdict.clone(), file.reason.clone(), file.cve_ids.clone()),
            None => (
                assessed.cve.verdict.clone(),
                assessed.cve.reason.clone(),
                assessed.cve.cve_ids.clone(),
            ),
        };
        let mut entry = SiteEntry {
            category: String::new(),
            host: assessed.host,
            ip: assessed.ip,
            port: assessed.port,
            scheme: assessed.scheme,
            php_version: assessed.cve.version_raw.clone(),
            applications: assessed.applications,
            cve_ids,
            verdict: verdict.clone(),
            reason,
        };
        if assessed.cve.verified_php {
            entry.category = "php".to_string();
            report.php.push(entry.clone());
        }
        if assessed.is_app {
            entry.category = "app".to_string();
            report.app.push(entry.clone());
        }
        let vuln_member = match overrides {
            // With `--cve`, the file is the authority: a host it does not
            // name has no CVE data and is never listed as vulnerable.
            Some(map) => map.get(key).is_some_and(|file| file.verdict == "vulnerable"),
            None => verdict == "vulnerable",
        };
        if vuln_member {
            entry.category = "vuln".to_string();
            report.vuln.push(entry);
        }
    }
    for entries in [&mut report.php, &mut report.app, &mut report.vuln] {
        entries.sort_by(|a, b| {
            (a.host.to_lowercase(), a.ip.clone().unwrap_or_default())
                .cmp(&(b.host.to_lowercase(), b.ip.clone().unwrap_or_default()))
        });
    }
    report
}

/// Assessed facts for one site: the shared base behind all three entries.
struct AssessedSite {
    host: String,
    ip: Option<String>,
    port: Option<u16>,
    scheme: Option<String>,
    applications: Vec<String>,
    is_app: bool,
    cve: crate::cve_check::CveRecord,
}

/// Group one site's rows into cve-check JSONL shapes (the exact shapes its
/// gate ingests), assess them with the shared verdict logic, and derive the
/// display facts. Returns `None` when the site has no assessable rows.
fn assess_site(key: &str, bits: &SiteBits<'_>) -> Option<AssessedSite> {
    let mut values = Vec::new();
    for row in &bits.fingerprint {
        values.push(serde_json::json!({
            "ip": key,
            "port": row.port,
            "scheme": row.scheme,
            "server": row.server,
            "php_detected": row.php_detected,
            "php_version": row.php_version,
            "php_signals": row.php_signals,
            "wordpress_detected": row.wordpress_detected,
            "wordpress_version": row.wordpress_version,
            "wordpress_signals": row.wordpress_signals,
            "php_apps": row.php_apps,
        }));
    }
    for record in &bits.probe {
        let mut value = serde_json::to_value(*record).unwrap_or(serde_json::Value::Null);
        if let Some(object) = value.as_object_mut() {
            object.insert("host".to_string(), serde_json::json!(key));
        }
        values.push(value);
    }
    if let Some(row) = bits.host_check {
        values.push(serde_json::json!({
            "host": key,
            "php_raw": row.php_raw,
            "php_version": row.php_version,
            "packages_raw": row.packages_raw,
            "packages": [],
            "error": null,
        }));
    }
    if values.is_empty() {
        return None;
    }
    let (records, _) = crate::cve_check::assess(values);
    let cve = records.into_iter().next()?;

    let mut applications: Vec<String> = Vec::new();
    let mut is_app = false;
    for row in &bits.fingerprint {
        if row.wordpress_detected {
            is_app = true;
            if !applications.iter().any(|name| name == "WordPress") {
                applications.push("WordPress".to_string());
            }
        }
        for app in &row.php_apps {
            is_app = true;
            if !applications.iter().any(|name| name == &app.name) {
                applications.push(app.name.clone());
            }
        }
    }
    for record in &bits.probe {
        if let Some(stack) = record.stack_hint.as_deref() {
            if let Some(name) = display_app(stack) {
                is_app = true;
                if !applications.iter().any(|existing| existing == name) {
                    applications.push(name.to_string());
                }
            }
        }
        for text in [&record.generator, &record.x_generator].into_iter().flatten() {
            if let Some(stack) = crate::probe::stack_from_text(text) {
                if let Some(name) = display_app(stack) {
                    is_app = true;
                    if !applications.iter().any(|existing| existing == name) {
                        applications.push(name.to_string());
                    }
                }
            }
        }
    }
    applications.sort_unstable();

    // Preferred display port: 443 first (mirroring prefer-HTTPS), rows with
    // an HTTP status before transport errors, then the lowest port.
    let mut candidates: Vec<(u16, String, bool)> = Vec::new();
    for row in &bits.fingerprint {
        candidates.push((row.port, row.scheme.clone(), row.has_status));
    }
    for record in &bits.probe {
        candidates.push((record.port, record.scheme.clone(), record.status.is_some()));
    }
    candidates.sort_by_key(|candidate| (!candidate.2, candidate.0 != 443, candidate.0));
    let (port, scheme) = candidates
        .first()
        .map(|(port, scheme, _)| (Some(*port), Some(scheme.clone())))
        .unwrap_or((None, None));

    // Display host prefers a hostname label; the IP is shown separately.
    let mut ip = bits.ip_hint.clone();
    if ip.is_none() {
        ip = cve.ip.clone().filter(|label| is_ip(label));
    }
    let host = bits
        .name_hint
        .clone()
        .or_else(|| ip.clone())
        .unwrap_or_else(|| key.to_string());

    Some(AssessedSite {
        host,
        ip,
        port,
        scheme,
        applications,
        is_app,
        cve,
    })
}

/// One table line per entry: `key=value` tokens, one host per line, so the
/// report stays parseable. Vulnerable entries also carry the CVE ids and the
/// verdict reason.
fn format_entry(entry: &SiteEntry) -> String {
    let mut line = format!(
        "host={} ip={} port={} scheme={} php={} apps={}",
        entry.host,
        entry.ip.as_deref().unwrap_or("-"),
        entry
            .port
            .map(|port| port.to_string())
            .unwrap_or_else(|| "-".to_string()),
        entry.scheme.as_deref().unwrap_or("-"),
        entry.php_version.as_deref().unwrap_or("-"),
        if entry.applications.is_empty() {
            "-".to_string()
        } else {
            entry.applications.join(",")
        },
    );
    if entry.category == "vuln" {
        line.push_str(&format!(
            " cve_ids={} reason={}",
            if entry.cve_ids.is_empty() {
                "-".to_string()
            } else {
                entry.cve_ids.join(",")
            },
            entry.reason,
        ));
    }
    line
}

/// Human-readable report: three clearly headed sections in order (PHP,
/// application, PHP2Shell vulnerable), each with its count, then the
/// summary. Only the lists selected by `filter` print; the summary always
/// covers all three lists.
#[must_use]
pub fn format_table(report: &SiteReport, db_label: &str, filter: ListType) -> String {
    let mut out = format!("ftw: site list from {db_label} (offline, no requests sent)\n");
    let sections = [
        ("php", "Running PHP", &report.php),
        ("app", "Running a fingerprinted application", &report.app),
        ("vuln", "PHP2Shell vulnerable", &report.vuln),
    ];
    for (category, title, entries) in sections {
        if !filter.includes(category) {
            continue;
        }
        out.push_str(&format!("## {title} ({})\n", entries.len()));
        if entries.is_empty() {
            out.push_str("(none)\n");
        } else {
            for entry in entries {
                out.push_str(&format!("{}\n", format_entry(entry)));
            }
        }
    }
    out.push_str("## Summary\n");
    out.push_str(&format_summary(report));
    out
}

/// Shared count line: distinct-host total plus each list count. Lists
/// overlap, so the counts can sum to more than the distinct-host total.
#[must_use]
pub fn summary_counts(report: &SiteReport) -> String {
    format!(
        "distinct_hosts={} php={} app={} vuln={}",
        report.distinct_hosts,
        report.php.len(),
        report.app.len(),
        report.vuln.len(),
    )
}

/// Table tail (and the `--format json` stderr summary source): the count
/// line plus the overlap note.
#[must_use]
pub fn format_summary(report: &SiteReport) -> String {
    format!(
        "{}\nnote: lists overlap; counts can sum to more than distinct hosts\n",
        summary_counts(report),
    )
}

/// JSONL lines for the filtered view: one JSON object per list entry, in
/// report order (PHP section, then application, then vulnerable).
#[must_use]
pub fn format_json_lines(report: &SiteReport, filter: ListType) -> Vec<String> {
    let mut lines = Vec::new();
    for entries in [&report.php, &report.app, &report.vuln] {
        for entry in entries {
            if !filter.includes(&entry.category) {
                continue;
            }
            lines.push(serde_json::to_string(entry).unwrap_or_else(|_| "{}".to_string()));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn temp_db(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("ftw-listtest-{tag}-{nanos}-{}.db", std::process::id()))
    }

    fn cleanup(path: &std::path::Path) {
        std::fs::remove_file(path).ok();
        std::fs::remove_file(path.with_extension("db-wal")).ok();
        std::fs::remove_file(path.with_extension("db-shm")).ok();
    }

    #[allow(clippy::too_many_arguments)]
    fn fp_record(
        ip: &str,
        port: u16,
        scheme: &str,
        server: Option<&str>,
        php_detected: bool,
        php_version: Option<&str>,
        signals: &[&str],
        wordpress: bool,
        apps: &[&str],
    ) -> crate::fingerprint::FingerprintRecord {
        crate::fingerprint::FingerprintRecord {
            ip: ip.to_string(),
            port,
            scheme: scheme.to_string(),
            final_url: format!("{scheme}://{ip}:{port}/"),
            status: Some(200),
            server: server.map(str::to_owned),
            tls: if scheme == "https" { "ok".to_string() } else { "n/a".to_string() },
            error: None,
            php_detected,
            php_version: php_version.map(str::to_owned),
            php_signals: signals.iter().map(|signal| signal.to_string()).collect(),
            wordpress_detected: wordpress,
            wordpress_version: None,
            wordpress_signals: if wordpress {
                vec!["generator".to_string()]
            } else {
                Vec::new()
            },
            php_apps: apps
                .iter()
                .map(|name| crate::tech::PhpApp {
                    name: name.to_string(),
                    version: None,
                    signals: vec!["generator".to_string()],
                })
                .collect(),
            tailwind_detected: false,
            tailwind_confidence: "none".to_string(),
            tailwind_signals: Vec::new(),
            fetch_method: "get".to_string(),
            head_status: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn probe_record(
        host: &str,
        port: u16,
        server: Option<&str>,
        stack: Option<&str>,
        generator: Option<&str>,
    ) -> crate::probe::ProbeRecord {
        crate::probe::ProbeRecord {
            host: host.to_string(),
            port,
            scheme: if port == 443 { "https".to_string() } else { "http".to_string() },
            status: Some(200),
            final_url: format!("http://{host}:{port}/"),
            server: server.map(str::to_owned),
            cookie_names: Vec::new(),
            x_generator: None,
            via: None,
            generator: generator.map(str::to_owned),
            title: None,
            asset_hints: Vec::new(),
            tls_cn: None,
            tls_san: Vec::new(),
            tls_issuer: None,
            tls_not_after: None,
            favicon_sha256: None,
            robots_present: false,
            robots_status: None,
            robots_snippet: String::new(),
            robots_truncated: false,
            sitemap_present: false,
            sitemap_status: None,
            sitemap_snippet: String::new(),
            sitemap_truncated: false,
            confidence: "low".to_string(),
            confidence_signals: vec!["generator-meta".to_string()],
            stack_hint: stack.map(str::to_owned),
            remote_version_hint: None,
            patch_status: crate::probe::PATCH_UNKNOWN_FROM_REMOTE.to_string(),
            host_check: None,
            error: None,
        }
    }

    fn hc_record(
        host: &str,
        php_version: Option<&str>,
        php_raw: &str,
        packages: &[(&str, &str)],
    ) -> crate::host_check::HostCheckRecord {
        crate::host_check::HostCheckRecord {
            host: host.to_string(),
            php_raw: php_raw.to_string(),
            php_version: php_version.map(str::to_owned),
            packages_raw: packages
                .iter()
                .map(|(name, version)| format!("{name} {version}"))
                .collect::<Vec<_>>()
                .join("\n"),
            packages: packages
                .iter()
                .map(|(name, version)| crate::host_check::PhpPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                })
                .collect(),
            error: None,
        }
    }

    /// Seed the nine-host fixture: PHP only, app+PHP patched, vuln+PHP,
    /// all three, none, 80+443 dedup, host-check only, unknown-version app,
    /// and a probe-only WordPress host.
    fn seed_fixture(conn: &rusqlite::Connection) {
        let fps = [
            // 10.9.0.1: PHP only (8.3.36 is exactly the fixed version).
            fp_record("10.9.0.1", 443, "https", Some("nginx/1.24.0"), true, Some("8.3.36"), &["x-powered-by"], false, &[]),
            // 10.9.0.2: app + PHP, patched (8.4.27 is exactly fixed).
            fp_record("10.9.0.2", 443, "https", Some("Apache/2.4.58"), true, Some("8.4.27"), &["x-powered-by"], true, &[]),
            // 10.9.0.3: vuln + PHP, no app (8.2.10 below fixed 8.2.35).
            fp_record("10.9.0.3", 443, "https", Some("nginx/1.24.0"), true, Some("8.2.10"), &["x-powered-by"], false, &[]),
            // 10.9.0.4: all three (WordPress + Joomla on unpatched PHP).
            fp_record("10.9.0.4", 443, "https", Some("Apache/2.4.58"), true, Some("8.2.10"), &["x-powered-by"], true, &["Joomla"]),
            // 10.9.0.5: none of the three (plain static server).
            fp_record("10.9.0.5", 80, "http", Some("nginx/1.24.0"), false, None, &[], false, &[]),
            // 10.9.0.6: same signals on 80 and 443 (dedups to one entry).
            fp_record("10.9.0.6", 80, "http", Some("Apache/2.4.58"), true, Some("8.2.10"), &["x-powered-by"], true, &[]),
            fp_record("10.9.0.6", 443, "https", Some("Apache/2.4.58"), true, Some("8.2.10"), &["x-powered-by"], true, &[]),
            // 10.9.0.8: WordPress without any PHP version (unknown, not vuln).
            fp_record("10.9.0.8", 80, "http", Some("Apache/2.4.58"), false, None, &[], true, &[]),
        ];
        for record in &fps {
            db::upsert_fingerprint(conn, record).expect("seed fingerprint row");
        }
        // 10.9.0.7: host-check only (no fingerprint or probe rows at all).
        db::upsert_host_check(
            conn,
            &hc_record(
                "10.9.0.7",
                Some("8.2.10"),
                "PHP 8.2.10 (cli) (built: Aug 30 2024) ( NTS )",
                &[("php8.2-cli", "8.2.10-2ubuntu1")],
            ),
        )
        .expect("seed host-check row");
        // 10.9.0.9: probe only, WordPress via generator meta, no version.
        db::upsert_probe(
            conn,
            &probe_record("10.9.0.9", 80, Some("nginx/1.24.0"), Some("wordpress"), Some("WordPress 6.5")),
        )
        .expect("seed probe row");
    }

    fn fixture_report() -> (SiteReport, std::path::PathBuf) {
        let path = temp_db("fixture");
        let conn = db::open(&path).expect("open fixture db");
        seed_fixture(&conn);
        let fingerprint = db::read_fingerprint_rows(&conn).expect("read fingerprint");
        let probe = db::read_probe_records(&conn).expect("read probe");
        let host_checks = db::read_host_check_rows(&conn).expect("read host-check");
        let report = build_report(&fingerprint, &probe, &host_checks, None);
        (report, path)
    }

    fn hosts(entries: &[SiteEntry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.host.as_str()).collect()
    }

    #[test]
    fn categories_overlap_with_correct_counts() {
        let (report, path) = fixture_report();
        assert_eq!(report.distinct_hosts, 9);
        assert_eq!(
            hosts(&report.php),
            vec!["10.9.0.1", "10.9.0.2", "10.9.0.3", "10.9.0.4", "10.9.0.6", "10.9.0.7", "10.9.0.8", "10.9.0.9"],
            "PHP list: every verified host except the static one"
        );
        assert_eq!(
            hosts(&report.app),
            vec!["10.9.0.2", "10.9.0.4", "10.9.0.6", "10.9.0.8", "10.9.0.9"],
            "app list: WordPress / Joomla / probe-generator hosts only"
        );
        assert_eq!(
            hosts(&report.vuln),
            vec!["10.9.0.3", "10.9.0.4", "10.9.0.6", "10.9.0.7"],
            "vuln list: only verdict=vulnerable hosts"
        );
        for entries in [&report.php, &report.app, &report.vuln] {
            assert!(
                entries.iter().any(|entry| entry.host == "10.9.0.4"),
                "10.9.0.4 must be in every list"
            );
        }
        cleanup(&path);
    }

    #[test]
    fn dedup_prefers_443_and_lists_each_host_once() {
        let (report, path) = fixture_report();
        for entries in [&report.php, &report.app, &report.vuln] {
            assert_eq!(
                entries.iter().filter(|entry| entry.host == "10.9.0.6").count(),
                1,
                "10.9.0.6 must appear exactly once per list"
            );
        }
        let entry = report
            .php
            .iter()
            .find(|entry| entry.host == "10.9.0.6")
            .expect("deduped host present");
        assert_eq!(entry.port, Some(443), "preferred port is the 443 record");
        assert_eq!(entry.scheme.as_deref(), Some("https"));
        assert_eq!(entry.php_version.as_deref(), Some("8.2.10"), "raw version preserved");
        assert_eq!(entry.applications, vec!["WordPress".to_string()]);
        cleanup(&path);
    }

    #[test]
    fn vuln_entries_carry_cve_ids_and_reason_but_unknown_and_patched_do_not_list() {
        let (report, path) = fixture_report();
        for entry in &report.vuln {
            assert_eq!(entry.category, "vuln");
            assert_eq!(
                entry.cve_ids,
                vec!["CVE-2026-109618".to_string(), "CVE-2026-109619".to_string()]
            );
            assert_eq!(entry.verdict, "vulnerable");
            assert!(!entry.reason.is_empty(), "vuln entries name the reason");
        }
        for host in ["10.9.0.1", "10.9.0.2", "10.9.0.8", "10.9.0.9"] {
            assert!(
                report.vuln.iter().all(|entry| entry.host != host),
                "{host} must not be in the vuln list"
            );
            assert!(
                report.php.iter().any(|entry| entry.host == host),
                "{host} stays in the PHP list"
            );
        }
        cleanup(&path);
    }

    #[test]
    fn host_check_only_host_has_no_port_but_keeps_version_and_verdict() {
        let (report, path) = fixture_report();
        let entry = report
            .vuln
            .iter()
            .find(|entry| entry.host == "10.9.0.7")
            .expect("host-check-only host is vulnerable");
        assert_eq!(entry.port, None, "no fingerprint/probe row means no port");
        assert_eq!(entry.php_version.as_deref(), Some("8.2.10"));
        assert!(entry.applications.is_empty());
        assert!(entry.reason.contains("8.2.10"), "reason names the version: {}", entry.reason);
        cleanup(&path);
    }

    #[test]
    fn cve_overrides_replace_the_vuln_list_only() {
        let path = temp_db("overrides");
        let conn = db::open(&path).expect("open fixture db");
        seed_fixture(&conn);
        let fingerprint = db::read_fingerprint_rows(&conn).expect("read fingerprint");
        let probe = db::read_probe_records(&conn).expect("read probe");
        let host_checks = db::read_host_check_rows(&conn).expect("read host-check");
        let mut overrides = HashMap::new();
        overrides.insert(
            "10.9.0.3".to_string(),
            CveOverride {
                verdict: "patched".to_string(),
                reason: "8.2.35 >= fixed 8.2.35".to_string(),
                cve_ids: vec!["CVE-2026-109618".to_string(), "CVE-2026-109619".to_string()],
            },
        );
        overrides.insert(
            "10.9.0.5".to_string(),
            CveOverride {
                verdict: "vulnerable".to_string(),
                reason: "file says so".to_string(),
                cve_ids: vec!["CVE-2026-109618".to_string()],
            },
        );
        let report = build_report(&fingerprint, &probe, &host_checks, Some(&overrides));
        assert!(
            report.vuln.iter().all(|entry| entry.host != "10.9.0.3"),
            "file-patched host leaves the vuln list"
        );
        let entry = report
            .vuln
            .iter()
            .find(|entry| entry.host == "10.9.0.5")
            .expect("file-vulnerable host joins the vuln list");
        assert_eq!(entry.cve_ids, vec!["CVE-2026-109618".to_string()]);
        assert_eq!(entry.reason, "file says so");
        assert_eq!(report.php.len(), 8);
        assert_eq!(report.app.len(), 5);
        assert_eq!(report.distinct_hosts, 9);
        cleanup(&path);
    }

    #[test]
    fn vendor_backport_proof_from_the_database_patches() {
        let path = temp_db("backport");
        let conn = db::open(&path).expect("open fixture db");
        let fp = fp_record("10.9.0.20", 443, "https", Some("Apache/2.4.41 (Ubuntu)"), true, Some("8.2.10"), &["x-powered-by"], false, &[]);
        db::upsert_fingerprint(&conn, &fp).expect("seed fingerprint");
        db::upsert_host_check(
            &conn,
            &hc_record(
                "10.9.0.20",
                Some("8.2.10"),
                "PHP 8.2.10-1ubuntu1 (apache2handler) (built: ...)",
                &[("php8.2", "8.2.10-1ubuntu1 CVE-2026-109618 fixed")],
            ),
        )
        .expect("seed host-check");
        let fingerprint = db::read_fingerprint_rows(&conn).expect("read fingerprint");
        let probe = db::read_probe_records(&conn).expect("read probe");
        let host_checks = db::read_host_check_rows(&conn).expect("read host-check");
        let report = build_report(&fingerprint, &probe, &host_checks, None);
        assert_eq!(hosts(&report.php), vec!["10.9.0.20"], "host-check version verifies PHP");
        assert!(report.vuln.is_empty(), "backport proof patches the host");
        cleanup(&path);
    }

    #[test]
    fn table_sections_keep_order_counts_and_summary() {
        let (report, path) = fixture_report();
        let text = format_table(&report, "ftw.db", ListType::All);
        let php_at = text.find("## Running PHP (8)").expect("PHP section with count");
        let app_at = text.find("## Running a fingerprinted application (5)").expect("app section with count");
        let vuln_at = text.find("## PHP2Shell vulnerable (4)").expect("vuln section with count");
        let summary_at = text.find("## Summary").expect("summary section");
        assert!(php_at < app_at && app_at < vuln_at && vuln_at < summary_at, "sections print in order:\n{text}");
        assert!(text.contains("distinct_hosts=9 php=8 app=5 vuln=4"), "summary counts:\n{text}");
        assert!(text.contains("lists overlap"), "overlap note:\n{text}");
        assert_eq!(text.matches("host=10.9.0.6 ").count(), 3, "deduped host prints once per section");
        assert_eq!(text.matches("host=10.9.0.4 ").count(), 3, "overlap host prints in all three sections");
        assert!(text.contains("cve_ids=CVE-2026-109618,CVE-2026-109619"), "vuln lines carry CVE ids");
        cleanup(&path);
    }

    #[test]
    fn type_filter_shows_only_that_section() {
        let (report, path) = fixture_report();
        for (filter, want, drop) in [
            (ListType::Php, "## Running PHP", "## Running a fingerprinted application"),
            (ListType::App, "## Running a fingerprinted application", "## PHP2Shell vulnerable"),
            (ListType::Vuln, "## PHP2Shell vulnerable", "## Running PHP"),
        ] {
            let text = format_table(&report, "ftw.db", filter);
            assert!(text.contains(want), "{want} present for {filter:?}");
            assert!(!text.contains(drop), "{drop} hidden for {filter:?}");
            assert!(text.contains("distinct_hosts=9"), "summary stays global for {filter:?}");
        }
        cleanup(&path);
    }

    #[test]
    fn json_lines_parse_and_match_the_table() {
        let (report, path) = fixture_report();
        let lines = format_json_lines(&report, ListType::All);
        assert_eq!(lines.len(), 8 + 5 + 4, "one line per list entry");
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut seen = std::collections::HashSet::new();
        for line in &lines {
            let value: serde_json::Value = serde_json::from_str(line).expect("JSONL parses");
            for key in ["category", "host", "ip", "port", "scheme", "php_version", "applications", "cve_ids", "verdict", "reason"] {
                assert!(value.get(key).is_some(), "entry carries {key}: {line}");
            }
            let category = value["category"].as_str().expect("category string");
            *counts.entry(category.to_string()).or_insert(0) += 1;
            seen.insert(format!("{category}:{}", value["host"].as_str().unwrap_or_default()));
        }
        assert_eq!(counts.get("php"), Some(&8));
        assert_eq!(counts.get("app"), Some(&5));
        assert_eq!(counts.get("vuln"), Some(&4));
        let text = format_table(&report, "ftw.db", ListType::All);
        for key in &seen {
            let (category, host) = key.split_once(':').expect("split key");
            let section = match category {
                "php" => "## Running PHP",
                "app" => "## Running a fingerprinted application",
                _ => "## PHP2Shell vulnerable",
            };
            let start = text.find(section).expect("section present");
            let rest = &text[start..];
            let end = rest[section.len()..].find("## ").map(|at| at + section.len());
            let section_text = end.map(|at| &rest[..at]).unwrap_or(rest);
            assert!(section_text.contains(&format!("host={host} ")), "{host} in the {category} table section");
        }
        let php_only = format_json_lines(&report, ListType::Php);
        assert_eq!(php_only.len(), 8);
        assert!(php_only.iter().all(|line| line.contains("\"category\":\"php\"")));
        cleanup(&path);
    }
}
