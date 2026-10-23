//! Remote-first PHP2Shell CVE assessment (`ftw cve-check`).
//!
//! Pure offline assessment of existing JSONL output files for authorized
//! ranges only: `ftw fingerprint` and/or `ftw probe` records plus optional
//! `ftw host-check` records. Sends no requests, runs no exploits, never
//! probes for phpinfo — version comparison only.
//!
//! The CVE rule lives in [`CVE_RULES`] as data so future CVEs can be added
//! without rewriting the checker.
//!
//! Schema adaptation (read from the actual writers, never invented):
//! - fingerprint lines carry `ip`, `server`, `php_detected`, `php_version`
//!   (strict `PHP/x.y.z` from X-Powered-By), `php_signals` (`x-powered-by`,
//!   `server`, `phpsessid-cookie`), `wordpress_detected`, and `php_apps`
//!   (`[{name, version, signals}]`). Tailwind signals never verify PHP.
//! - probe lines carry `host`, `server`, `cookie_names`, `remote_version_hint`
//!   (first raw X-Powered-By / Server / generator value with a version-like
//!   token), `confidence_signals` (channel names incl. `x-powered-by`), and
//!   `stack_hint` (`wordpress`, `php`, ...; `ghost`, `shopify`, and generic
//!   themes are NOT PHP). An inline `host_check` summary
//!   (`{host, php_version, package_count}`) counts as host-check evidence
//!   without backport proof (no package list).
//! - host-check lines carry `host`, `php_version`, verbatim `php_raw` (whose
//!   `(sapi)` token is authoritative), and `packages_raw` (a CVE id named
//!   there counts as vendor-backport proof).
//!
//! `ftw probe --host-check` merges host-check summaries into probe rows, so
//! probe-only input already carries host-check versions where they exist;
//! a separate `--host-check` file adds package lists (backport proof) and
//! authoritative SAPI.

use std::collections::HashMap;

use serde::Serialize;

/// One assessable CVE rule: the only rule in this improvement is PHP2Shell
/// (unauthenticated RCE in PHP itself), fixed per branch. Future CVEs append
/// here; the checker below does not change.
pub struct CveRule {
    /// Short rule name for humans.
    pub name: &'static str,
    /// CVE ids evaluated by this rule (also the backport-proof search keys).
    pub ids: &'static [&'static str],
    /// `(major, minor, fixed_patch)` per affected branch.
    pub fixed: &'static [(u64, u64, u64)],
}

pub static CVE_RULES: &[CveRule] = &[CveRule {
    name: "PHP2Shell",
    ids: &["CVE-2026-109618", "CVE-2026-109619"],
    fixed: &[(8, 2, 35), (8, 3, 36), (8, 4, 27), (8, 5, 12)],
}];

/// Stack votes that verify PHP. Anything else (`ghost`, `shopify`,
/// `generic-theme`, Tailwind, a JS framework, a static site) does NOT.
const PHP_STACKS: &[&str] = &[
    "wordpress",
    "drupal",
    "joomla",
    "magento",
    "phpbb",
    "mediawiki",
    "prestashop",
    "opencart",
    "moodle",
    "php",
];

/// A parsed PHP version token: base semver plus any distro suffix kept in
/// its own field (`8.2.10-2ubuntu1` → base `8.2.10`, suffix `-2ubuntu1`).
/// Minor and patch may be absent (`PHP/8.2`, `PHP/8`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVersion {
    pub major: u64,
    pub minor: Option<u64>,
    pub patch: Option<u64>,
    pub suffix: String,
}

impl ParsedVersion {
    fn display_base(&self) -> String {
        match (self.minor, self.patch) {
            (Some(minor), Some(patch)) => format!("{}.{}.{}", self.major, minor, patch),
            (Some(minor), None) => format!("{}.{}", self.major, minor),
            _ => self.major.to_string(),
        }
    }
}

/// Find a `PHP/x.y[.z][suffix]` token in free text (X-Powered-By value,
/// Server header, remote version hint), case-insensitively. Returns the raw
/// token verbatim plus the parsed base version and distro suffix. App, CMS,
/// and server-software versions are never matched — only `PHP/`-prefixed
/// tokens count.
pub fn parse_php_token(text: &str) -> Option<(String, ParsedVersion)> {
    let lower = text.to_lowercase();
    // Byte index from the lowercased copy: `get` keeps this panic-free on
    // non-ASCII input (misaligned index just yields no token).
    let mut rest = text.get(lower.find("php/")? + 4..)?;
    // The token ends at whitespace or a quoting/delimiter character.
    let end = rest
        .find(|c: char| {
            c.is_whitespace() || matches!(c, '"' | '\'' | ';' | ',' | '(' | ')')
        })
        .unwrap_or(rest.len());
    rest = &rest[..end];
    let run_len = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .map(char::len_utf8)
        .sum();
    if run_len == 0 {
        return None;
    }
    let (run, suffix) = rest.split_at(run_len);
    let parts: Vec<&str> = run.split('.').collect();
    if parts.len() > 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    let major: u64 = parts[0].parse().ok()?;
    let minor: Option<u64> = parts.get(1).map(|s| s.parse()).transpose().ok()?;
    let patch: Option<u64> = parts.get(2).map(|s| s.parse()).transpose().ok()?;
    Some((
        format!("PHP/{}", rest),
        ParsedVersion {
            major,
            minor,
            patch,
            suffix: suffix.to_string(),
        },
    ))
}

/// Merged per-host evidence from every input row for that host.
#[derive(Debug, Default)]
struct HostEvidence {
    ip: Option<String>,
    hc_php_version: Option<String>,
    hc_packages_raw: Option<String>,
    hc_sapi: Option<String>,
    fp_php_detected: bool,
    fp_php_version: Option<String>,
    fp_xpb: bool,
    fp_cookie: bool,
    fp_wordpress: bool,
    fp_apps: bool,
    /// First `server` header seen from any row (fingerprint or probe).
    server: Option<String>,
    /// Any server header, or the fingerprint `server` signal, mentions PHP.
    server_php: bool,
    probe_cookie: bool,
    probe_xpb_channel: bool,
    probe_remote_hint: Option<String>,
    probe_stack: Option<String>,
}

fn str_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

fn str_list(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn bool_field(value: &serde_json::Value, key: &str) -> bool {
    value.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Authoritative SAPI is the `(token)` right after the version in `php -v`
/// output (`PHP 8.2.10-2ubuntu1 (cli)` → `cli`). Anything else in the raw
/// text is not a SAPI claim.
fn sapi_from_php_raw(php_raw: &str) -> Option<String> {
    let first = php_raw.lines().next().unwrap_or("").trim();
    let open = first.find('(')?;
    let close = first[open..].find(')')?;
    let token = first[open + 1..open + close].trim().to_lowercase();
    if token.is_empty() || token.contains(char::is_whitespace) {
        return None;
    }
    Some(token)
}

fn ingest_row(evidence: &mut HostEvidence, value: &serde_json::Value) {
    if let Some(ip) = str_field(value, "ip") {
        evidence.ip.get_or_insert(ip);
    }
    // Fingerprint shape: `php_detected` only exists on fingerprint lines.
    if value.get("php_detected").is_some() {
        evidence.fp_php_detected |= bool_field(value, "php_detected");
        if evidence.fp_php_version.is_none() {
            evidence.fp_php_version = str_field(value, "php_version");
        }
        if evidence.server.is_none() {
            evidence.server = str_field(value, "server");
        }
        let signals = str_list(value, "php_signals");
        evidence.fp_xpb |= signals.iter().any(|s| s == "x-powered-by");
        evidence.server_php |= signals.iter().any(|s| s == "server");
        evidence.server_php |= evidence
            .server
            .as_deref()
            .is_some_and(|s| s.to_lowercase().contains("php"));
        evidence.fp_cookie |= signals.iter().any(|s| s == "phpsessid-cookie");
        evidence.fp_wordpress |= bool_field(value, "wordpress_detected");
        evidence.fp_apps |= value
            .get("php_apps")
            .and_then(|v| v.as_array())
            .is_some_and(|apps| !apps.is_empty());
    }
    // Probe shape: `cookie_names` only exists on probe lines.
    if value.get("cookie_names").is_some() {
        if evidence.server.is_none() {
            evidence.server = str_field(value, "server");
        }
        evidence.server_php |= evidence
            .server
            .as_deref()
            .is_some_and(|s| s.to_lowercase().contains("php"));
        evidence.probe_cookie |= str_list(value, "cookie_names")
            .iter()
            .any(|name| name.eq_ignore_ascii_case("phpsessid"));
        let channels = str_list(value, "confidence_signals");
        evidence.probe_xpb_channel |= channels.iter().any(|c| c == "x-powered-by");
        if evidence.probe_remote_hint.is_none() {
            evidence.probe_remote_hint = str_field(value, "remote_version_hint");
        }
        if evidence.probe_stack.is_none() {
            evidence.probe_stack = str_field(value, "stack_hint");
        }
        // Inline host-check summary merged by `ftw probe --host-check`:
        // version only, no package list, so no backport proof from it.
        if let Some(summary) = value.get("host_check") {
            if evidence.hc_php_version.is_none() {
                evidence.hc_php_version = str_field(summary, "php_version");
            }
        }
    }
    // Host-check shape: `php_raw` only exists on host-check lines.
    if value.get("php_raw").is_some() {
        if evidence.hc_php_version.is_none() {
            evidence.hc_php_version = str_field(value, "php_version");
        }
        if evidence.hc_packages_raw.is_none() {
            evidence.hc_packages_raw = str_field(value, "packages_raw");
        }
        if evidence.hc_sapi.is_none() {
            evidence.hc_sapi = str_field(value, "php_raw").and_then(|raw| sapi_from_php_raw(&raw));
        }
    }
}

/// One verdict per host. No other values are emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Vulnerable,
    Patched,
    UnknownAssumeVulnerable,
    NotApplicable,
}

impl Verdict {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vulnerable => "vulnerable",
            Self::Patched => "patched",
            Self::UnknownAssumeVulnerable => "unknown_assume_vulnerable",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Scope-gate outcome: whether the host is verified to run PHP, plus the
/// winning verification source and its confidence.
struct Gate {
    verified: bool,
    verification_source: &'static str,
    confidence: &'static str,
}

/// The scope gate, evaluated first. Only checked hosts proceed to a
/// verdict; anything else is `not_applicable` and is never counted as
/// vulnerable or unknown.
fn scope_gate(evidence: &HostEvidence) -> Gate {
    if evidence.hc_php_version.is_some() {
        return Gate {
            verified: true,
            verification_source: "host-check",
            confidence: "high",
        };
    }
    let xpb_php = evidence.fp_xpb
        || evidence.fp_php_version.is_some()
        || evidence
            .probe_remote_hint
            .as_deref()
            .and_then(parse_php_token)
            .is_some()
        || (evidence.probe_xpb_channel && evidence.probe_stack.as_deref() == Some("php"));
    if xpb_php {
        return Gate {
            verified: true,
            verification_source: "x-powered-by",
            confidence: "high",
        };
    }
    if evidence.server_php {
        return Gate {
            verified: true,
            verification_source: "server",
            confidence: "medium",
        };
    }
    if evidence.fp_cookie || evidence.probe_cookie {
        return Gate {
            verified: true,
            verification_source: "cookie",
            confidence: "medium",
        };
    }
    if evidence.fp_php_detected
        || evidence.probe_stack.as_deref() == Some("php")
    {
        return Gate {
            verified: true,
            verification_source: "php-detected",
            confidence: "medium",
        };
    }
    let wordpress = evidence.fp_wordpress
        || evidence.probe_stack.as_deref() == Some("wordpress");
    if wordpress {
        return Gate {
            verified: true,
            verification_source: "wordpress",
            confidence: "low",
        };
    }
    if evidence.fp_apps
        || evidence
            .probe_stack
            .as_deref()
            .is_some_and(|stack| PHP_STACKS.contains(&stack))
    {
        return Gate {
            verified: true,
            verification_source: "php-app",
            confidence: "low",
        };
    }
    Gate {
        verified: false,
        verification_source: "none",
        confidence: "none",
    }
}

/// A CVE id named in the host-check package list counts as vendor-backport
/// proof. A remote version string alone can never prove a backport.
fn backport_proven(evidence: &HostEvidence, rule: &CveRule) -> bool {
    evidence
        .hc_packages_raw
        .as_deref()
        .is_some_and(|packages| {
            let lowered = packages.to_lowercase();
            rule.ids
                .iter()
                .any(|id| lowered.contains(&id.to_lowercase()))
        })
}

/// Fixed patch for `(major, minor)` under this rule, if the branch is covered.
fn fixed_for(rule: &CveRule, major: u64, minor: u64) -> Option<u64> {
    rule.fixed
        .iter()
        .find(|(branch_major, branch_minor, _)| {
            *branch_major == major && *branch_minor == minor
        })
        .map(|(_, _, fixed_patch)| *fixed_patch)
}

/// The verdict core: pure version comparison, no I/O. `version` is the
/// winning version (host-check > X-Powered-By > Server) with whether its raw
/// token carried a distro suffix.
fn decide(
    rule: &CveRule,
    version: Option<&ParsedVersion>,
    has_suffix: bool,
    backport_proof: bool,
) -> (Verdict, String) {
    if backport_proof {
        return (
            Verdict::Patched,
            format!(
                "vendor backport confirmed via host-check ({})",
                rule.ids.join(", ")
            ),
        );
    }
    let Some(version) = version else {
        return (
            Verdict::UnknownAssumeVulnerable,
            "verified PHP but no PHP version found".to_string(),
        );
    };
    let base = version.display_base();
    // Branches at or below 8.1 have no official PHP release: vulnerable
    // unless a backport is proven (checked above).
    let old_branch = version.major < 8
        || (version.major == 8 && version.minor.is_some_and(|minor| minor <= 1));
    if old_branch {
        return (
            Verdict::Vulnerable,
            format!("PHP {base}, no supported release and no backport proof"),
        );
    }
    let (Some(minor), Some(patch)) = (version.minor, version.patch) else {
        return (
            Verdict::UnknownAssumeVulnerable,
            format!("partial PHP version {base}, patch unknown"),
        );
    };
    let Some(fixed) = fixed_for(rule, version.major, minor) else {
        return (
            Verdict::UnknownAssumeVulnerable,
            format!("PHP {base} not covered by {} rule", rule.name),
        );
    };
    if has_suffix {
        return (
            Verdict::UnknownAssumeVulnerable,
            format!("PHP {base} with distro suffix, backport unconfirmed"),
        );
    }
    if patch < fixed {
        (
            Verdict::Vulnerable,
            format!("{base} < fixed {}.{}.{}", version.major, minor, fixed),
        )
    } else {
        (
            Verdict::Patched,
            format!("{base} >= fixed {}.{}.{}", version.major, minor, fixed),
        )
    }
}

/// One streamed assessment record per host.
#[derive(Debug, Serialize)]
pub struct CveRecord {
    pub host: String,
    pub ip: Option<String>,
    pub verified_php: bool,
    pub verification_source: String,
    pub version_source: String,
    pub version_raw: Option<String>,
    pub version_parsed: Option<String>,
    pub distro_suffix: Option<String>,
    pub backport_check_needed: bool,
    pub sapi: Option<String>,
    pub sapi_source: String,
    pub cve_ids: Vec<String>,
    pub verdict: String,
    pub confidence: String,
    pub priority: u8,
    pub reason: String,
}

/// Aggregate counts for one assessment run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CveSummary {
    pub total: usize,
    pub checked: usize,
    pub not_applicable: usize,
    pub vulnerable: usize,
    pub unknown_assume_vulnerable: usize,
    pub patched: usize,
    /// Vulnerable hosts on Apache / mod_php: patch these first.
    pub priority_apache_mod_php: usize,
}

impl CveSummary {
    fn record(&mut self, record: &CveRecord) {
        self.total += 1;
        match record.verdict.as_str() {
            "vulnerable" => {
                self.checked += 1;
                self.vulnerable += 1;
                if record.priority == 1 {
                    self.priority_apache_mod_php += 1;
                }
            }
            "unknown_assume_vulnerable" => {
                self.checked += 1;
                self.unknown_assume_vulnerable += 1;
            }
            "patched" => {
                self.checked += 1;
                self.patched += 1;
            }
            _ => self.not_applicable += 1,
        }
    }
}

/// One stderr summary line: verdict counts plus checked vs not_applicable
/// totals. Existing probe and host-check output formats are unchanged.
#[must_use]
pub fn format_summary(summary: &CveSummary) -> String {
    format!(
        "ftw: cve-check assessed {} hosts (checked {}, not applicable {}): {} vulnerable ({} priority apache/mod_php), {} unknown_assume_vulnerable, {} patched, {} not_applicable",
        summary.total,
        summary.checked,
        summary.not_applicable,
        summary.vulnerable,
        summary.priority_apache_mod_php,
        summary.unknown_assume_vulnerable,
        summary.patched,
        summary.not_applicable,
    )
}

fn server_is_apache(server: Option<&str>) -> bool {
    server.is_some_and(|s| s.to_lowercase().contains("apache"))
}

/// Triage sort rank, never a verdict change: vulnerable on Apache/mod_php
/// first, then vulnerable, then unknown, then patched, then not_applicable.
fn priority_for(
    verdict: Verdict,
    server: Option<&str>,
    sapi: Option<&str>,
) -> u8 {
    if verdict == Verdict::Vulnerable
        && (server_is_apache(server)
            || matches!(sapi, Some(s) if s == "apache2handler" || s == "mod_php"))
    {
        return 1;
    }
    match verdict {
        Verdict::Vulnerable => 2,
        Verdict::UnknownAssumeVulnerable => 3,
        Verdict::Patched => 4,
        Verdict::NotApplicable => 5,
    }
}

/// Assess every host found in already-parsed JSONL values (fingerprint,
/// probe, and host-check rows distinguished by shape). Returns records in
/// first-seen host order plus the summary.
pub fn assess(values: Vec<serde_json::Value>) -> (Vec<CveRecord>, CveSummary) {
    let mut order: Vec<String> = Vec::new();
    let mut merged: HashMap<String, HostEvidence> = HashMap::new();
    for value in &values {
        let host = value
            .get("host")
            .or_else(|| value.get("ip"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(str::to_owned);
        let Some(host) = host else { continue };
        let evidence = merged.entry(host.clone()).or_default();
        if !order.contains(&host) {
            order.push(host);
        }
        ingest_row(evidence, value);
    }
    let rule = &CVE_RULES[0];
    let mut records = Vec::with_capacity(order.len());
    let mut summary = CveSummary::default();
    for host in order {
        let evidence = &merged[&host];
        records.push(assess_host(&host, evidence, rule));
        summary.record(records.last().expect("just pushed"));
    }
    (records, summary)
}

fn assess_host(host: &str, evidence: &HostEvidence, rule: &CveRule) -> CveRecord {
    let gate = scope_gate(evidence);
    let ip = evidence.ip.clone().or_else(|| {
        host.parse::<std::net::IpAddr>()
            .is_ok()
            .then(|| host.to_owned())
    });
    // Merging precedence: host-check version always wins over remote, and
    // remote wins over app inference (which never yields a version anyway).
    // WordPress and app versions are NEVER used as the PHP version.
    let mut version_source = "none";
    let mut version_raw: Option<String> = None;
    let mut parsed: Option<ParsedVersion> = None;
    if let Some(version) = evidence.hc_php_version.as_deref() {
        // Host-check versions are strict `major.minor.patch`, no suffix.
        if let Some((_, parsed_version)) =
            parse_php_token(&format!("PHP/{version}"))
        {
            version_source = "host-check";
            version_raw = Some(version.to_owned());
            parsed = Some(parsed_version);
        }
    }
    if parsed.is_none() {
        if let Some(version) = evidence.fp_php_version.as_deref() {
            if let Some((_, parsed_version)) = parse_php_token(&format!("PHP/{version}")) {
                version_source = "x-powered-by";
                version_raw = Some(version.to_owned());
                parsed = Some(parsed_version);
            }
        }
    }
    if parsed.is_none() {
        if let Some(hint) = evidence.probe_remote_hint.as_deref() {
            if let Some((raw, parsed_version)) = parse_php_token(hint) {
                version_source = "x-powered-by";
                version_raw = Some(raw);
                parsed = Some(parsed_version);
            }
        }
    }
    if parsed.is_none() {
        if let Some(server) = evidence.server.as_deref() {
            if let Some((raw, parsed_version)) = parse_php_token(server) {
                version_source = "server";
                version_raw = Some(raw);
                parsed = Some(parsed_version);
            }
        }
    }
    let has_suffix = parsed.as_ref().is_some_and(|v| !v.suffix.is_empty());
    let proof = backport_proven(evidence, rule);
    // SAPI: host-check is authoritative; remote is inferred only and never
    // downgrades a verdict (it only feeds the triage priority).
    let (sapi, sapi_source) = match evidence.hc_sapi.clone() {
        Some(sapi) => (Some(sapi), "host-check"),
        None => match evidence.server.as_deref() {
            Some(server) if server.to_lowercase().contains("apache") => {
                (Some("mod_php".to_string()), "inferred")
            }
            Some(server) if server.to_lowercase().contains("nginx") => {
                (Some("fpm".to_string()), "inferred")
            }
            _ => (None, "none"),
        },
    };
    let (verdict, mut reason) = if gate.verified {
        decide(rule, parsed.as_ref(), has_suffix, proof)
    } else {
        (
            Verdict::NotApplicable,
            "no verified PHP".to_string(),
        )
    };
    // Unknown with a verified technology names what was seen.
    if verdict == Verdict::UnknownAssumeVulnerable
        && reason == "verified PHP but no PHP version found"
    {
        reason = match gate.verification_source {
            "wordpress" => "WordPress detected, no PHP version header".to_string(),
            "php-app" => "PHP technology detected, no PHP version header".to_string(),
            source => format!("{source} indicates PHP, no PHP version header"),
        };
    }
    let priority = priority_for(verdict, evidence.server.as_deref(), sapi.as_deref());
    CveRecord {
        host: host.to_owned(),
        ip,
        verified_php: gate.verified,
        verification_source: gate.verification_source.to_string(),
        version_source: version_source.to_string(),
        version_raw,
        version_parsed: parsed.as_ref().map(|v| v.display_base()),
        distro_suffix: parsed.as_ref().and_then(|v| {
            if v.suffix.is_empty() {
                None
            } else {
                Some(v.suffix.clone())
            }
        }),
        backport_check_needed: has_suffix && !proof && gate.verified,
        sapi,
        sapi_source: sapi_source.to_string(),
        cve_ids: if gate.verified {
            rule.ids.iter().map(|id| id.to_string()).collect()
        } else {
            Vec::new()
        },
        verdict: verdict.as_str().to_string(),
        confidence: gate.confidence.to_string(),
        priority,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Minimal fingerprint row in the real writer shape.
    fn fp(
        ip: &str,
        server: Option<&str>,
        php_detected: bool,
        php_version: Option<&str>,
        signals: &[&str],
        wordpress: bool,
        apps: &[&str],
    ) -> serde_json::Value {
        json!({
            "ip": ip,
            "port": 80,
            "scheme": "http",
            "final_url": format!("http://{ip}/"),
            "status": 200,
            "server": server,
            "tls": "n/a",
            "error": null,
            "php_detected": php_detected,
            "php_version": php_version,
            "php_signals": signals,
            "wordpress_detected": wordpress,
            "wordpress_version": null,
            "wordpress_signals": [],
            "php_apps": apps.iter().map(|name| json!({"name": name, "version": null, "signals": []})).collect::<Vec<_>>(),
            "tailwind_detected": false,
            "tailwind_confidence": "none",
            "tailwind_signals": [],
            "fetch_method": "get",
            "head_status": null,
        })
    }

    /// Minimal probe row in the real writer shape.
    #[allow(clippy::too_many_arguments)]
    fn probe(
        host: &str,
        server: Option<&str>,
        cookies: &[&str],
        remote_hint: Option<&str>,
        channels: &[&str],
        stack: Option<&str>,
    ) -> serde_json::Value {
        json!({
            "host": host,
            "port": 80,
            "scheme": "http",
            "status": 200,
            "final_url": format!("http://{host}/"),
            "server": server,
            "cookie_names": cookies,
            "x_generator": null,
            "via": null,
            "generator": null,
            "title": null,
            "asset_hints": [],
            "tls_cn": null,
            "tls_san": [],
            "tls_issuer": null,
            "tls_not_after": null,
            "favicon_sha256": null,
            "robots_present": false,
            "robots_status": null,
            "robots_snippet": "",
            "robots_truncated": false,
            "sitemap_present": false,
            "sitemap_status": null,
            "sitemap_snippet": "",
            "sitemap_truncated": false,
            "confidence": "low",
            "confidence_signals": channels,
            "stack_hint": stack,
            "remote_version_hint": remote_hint,
            "patch_status": "unknown_from_remote",
            "host_check": null,
            "error": null,
        })
    }

    /// Minimal host-check row in the real writer shape.
    fn hc(host: &str, php_version: Option<&str>, php_raw: &str, packages: &str) -> serde_json::Value {
        json!({
            "host": host,
            "php_raw": php_raw,
            "php_version": php_version,
            "packages_raw": packages,
            "packages": [],
            "error": null,
        })
    }

    fn assess_all(rows: &[serde_json::Value]) -> (Vec<CveRecord>, CveSummary) {
        assess(rows.to_vec())
    }

    fn only_record(rows: &[serde_json::Value]) -> CveRecord {
        let (records, summary) = assess_all(rows);
        assert_eq!(summary.total, 1);
        records.into_iter().next().expect("one record")
    }

    #[test]
    fn gate_static_site_and_tailwind_are_not_applicable() {
        let static_row = probe("10.0.0.1", Some("nginx/1.24.0"), &[], None, &[], None);
        let record = only_record(&[static_row]);
        assert_eq!(record.verdict, "not_applicable");
        assert!(!record.verified_php);
        assert_eq!(record.reason, "no verified PHP");
        assert_eq!(record.confidence, "none");
        assert!(record.cve_ids.is_empty());
        assert_eq!(record.priority, 5);

        let mut tailwind = fp("10.0.0.2", Some("nginx/1.24.0"), false, None, &[], false, &[]);
        tailwind["tailwind_detected"] = json!(true);
        let record = only_record(&[tailwind]);
        assert_eq!(record.verdict, "not_applicable", "Tailwind alone never verifies PHP");
    }

    #[test]
    fn gate_ghost_and_generic_stacks_are_not_applicable() {
        let ghost = probe("10.0.0.3", Some("nginx/1.24.0"), &[], None, &["server"], Some("ghost"));
        let record = only_record(&[ghost]);
        assert_eq!(record.verdict, "not_applicable");
    }

    #[test]
    fn gate_wordpress_without_version_is_unknown_never_patched() {
        let wp = fp("10.0.0.4", Some("Apache/2.4.58"), false, None, &[], true, &[]);
        let record = only_record(&[wp]);
        assert_eq!(record.verdict, "unknown_assume_vulnerable");
        assert_eq!(record.confidence, "low");
        assert_eq!(record.reason, "WordPress detected, no PHP version header");
        assert!(record.version_parsed.is_none());
    }

    #[test]
    fn gate_app_version_is_never_used_as_php_version() {
        let mut row = fp("10.0.0.5", Some("Apache/2.4.58"), false, None, &[], true, &["woocommerce"]);
        row["wordpress_version"] = json!("6.5.0");
        let record = only_record(&[row]);
        assert_eq!(record.verdict, "unknown_assume_vulnerable");
        assert!(record.version_parsed.is_none(), "CMS version must not leak into the PHP version");
    }

    #[test]
    fn gate_phpsessid_cookie_verifies() {
        let row = probe("10.0.0.6", Some("nginx/1.24.0"), &["PHPSESSID"], None, &["cookies"], Some("php"));
        let record = only_record(&[row]);
        assert!(record.verified_php);
        assert_eq!(record.verification_source, "cookie");
        // No version anywhere: unknown, never patched.
        assert_eq!(record.verdict, "unknown_assume_vulnerable");
    }

    #[test]
    fn parses_plain_versions() {
        let (raw, parsed) = parse_php_token("PHP/8.2.30").expect("plain token");
        assert_eq!(raw, "PHP/8.2.30");
        assert_eq!(
            parsed,
            ParsedVersion { major: 8, minor: Some(2), patch: Some(30), suffix: String::new() }
        );
    }

    #[test]
    fn parses_distro_suffix_into_its_own_field() {
        let (raw, parsed) = parse_php_token("Apache/2.4.41 (Ubuntu) PHP/7.4.3-4ubuntu2.20")
            .expect("server token");
        assert_eq!(raw, "PHP/7.4.3-4ubuntu2.20");
        assert_eq!(parsed.display_base(), "7.4.3");
        assert_eq!(parsed.suffix, "-4ubuntu2.20");
    }

    #[test]
    fn parses_partial_and_rejects_missing_versions() {
        let (_, partial) = parse_php_token("PHP/8.2").expect("partial minor");
        assert_eq!((partial.major, partial.minor, partial.patch), (8, Some(2), None));
        let (_, major_only) = parse_php_token("PHP/8").expect("partial major");
        assert_eq!((major_only.major, major_only.minor), (8, None));
        assert!(parse_php_token("Apache/2.4.41").is_none(), "no PHP token");
        assert!(parse_php_token("PHP/").is_none(), "empty version");
        assert!(parse_php_token("PHP/8.x").is_none(), "non-numeric component");
        assert!(parse_php_token("not a version").is_none());
    }

    #[test]
    fn verdict_table_covers_every_branch() {
        let rule = &CVE_RULES[0];
        let full = |text: &str| parse_php_token(text).map(|(_, v)| v);
        let decide_full =
            |text: &str, suffix: bool, proof: bool| decide(rule, full(text).as_ref(), suffix, proof);
        // Below / at / above fixed for every covered branch.
        for (below, at, above) in [
            ("PHP/8.2.30", "PHP/8.2.35", "PHP/8.2.40"),
            ("PHP/8.3.0", "PHP/8.3.36", "PHP/8.3.99"),
            ("PHP/8.4.26", "PHP/8.4.27", "PHP/8.4.30"),
            ("PHP/8.5.0", "PHP/8.5.12", "PHP/8.5.13"),
        ] {
            let (verdict, reason) = decide_full(below, false, false);
            assert_eq!(verdict, Verdict::Vulnerable, "{below}");
            assert!(reason.contains("< fixed"), "reason shows the bar: {reason}");
            let (verdict, reason) = decide_full(at, false, false);
            assert_eq!(verdict, Verdict::Patched, "{at}");
            assert!(reason.contains(">= fixed"), "reason shows the bar: {reason}");
            let (verdict, _) = decide_full(above, false, false);
            assert_eq!(verdict, Verdict::Patched, "{above}");
        }
        // Suffix without proof is unknown even below the fixed version.
        let (verdict, _) = decide_full("PHP/8.2.30-1ubuntu1", true, false);
        assert_eq!(verdict, Verdict::UnknownAssumeVulnerable);
        // 8.1 and older: vulnerable without proof, patched with proof.
        let (verdict, reason) = decide_full("PHP/8.1.27", false, false);
        assert_eq!(verdict, Verdict::Vulnerable, "8.1 without backport");
        assert!(reason.contains("no backport proof"), "{reason}");
        let (verdict, _) = decide_full("PHP/8.1.27", false, true);
        assert_eq!(verdict, Verdict::Patched, "8.1 with proven backport");
        let (verdict, _) = decide_full("PHP/7.4.33", false, false);
        assert_eq!(verdict, Verdict::Vulnerable, "7.4 without backport");
        // Partial and uncovered versions are unknown, never patched.
        let (_, partial) = parse_php_token("PHP/8.2").expect("partial");
        let (verdict, _) = decide(rule, Some(&partial), false, false);
        assert_eq!(verdict, Verdict::UnknownAssumeVulnerable);
        let (_, future) = parse_php_token("PHP/9.0.0").expect("future");
        let (verdict, _) = decide(rule, Some(&future), false, false);
        assert_eq!(verdict, Verdict::UnknownAssumeVulnerable);
    }

    #[test]
    fn host_check_version_overrides_remote_in_both_directions() {
        // Remote says patched, host-check says vulnerable: host-check wins.
        let rows = vec![
            probe(
                "10.0.1.1",
                Some("Apache/2.4.58"),
                &[],
                Some("PHP/8.2.35"),
                &["server"],
                Some("php"),
            ),
            hc(
                "10.0.1.1",
                Some("8.2.10"),
                "PHP 8.2.10 (cli) (built: Aug 30 2024) ( NTS )",
                "php8.2-cli 8.2.10-2ubuntu1",
            ),
        ];
        let record = only_record(&rows);
        assert_eq!(record.verdict, "vulnerable");
        assert_eq!(record.version_source, "host-check");
        assert_eq!(record.version_parsed.as_deref(), Some("8.2.10"));
        assert_eq!(record.sapi.as_deref(), Some("cli"));
        assert_eq!(record.sapi_source, "host-check");
        assert_eq!(record.reason, "8.2.10 < fixed 8.2.35");

        // Remote says vulnerable, host-check says patched: host-check wins.
        let rows = vec![
            fp("10.0.1.2", Some("Apache/2.4.58"), true, Some("8.3.10"), &["x-powered-by"], false, &[]),
            hc(
                "10.0.1.2",
                Some("8.3.36"),
                "PHP 8.3.36 (fpm-fcgi) (built: Jan 1 2026)",
                "php8.3-fpm 8.3.36-1ubuntu1",
            ),
        ];
        let record = only_record(&rows);
        assert_eq!(record.verdict, "patched");
        assert_eq!(record.version_source, "host-check");
        assert_eq!(record.reason, "8.3.36 >= fixed 8.3.36");
    }

    #[test]
    fn distro_suffix_flags_backport_check_and_cve_proof_patches() {
        // No host-check: suffix with no proof is unknown with the flag set.
        let rows = vec![probe(
            "10.0.2.1",
            Some("Apache/2.4.41 (Ubuntu) PHP/8.2.30-1ubuntu1"),
            &[],
            None,
            &["server"],
            Some("php"),
        )];
        let record = only_record(&rows);
        assert_eq!(record.verdict, "unknown_assume_vulnerable");
        assert!(record.backport_check_needed);
        assert_eq!(record.distro_suffix.as_deref(), Some("-1ubuntu1"));
        assert_eq!(record.version_parsed.as_deref(), Some("8.2.30"));
        assert_eq!(
            record.reason,
            "PHP 8.2.30 with distro suffix, backport unconfirmed"
        );

        // Same suffix plus a CVE id in the host-check package list: patched.
        let rows = vec![
            probe(
                "10.0.2.2",
                Some("Apache/2.4.41 (Ubuntu) PHP/8.2.30-1ubuntu1"),
                &[],
                None,
                &["server"],
                Some("php"),
            ),
            hc(
                "10.0.2.2",
                Some("8.2.30"),
                "PHP 8.2.30-1ubuntu1 (apache2handler) (built: ...)",
                "php8.2 8.2.30-1ubuntu1 CVE-2026-109618 fixed",
            ),
        ];
        let record = only_record(&rows);
        assert_eq!(record.verdict, "patched");
        assert!(!record.backport_check_needed);
        assert_eq!(record.sapi.as_deref(), Some("apache2handler"));
    }

    #[test]
    fn priority_puts_apache_mod_php_vulnerable_first() {
        let apache_vuln = only_record(&[probe(
            "10.0.3.1",
            Some("Apache/2.4.58"),
            &["PHPSESSID"],
            Some("PHP/8.2.10"),
            &["cookies", "x-powered-by"],
            Some("php"),
        )]);
        assert_eq!(apache_vuln.verdict, "vulnerable");
        assert_eq!(apache_vuln.priority, 1);
        assert_eq!(apache_vuln.sapi.as_deref(), Some("mod_php"));
        assert_eq!(apache_vuln.sapi_source, "inferred");

        let nginx_vuln = only_record(&[probe(
            "10.0.3.2",
            Some("nginx/1.24.0"),
            &[],
            Some("PHP/8.2.10"),
            &["x-powered-by"],
            Some("php"),
        )]);
        assert_eq!(nginx_vuln.verdict, "vulnerable");
        assert_eq!(nginx_vuln.priority, 2);
        assert_eq!(nginx_vuln.sapi.as_deref(), Some("fpm"));
    }

    #[test]
    fn end_to_end_fixture_mixes_verdicts_and_counts() {
        let probe_jsonl = [
            probe("10.1.0.1", Some("Apache/2.4.58"), &[], Some("PHP/8.2.30"), &["x-powered-by"], Some("php")),
            probe("10.1.0.2", Some("nginx/1.24.0"), &[], Some("PHP/8.3.36"), &["x-powered-by"], Some("php")),
            probe("10.1.0.3", Some("nginx/1.24.0"), &[], None, &[], Some("wordpress")),
            probe("10.1.0.4", Some("nginx/1.24.0 (Ubuntu)"), &[], None, &[], None),
            fp("10.1.0.5", Some("Apache/2.4.41"), false, None, &[], false, &[]),
            fp("10.1.0.6", Some("nginx/1.24.0"), true, Some("8.4.20"), &["x-powered-by"], false, &[]),
        ];
        let hc_jsonl = [hc(
            "10.1.0.1",
            Some("8.2.10"),
            "PHP 8.2.10 (cli) (built: Aug 30 2024) ( NTS )",
            "php8.2-cli 8.2.10-2ubuntu1",
        )];
        let mut values: Vec<serde_json::Value> = probe_jsonl.into_iter().collect();
        values.extend(hc_jsonl);
        let (records, summary) = assess(values);
        let verdict_of = |host: &str| {
            records
                .iter()
                .find(|record| record.host == host)
                .map(|record| record.verdict.as_str())
                .expect("host present")
        };
        // 10.1.0.1: host-check 8.2.10 wins over remote 8.2.30 → vulnerable.
        assert_eq!(verdict_of("10.1.0.1"), "vulnerable");
        // 10.1.0.2: XPB 8.3.36 at the fixed version → patched.
        assert_eq!(verdict_of("10.1.0.2"), "patched");
        // 10.1.0.3: WordPress, no version → unknown.
        assert_eq!(verdict_of("10.1.0.3"), "unknown_assume_vulnerable");
        // 10.1.0.4: plain nginx, no signal → not applicable.
        assert_eq!(verdict_of("10.1.0.4"), "not_applicable");
        // 10.1.0.5: Apache alone is not PHP verification → not applicable.
        assert_eq!(verdict_of("10.1.0.5"), "not_applicable");
        // 10.1.0.6: fingerprint XPB 8.4.20 → vulnerable.
        assert_eq!(verdict_of("10.1.0.6"), "vulnerable");
        assert_eq!(
            summary,
            CveSummary {
                total: 6,
                checked: 4,
                not_applicable: 2,
                vulnerable: 2,
                unknown_assume_vulnerable: 1,
                patched: 1,
                priority_apache_mod_php: 1,
            }
        );
    }
}

