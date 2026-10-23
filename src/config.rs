//! TOML config file: persistent defaults for CLI options.
//!
//! Discovery order: (1) `--config <FILE>` when explicitly passed (a missing
//! file is an immediate error naming the path); (2) `./ftw.toml` in the
//! current working directory; (3) `$HOME/.config/ftw/config.toml`;
//! (4) no config file, which is not an error — built-in defaults apply.
//!
//! Layout mirrors the subcommands plus a global section:
//!
//! ```toml
//! [global]
//! db = "ftw.db"
//! [scan]
//! concurrency = 500
//! [fingerprint]
//! scheme = "auto"
//! [crawl]
//! requests_per_minute = 0
//! [crawl.rate_limits]
//! "wordpress.org" = 5
//! ```
//!
//! Precedence is strict: CLI flag explicitly passed > config file value >
//! built-in default. CLI value options are `Option<T>` with no clap
//! defaults, so a clap default can never shadow the config file; each
//! resolved value records its [`Source`] for the verbose effective-config
//! print. Unknown keys fail listing every unknown dotted key plus the file
//! path; invalid values fail before any work starts, also naming the file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Where one resolved option value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Cli,
    Config,
    Default,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cli => f.write_str("cli"),
            Self::Config => f.write_str("config"),
            Self::Default => f.write_str("default"),
        }
    }
}

/// Resolve one option: CLI when explicitly passed, else config file, else
/// the built-in default.
#[must_use]
pub fn resolve<T: Clone>(cli: Option<T>, cfg: Option<T>, default: T) -> (T, Source) {
    match (cli, cfg) {
        (Some(value), _) => (value, Source::Cli),
        (None, Some(value)) => (value, Source::Config),
        (None, None) => (default, Source::Default),
    }
}

/// Resolve a positive CLI flag (passed means true) over an optional config
/// boolean, falling back to the built-in default.
#[must_use]
pub fn resolve_flag(cli: bool, cfg: Option<bool>, default: bool) -> (bool, Source) {
    if cli {
        (true, Source::Cli)
    } else {
        resolve(None, cfg, default)
    }
}

/// Resolve the prefer-HTTPS toggle from the negative `--no-prefer-https`
/// CLI flag and the positive `prefer_https` config key. An explicitly
/// passed CLI flag always wins; otherwise the config value applies; the
/// built-in default prefers HTTPS.
#[must_use]
pub fn resolve_prefer_https(cli_no_prefer: bool, cfg: Option<bool>) -> (bool, Source) {
    if cli_no_prefer {
        (false, Source::Cli)
    } else {
        resolve(None, cfg, true)
    }
}

/// One effective-config line for `--verbose` stderr:
/// `config: <section>.<key> = <value> (<source>)`.
#[must_use]
pub fn line(section: &str, key: &str, value: &str, source: Source) -> String {
    format!("config: {section}.{key} = {value} ({source})")
}

/// Timeout in seconds from TOML, accepting both `timeout = 2` and
/// `timeout = 2.5`. Out-of-range values (negative, zero, non-finite) are
/// kept here and rejected by validation with the file path and key.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TimeoutSecs(pub f64);

impl<'de> serde::Deserialize<'de> for TimeoutSecs {
    fn deserialize<D: serde::Deserializer<'de>>(into: D) -> Result<Self, D::Error> {
        struct Seconds;
        impl serde::de::Visitor<'_> for Seconds {
            type Value = TimeoutSecs;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a number of seconds")
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(TimeoutSecs(value as f64))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(TimeoutSecs(value as f64))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(TimeoutSecs(value))
            }
        }
        into.deserialize_any(Seconds)
    }
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GlobalSection {
    pub db: Option<PathBuf>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScanSection {
    pub input: Option<PathBuf>,
    pub ports: Option<Vec<u16>>,
    pub concurrency: Option<usize>,
    pub timeout: Option<TimeoutSecs>,
    pub verbose: Option<bool>,
    pub quiet: Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FingerprintSection {
    pub concurrency: Option<usize>,
    pub timeout: Option<TimeoutSecs>,
    pub scheme: Option<String>,
    pub insecure: Option<bool>,
    pub max_redirects: Option<usize>,
    pub body_cap: Option<usize>,
    pub fetch_mode: Option<String>,
    pub prefer_https: Option<bool>,
    pub verbose: Option<bool>,
    pub quiet: Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CrawlSection {
    pub concurrency: Option<usize>,
    pub timeout: Option<TimeoutSecs>,
    pub max_depth: Option<i64>,
    pub max_pages: Option<usize>,
    pub body_cap: Option<usize>,
    pub max_redirects: Option<usize>,
    pub insecure: Option<bool>,
    pub requests_per_minute: Option<u64>,
    pub rate_limits: Option<HashMap<String, u64>>,
    pub verbose: Option<bool>,
    pub quiet: Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProbeSection {
    pub concurrency: Option<usize>,
    pub timeout: Option<TimeoutSecs>,
    pub insecure: Option<bool>,
    pub body_cap: Option<usize>,
    #[serde(alias = "host-check")]
    pub host_check: Option<PathBuf>,
    pub verbose: Option<bool>,
    pub quiet: Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HostCheckSection {
    pub concurrency: Option<usize>,
    pub timeout: Option<TimeoutSecs>,
    pub verbose: Option<bool>,
    pub quiet: Option<bool>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileConfig {
    pub global: GlobalSection,
    pub scan: ScanSection,
    pub fingerprint: FingerprintSection,
    pub crawl: CrawlSection,
    pub probe: ProbeSection,
    #[serde(alias = "host-check")]
    pub host_check: HostCheckSection,
}

/// Known fields per section. `[crawl.rate_limits]` keys are canonical
/// domains and therefore arbitrary — any key is allowed there.
fn section_fields(section: &str) -> &'static [&'static str] {
    match section {
        "global" => &["db"],
        "scan" => &["input", "ports", "concurrency", "timeout", "verbose", "quiet"],
        "fingerprint" => &[
            "concurrency",
            "timeout",
            "scheme",
            "insecure",
            "max_redirects",
            "body_cap",
            "fetch_mode",
            "prefer_https",
            "verbose",
            "quiet",
        ],
        "crawl" => &[
            "concurrency",
            "timeout",
            "max_depth",
            "max_pages",
            "body_cap",
            "max_redirects",
            "insecure",
            "requests_per_minute",
            "rate_limits",
            "verbose",
            "quiet",
        ],
        "probe" => &[
            "concurrency",
            "timeout",
            "insecure",
            "body_cap",
            "host-check",
            "host_check",
            "verbose",
            "quiet",
        ],
        "host-check" | "host_check" => &[
            "concurrency",
            "timeout",
            "verbose",
            "quiet",
        ],
        _ => &[],
    }
}

/// Collect every unknown dotted key (`section.field`) so typos fail listing
/// all of them at once instead of only the first.
fn check_unknown(table: &toml::Table, origin: &str) -> Result<(), String> {
    let mut unknown = Vec::new();
    for section in table.keys() {
        let known = section_fields(section);
        if known.is_empty() {
            unknown.push(section.clone());
            continue;
        }
        if let Some(fields) = table[section].as_table() {
            for field in fields.keys() {
                if section == "crawl" && field == "rate_limits" {
                    continue;
                }
                if !known.contains(&field.as_str()) {
                    unknown.push(format!("{section}.{field}"));
                }
            }
        }
    }
    if unknown.is_empty() {
        Ok(())
    } else {
        unknown.sort_unstable();
        Err(format!(
            "{origin}: unknown config key(s): {}",
            unknown.join(", ")
        ))
    }
}

/// Locate the config file: explicit `--config` (missing is an immediate
/// error), else `./ftw.toml`, else `$HOME/.config/ftw/config.toml`, else
/// none (not an error).
pub fn discover(explicit: Option<&Path>) -> Result<Option<PathBuf>, String> {
    if let Some(path) = explicit {
        if !path.exists() {
            return Err(format!("config file not found: {}", path.display()));
        }
        return Ok(Some(path.to_path_buf()));
    }
    let local = PathBuf::from("ftw.toml");
    if local.is_file() {
        return Ok(Some(local));
    }
    if let Ok(home) = std::env::var("HOME") {
        let global = PathBuf::from(home).join(".config/ftw/config.toml");
        if global.is_file() {
            return Ok(Some(global));
        }
    }
    Ok(None)
}

/// Read and parse one config file. Unknown keys, invalid values, and broken
/// TOML syntax all fail here naming the file — before any work starts.
pub fn load(path: &Path) -> Result<FileConfig, String> {
    let origin = path.display().to_string();
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("{origin}: cannot read config file: {err}"))?;
    let table: toml::Table =
        toml::from_str(&text).map_err(|err| format!("{origin}: invalid TOML: {err}"))?;
    check_unknown(&table, &origin)?;
    toml::Value::Table(table)
        .try_into()
        .map_err(|err| format!("{origin}: invalid config value: {err}"))
}

/// Reject a zero count where at least one is required (concurrency,
/// max_pages). The config file path is named when the value came from it.
pub fn require_at_least_one(
    section: &str,
    key: &str,
    value: usize,
    source: Source,
    cfg_path: Option<&Path>,
) -> Result<(), String> {
    if value != 0 {
        return Ok(());
    }
    Err(match (source, cfg_path) {
        (Source::Config, Some(path)) => format!(
            "{}: [{section}] {key} must be at least 1",
            path.display()
        ),
        _ => format!("[{section}] {key} must be at least 1"),
    })
}

/// Reject max_depth values that are neither -1 (no limit) nor >= 1.
/// Zero and anything below -1 are errors, whether they came from the CLI
/// or the config file.
pub fn require_valid_depth(
    section: &str,
    key: &str,
    value: i64,
    source: Source,
    cfg_path: Option<&Path>,
) -> Result<(), String> {
    if value == -1 || value >= 1 {
        return Ok(());
    }
    Err(match (source, cfg_path) {
        (Source::Config, Some(path)) => format!(
            "{}: [{section}] {key} must be -1 (no limit) or at least 1",
            path.display()
        ),
        _ => format!("[{section}] {key} must be -1 (no limit) or at least 1"),
    })
}

/// Reject non-positive or non-finite timeouts.
pub fn require_positive_seconds(
    section: &str,
    key: &str,
    value: f64,
    source: Source,
    cfg_path: Option<&Path>,
) -> Result<(), String> {
    if value.is_finite() && value > 0.0 {
        return Ok(());
    }
    Err(match (source, cfg_path) {
        (Source::Config, Some(path)) => format!(
            "{}: [{section}] {key} must be a positive number of seconds",
            path.display()
        ),
        _ => format!("[{section}] {key} must be a positive number of seconds"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(tag: &str, body: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("ftw-cfgtest-{tag}-{nanos}.toml"));
        std::fs::write(&path, body).expect("write config");
        path
    }

    /// Precedence: CLI beats config beats built-in default, with sources.
    #[test]
    fn resolve_orders_cli_over_config_over_default() {
        assert_eq!(resolve(Some(10), Some(5), 0), (10, Source::Cli));
        assert_eq!(resolve(None, Some(5), 0), (5, Source::Config));
        assert_eq!(resolve(None::<u64>, None, 0), (0, Source::Default));
        assert_eq!(resolve_flag(true, Some(false), false), (true, Source::Cli));
        assert_eq!(resolve_flag(false, Some(true), false), (true, Source::Config));
        assert_eq!(resolve_flag(false, None, true), (true, Source::Default));
        assert_eq!(resolve_prefer_https(true, Some(true)), (false, Source::Cli));
        assert_eq!(resolve_prefer_https(false, Some(false)), (false, Source::Config));
        assert_eq!(resolve_prefer_https(false, None), (true, Source::Default));
    }

    /// A config file setting only some options leaves the rest unset (never
    /// zeroed): unset fields deserialize to `None`.
    #[test]
    fn partial_config_leaves_other_options_unset() {
        let path = write_config("partial", "[crawl]\nrequests_per_minute = 5\n");
        let file = load(&path).expect("load partial config");
        assert_eq!(file.crawl.requests_per_minute, Some(5));
        assert_eq!(file.crawl.max_pages, None, "unset options stay None");
        assert_eq!(file.crawl.concurrency, None);
        assert_eq!(file.crawl.timeout, None);
        assert!(file.crawl.rate_limits.is_none());
        assert_eq!(file.scan.concurrency, None, "other sections stay empty");
        std::fs::remove_file(&path).ok();
    }

    /// A missing section is valid; integer timeouts parse as seconds.
    #[test]
    fn missing_sections_are_valid_and_int_timeouts_parse() {
        let path = write_config("sparse", "[scan]\nconcurrency = 10\n");
        let file = load(&path).expect("load sparse config");
        assert_eq!(file.scan.concurrency, Some(10));
        assert_eq!(file.crawl.requests_per_minute, None);

        let path = write_config("int-timeout", "[crawl]\ntimeout = 2\n");
        let file = load(&path).expect("load int timeout");
        assert_eq!(file.crawl.timeout.map(|t| t.0), Some(2.0));
        std::fs::remove_file(&path).ok();
    }

    /// Unknown keys fail listing every typo plus the file path.
    #[test]
    fn unknown_keys_fail_naming_all_of_them() {
        let path = write_config(
            "unknown",
            "[crawl]\nconcurrnecy = 5\nmax_pgaes = 3\n[scan]\nbonus = 1\n",
        );
        let err = load(&path).expect_err("typos must fail");
        assert!(err.contains("crawl.concurrnecy"), "names typo 1: {err}");
        assert!(err.contains("crawl.max_pgaes"), "names typo 2: {err}");
        assert!(err.contains("scan.bonus"), "names typo 3: {err}");
        assert!(err.contains(&path.display().to_string()), "names path: {err}");
        std::fs::remove_file(&path).ok();
    }

    /// Unknown top-level sections fail too.
    #[test]
    fn unknown_section_fails() {
        let path = write_config("section", "[bogus]\nx = 1\n");
        let err = load(&path).expect_err("unknown section must fail");
        assert!(err.contains("bogus"), "names the section: {err}");
        std::fs::remove_file(&path).ok();
    }

    /// Malformed TOML fails with the parse error and the path.
    #[test]
    fn malformed_toml_fails_with_path() {
        let path = write_config("broken", "[crawl\nrequests_per_minute = \n");
        let err = load(&path).expect_err("broken TOML must fail");
        assert!(err.contains(&path.display().to_string()), "names path: {err}");
        std::fs::remove_file(&path).ok();
    }

    /// Invalid values fail naming the file: negative rate limit (a TOML
    /// integer that cannot fit `u64`), zero concurrency/pages, bad timeouts.
    #[test]
    fn invalid_values_fail_with_path_and_key() {
        let path = write_config("neg-rpm", "[crawl]\nrequests_per_minute = -5\n");
        let err = load(&path).expect_err("negative rpm must fail");
        assert!(err.contains(&path.display().to_string()), "names path: {err}");
        assert!(
            err.contains("requests_per_minute"),
            "names the key: {err}"
        );
        std::fs::remove_file(&path).ok();

        let path = write_config("zero", "[crawl]\nconcurrency = 0\n");
        let file = load(&path).expect("zero parses; validation rejects");
        let err = require_at_least_one("crawl", "concurrency", 0, Source::Config, Some(&path))
            .expect_err("zero concurrency must fail");
        assert!(err.contains("concurrency"), "names the key: {err}");
        assert!(err.contains(&path.display().to_string()), "names path: {err}");
        drop(file);
        std::fs::remove_file(&path).ok();

        assert!(require_positive_seconds("crawl", "timeout", 0.0, Source::Config, None).is_err());
        assert!(require_positive_seconds("crawl", "timeout", -1.0, Source::Config, None).is_err());
        assert!(
            require_positive_seconds("crawl", "timeout", f64::INFINITY, Source::Config, None)
                .is_err()
        );
        assert!(require_positive_seconds("crawl", "timeout", 2.5, Source::Config, None).is_ok());
    }

    #[test]
    fn valid_depth_accepts_only_minus_one_or_at_least_one() {
        for value in [-1, 1, 2, 100] {
            assert!(
                require_valid_depth("crawl", "max_depth", value, Source::Cli, None).is_ok(),
                "{value} must be accepted"
            );
        }
        for value in [i64::MIN, -100, -2, 0] {
            let err =
                require_valid_depth("crawl", "max_depth", value, Source::Cli, None).expect_err(
                    "{value} must be rejected",
                );
            assert!(err.contains("max_depth"), "names the key: {err}");
        }
    }

    /// Explicit `--config` to a missing file fails before any work.
    #[test]
    fn missing_explicit_config_fails() {
        let missing = std::env::temp_dir().join("ftw-cfgtest-no-such-file.toml");
        std::fs::remove_file(&missing).ok();
        let err = discover(Some(&missing)).expect_err("missing file must fail");
        assert!(err.contains(&missing.display().to_string()), "names path: {err}");
    }
}
