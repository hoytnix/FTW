# Progress — FTW

## Build status
- Version `0.2.0` (`Cargo.toml`, `Cargo.lock`, README banner; `ftw --version`
  reports `FTW 0.2.0`).
- `cargo build` clean, 0 warnings.
- `cargo clippy --all-targets -- -D warnings` clean (system stable toolchain;
  clippy 0.1.99).
- `cargo test` 60/60 green (52 unit + 8 CLI in `tests/live_output.rs`).
  Scan/fingerprint detection, fetch-mode, tech, and verbose/quiet behavior
  unchanged; results moved from files to the master SQLite database, and the
  new `crawl` subcommand is covered (chain/cycle/external/depth, non-HTML,
  redirects, skips, error kinds, single-writer proof, legacy-flag rejection).

## Completed modules
- `src/db.rs` (new): master SQLite database, opened once per run (WAL,
  busy_timeout 5000, synchronous NORMAL, `CREATE TABLE IF NOT EXISTS` +
  indexes, checkpoint on exit). `scan_results` upsert on `(ip, port)`,
  `fingerprint_results` upsert on `(ip, port, scheme)` with signal arrays as
  JSON text, `crawl_pages` upsert on normalized `url`, `crawl_links`
  `INSERT OR IGNORE`; `open_ports` / `crawl_seeds` (2xx–3xx only) seed
  queries; structural test proving only `db.rs` executes statements and only
  the writer path owns a connection.
- `src/crawl.rs` (new): `ftw crawl` — coordinator-owned visited set +
  frontier, semaphore-gated workers (permit before spawn), GET-only fetches,
  redirect following with off-host stop, same-host scope (IP seeds also match
  port), `<a href>`-only extraction with normalization/dedup, admin/action
  skips, `--body-cap` streaming without storing bodies, per-kind error stats.
- `src/targets.rs` (YAML map/sequence parse, bare-IP fallback, aggregate dedup,
  lazy cursor iterator + unit tests). Unchanged in Phase 2.
- `src/scanner.rs` (probe open/closed/filtered + semaphore-gated `scan`).
  Unchanged in Phase 2.
- `src/output.rs` (`BufWriter` streaming writer + line formatter, unchanged;
  added `run_probe_writer` JSON-lines streaming writer returning ProbeStats).
- `src/main.rs` (clap `scan`/`probe` subcommand wiring + end-to-end loopback
  test, unchanged apart from the subcommand move).
- `src/probe.rs`: scan-output parse (open-only, deduped), per-scheme attempt
  with FTW User-Agent/timeout/redirect cap/body cap, TLS-vs-HTTP status
  split, `http`/`tls_error`/`connect_error`/`timeout`/`other` classification,
  passive PHP fingerprinting (strict `PHP/x.y.z` version parse),
  semaphore-gated spawn + bounded mpsc + single writer, 64 KiB body preview
  (`collect_preview`) feeding `tech` fingerprinting, path-logging end-to-end
  tests (no body in output, only `/` requested); explicit `--fetch-mode`
  (`get` default single GET; `head` single HEAD with header-only PHP/tech
  signals; `both` HEAD-then-GET always with header union and GET superseding
  status/URL, `get-fallback` + null `head_status` on HEAD 405/501/failure),
  one record per port per scheme, one semaphore permit held for the whole
  sequence. No automatic HEAD-first skipping.
- `src/tech.rs` (new): no-network technology fingerprinting of the
  already-fetched response via `scraper` (meta/link-href/script-src/img-src/
  class/title parsing; raw-text search only for exact `Powered by phpBB` and
  `Drupal.settings`): WordPress (`generator`/`wp-content/`/`wp-includes/`/
  `wp-json` + version + `woocommerce-plugin` note), 8 PHP apps
  (Joomla/Drupal/Magento/phpBB/MediaWiki/PrestaShop/OpenCart/Moodle, versions
  from generator tags only), TailwindCSS (`tailwind-cdn`/`tailwind-link`
  strong, `utility-classes` weak-only), 4 unit tests; extended with `Link`
  response-header parsing (same `(href, rel)` shape, WordPress check only)
  and `head_identifies_app` (WP `Link` / `X-Magento-*` skip rule), 2 more
  unit tests.

## Known issues
- `cargo fmt --check` under the newer 1.99 rustfmt flags style drift in
  untouched Phase 1 files too (import order, line collapsing); new code
  intentionally matches the repo's existing style instead. Not a gate
  failure (`build` + `clippy -D warnings` are the gates, both clean).

## Roadmap
- Done: Phase 2 implementation, tests, live loopback scan→probe smoke test,
  tech fingerprinting, HEAD-first optimization (all committed and pushed),
  tag-triggered release workflow. Release-workflow changes left uncommitted
  in the working tree for review.
