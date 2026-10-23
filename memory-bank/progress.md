# Progress — FTW

## Build status
- `cargo build` clean, 0 warnings.
- `cargo clippy --all-targets -- -D warnings` clean (rustup stable 1.99.1
  toolchain installed 2026-10-23 to run the gate; clippy 0.1.99).
- `cargo test` 26/26 green (20 pre-existing: 4 Phase 1 + 7 probe + 9 tech;
  6 new HEAD-first: 2 `tech.rs` unit + 4 method-logging end-to-end probe
  tests).

## Completed modules
- `src/targets.rs` (YAML map/sequence parse, bare-IP fallback, aggregate dedup,
  lazy cursor iterator + unit tests). Unchanged in Phase 2.
- `src/scanner.rs` (probe open/closed/filtered + semaphore-gated `scan`).
  Unchanged in Phase 2.
- `src/output.rs` (`BufWriter` streaming writer + line formatter, unchanged;
  added `run_probe_writer` JSON-lines streaming writer returning ProbeStats).
- `src/main.rs` (clap `scan`/`probe` subcommand wiring + end-to-end loopback
  test, unchanged apart from the subcommand move).
- `src/probe.rs` (new): scan-output parse (open-only, deduped), single
  `GET /` per scheme attempt with FTW User-Agent/timeout/redirect cap/body
  cap, TLS-vs-HTTP status split, `http`/`tls_error`/`connect_error`/
  `timeout`/`other` classification, passive PHP fingerprinting (4 signals,
  strict `PHP/x.y.z` version parse), semaphore-gated spawn + bounded mpsc +
  single writer (Phase 1 architecture), 7 tests; extended additively with a
  64 KiB body preview (`collect_preview`) feeding `tech` fingerprinting and 5
  path-logging end-to-end tech tests (all existing fields unchanged); then
  with a HEAD-first strategy (`HEAD /` via the same client, GET skipped only
  on WP `Link`/`X-Magento-*` headers, GET fallback on 4xx/5xx or HEAD
  failure, header union, `fetch_method`/`head_status` fields) and 4
  method-logging end-to-end HEAD tests.
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
  summary. Changes left uncommitted in the working tree for review, nothing
  pushed.
