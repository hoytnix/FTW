# Progress — FTW

## Build status
- `cargo build` clean, 0 warnings.
- `cargo clippy --all-targets -- -D warnings` clean (rustup stable 1.99.1
  toolchain installed 2026-10-23 to run the gate; clippy 0.1.99).
- `cargo test` 11/11 green (4 Phase 1 + 7 new probe tests).

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
  single writer (Phase 1 architecture), 7 tests.

## Known issues
- `cargo fmt --check` under the newer 1.99 rustfmt flags style drift in
  untouched Phase 1 files too (import order, line collapsing); new code
  intentionally matches the repo's existing style instead. Not a gate
  failure (`build` + `clippy -D warnings` are the gates, both clean).

## Roadmap
- Done: Phase 2 implementation, tests, live loopback scan→probe smoke test,
  summary. Changes left uncommitted in the working tree for review, nothing
  pushed.
