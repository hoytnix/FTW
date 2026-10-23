# Active Context — FTW

## Current focus
Phase 2 (`ftw probe`) built and verified: HTTP/HTTPS probing of open ports
from Phase 1 scan output, with passive PHP fingerprinting plus additive
technology fingerprinting (`src/tech.rs`: WordPress, 8 PHP apps, TailwindCSS
from a 64 KiB body preview, no extra requests), plus a HEAD-first request
strategy (HEAD then GET only when needed; `fetch_method`/`head_status`
fields). Phase 1 `scan` behavior and output format unchanged (flags moved
under `scan` subcommand).

## Active work stream
1. Restructured CLI into `scan` / `probe` subcommands (clap derive).
2. Added `src/probe.rs` (scan-output parsing, HTTPS-first/auto logic, TLS
   classification, PHP fingerprinting, semaphore-gated pipeline) and a JSON
   streaming writer in `src/output.rs`.
3. Crates added: reqwest (rustls-tls, no default features) + serde_json.
4. Verified: `cargo build` clean, `cargo clippy --all-targets -- -D warnings`
   clean (via rustup stable 1.99.1 toolchain installed for the gate),
   `cargo test` 11/11 green, live loopback smoke of scan→probe.
5. Tech fingerprinting improvement applied and verified: `cargo build` clean,
   `cargo clippy --all-targets -- -D warnings` clean, `cargo test` 20/20
   green (11 pre-existing + 9 new tech tests). Committed and pushed (888cfc4).
6. HEAD-first optimization applied and verified: `cargo build` clean,
   `cargo clippy --all-targets -- -D warnings` clean, `cargo test` 26/26
   green (20 pre-existing + 6 new HEAD-first tests). Committed and pushed
   (024de5b).
7. Fetch-mode improvement applied and verified (supersedes HEAD-first):
   explicit `--fetch-mode get|head|both` (default `get`), auto-skip removed,
   `cargo build` clean, `cargo clippy --all-targets -- -D warnings` clean,
   `cargo test` 30/30 green (22 pre-existing + 8 new fetch-mode tests).
7. Release workflow added (`.github/workflows/release.yml`, tag `v*` →
   deb/nsis/dmg via cargo-packager) plus minimal packager metadata in
   `Cargo.toml` (identifier `com.tehwiz.ftw`); YAML/manifest/build/clippy/
   test all verified locally. Changes left uncommitted.
8. Sync this file + progress.md; leave changes uncommitted for review.

## Recent state changes
- 2026-10-23: added hacker-zine README.md + Kopimi LICENSE; banner swapped
  to user-supplied dollar-sign FTW art. Left uncommitted.
- 2026-10-23: rebranded "Fuck The World" to "Fuck Teh World" (CLI about +
  project brief); tests 11/11 green. Left uncommitted.
- 2026-10-23: Phase 2 implementation complete and verified (build clean,
  clippy clean, 11/11 tests green). Known non-issue: `cargo fmt --check`
  with the newer 1.99 rustfmt reports style drift even in untouched Phase 1
  files (import ordering/line collapsing), so no reformat was applied; new
  code matches the repo's existing style. Changes left uncommitted.
- 2026-10-23: Phase 1 implementation complete (build clean, 4/4 tests green).
