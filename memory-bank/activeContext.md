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
8. Live-output improvement applied and verified: `--verbose`/`--quiet`
   (`-v`/`-q`) on both subcommands, writer-only stdout duplication with
   flush-per-event,
   stderr verbose lines + summaries, `cargo build` / clippy clean,
   `cargo test` 39/39 green (34 unit + 5 new CLI). Changes left uncommitted.
9. Rebrand `probe` → `fingerprint` (subcommand, module, args, docs;
   detection/behavior unchanged), then master-SQLite improvement + new
   `crawl` subcommand applied and verified: `cargo build` clean,
   `cargo clippy --all-targets -- -D warnings` clean,
   `cargo test` 60/60 green (52 unit + 8 CLI). All scan/fingerprint/crawl
   results live in one `--db` file (default `ftw.db`); removed `--output` /
   `--scan-output` are rejected with a clap error pointing at `--db`.
   Single writer task owns the only connection (WAL, busy_timeout 5000,
   synchronous NORMAL, checkpoint on exit). Changes left uncommitted.
10. Sync this file + progress.md; leave changes uncommitted for review.
11. Prefer-HTTPS fingerprint deduplication applied and verified: `cargo build`
    clean, `cargo clippy --all-targets -- -D warnings` clean,
    `cargo test` 69/69 green (59 unit + 10 CLI). `ftw fingerprint` now groups
    open ports by IP and, by default, fingerprints only 443 (HTTPS-only, never
    plaintext HTTP to 443) when one IP has both 80 and 443 open; the skipped
    80 gets no row and no crawl seed, and a 443 transport failure
    (timeout/tls_error/connect_error, no status) falls back to 80 exactly
    once. `--scheme http` or `--no-prefer-https` disables it entirely.
    Summary now ends with `skipped_prefer_https=` + `fallback_to_http=`;
    `--verbose` prints `skipped <ip>:80 (prefer 443)` per skip. Scan targets,
    detection, schema, and verbose/quiet behavior unchanged. Changes left
    uncommitted.
12. Happy-path DB integration test added and verified: literal port 443 is
    unbindable without privileges here, so new `tests/shim_443.c` (built with
    `cc` at test time) remaps port 443 to a free high port for both the
    `openssl s_server` TLS fixture and the `ftw` binary; seeded 80+443 yields
    only the 443 row (HTTPS 200), scan rows stay open, summary reports
    `skipped_prefer_https=1` + `fallback_to_http=0`. `cargo build` /
    clippy / `cargo test` 70/70 green (59 unit + 11 CLI). Changes left
    uncommitted.

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
