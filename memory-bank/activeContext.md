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
13. Crawl per-domain rate limiting applied and verified: new
    `src/rate_limit.rs` (canonical domains, shared Arc sliding-window
    limiter, 60 s production window), `ftw crawl --requests-per-minute <N>`
    (default 0 = unlimited, negatives rejected by clap), worker order
    rate-wait → semaphore → fetch with no permit held while waiting, verbose
    `rate-limit wait <domain> <s>s` lines, summary with setting/waits/longest
    wait. No schema change, no other crawl flags. `cargo build` / clippy /
    `cargo test` 79/79 green (67 unit + 12 CLI). Changes left uncommitted.
14. TOML config-file defaults applied and verified (v0.2.3, Cargo.toml only):
    new `src/config.rs` (discovery `--config` > `./ftw.toml` >
    `$HOME/.config/ftw/config.toml` > none; CLI > config > built-in
    precedence via `Option` CLI args; unknown-key and invalid-value failures
    naming path+key; int-or-float timeouts), `--config` on all three
    subcommands, `[crawl.rate_limits]` per-domain overrides through the
    limiter's canonicalization, verbose `config: <section>.<key> = <v>
    (<source>)` lines. No schema change, no other new flags. `cargo build`
    / clippy / `cargo test` 93/93 green (78 unit + 15 CLI). Committed,
    tagged `v0.2.3`, and pushed.
15. Release-workflow glibc fix applied (uncommitted): Linux .deb jobs moved
    into a `rust:1-bookworm` container (glibc 2.36 baseline) so the arm64
    .deb no longer requires GLIBC_2.38/2.39; Windows/macOS jobs unchanged.
    Verified: YAML parses, `cargo build` / clippy clean, readelf confirms
    new-glibc hosts bake in 2.38/2.39. Container proof runs in CI on next
    tag push (no container runtime on this machine).
16. `ftw host-check` now seeds from the master database (distinct IPs with
    open ports via new `db::host_check_seeds`); the YAML inventory is gone
    (`--inventory` rejected pointing at `--db`, `host_check.inventory`
    config key removed, parser/credential-refusal code deleted). Verified:
    build/clippy clean, 112/112 tests green (96 unit + 16 CLI), live smoke
    of empty-seed warning and flag rejection. probe `--host-check` JSONL
    merge unchanged. Committed and pushed (b26057d).
17. `ftw crawl --max-depth` redefined (was hop count, default 2): now
    absolute URL depth from the host root via new `url_depth()` (`/` = 1,
    index pages count as their directory), default -1 = no limit, 0 and
    < -1 rejected by new `config::require_valid_depth`
    (`allow_hyphen_values` so `-1` parses). Seeds always fetched;
    over-deep pages recorded but followed nowhere; `depth` in every
    streamed JSONL stdout line, the verbose line, and `crawl_pages`.
    Verified: build/clippy clean, 117/117 green (100 unit + 17 CLI),
    incl. new absolute-depth loopback test. Left uncommitted, not pushed.
17. Phase 2 fingerprinting probe (`ftw probe`) + authoritative on-host check
    (`ftw host-check`) implemented and verified for authorized ranges only:
    new `src/probe.rs` (port-fixed scheme, single GET / with 32 KiB cap,
    cookie names only, X-Generator/Via/title/generator-meta/asset hints,
    same-pass TLS CN/SAN/issuer/not-after via capture verifier + x509-parser,
    favicon SHA-256, 16 KiB robots/sitemap presence+snippets, signal-count
    confidence, remote-version-hint-only with `unknown_from_remote`), new
    `src/host_check.rs` (DB-seeded hosts, SSH BatchMode with existing
    config/agent only, verbatim `php -v` + package
    query, fixture-tested parsers, JSONL summaries merged by host), plus
    `probe_results`/`host_check_results` tables, single-writer streaming
    writers, `[probe]`/`[host_check]` config sections, and 20 new tests
    (loopback asserting every probe field incl. only-open-ports, host-check
    fixtures with no live SSH, TLS-fields live test via the 443 shim).
    `cargo build` clean, `cargo clippy --all-targets -- -D warnings` clean,
    `cargo test` 113/113 green (97 unit + 16 CLI). Changes left uncommitted.

## Recent state changes
- 2026-10-23: README.md now documents the new fingerprinting tech (`ftw
  probe` 0x05 + `ftw host-check` 0x06, `[probe]`/`[host_check]` config,
  renumbered config/full-run/greetz sections, test count 93→113).
  Verification green (build clean, clippy clean, 113/113 tests).
  Left uncommitted.
- 2026-10-23: Phase 2 probe (`ftw probe`) + `ftw host-check` complete and
  verified (build clean, clippy clean, 113/113 tests green). Left uncommitted.
- 2026-10-23: bumped to v0.2.4 (Cargo.toml + README banner), committed
  (`6a5df6a`), tagged `v0.2.4`, pushed commit + tag to origin. Tree clean.
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
