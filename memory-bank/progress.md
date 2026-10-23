# Progress — FTW

## Build status
- `cargo build` clean, 0 warnings (`--all-targets`); `cargo test` 4/4 green.
- `cargo clippy` NOT run: clippy is not installed and cannot be installed here
  (no rustup; apt needs a terminal for sudo; escalation prompts disabled).

## Completed modules
- `src/targets.rs` (YAML map/sequence parse, bare-IP fallback, aggregate dedup,
  lazy cursor iterator + unit tests).
- `src/scanner.rs` (probe open/closed/filtered + semaphore-gated `scan`).
- `src/output.rs` (`BufWriter` streaming writer + line formatter).
- `src/main.rs` (clap CLI wiring + end-to-end loopback test).

## Known issues
- Clippy gate unverified in this environment (see above); re-run
  `cargo clippy -- -D warnings` where clippy is installed.

## Roadmap
- Done: implementation, tests, live loopback run, summary. Changes left
  uncommitted in the working tree for review, nothing pushed.
