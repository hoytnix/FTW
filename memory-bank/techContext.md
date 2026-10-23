# Tech Context — FTW

## Stack
- Rust 2021, Tokio multi-threaded runtime (`#[tokio::main]`).
- Crates: `tokio` (full features), `clap` (derive feature),
  `ipnet`, `serde` (derive feature), `serde_yml`.
- No extra runtime dependencies; tests use std + Tokio only (temp files via
  `std::env::temp_dir`).

## Environment constraints
- Build/test/clippy via cargo (network access to crates.io required once
  to fetch dependencies).
- Verification gates: `cargo build` and `cargo clippy -- -D warnings` must be
  clean; `cargo test` runs the loopback integration test.

## Conventions
- `cargo fmt` style; no warnings allowed under clippy `-D warnings`.
- File layout: `src/main.rs`, `src/targets.rs`, `src/scanner.rs`,
  `src/output.rs`; loopback test as `#[cfg(test)]` unit test inside the crate
  (binary crate cannot be imported from `tests/`).
