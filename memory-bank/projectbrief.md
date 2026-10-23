# Project Brief — FTW (Fuck Teh World) Port Scanner

## Core goal
Build a Rust async TCP port scanner named `ftw` for authorized IP ranges only
(ranges the operator owns or has written permission to test).

## Scope
- Crate/binary name `ftw`; CLI brand "FTW", about/title
  "Fuck Teh World (FTW) — Authorized Async TCP Port Scanner".
- Clap-derived CLI: YAML input, ports (default 80,443), concurrency limit,
  timeout (default 2s), output file.
- YAML targets via serde + serde_yml; CIDR/Single-IP parsing with ipnet;
  dedup with `IpNet::aggregate`; lazy iteration (no full expansion).
- Tokio multi-threaded runtime; `Arc<Semaphore>` with permit acquired in the
  producer loop before `tokio::spawn`.
- Probe: `TcpStream::connect` + `tokio::time::timeout` → open / closed / filtered.
- Bounded mpsc channel to a single `BufWriter` streaming writer task.
- Modules: `targets.rs`, `scanner.rs`, `output.rs`, `main.rs` (CLI wiring only).

## Foundation
Rust 2021 edition. Crates: tokio (full), clap (derive), ipnet,
serde (derive), serde_yml. Package manager: cargo.
Verification: `cargo build`, `cargo clippy -- -D warnings`, `cargo test`
(loopback test included).
