# System Patterns — FTW

## Architecture
Pipeline: YAML → aggregate → lazy addr iterator → producer loop
(semaphore-gated spawn) → bounded mpsc → single streaming writer.

## State / classification matrix
| Probe outcome              | Status   |
|----------------------------|----------|
| `connect` succeeds         | open     |
| `ConnectionRefused`        | closed   |
| timeout or any other error | filtered |

## Design patterns
- Producer gate: `semaphore.acquire_owned().await` in the producer loop
  BEFORE `tokio::spawn`, so large CIDRs never queue unbounded tasks.
- Lazy iteration: cursor over aggregated `IpNet`s (`u32` for v4, `u128` for v6);
  never collect the address space.
- Single writer: bounded `tokio::sync::mpsc` channel + `BufWriter`; scan ends
  when all senders drop, then the writer flushes.
- `main.rs` does CLI wiring only; behavior lives in
  `targets.rs` / `scanner.rs` / `output.rs`.
