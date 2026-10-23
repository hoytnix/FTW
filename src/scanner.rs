//! Async TCP probe logic and semaphore-gated scan orchestration.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};

use crate::targets::TargetSet;

/// Classification of a single TCP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

impl PortStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
        }
    }
}

impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of probing one `(ip, port)` pair.
///
/// `reason` is the human classification reason used for verbose output only:
/// `"open"`, `"connection refused"`, or for filtered the underlying error
/// kind (`"timeout"`, `"host unreachable"`, `"network unreachable"`,
/// `"permission denied"`, or `"other"`). The output file format is unchanged
/// (`<ip>:<port> <status>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub status: PortStatus,
    pub reason: &'static str,
}

/// Map a failed-connect I/O error to its verbose reason string.
fn filtered_reason(err: &io::Error) -> &'static str {
    match err.kind() {
        io::ErrorKind::TimedOut => "timeout",
        io::ErrorKind::HostUnreachable => "host unreachable",
        io::ErrorKind::NetworkUnreachable => "network unreachable",
        io::ErrorKind::PermissionDenied => "permission denied",
        _ => "other",
    }
}

/// Probe one port with its classification reason: connect wins → open,
/// refused → closed, timeout (or any other network error) → filtered.
/// The classification matches [`probe`] exactly; only the reason is added.
pub async fn probe_with_reason(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> (PortStatus, &'static str) {
    let addr = SocketAddr::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => (PortStatus::Open, "open"),
        Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused => {
            (PortStatus::Closed, "connection refused")
        }
        Ok(Err(err)) => (PortStatus::Filtered, filtered_reason(&err)),
        Err(_) => (PortStatus::Filtered, "timeout"),
    }
}

/// Probe one port: connect wins → open, refused → closed, timeout (or any
/// other network error) → filtered.
#[allow(dead_code)]
pub async fn probe(ip: IpAddr, port: u16, timeout: Duration) -> PortStatus {
    probe_with_reason(ip, port, timeout).await.0
}

/// Scan every address × port, sending each result to `tx`.
///
/// The semaphore permit is acquired in this producer loop *before*
/// `tokio::spawn`, so large CIDR blocks never queue unbounded waiting tasks:
/// at most `concurrency` probes are in flight at once.
pub async fn scan(
    targets: &TargetSet,
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    tx: mpsc::Sender<ScanResult>,
) {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    for ip in targets.iter() {
        for &port in ports {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("scan semaphore never closes while scanning");
            let tx = tx.clone();
            tokio::spawn(async move {
                let (status, reason) = probe_with_reason(ip, port, timeout).await;
                drop(permit);
                let _ = tx.send(ScanResult { ip, port, status, reason }).await;
            });
        }
    }
}
