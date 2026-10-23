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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub status: PortStatus,
}

/// Probe one port: connect wins → open, refused → closed, timeout (or any
/// other network error) → filtered.
pub async fn probe(ip: IpAddr, port: u16, timeout: Duration) -> PortStatus {
    let addr = SocketAddr::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => PortStatus::Open,
        Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused => PortStatus::Closed,
        Ok(Err(_)) | Err(_) => PortStatus::Filtered,
    }
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
                let status = probe(ip, port, timeout).await;
                drop(permit);
                let _ = tx.send(ScanResult { ip, port, status }).await;
            });
        }
    }
}
