//! YAML target loading, CIDR deduplication, and lazy address iteration.
//!
//! Accepts either `{ targets: [...] }` or a top-level YAML sequence of CIDR
//! ranges / single IPs. Overlapping entries are merged with
//! [`ipnet::IpNet::aggregate`], and addresses are produced by a cursor
//! iterator so even huge ranges are never expanded into memory.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ipnet::IpNet;
use serde::Deserialize;

/// On-disk shape: `{ targets: [...] }` or a top-level `[...]`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TargetsDoc {
    Map { targets: Vec<String> },
    Seq(Vec<String>),
}

/// Failure to load or parse a YAML target file.
#[derive(Debug)]
pub enum TargetsError {
    Io(std::io::Error),
    Yaml(String),
    Addr(String),
}

impl fmt::Display for TargetsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "cannot read target file: {err}"),
            Self::Yaml(err) => write!(f, "invalid YAML target file: {err}"),
            Self::Addr(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for TargetsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Yaml(_) | Self::Addr(_) => None,
        }
    }
}

impl From<std::io::Error> for TargetsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Deduplicated set of authorized target networks.
#[derive(Debug, Clone, Default)]
pub struct TargetSet {
    nets: Vec<IpNet>,
}

impl TargetSet {
    /// Number of aggregated networks (after overlap removal).
    #[must_use]
    pub fn net_count(&self) -> usize {
        self.nets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// Total address count (saturating). Cheap: never iterates the space.
    #[must_use]
    pub fn address_count(&self) -> u128 {
        self.nets
            .iter()
            .map(net_size)
            .fold(0, |acc, n| acc.saturating_add(n))
    }

    /// Lazily iterate every address in every network, in order.
    pub fn iter(&self) -> TargetAddrIter<'_> {
        TargetAddrIter {
            nets: self.nets.iter(),
            cursor: None,
        }
    }
}

fn net_size(net: &IpNet) -> u128 {
    match net {
        IpNet::V4(n) => 1u128 << (32 - n.prefix_len()),
        IpNet::V6(n) => {
            let host_bits = 128 - n.prefix_len();
            if host_bits == 128 {
                u128::MAX
            } else {
                1u128 << host_bits
            }
        }
    }
}

/// Load, parse, and deduplicate targets from a YAML file.
pub fn load_targets(path: &Path) -> Result<TargetSet, TargetsError> {
    let text = std::fs::read_to_string(path)?;
    parse_targets(&text)
}

/// Parse and deduplicate targets from a YAML string.
pub fn parse_targets(text: &str) -> Result<TargetSet, TargetsError> {
    let doc: TargetsDoc =
        serde_yml::from_str(text).map_err(|err| TargetsError::Yaml(err.to_string()))?;
    let entries = match doc {
        TargetsDoc::Map { targets } => targets,
        TargetsDoc::Seq(entries) => entries,
    };
    let mut nets = Vec::with_capacity(entries.len());
    for entry in &entries {
        nets.push(parse_entry(entry)?);
    }
    Ok(TargetSet {
        nets: IpNet::aggregate(&nets),
    })
}

#[derive(Debug, Clone, Copy)]
enum Cursor {
    V4 { next: u32, end: u32 },
    V6 { next: u128, end: u128 },
}

/// Parse one target entry: `address/prefix` CIDR or a bare IP
/// (implying a /32 or /128 host route).
fn parse_entry(entry: &str) -> Result<IpNet, TargetsError> {
    if let Ok(net) = entry.parse::<IpNet>() {
        return Ok(net);
    }
    entry
        .parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|err| TargetsError::Addr(format!("invalid CIDR or IP address: {entry} ({err})")))
}

fn cursor_for(net: &IpNet) -> Cursor {
    match net {
        IpNet::V4(n) => Cursor::V4 {
            next: u32::from(n.network()),
            end: u32::from(n.broadcast()),
        },
        IpNet::V6(n) => {
            let start = u128::from(n.network());
            let host_bits = 128 - n.prefix_len();
            let end = if host_bits == 128 {
                u128::MAX
            } else {
                start + ((1u128 << host_bits) - 1)
            };
            Cursor::V6 { next: start, end }
        }
    }
}

/// Lazy address iterator over a [`TargetSet`]; holds only a cursor.
#[derive(Debug)]
pub struct TargetAddrIter<'a> {
    nets: std::slice::Iter<'a, IpNet>,
    cursor: Option<Cursor>,
}

impl Iterator for TargetAddrIter<'_> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        loop {
            match &mut self.cursor {
                Some(Cursor::V4 { next, end }) => {
                    let cur = *next;
                    if cur == *end {
                        self.cursor = None;
                    } else {
                        *next = cur + 1;
                    }
                    return Some(IpAddr::V4(Ipv4Addr::from(cur)));
                }
                Some(Cursor::V6 { next, end }) => {
                    let cur = *next;
                    if cur == *end {
                        self.cursor = None;
                    } else {
                        *next = cur + 1;
                    }
                    return Some(IpAddr::V6(Ipv6Addr::from(cur)));
                }
                None => {
                    let net = self.nets.next()?;
                    self.cursor = Some(cursor_for(net));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_map_shape_and_aggregates_overlap() {
        let set =
            parse_targets("targets:\n  - 10.0.0.0/24\n  - 10.0.0.0/25\n  - 127.0.0.1\n")
                .expect("parse targets");
        // /25 is absorbed into /24; the bare IP stays separate.
        assert_eq!(set.net_count(), 2);
        let addrs: Vec<IpAddr> = set.iter().collect();
        assert_eq!(addrs.len(), 256 + 1);
        assert!(addrs.contains(&IpAddr::from([127, 0, 0, 1])));
    }

    #[test]
    fn parses_top_level_sequence() {
        let set = parse_targets("- 192.168.1.0/31\n").expect("parse targets");
        assert_eq!(set.address_count(), 2);
    }

    #[test]
    fn rejects_garbage_entries() {
        assert!(parse_targets("targets:\n  - not-an-ip\n").is_err());
    }
}
