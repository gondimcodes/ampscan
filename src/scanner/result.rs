use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

/// Status of a single port probe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortStatus {
    /// Port responded to the probe — vulnerable to amplification
    Open,
    /// Port is open but protected (e.g., DNS refused recursion)
    OpenProtected,
    /// Host is alive but port did not respond — not vulnerable
    Closed,
    /// Host did not respond to ICMP — cannot determine port status
    Inconclusive,
    /// An error occurred during probing
    Error(String),
}

impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortStatus::Open => write!(f, "OPEN (VULNERABLE)"),
            PortStatus::OpenProtected => write!(f, "OPEN (PROTECTED)"),
            PortStatus::Closed => write!(f, "CLOSED"),
            PortStatus::Inconclusive => write!(f, "INCONCLUSIVE"),
            PortStatus::Error(e) => write!(f, "ERROR: {}", e),
        }
    }
}

/// Result of a single probe against one IP:port combination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub description: String,
    pub status: PortStatus,
    pub response_time_ms: Option<u64>,
    pub timestamp: DateTime<Utc>,
}

/// Aggregated report for an entire scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub prefixes_scanned: Vec<String>,
    pub total_ips: usize,
    pub total_probes: usize,
    pub results: Vec<ProbeResult>,
}

impl ScanReport {
    pub fn new(scan_id: String, prefixes: Vec<String>) -> Self {
        Self {
            scan_id,
            started_at: Utc::now(),
            finished_at: None,
            prefixes_scanned: prefixes,
            total_ips: 0,
            total_probes: 0,
            results: Vec::new(),
        }
    }

    pub fn finalize(&mut self) {
        self.finished_at = Some(Utc::now());
    }

    /// Get only the results where the port is open (vulnerable).
    pub fn vulnerable_results(&self) -> Vec<&ProbeResult> {
        self.results
            .iter()
            .filter(|r| r.status == PortStatus::Open)
            .collect()
    }

    /// Get only the results that are either open (vulnerable) or open (protected).
    pub fn detected_results(&self) -> Vec<&ProbeResult> {
        self.results
            .iter()
            .filter(|r| r.status == PortStatus::Open || r.status == PortStatus::OpenProtected)
            .collect()
    }

    /// Get unique IPs that have at least one vulnerable port.
    pub fn vulnerable_ips(&self) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = self
            .results
            .iter()
            .filter(|r| r.status == PortStatus::Open)
            .map(|r| r.ip)
            .collect();
        ips.sort();
        ips.dedup();
        ips
    }

    /// Get unique IPs that have at least one detected (vulnerable or protected) port.
    pub fn detected_ips(&self) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = self
            .results
            .iter()
            .filter(|r| r.status == PortStatus::Open || r.status == PortStatus::OpenProtected)
            .map(|r| r.ip)
            .collect();
        ips.sort();
        ips.dedup();
        ips
    }

    /// Count of vulnerable results grouped by service name.
    pub fn vulnerable_by_service(&self) -> Vec<(String, usize)> {
        let mut map = std::collections::HashMap::new();
        for r in self.vulnerable_results() {
            *map.entry(r.service_name.clone()).or_insert(0usize) += 1;
        }
        let mut sorted: Vec<_> = map.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted
    }
}
