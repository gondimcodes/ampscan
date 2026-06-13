use serde::{Deserialize, Serialize};

/// Represents an amplification port to be tested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub id: i64,
    pub port: u16,
    /// "udp" or "tcp"
    pub protocol: String,
    /// Human-readable name (e.g., "DNS", "NTP", "SNMP")
    pub name: String,
    /// Description of the amplification risk
    pub description: String,
    /// Probe type identifier: "dns", "snmp", "ntp", "udp_payload", "tcp_connect", etc.
    pub probe_type: String,
    /// Raw payload bytes for "udp_payload" probe type; None for code-built probes
    pub probe_payload: Option<Vec<u8>>,
    /// Whether this port is enabled for scanning
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Represents a network prefix (CIDR) to be scanned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prefix {
    pub id: i64,
    /// CIDR notation, e.g., "192.168.0.0/24" or "2001:db8::/120"
    pub prefix: String,
    /// Description of this prefix (e.g., customer name, AS number)
    pub description: String,
    /// 4 for IPv4, 6 for IPv6
    pub ip_version: u8,
    /// Whether this prefix is enabled for scanning
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Represents an admin user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    /// Argon2id hash — skipped in serialization to prevent accidental exposure
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: String,
    pub updated_at: String,
}
