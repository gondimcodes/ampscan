//! Port Repository
//!
//! Handles all SQLite database operations for amplification ports.
use super::models::Port;
use super::DbConn;
use anyhow::{Context, Result};

/// Helper to map a rusqlite Row to a Port struct.
fn row_to_port(row: &rusqlite::Row) -> rusqlite::Result<Port> {
    Ok(Port {
        id: row.get(0)?,
        port: row.get::<_, i64>(1)? as u16,
        protocol: row.get(2)?,
        name: row.get(3)?,
        description: row.get(4)?,
        probe_type: row.get(5)?,
        probe_payload: row.get(6)?,
        enabled: row.get::<_, i64>(7)? != 0,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

const SELECT_COLS: &str =
    "id, port, protocol, name, description, probe_type, probe_payload, enabled, created_at, updated_at";

/// Insert a new amplification port.
pub fn insert_port(
    conn: &DbConn,
    port: u16,
    protocol: &str,
    name: &str,
    description: &str,
    probe_type: &str,
    probe_payload: Option<&[u8]>,
) -> Result<i64> {
    let conn = conn.lock().unwrap();
    conn.execute(
        "INSERT INTO ports (port, protocol, name, description, probe_type, probe_payload)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![port as i64, protocol, name, description, probe_type, probe_payload],
    )
    .context("Failed to insert port (may already exist with same port/protocol)")?;
    Ok(conn.last_insert_rowid())
}

/// List all ports, ordered by port number.
pub fn list_ports(conn: &DbConn) -> Result<Vec<Port>> {
    let conn = conn.lock().unwrap();
    let mut stmt = conn
        .prepare(&format!("SELECT {} FROM ports ORDER BY port, protocol", SELECT_COLS))
        .context("Failed to prepare port list query")?;
    let ports = stmt
        .query_map([], row_to_port)?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to read ports")?;
    Ok(ports)
}

/// Get only enabled ports, ordered by port number.
pub fn get_enabled_ports(conn: &DbConn) -> Result<Vec<Port>> {
    let conn = conn.lock().unwrap();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {} FROM ports WHERE enabled = 1 ORDER BY port, protocol",
            SELECT_COLS
        ))
        .context("Failed to prepare enabled ports query")?;
    let ports = stmt
        .query_map([], row_to_port)?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to read enabled ports")?;
    Ok(ports)
}

/// Enable or disable a port by id.
pub fn toggle_port(conn: &DbConn, id: i64, enabled: bool) -> Result<()> {
    let conn = conn.lock().unwrap();
    let rows = conn.execute(
        "UPDATE ports SET enabled = ?1, updated_at = datetime('now') WHERE id = ?2",
        rusqlite::params![enabled as i64, id],
    )?;
    if rows == 0 {
        anyhow::bail!("Port with id {} not found", id);
    }
    Ok(())
}

/// Update port name and/or description.
pub fn update_port(
    conn: &DbConn,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<()> {
    let conn = conn.lock().unwrap();
    if let Some(name) = name {
        conn.execute(
            "UPDATE ports SET name = ?1, updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![name, id],
        )?;
    }
    if let Some(desc) = description {
        conn.execute(
            "UPDATE ports SET description = ?1, updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![desc, id],
        )?;
    }
    Ok(())
}

/// Delete a port by id.
pub fn delete_port(conn: &DbConn, id: i64) -> Result<()> {
    let conn = conn.lock().unwrap();
    let rows = conn.execute("DELETE FROM ports WHERE id = ?1", rusqlite::params![id])?;
    if rows == 0 {
        anyhow::bail!("Port with id {} not found", id);
    }
    Ok(())
}

/// Seed the database with the 20 default amplification ports from the original script.
/// Only inserts if the ports table is empty.
pub fn seed_default_ports(conn: &DbConn) -> Result<()> {
    // Check if already seeded
    {
        let c = conn.lock().unwrap();
        let count: i64 = c.query_row("SELECT COUNT(*) FROM ports", [], |row| row.get(0))?;
        if count > 0 {
            return Ok(());
        }
    }

    // (port, protocol, name, description, probe_type, probe_payload)
    let defaults: Vec<(u16, &str, &str, &str, &str, Vec<u8>)> = vec![
        // ── UDP probes ──────────────────────────────────────────────────
        (
            17, "udp", "QOTD",
            "Quote of the Day - legacy service that responds to any packet, used for DDoS amplification",
            "udp_payload", vec![],
        ),
        (
            19, "udp", "CHARGEN",
            "Character Generator - legacy service that generates a character stream, used for DDoS amplification",
            "udp_payload", vec![],
        ),
        (
            53, "udp", "DNS",
            "Domain Name System - open resolvers can amplify traffic up to 54x",
            "dns", vec![],
        ),
        (
            69, "udp", "TFTP",
            "Trivial File Transfer Protocol - exposed TFTP servers allow file extraction and amplification",
            "tftp", vec![],
        ),
        (
            111, "udp", "RPC",
            "Remote Procedure Call Portmapper - exposure allows service enumeration and amplification",
            "rpc", vec![],
        ),
        (
            123, "udp", "NTP",
            "Network Time Protocol - servers with monlist/readvar amplify traffic up to 556x",
            "ntp", vec![],
        ),
        (
            137, "udp", "NETBIOS",
            "NetBIOS Name Service - exposure reveals network information and allows amplification",
            "netbios", vec![],
        ),
        (
            161, "udp", "SNMP",
            "Simple Network Management Protocol - 'public' community exposes data and amplifies up to 6.3x",
            "snmp", vec![],
        ),
        (
            389, "udp", "LDAP",
            "CLDAP - Connectionless LDAP used for massive amplification up to 70x",
            "ldap", vec![],
        ),
        (
            427, "udp", "SLP",
            "Service Location Protocol - used for service amplification up to 2200x",
            "udp_payload",
            vec![
                0x02, 0x01, 0x00, 0x00, 0x36, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x02, 0x65, 0x6e, 0x00, 0x00, 0x00, 0x15, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
                0x65, 0x3a, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x61, 0x67, 0x65,
                0x6e, 0x74, 0x00, 0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 0x00,
                0x00, 0x00,
            ],
        ),
        (
            1900, "udp", "SSDP",
            "Simple Service Discovery Protocol - UPnP amplifies traffic up to 30x",
            "ssdp", vec![],
        ),
        (
            3283, "udp", "ARMS",
            "Apple Remote Management Service - amplification via Apple Remote Desktop",
            "udp_payload",
            vec![0x00, 0x14, 0x00, 0x01, 0x03],
        ),
        (
            3702, "udp", "WS-DISCOVERY",
            "Web Services Dynamic Discovery - SOAP/XML amplification up to 153x",
            "udp_payload",
            vec![0x3C, 0xAA, 0x3E, 0x0A],
        ),
        (
            5353, "udp", "mDNS",
            "Multicast DNS - open mDNS resolvers amplify up to 4.7x",
            "mdns", vec![],
        ),
        (
            5683, "udp", "CoAP",
            "Constrained Application Protocol - IoT devices amplify up to 34x",
            "udp_payload",
            vec![
                0x40, 0x01, 0x7d, 0x70, 0xbb, 0x2e, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e,
                0x6f, 0x77, 0x6e, 0x04, 0x63, 0x6f, 0x72, 0x65,
            ],
        ),
        (
            10001, "udp", "UBNT",
            "Ubiquiti Discovery Protocol - exposed Ubiquiti devices on the network",
            "udp_payload",
            vec![0x01, 0x00, 0x00, 0x00],
        ),
        (
            11211, "udp", "MEMCACHED",
            "Memcached - massive amplification up to 51000x, extremely dangerous",
            "memcached", vec![],
        ),
        (
            37810, "udp", "DVR-DHCPDiscover",
            "DVR DHCP Discovery - exposed cameras and DVRs responding to discovery",
            "udp_payload",
            vec![0xFF],
        ),
        // ── TCP probes ──────────────────────────────────────────────────
        (
            4145, "tcp", "MT4145",
            "MikroTik open SOCKS proxy - may indicate a compromised MikroTik device",
            "tcp_connect", vec![],
        ),
        (
            5678, "tcp", "MT5678",
            "MikroTik Meris botnet - indicates possible Meris botnet infection (DDoS)",
            "tcp_connect", vec![],
        ),
    ];

    for (port, proto, name, desc, probe_type, payload) in defaults {
        let payload_opt = if payload.is_empty() {
            None
        } else {
            Some(payload.as_slice())
        };
        insert_port(conn, port, proto, name, desc, probe_type, payload_opt)?;
    }

    Ok(())
}
