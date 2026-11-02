//! Port Repository
//!
//! Handles all SQLite database operations for amplification ports.
use super::models::Port;
use super::{lock_db, DbConn};
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
    let c = lock_db(conn)?;
    c.execute(
        "INSERT OR IGNORE INTO ports (port, protocol, name, description, probe_type, probe_payload)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            port as i64,
            protocol,
            name,
            description,
            probe_type,
            probe_payload
        ],
    )
    .context("Failed to insert port")?;
    Ok(c.last_insert_rowid())
}

/// List all ports, ordered by port number.
pub fn list_ports(conn: &DbConn) -> Result<Vec<Port>> {
    let c = lock_db(conn)?;
    let mut stmt = c
        .prepare(&format!(
            "SELECT {} FROM ports ORDER BY port, protocol",
            SELECT_COLS
        ))
        .context("Failed to prepare port list query")?;
    let ports = stmt
        .query_map([], row_to_port)?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to read ports")?;
    Ok(ports)
}

/// Get only enabled ports, ordered by port number.
pub fn get_enabled_ports(conn: &DbConn) -> Result<Vec<Port>> {
    let c = lock_db(conn)?;
    let mut stmt = c
        .prepare(&format!(
            "SELECT {} FROM ports WHERE enabled != 0 ORDER BY port, protocol",
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
    let c = lock_db(conn)?;
    let val = if enabled { 1 } else { 0 };
    let rows = c.execute(
        "UPDATE ports SET enabled = ?1, updated_at = datetime('now') WHERE id = ?2",
        rusqlite::params![val, id],
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
    let c = lock_db(conn)?;
    if let Some(name) = name {
        c.execute(
            "UPDATE ports SET name = ?1, updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![name, id],
        )?;
    }
    if let Some(desc) = description {
        c.execute(
            "UPDATE ports SET description = ?1, updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![desc, id],
        )?;
    }
    Ok(())
}

/// Delete a port by id.
pub fn delete_port(conn: &DbConn, id: i64) -> Result<()> {
    let c = lock_db(conn)?;
    let rows = c.execute("DELETE FROM ports WHERE id = ?1", rusqlite::params![id])?;
    if rows == 0 {
        anyhow::bail!("Port with id {} not found", id);
    }
    Ok(())
}

/// Seed the database with default amplification ports.
pub fn seed_default_ports(conn: &DbConn) -> Result<()> {
    for p in super::default_ports::DEFAULT_PORTS {
        let payload_opt = if p.payload.is_empty() {
            None
        } else {
            Some(p.payload)
        };
        insert_port(
            conn,
            p.port,
            p.protocol,
            p.name,
            p.description,
            p.probe_type,
            payload_opt,
        )?;
    }

    Ok(())
}
