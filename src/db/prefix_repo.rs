use super::models::Prefix;
use super::DbConn;
use anyhow::{Context, Result};

const SELECT_COLS: &str =
    "id, prefix, description, ip_version, enabled, created_at, updated_at";

fn row_to_prefix(row: &rusqlite::Row) -> rusqlite::Result<Prefix> {
    Ok(Prefix {
        id: row.get(0)?,
        prefix: row.get(1)?,
        description: row.get(2)?,
        ip_version: row.get::<_, i64>(3)? as u8,
        enabled: row.get::<_, i64>(4)? != 0,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

/// Insert a new network prefix.
/// Automatically detects IPv4 vs IPv6 from the prefix string.
pub fn insert_prefix(conn: &DbConn, prefix: &str, description: &str) -> Result<i64> {
    // Validate and detect IP version
    let net: ipnet::IpNet = prefix
        .parse()
        .with_context(|| format!("Invalid CIDR prefix: '{}'", prefix))?;
    let ip_version: u8 = if net.addr().is_ipv4() { 4 } else { 6 };

    // Safety check for IPv6 prefix size
    if ip_version == 6 {
        let prefix_len = net.prefix_len();
        if prefix_len < 112 {
            anyhow::bail!(
                "IPv6 prefix /{} is too large (would scan {} hosts). \
                 Maximum allowed is /112 (65536 hosts). \
                 Use a more specific prefix.",
                prefix_len,
                if prefix_len < 64 {
                    "billions of".to_string()
                } else {
                    format!("2^{}", 128 - prefix_len)
                }
            );
        }
    }

    let conn = conn.lock().unwrap();
    conn.execute(
        "INSERT INTO prefixes (prefix, description, ip_version)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![prefix, description, ip_version as i64],
    )
    .context("Failed to insert prefix (may already exist)")?;
    Ok(conn.last_insert_rowid())
}

/// List all prefixes.
pub fn list_prefixes(conn: &DbConn) -> Result<Vec<Prefix>> {
    let conn = conn.lock().unwrap();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {} FROM prefixes ORDER BY ip_version, prefix",
            SELECT_COLS
        ))
        .context("Failed to prepare prefix list query")?;
    let prefixes = stmt
        .query_map([], row_to_prefix)?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to read prefixes")?;
    Ok(prefixes)
}

/// Get only enabled prefixes.
pub fn get_enabled_prefixes(conn: &DbConn) -> Result<Vec<Prefix>> {
    let conn = conn.lock().unwrap();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {} FROM prefixes WHERE enabled = 1 ORDER BY ip_version, prefix",
            SELECT_COLS
        ))
        .context("Failed to prepare enabled prefixes query")?;
    let prefixes = stmt
        .query_map([], row_to_prefix)?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to read enabled prefixes")?;
    Ok(prefixes)
}

/// Enable or disable a prefix by id.
pub fn toggle_prefix(conn: &DbConn, id: i64, enabled: bool) -> Result<()> {
    let conn = conn.lock().unwrap();
    let rows = conn.execute(
        "UPDATE prefixes SET enabled = ?1, updated_at = datetime('now') WHERE id = ?2",
        rusqlite::params![enabled as i64, id],
    )?;
    if rows == 0 {
        anyhow::bail!("Prefix with id {} not found", id);
    }
    Ok(())
}

/// Update prefix and/or description.
pub fn update_prefix(
    conn: &DbConn,
    id: i64,
    prefix: Option<&str>,
    description: Option<&str>,
) -> Result<()> {
    if let Some(prefix) = prefix {
        // Validate new prefix
        let net: ipnet::IpNet = prefix
            .parse()
            .with_context(|| format!("Invalid CIDR prefix: '{}'", prefix))?;
        let ip_version: i64 = if net.addr().is_ipv4() { 4 } else { 6 };

        let conn = conn.lock().unwrap();
        conn.execute(
            "UPDATE prefixes SET prefix = ?1, ip_version = ?2, updated_at = datetime('now') WHERE id = ?3",
            rusqlite::params![prefix, ip_version, id],
        )?;
    }
    if let Some(desc) = description {
        let conn = conn.lock().unwrap();
        conn.execute(
            "UPDATE prefixes SET description = ?1, updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![desc, id],
        )?;
    }
    Ok(())
}

/// Delete a prefix by id.
pub fn delete_prefix(conn: &DbConn, id: i64) -> Result<()> {
    let conn = conn.lock().unwrap();
    let rows = conn.execute("DELETE FROM prefixes WHERE id = ?1", rusqlite::params![id])?;
    if rows == 0 {
        anyhow::bail!("Prefix with id {} not found", id);
    }
    Ok(())
}
