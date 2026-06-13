pub mod models;
pub mod port_repo;
pub mod prefix_repo;
pub mod user_repo;

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

/// Thread-safe handle to the encrypted SQLCipher database.
pub type DbConn = Arc<Mutex<Connection>>;

/// Open (or create) an encrypted database at the given path with the given key.
/// Runs migrations to ensure schema is up to date.
pub fn open_database(path: &str, key: &str) -> Result<DbConn> {
    let conn = Connection::open(path)
        .with_context(|| format!("Failed to open database file: {}", path))?;

    // Set the SQLCipher encryption key (AES-256)
    conn.pragma_update(None, "key", key)
        .context("Failed to set database encryption key")?;

    // Verify the key is correct by attempting to read the schema
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .context(
            "Invalid database encryption key. \
             Check that AMPSCAN_DB_KEY is set correctly.",
        )?;

    // Performance: enable WAL mode
    conn.pragma_update(None, "journal_mode", "WAL").ok();

    let conn = Arc::new(Mutex::new(conn));
    run_migrations(&conn)?;
    Ok(conn)
}

/// Create all tables if they don't exist yet.
fn run_migrations(conn: &DbConn) -> Result<()> {
    let conn = conn.lock().unwrap();
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL CHECK(protocol IN ('udp', 'tcp')),
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            probe_type TEXT NOT NULL,
            probe_payload BLOB,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(port, protocol)
        );

        CREATE TABLE IF NOT EXISTS prefixes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prefix TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            ip_version INTEGER NOT NULL CHECK(ip_version IN (4, 6)),
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        ",
    )
    .context("Failed to run database migrations")?;
    Ok(())
}

/// Get database path from env var or use default.
pub fn get_db_path() -> String {
    std::env::var("AMPSCAN_DB_PATH").unwrap_or_else(|_| "ampscan.db".to_string())
}

/// Get database encryption key from env var. Fails if not set.
pub fn get_db_key() -> Result<String> {
    std::env::var("AMPSCAN_DB_KEY").context(
        "AMPSCAN_DB_KEY environment variable not set.\n\
         Set it with: export AMPSCAN_DB_KEY='your-secret-key'\n\
         Use a strong, random key (e.g., 32+ characters).",
    )
}
