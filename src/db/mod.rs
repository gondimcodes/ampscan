pub mod models;
pub mod port_repo;
pub mod prefix_repo;
pub mod user_repo;

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroize;

/// Thread-safe handle to the encrypted SQLCipher database.
pub type DbConn = Arc<Mutex<Connection>>;

/// Lock the database, converting a PoisonError into an anyhow::Error.
///
/// Using `.unwrap()` on a poisoned Mutex causes a panic cascade: if any thread panics
/// while holding the lock, every subsequent access via unwrap() also panics.
/// This helper converts the PoisonError into a recoverable error.
pub(crate) fn lock_db(conn: &DbConn) -> Result<MutexGuard<'_, Connection>> {
    conn.lock()
        .map_err(|_| anyhow::anyhow!("Database lock is poisoned (a thread panicked while holding it). Restart the process."))
}

/// Open (or create) an encrypted database at the given path with the given key.
/// Runs migrations to ensure schema is up to date.
pub fn open_database(path: &str, key: &str) -> Result<DbConn> {
    let conn = Connection::open(path)
        .with_context(|| format!("Failed to open database file: {}", path))?;

    // Set the SQLCipher encryption key (AES-256).
    // The key is passed as a string pragma; SQLCipher copies it into its internal state.
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

// ─────────────────────────────────────────────────────────────────────────────
// Schema
// ─────────────────────────────────────────────────────────────────────────────

const BASE_SCHEMA: &str = "
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
";

/// Create all tables and apply any pending schema migrations.
///
/// The `schema_version` table tracks the migration level applied to this database,
/// allowing safe incremental ALTER TABLE migrations in future versions without
/// requiring a full re-initialization.
fn run_migrations(conn: &DbConn) -> Result<()> {
    let c = lock_db(conn)?;

    // Step 1: Create base tables (safe to run on any existing DB)
    c.execute_batch(BASE_SCHEMA)
        .context("Failed to create base database schema")?;

    // Step 2: Create schema versioning table if it doesn't exist
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .context("Failed to create schema_version table")?;

    // Step 3: Determine current version (0 = pre-versioning, i.e. v1.2.x databases)
    let current_version: i64 = c
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Step 4: Apply pending migrations in order
    //
    // Migration 1 (v1.3.0): Initial versioning baseline.
    // All databases — whether freshly created or upgraded from v1.2.x — are brought
    // to version 1. No schema changes are needed; this simply records the baseline.
    if current_version < 1 {
        c.execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .context("Failed to record migration to version 1")?;
    }

    // Future migrations go here:
    // if current_version < 2 {
    //     c.execute_batch("ALTER TABLE ports ADD COLUMN amplification_factor REAL;")?;
    //     c.execute("INSERT INTO schema_version (version) VALUES (2)", [])?;
    // }

    // Step 5: Legacy data fixes (carried over from v1.2.x)
    let _ = c.execute(
        "UPDATE ports SET description = ?1 WHERE port = 161 AND protocol = 'udp'",
        rusqlite::params!["Simple Network Management Protocol - 'public' community exposes data and amplifies up to 6.3x"],
    );
    let _ = c.execute(
        "UPDATE ports SET description = ?1 WHERE port = 137 AND protocol = 'udp'",
        rusqlite::params!["NetBIOS Name Service - exposure reveals network information and allows amplification"],
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Environment helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Get database path from env var or use default.
pub fn get_db_path() -> String {
    std::env::var("AMPSCAN_DB_PATH").unwrap_or_else(|_| "ampscan.db".to_string())
}

/// Get database encryption key from env var, then immediately remove it from the
/// environment to reduce the window during which child processes or same-UID
/// processes could read it via /proc/<pid>/environ or `env` inspection.
///
/// # Security note
/// The key is returned as a plain `String`. Callers are responsible for zeroizing
/// it after use via `zeroize::Zeroize::zeroize(&mut key)`.
/// The AMPSCAN_DB_KEY env var is still visible in /proc/<pid>/environ *before*
/// this function runs (snapshot at process start), but removing it here prevents
/// inheritance by child processes (e.g., shell expansions, PDF tools).
pub fn get_db_key() -> Result<String> {
    let key = std::env::var("AMPSCAN_DB_KEY").context(
        "AMPSCAN_DB_KEY environment variable not set.\n\
         Set it with: export AMPSCAN_DB_KEY='your-secret-key'\n\
         Use a strong, random key (e.g., 32+ characters).",
    )?;
    // Remove from environment immediately after reading
    std::env::remove_var("AMPSCAN_DB_KEY");
    Ok(key)
}

/// Zeroize a key string, overwriting its heap memory with zeros before drop.
/// Call this after the key is no longer needed (e.g., after open_database returns).
pub fn zeroize_key(key: &mut String) {
    key.zeroize();
}
