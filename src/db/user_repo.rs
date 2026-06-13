use super::models::User;
use super::DbConn;
use crate::auth;
use anyhow::{Context, Result};

/// Create a new admin user with an Argon2id-hashed password.
pub fn create_user(conn: &DbConn, username: &str, password: &str) -> Result<i64> {
    let password_hash = auth::hash_password(password)?;
    let conn = conn.lock().unwrap();
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        rusqlite::params![username, password_hash],
    )
    .with_context(|| format!("Failed to create user '{}' (may already exist)", username))?;
    Ok(conn.last_insert_rowid())
}

/// Authenticate a user by verifying password against stored Argon2id hash.
/// Returns the User on success, error on failure.
pub fn authenticate(conn: &DbConn, username: &str, password: &str) -> Result<User> {
    let user = get_user_by_username(conn, username)?;
    if auth::verify_password(password, &user.password_hash)? {
        Ok(user)
    } else {
        anyhow::bail!("Authentication failed: invalid password for user '{}'", username)
    }
}

/// Get a user by username.
pub fn get_user_by_username(conn: &DbConn, username: &str) -> Result<User> {
    let conn = conn.lock().unwrap();
    conn.query_row(
        "SELECT id, username, password_hash, created_at, updated_at
         FROM users WHERE username = ?1",
        rusqlite::params![username],
        |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password_hash: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        },
    )
    .with_context(|| format!("User '{}' not found", username))
}

/// List all users (without password hashes in the display).
pub fn list_users(conn: &DbConn) -> Result<Vec<User>> {
    let conn = conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, username, password_hash, created_at, updated_at
             FROM users ORDER BY username",
        )
        .context("Failed to prepare user list query")?;
    let users = stmt
        .query_map([], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                password_hash: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to read users")?;
    Ok(users)
}

/// Change a user's password.
pub fn change_password(conn: &DbConn, username: &str, new_password: &str) -> Result<()> {
    let new_hash = auth::hash_password(new_password)?;
    let conn = conn.lock().unwrap();
    let rows = conn.execute(
        "UPDATE users SET password_hash = ?1, updated_at = datetime('now') WHERE username = ?2",
        rusqlite::params![new_hash, username],
    )?;
    if rows == 0 {
        anyhow::bail!("User '{}' not found", username);
    }
    Ok(())
}

/// Delete a user by id.
pub fn delete_user(conn: &DbConn, id: i64) -> Result<()> {
    let conn = conn.lock().unwrap();
    // Prevent deleting the last user
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
    if count <= 1 {
        anyhow::bail!("Cannot delete the last admin user");
    }
    let rows = conn.execute("DELETE FROM users WHERE id = ?1", rusqlite::params![id])?;
    if rows == 0 {
        anyhow::bail!("User with id {} not found", id);
    }
    Ok(())
}

/// Check if any users exist (for initial setup detection).
pub fn has_users(conn: &DbConn) -> Result<bool> {
    let conn = conn.lock().unwrap();
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
    Ok(count > 0)
}
