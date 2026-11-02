//! Authentication and database connection helper for CLI operations
use super::args::Cli;
use crate::auth;
use crate::db::{self, user_repo, DbConn};
use anyhow::Result;
use std::io::{self, Write};

/// Open the database and authenticate the user.
pub fn open_and_auth(cli: &Cli) -> Result<DbConn> {
    let db_path = match &cli.db_path {
        Some(p) => p.as_str(),
        None => anyhow::bail!("O parâmetro --db-path é obrigatório."),
    };

    // Ensure database file exists before trying to open it
    if !std::path::Path::new(db_path).exists() {
        anyhow::bail!(
            "Database file '{}' not found. Run 'ampscan init' first.",
            db_path
        );
    }

    let mut key = db::get_db_key()?;
    let db = db::open_database(db_path, &key)?;
    // Zeroize our copy of the key from the heap immediately after the connection is open.
    // SQLCipher has already copied it into its internal cipher state.
    db::zeroize_key(&mut key);

    // Check if initialized
    if !user_repo::has_users(&db)? {
        anyhow::bail!("Database not initialized. Run 'ampscan init' first.");
    }

    // Get username
    let username = match &cli.user {
        Some(u) => u.clone(),
        None => {
            print!("Username: ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };

    let password = auth::prompt_password()?;
    user_repo::authenticate(&db, &username, &password)?;

    Ok(db)
}

/// Prompt for a username interactively.
pub fn prompt_username() -> Result<String> {
    print!("Username: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let username = input.trim().to_string();
    if username.is_empty() {
        anyhow::bail!("Username cannot be empty.");
    }
    Ok(username)
}
