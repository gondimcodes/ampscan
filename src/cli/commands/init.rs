//! CLI init command implementation
use crate::auth;
use crate::cli::args::Cli;
use crate::cli::auth_helper::prompt_username;
use crate::db::{self, port_repo, user_repo};
use anyhow::Result;
use colored::Colorize;

pub async fn cmd_init(cli: &Cli) -> Result<()> {
    let db_path = cli.db_path.as_deref().unwrap_or("ampscan.db");
    let mut key = db::get_db_key()?;

    println!("{}", "Initializing database...".cyan());

    // If database files already exist, remove them to allow fresh initialization
    if std::path::Path::new(db_path).exists() {
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
        let _ = std::fs::remove_file(format!("{}-shm", db_path));
    }

    let db = db::open_database(db_path, &key)?;
    db::zeroize_key(&mut key);

    // Seed default ports
    port_repo::seed_default_ports(&db)?;
    println!(
        "  {} Default amplification ports registered / synchronized",
        "✓".green()
    );

    // Create admin user if none exists
    if !user_repo::has_users(&db)? {
        println!("\n{}", "Creating administrator user:".yellow());
        let username = prompt_username()?;
        let password = auth::prompt_new_password()?;
        user_repo::create_user(&db, &username, &password)?;
        println!("  {} User '{}' successfully created", "✓".green(), username);
    } else {
        println!(
            "  {} Users already exist, skipping admin creation",
            "ℹ".blue()
        );
    }

    println!(
        "\n{} Database initialized at: {}",
        "✓".green().bold(),
        db_path
    );
    println!(
        "  The database is encrypted with AES-256 (SQLCipher).\n  \
         Keep your AMPSCAN_DB_KEY secure!"
    );

    Ok(())
}
