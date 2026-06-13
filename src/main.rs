//! AmpScan CLI Entrypoint
//!
//! This file parses command-line arguments using `clap` and acts as the main
//! orchestrator for all AmpScan functionality, including database initialization,
//! port/prefix management, user authentication, and executing network scans.
use ampscan::db::{self, port_repo, prefix_repo, user_repo, DbConn};
use ampscan::scanner::{self, ScanConfig};
use ampscan::{auth, report};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use std::io::{self, Write};
use std::net::IpAddr;
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════════════
// CLI Structure (clap derive)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Parser)]
#[command(
    name = "ampscan",
    about = "AmpScan — DDoS Amplification Port Testing Tool",
    long_about = "Tests DDoS amplification ports across IPv4/IPv6 prefixes.\n\
                  Requires AMPSCAN_DB_KEY as an environment variable for database encryption.",
    version
)]
struct Cli {
    /// Database file path
    #[arg(long, default_value = "ampscan.db", global = true)]
    db_path: String,

    /// Admin user (or set AMPSCAN_USER environment variable)
    #[arg(short, long, global = true, env = "AMPSCAN_USER")]
    user: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize database and create administrator user
    Init,

    /// Manage amplification ports
    #[command(subcommand)]
    Port(PortCommands),

    /// Manage network prefixes (CIDR)
    #[command(subcommand)]
    Prefix(PrefixCommands),

    /// Manage administrator users
    #[command(subcommand)]
    User(UserCommands),

    /// Execute amplification scan
    #[command(subcommand)]
    Scan(ScanCommands),
}

#[derive(Subcommand)]
enum PortCommands {
    /// List all registered ports
    List,
    /// Enable a port for testing
    Enable {
        /// Port ID
        id: i64,
    },
    /// Disable a port (will not be tested)
    Disable {
        /// Port ID
        id: i64,
    },
}

#[derive(Subcommand)]
enum PrefixCommands {
    /// List all registered prefixes
    List,
    /// Add a new network prefix
    Add {
        /// CIDR Prefix (e.g., 192.168.0.0/24 or 2001:db8::/120)
        #[arg(short, long)]
        prefix: String,
        /// Description (e.g., client name, AS)
        #[arg(short, long, default_value = "")]
        description: String,
    },
    /// Edit an existing prefix
    Edit {
        /// Prefix ID
        id: i64,
        /// New CIDR Prefix
        #[arg(short, long)]
        prefix: Option<String>,
        /// New description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Remove a prefix
    Remove {
        /// Prefix ID
        id: i64,
    },
    /// Enable a prefix for scanning
    Enable {
        /// Prefix ID
        id: i64,
    },
    /// Disable a prefix (will not be scanned)
    Disable {
        /// Prefix ID
        id: i64,
    },
}

#[derive(Subcommand)]
enum UserCommands {
    /// List users
    List,
    /// Add a new administrator user
    Add {
        /// Username
        #[arg(short = 'n', long)]
        username: String,
    },
    /// Change a user's password
    ChangePassword {
        /// Username
        #[arg(short = 'n', long)]
        username: String,
    },
    /// Remove a user
    Remove {
        /// User ID
        id: i64,
    },
}

#[derive(Subcommand)]
enum ScanCommands {
    /// Run a full scan on all enabled prefixes
    Run {
        /// Maximum number of simultaneous probes
        #[arg(short, long, default_value = "256")]
        concurrency: usize,
        /// Timeout per probe in seconds
        #[arg(short, long, default_value = "3")]
        timeout: u64,
        /// Output PDF report file path
        #[arg(short, long, default_value = "ampscan_report.pdf")]
        output: String,
        /// Disable ICMP check (doesn't require root, but loses Closed/Inconclusive distinction)
        #[arg(long)]
        no_icmp: bool,
        /// Manual CIDR prefix to test directly (ignores database and skips PDF)
        #[arg(long)]
        prefix: Option<String>,
        /// Request PDF report generation
        #[arg(long)]
        pdf: bool,
        /// Company/client name for the report
        #[arg(long)]
        client_name: Option<String>,
        /// PDF report recipient (e.g., manager or department name)
        #[arg(long)]
        recipient: Option<String>,
    },
    /// Test a single IP against all enabled ports
    Single {
        /// IP Address (IPv4 or IPv6)
        ip: String,
        /// Timeout per probe in seconds
        #[arg(short, long, default_value = "3")]
        timeout: u64,
        /// Disable ICMP check
        #[arg(long)]
        no_icmp: bool,
    },
}

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

fn print_header() {
    let version = env!("CARGO_PKG_VERSION");
    let banner = format!(
        "{}\n{}\n{}",
        r#"    _                     ____                  
   / \   _ __ ___  _ __  / ___|  ___ __ _ _ __  
  / _ \ | '_ ` _ \| '_ \|___ \ / __/ _` | '_ \ 
 / ___ \| | | | | | |_) |___) | (_| (_| | | | |
/_/   \_\_| |_| |_| .__/|____/ \___\__,_|_| |_|
                  |_|                           "#
            .cyan()
            .bold(),
        r#" ___ ____  ____  __                     
|_ _/ ___||  _ \/ _| ___   ___ _   _ ___ 
 | |\___ \| |_) | |_ / _ \ / __| | | / __|
 | | ___) |  __/|  _| (_) | (__| |_| \__ \
|___|____/|_|   |_|  \___/ \___|\__,_|___/"#
            .yellow()
            .bold(),
        "=====================================================================".cyan()
    );
    println!("{}", banner);
    println!(
        "{} {}        {} {}",
        "Version:".yellow(),
        version.bold(),
        "Website:".yellow(),
        "https://ispfocus.net.br".underline().blue()
    );
    println!(
        "{}\n",
        "=====================================================================".cyan()
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    print_header();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init => cmd_init(&cli).await,
        Commands::Port(cmd) => {
            let db = open_and_auth(&cli)?;
            cmd_port(&db, cmd)
        }
        Commands::Prefix(cmd) => {
            let db = open_and_auth(&cli)?;
            cmd_prefix(&db, cmd)
        }
        Commands::User(cmd) => {
            let db = open_and_auth(&cli)?;
            cmd_user(&db, cmd)
        }
        Commands::Scan(cmd) => {
            let db = open_and_auth(&cli)?;
            cmd_scan(&db, cmd).await
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Open the database and authenticate the user.
fn open_and_auth(cli: &Cli) -> Result<DbConn> {
    // Ensure database file exists before trying to open it
    if !std::path::Path::new(&cli.db_path).exists() {
        anyhow::bail!("Database not initialized. Run 'ampscan init' first.");
    }

    let key = db::get_db_key()?;
    let db = db::open_database(&cli.db_path, &key)?;

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
fn prompt_username() -> Result<String> {
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

/// Parse hex string to bytes (e.g., "FF0102" -> [0xFF, 0x01, 0x02]).
#[allow(dead_code)]
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim().replace(' ', "");
    if hex.len() % 2 != 0 {
        anyhow::bail!("Hex string must have even length");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).context("Invalid hex digit"))
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Command: init
// ═══════════════════════════════════════════════════════════════════════════

async fn cmd_init(cli: &Cli) -> Result<()> {
    let key = db::get_db_key()?;

    println!("{}", "Initializing database...".cyan());

    // If database files already exist, remove them to allow fresh initialization
    if std::path::Path::new(&cli.db_path).exists() {
        let _ = std::fs::remove_file(&cli.db_path);
        let _ = std::fs::remove_file(format!("{}-wal", cli.db_path));
        let _ = std::fs::remove_file(format!("{}-shm", cli.db_path));
    }

    let db = db::open_database(&cli.db_path, &key)?;

    // Seed default ports
    port_repo::seed_default_ports(&db)?;
    println!(
        "  {} 20 default amplification ports registered",
        "✓".green()
    );

    // Create admin user if none exists
    if !user_repo::has_users(&db)? {
        println!("\n{}", "Creating administrator user:".yellow());
        let username = prompt_username()?;
        let password = auth::prompt_new_password()?;
        user_repo::create_user(&db, &username, &password)?;
        println!(
            "  {} User '{}' successfully created",
            "✓".green(),
            username
        );
    } else {
        println!(
            "  {} Users already exist, skipping admin creation",
            "ℹ".blue()
        );
    }

    println!(
        "\n{} Database initialized at: {}",
        "✓".green().bold(),
        cli.db_path
    );
    println!(
        "  The database is encrypted with AES-256 (SQLCipher).\n  \
         Keep your AMPSCAN_DB_KEY secure!"
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Command: port
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_port(db: &DbConn, cmd: &PortCommands) -> Result<()> {
    match cmd {
        PortCommands::List => {
            let ports = port_repo::list_ports(db)?;
            if ports.is_empty() {
                println!("No registered ports.");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    Cell::new("ID"),
                    Cell::new("Port"),
                    Cell::new("Proto"),
                    Cell::new("Name"),
                    Cell::new("Probe"),
                    Cell::new("Enabled"),
                    Cell::new("Description"),
                ]);

            for p in &ports {
                let status = if p.enabled {
                    Cell::new("✓").fg(Color::Green)
                } else {
                    Cell::new("✗").fg(Color::Red)
                };
                table.add_row(vec![
                    Cell::new(p.id),
                    Cell::new(p.port),
                    Cell::new(&p.protocol),
                    Cell::new(&p.name),
                    Cell::new(&p.probe_type),
                    status,
                    Cell::new(&p.description),
                ]);
            }
            println!("{}", table);
            println!("Total: {} ports", ports.len());
        }

        PortCommands::Enable { id } => {
            port_repo::toggle_port(db, *id, true)?;
            println!("{} Port ID {} enabled", "✓".green(), id);
        }

        PortCommands::Disable { id } => {
            port_repo::toggle_port(db, *id, false)?;
            println!("{} Port ID {} disabled", "✓".green(), id);
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Command: prefix
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_prefix(db: &DbConn, cmd: &PrefixCommands) -> Result<()> {
    match cmd {
        PrefixCommands::List => {
            let prefixes = prefix_repo::list_prefixes(db)?;
            if prefixes.is_empty() {
                println!("No registered prefixes. Use 'ampscan prefix add' to add one.");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    Cell::new("ID"),
                    Cell::new("Prefix"),
                    Cell::new("IPv"),
                    Cell::new("Enabled"),
                    Cell::new("Description"),
                ]);

            for p in &prefixes {
                let status = if p.enabled {
                    Cell::new("✓").fg(Color::Green)
                } else {
                    Cell::new("✗").fg(Color::Red)
                };
                table.add_row(vec![
                    Cell::new(p.id),
                    Cell::new(&p.prefix),
                    Cell::new(format!("v{}", p.ip_version)),
                    status,
                    Cell::new(&p.description),
                ]);
            }
            println!("{}", table);
        }

        PrefixCommands::Add {
            prefix,
            description,
        } => {
            let id = prefix_repo::insert_prefix(db, prefix, description)?;
            println!(
                "{} Prefix {} added with ID {}",
                "✓".green(),
                prefix,
                id
            );
        }

        PrefixCommands::Edit {
            id,
            prefix,
            description,
        } => {
            prefix_repo::update_prefix(db, *id, prefix.as_deref(), description.as_deref())?;
            println!("{} Prefix ID {} updated", "✓".green(), id);
        }

        PrefixCommands::Remove { id } => {
            prefix_repo::delete_prefix(db, *id)?;
            println!("{} Prefix ID {} removed", "✓".green(), id);
        }

        PrefixCommands::Enable { id } => {
            prefix_repo::toggle_prefix(db, *id, true)?;
            println!("{} Prefix ID {} enabled", "✓".green(), id);
        }

        PrefixCommands::Disable { id } => {
            prefix_repo::toggle_prefix(db, *id, false)?;
            println!("{} Prefix ID {} disabled", "✓".green(), id);
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Command: user
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_user(db: &DbConn, cmd: &UserCommands) -> Result<()> {
    match cmd {
        UserCommands::List => {
            let users = user_repo::list_users(db)?;
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    Cell::new("ID"),
                    Cell::new("Username"),
                    Cell::new("Created at"),
                ]);

            for u in &users {
                table.add_row(vec![
                    Cell::new(u.id),
                    Cell::new(&u.username),
                    Cell::new(&u.created_at),
                ]);
            }
            println!("{}", table);
        }

        UserCommands::Add { username } => {
            let password = auth::prompt_new_password()?;
            let id = user_repo::create_user(db, username, &password)?;
            println!(
                "{} User '{}' created with ID {}",
                "✓".green(),
                username,
                id
            );
        }

        UserCommands::ChangePassword { username } => {
            println!("Changing password for '{}':", username);
            let new_password = auth::prompt_new_password()?;
            user_repo::change_password(db, username, &new_password)?;
            println!("{} Password successfully changed", "✓".green());
        }

        UserCommands::Remove { id } => {
            user_repo::delete_user(db, *id)?;
            println!("{} User ID {} removed", "✓".green(), id);
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Command: scan
// ═══════════════════════════════════════════════════════════════════════════

async fn cmd_scan(db: &DbConn, cmd: &ScanCommands) -> Result<()> {
    match cmd {
        ScanCommands::Run {
            concurrency,
            timeout,
            output,
            no_icmp,
            prefix,
            pdf,
            client_name,
            recipient,
        } => {
            let ports = port_repo::get_enabled_ports(db)?;
            if ports.is_empty() {
                anyhow::bail!(
                    "No enabled ports. Use 'ampscan port list' to view ports."
                );
            }

            let prefixes = match prefix {
                Some(p) => {
                    vec![ampscan::db::models::Prefix {
                        id: 0,
                        prefix: p.clone(),
                        description: "Manual prefix".to_string(),
                        ip_version: if p.contains(':') { 6 } else { 4 },
                        enabled: true,
                        created_at: "".to_string(),
                        updated_at: "".to_string(),
                    }]
                }
                None => {
                    let list = prefix_repo::get_enabled_prefixes(db)?;
                    if list.is_empty() {
                        anyhow::bail!(
                            "No enabled prefixes in the database. Register a prefix or use --prefix."
                        );
                    }
                    list
                }
            };

            println!("\n{} Starting scan...", "▶".cyan().bold());
            println!(
                "  Enabled ports: {} | Prefixes: {} | Concurrency: {} | Timeout: {}s",
                ports.len(),
                prefixes.len(),
                concurrency,
                timeout
            );

            let config = ScanConfig {
                concurrency: *concurrency,
                timeout: Duration::from_secs(*timeout),
                use_icmp: !no_icmp,
            };

            let report = scanner::run_scan(ports, prefixes, &config).await?;

            // Print terminal summary of detected results (vulnerable + protected)
            let detected = report.detected_results();
            if !detected.is_empty() {
                println!("\n{} Open ports found:", "ℹ".cyan().bold());

                let mut table = Table::new();
                table
                    .load_preset(UTF8_FULL)
                    .apply_modifier(UTF8_ROUND_CORNERS)
                    .set_header(vec![
                        Cell::new("IP"),
                        Cell::new("Port"),
                        Cell::new("Proto"),
                        Cell::new("Service"),
                        Cell::new("Status"),
                        Cell::new("Time (ms)"),
                    ]);

                for r in &detected {
                    let (ip_cell, status_cell) = match r.status {
                        scanner::result::PortStatus::Open => (
                            Cell::new(r.ip.to_string()).fg(Color::Red),
                            Cell::new("Vulnerable").fg(Color::Red),
                        ),
                        scanner::result::PortStatus::OpenProtected => (
                            Cell::new(r.ip.to_string()).fg(Color::Yellow),
                            Cell::new("Protected").fg(Color::Yellow),
                        ),
                        _ => (Cell::new(r.ip.to_string()), Cell::new("")),
                    };

                    table.add_row(vec![
                        ip_cell,
                        Cell::new(r.port),
                        Cell::new(r.protocol.to_uppercase()),
                        Cell::new(&r.service_name),
                        status_cell,
                        Cell::new(
                            r.response_time_ms
                                .map(|t| t.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                        ),
                    ]);
                }
                println!("{}", table);
            } else {
                println!(
                    "\n{} No open/vulnerable amplification ports found.",
                    "✓".green().bold()
                );
            }

            // Generate PDF only if requested via --pdf flag
            if *pdf {
                println!("\n{} Generating PDF report: {}", "📄".to_string(), output);
                let app_config = report::AppConfig::load();
                report::generate_pdf(&report, output, client_name.as_deref(), recipient.as_deref(), &app_config)?;
                println!("{} Report generated successfully!", "✓".green().bold());
            } else {
                println!(
                    "\n{} Prefix scan completed (PDF generation not requested).",
                    "ℹ".blue().bold()
                );
            }
        }

        ScanCommands::Single {
            ip,
            timeout,
            no_icmp,
        } => {
            let ip_addr: IpAddr = ip
                .parse()
                .with_context(|| format!("Invalid IP address: {}", ip))?;

            let ports = port_repo::get_enabled_ports(db)?;
            if ports.is_empty() {
                anyhow::bail!("No enabled ports to test.");
            }

            println!(
                "\n{} Testing {} ({} ports)...\n",
                "▶".cyan().bold(),
                ip_addr,
                ports.len()
            );

            let config = ScanConfig {
                concurrency: 1,
                timeout: Duration::from_secs(*timeout),
                use_icmp: !no_icmp,
            };

            let results = scanner::scan_single_ip(ip_addr, ports, &config).await?;

            // Display results with colors like the original script
            for r in &results {
                let status_str = match &r.status {
                    scanner::result::PortStatus::Open => {
                        format!("{}", "Open".red().bold())
                    }
                    scanner::result::PortStatus::OpenProtected => {
                        format!("{}", "Open/Protected".yellow().bold())
                    }
                    scanner::result::PortStatus::Closed => {
                        format!("{}", "Closed".green())
                    }
                    scanner::result::PortStatus::Inconclusive => {
                        format!("{}", "Inconclusive".blue())
                    }
                    scanner::result::PortStatus::Error(e) => {
                        format!("{}: {}", "Error".yellow(), e)
                    }
                };

                println!(
                    "Testing {} ({}/{}): {}",
                    r.service_name, r.port, r.protocol, status_str
                );
            }

            // Summary
            let open_count = results
                .iter()
                .filter(|r| r.status == scanner::result::PortStatus::Open)
                .count();
            let protected_count = results
                .iter()
                .filter(|r| r.status == scanner::result::PortStatus::OpenProtected)
                .count();
            println!(
                "\n{}: {} vulnerable, {} protected (total: {} ports tested on {})",
                "Result".bold(),
                open_count,
                protected_count,
                results.len(),
                ip_addr
            );
        }
    }
    Ok(())
}

/// Truncate a string for table display.
#[allow(dead_code)]
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        format!("{}...", truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_generic_utf8() {
        // ASCII normal
        assert_eq!(truncate("hello world", 8), "hello...");
        assert_eq!(truncate("hello", 10), "hello");

        // String with accented characters
        let s1 = "possible infection";
        assert_eq!(truncate(s1, 11), "possible...");
        assert_eq!(truncate(s1, 18), "possible infection");

        // String with emojis (multi-byte)
        let s2 = "Alert 🚨 security";
        assert_eq!(truncate(s2, 10), "Alert 🚨..."); // '🚨' is 1 char

        // Extreme limits
        assert_eq!(truncate("", 5), "");
        assert_eq!(truncate("abc", 0), "...");
    }
}
