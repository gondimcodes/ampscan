//! AmpScan CLI Entrypoint
//!
//! Parses command-line arguments and dispatches to modular command handlers.

use ampscan::cli::{
    cmd_init, cmd_port, cmd_prefix, cmd_scan, cmd_user, open_and_auth, Cli, Commands,
};
use anyhow::Result;
use clap::Parser;
use colored::Colorize;

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
        Commands::Tui {
            concurrency,
            timeout,
            retries,
            pdf,
            output,
            client_name,
            recipient,
            check_php,
            http_host,
        } => {
            let db_p = cli.db_path.as_deref().unwrap_or("");
            if db_p.is_empty() {
                anyhow::bail!("O caminho do banco de dados (--db-path) é obrigatório para carregar a TUI com os alvos.");
            }
            if let Some(ref h) = http_host {
                ampscan::scanner::probes::http::validate_http_host(h)?;
            }
            ampscan::tui::run_tui(
                db_p.to_string(),
                *concurrency,
                *timeout,
                *retries,
                *pdf,
                output.clone(),
                client_name.clone(),
                recipient.clone(),
                *check_php,
                http_host.clone(),
            )
            .await
        }
    }
}
