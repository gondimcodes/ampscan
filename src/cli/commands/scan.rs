//! CLI scan command implementation and output formatting
use crate::cli::args::ScanCommands;
use crate::db::{port_repo, prefix_repo, DbConn};
use crate::report;
use crate::scanner::{self, ScanConfig};
use anyhow::{Context, Result};
use colored::Colorize;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use ipnet::IpNet;
use std::net::IpAddr;
use std::time::Duration;

pub async fn cmd_scan(db: &DbConn, cmd: &ScanCommands) -> Result<()> {
    match cmd {
        ScanCommands::Run {
            concurrency,
            timeout,
            retries,
            output,
            prefix,
            pdf,
            client_name,
            recipient,
            check_php,
        } => {
            let ports = port_repo::get_enabled_ports(db)?;
            if ports.is_empty() {
                anyhow::bail!("No enabled ports. Use 'ampscan port list' to view ports.");
            }

            let prefixes = match prefix {
                Some(p) => {
                    // Validate the manually provided --prefix early, before
                    // any network activity, to give immediate feedback.
                    let net: IpNet = p
                        .parse()
                        .with_context(|| format!("Invalid CIDR prefix: '{}'", p))?;

                    // Enforce the same size limits as the DB-registered prefixes
                    match &net {
                        IpNet::V4(net4) => {
                            let start: u32 = net4.network().into();
                            let end: u32 = net4.broadcast().into();
                            let count = (end as u64 - start as u64 + 1) as usize;
                            if count > 65_536 {
                                anyhow::bail!(
                                    "Prefix {} is too large ({} hosts). Maximum is 65536 (/16).",
                                    p,
                                    count
                                );
                            }
                        }
                        IpNet::V6(net6) => {
                            if net6.prefix_len() < 112 {
                                anyhow::bail!(
                                    "IPv6 prefix /{} is too large. Maximum allowed is /112.",
                                    net6.prefix_len()
                                );
                            }
                        }
                    }

                    let ip_version: u8 = if net.addr().is_ipv4() { 4 } else { 6 };
                    vec![crate::db::models::Prefix {
                        id: 0,
                        prefix: p.clone(),
                        description: "Manual prefix".to_string(),
                        ip_version,
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

            // Attempt to raise file descriptor limit for Unix
            if let Err(e) = crate::sys_limits::try_raise_fd_limit(*concurrency) {
                eprintln!("⚠️  Failed to raise system file descriptor limit: {}", e);
            }

            println!("\n{} Starting scan...", "🌐".cyan().bold());
            println!(
                "  Enabled ports: {} | Prefixes: {} | Concurrency: {} | Timeout: {}s | Retries: {}",
                ports.len().to_string().bold(),
                prefixes.len().to_string().bold(),
                concurrency.to_string().bold(),
                timeout.to_string().bold(),
                retries.to_string().bold()
            );
            if *check_php {
                println!(
                    "  Audit Profile: {}",
                    "Full Amplification + PHP2Shell (CVE-2026-109618 / CVE-2026-109619)"
                        .yellow()
                        .bold()
                );
            }

            let config = ScanConfig {
                concurrency: *concurrency,
                timeout: Duration::from_secs(*timeout),
                retries: *retries,
                check_php: *check_php,
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
                        Cell::new("IP").fg(Color::Cyan),
                        Cell::new("Port").fg(Color::Cyan),
                        Cell::new("Proto").fg(Color::Cyan),
                        Cell::new("Service").fg(Color::Cyan),
                        Cell::new("Status").fg(Color::Cyan),
                        Cell::new("Time (ms)").fg(Color::Cyan),
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

                    let time_str = r
                        .response_time_ms
                        .map(|t| format!("{} ms", t))
                        .unwrap_or_else(|| "-".to_string());
                    let mut time_cell = Cell::new(time_str);
                    if let Some(ms) = r.response_time_ms {
                        if ms < 50 {
                            time_cell = time_cell.fg(Color::Green);
                        } else if ms < 150 {
                            time_cell = time_cell.fg(Color::Yellow);
                        } else {
                            time_cell = time_cell.fg(Color::Red);
                        }
                    }

                    table.add_row(vec![
                        ip_cell,
                        Cell::new(r.port),
                        Cell::new(r.protocol.to_uppercase()),
                        Cell::new(&r.service_name),
                        status_cell,
                        time_cell,
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
                println!("\n📄 Generating PDF report: {}", output);
                let app_config = report::AppConfig::load();
                report::generate_pdf(
                    &report,
                    output,
                    client_name.as_deref(),
                    recipient.as_deref(),
                    &app_config,
                )?;
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
            concurrency,
            retries,
            check_php,
        } => {
            let ip_addr: IpAddr = ip
                .parse()
                .with_context(|| format!("Invalid IP address: {}", ip))?;

            let ports = port_repo::get_enabled_ports(db)?;
            if ports.is_empty() {
                anyhow::bail!("No enabled ports to test.");
            }

            // Attempt to raise file descriptor limit for Unix
            if let Err(e) = crate::sys_limits::try_raise_fd_limit(*concurrency) {
                eprintln!("⚠️  Failed to raise system file descriptor limit: {}", e);
            }

            println!(
                "\n{} Testing {} ({} ports, Concurrency: {}, Retries: {})...\n",
                "▶".cyan().bold(),
                ip_addr,
                ports.len(),
                concurrency.to_string().bold(),
                retries.to_string().bold()
            );

            let config = ScanConfig {
                concurrency: *concurrency,
                timeout: Duration::from_secs(*timeout),
                retries: *retries,
                check_php: *check_php,
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
pub fn truncate(s: &str, max_len: usize) -> String {
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
