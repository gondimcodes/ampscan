pub mod app;
pub mod events;
pub mod ui;

use app::{App, TuiEvent};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

pub async fn run_tui(
    db_path: String,
    concurrency: usize,
    timeout: u64,
    retries: usize,
    pdf_export: bool,
    pdf_output: String,
    pdf_client_name: Option<String>,
    pdf_recipient: Option<String>,
) -> anyhow::Result<()> {
    // Read database encryption key once at startup before removing it from env
    let db_key = crate::db::get_db_key().unwrap_or_default();

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state with persistent db_key and CLI parameters
    let mut app = App::new(
        db_path.clone(),
        db_key.clone(),
        concurrency,
        timeout,
        retries,
        pdf_export,
        pdf_output,
        pdf_client_name,
        pdf_recipient,
    );

    // Load prefixes and ports from DB on startup
    if let Ok(mut conn) = crate::db::open_database(&db_path, &db_key) {
        if let Ok(prefixes) = crate::db::prefix_repo::get_enabled_prefixes(&mut conn) {
            app.prefixes = prefixes;
        }
        if let Ok(ports) = crate::db::port_repo::get_enabled_ports(&mut conn) {
            app.ports = ports;
        }
    }

    // Channel for background scan events
    let (tx, mut rx) = mpsc::unbounded_channel::<TuiEvent>();

    // Main TUI Event Loop
    loop {
        // Drain any incoming scan events from background task
        while let Ok(tui_event) = rx.try_recv() {
            match tui_event {
                TuiEvent::ScanStarted(total) => {
                    app.stats.total_probes = total;
                }
                TuiEvent::ProbeCompleted(res) => {
                    app.add_probe_result(res);
                }
                TuiEvent::ScanFinished => {
                    app.is_scanning = false;

                    // If --pdf flag was supplied via CLI, generate PDF report automatically
                    if app.pdf_export {
                        let scan_id = uuid::Uuid::new_v4().to_string();
                        let prefixes: Vec<String> = app.prefixes.iter().map(|p| p.prefix.clone()).collect();
                        let mut report = crate::scanner::result::ScanReport::new(scan_id, prefixes);
                        
                        // Calculate total unique IPs tested from logs
                        let mut unique_ips: Vec<_> = app.logs.iter().map(|l| l.ip).collect();
                        unique_ips.sort();
                        unique_ips.dedup();
                        
                        report.total_ips = unique_ips.len();
                        report.total_probes = app.stats.total_probes.max(app.logs.len());
                        report.results = app.logs.clone();
                        
                        // Preserve start time if available
                        if let Some(start_inst) = app.stats.start_time {
                            let elapsed = start_inst.elapsed();
                            report.started_at = chrono::Utc::now() - chrono::Duration::from_std(elapsed).unwrap_or_default();
                        }
                        
                        report.finalize();

                        let app_config = crate::report::AppConfig::load();
                        match crate::report::generate_pdf(
                            &report,
                            &app.pdf_output,
                            app.pdf_client_name.as_deref(),
                            app.pdf_recipient.as_deref(),
                            &app_config,
                        ) {
                            Ok(_) => {
                                app.status_message = Some(format!(
                                    "Scan completed! PDF report generated: {}",
                                    app.pdf_output
                                ));
                            }
                            Err(e) => {
                                app.status_message = Some(format!(
                                    "Scan completed! PDF report error: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        app.status_message = Some("Scan completed!".to_string());
                    }
                }
                TuiEvent::ScanError(msg) => {
                    app.is_scanning = false;
                    app.status_message = Some(format!("Scan error: {}", msg));
                }
            }
        }

        terminal.draw(|f| ui::render(f, &app))?;

        if let Ok(action) = events::handle_events(&mut app) {
            match action {
                events::UserAction::StartSingleScan => {
                    if !app.is_scanning {
                        let target_str = app.single_ip_input.trim().to_string();
                        let is_valid = !target_str.is_empty() 
                            && (IpAddr::from_str(&target_str).is_ok() || ipnet::IpNet::from_str(&target_str).is_ok());

                        if target_str.is_empty() {
                            app.status_message = Some("Please enter a target IP or CIDR prefix in Target Scan tab".to_string());
                        } else if !is_valid {
                            app.status_message = Some(format!("Invalid IP or CIDR Prefix: '{}'", target_str));
                        } else {
                            app.is_scanning = true;
                            app.logs.clear();
                            app.stats = app::ScanStats::default();
                            app.stats.start_time = Some(std::time::Instant::now());

                            let db_path = app.db_path.clone();
                            let db_key = app.db_key.clone();
                            let tx = tx.clone();
                            let concurrency: usize = app.concurrency_input.parse().unwrap_or(256);
                            let timeout_secs: u64 = app.timeout_input.parse().unwrap_or(3);
                            let retries: usize = app.retries_input.parse().unwrap_or(2);

                            app.status_message = Some(format!("Starting target scan for {}...", target_str));

                            tokio::spawn(async move {
                                let mut conn_res = crate::db::open_database(&db_path, &db_key);
                                let conn = match conn_res {
                                    Ok(ref mut c) => c,
                                    Err(e) => {
                                        let _ = tx.send(TuiEvent::ScanError(format!("DB open error: {}", e)));
                                        return;
                                    }
                                };

                                let ports = match crate::db::port_repo::get_enabled_ports(conn) {
                                    Ok(p) => p,
                                    Err(e) => {
                                        let _ = tx.send(TuiEvent::ScanError(format!("DB port error: {}", e)));
                                        return;
                                    }
                                };

                                let config = crate::scanner::ScanConfig {
                                    concurrency,
                                    timeout: Duration::from_secs(timeout_secs),
                                    retries,
                                };

                                if let Err(e) = crate::scanner::scan_target_with_channel(&target_str, ports, &config, Some(tx.clone())).await {
                                    let _ = tx.send(TuiEvent::ScanError(e.to_string()));
                                } else {
                                    let _ = tx.send(TuiEvent::ScanFinished);
                                }
                            });
                        }
                    }
                }
                events::UserAction::StartFullScan => {
                    if !app.is_scanning {
                        app.is_scanning = true;
                        app.logs.clear();
                        app.stats = app::ScanStats::default();
                        app.stats.start_time = Some(std::time::Instant::now());

                        let db_path = app.db_path.clone();
                        let db_key = app.db_key.clone();
                        let tx = tx.clone();
                        let concurrency: usize = app.concurrency_input.parse().unwrap_or(256);
                        let timeout_secs: u64 = app.timeout_input.parse().unwrap_or(3);
                        let retries: usize = app.retries_input.parse().unwrap_or(2);

                        app.status_message = Some("Starting full database CIDR scan...".to_string());

                        tokio::spawn(async move {
                            let mut conn_res = crate::db::open_database(&db_path, &db_key);
                            let conn = match conn_res {
                                Ok(ref mut c) => c,
                                Err(e) => {
                                    let _ = tx.send(TuiEvent::ScanError(format!("DB open error: {}", e)));
                                    return;
                                }
                            };

                            let ports = match crate::db::port_repo::get_enabled_ports(conn) {
                                Ok(p) => p,
                                Err(e) => {
                                    let _ = tx.send(TuiEvent::ScanError(format!("DB port error: {}", e)));
                                    return;
                                }
                            };

                            let prefixes = match crate::db::prefix_repo::get_enabled_prefixes(conn) {
                                Ok(p) => p,
                                Err(e) => {
                                    let _ = tx.send(TuiEvent::ScanError(format!("DB prefix error: {}", e)));
                                    return;
                                }
                            };

                            if prefixes.is_empty() {
                                let _ = tx.send(TuiEvent::ScanError("No enabled prefixes found in database".to_string()));
                                return;
                            }

                            let config = crate::scanner::ScanConfig {
                                concurrency,
                                timeout: Duration::from_secs(timeout_secs),
                                retries,
                            };

                            if let Err(e) = crate::scanner::run_scan_with_channel(ports, prefixes, &config, Some(tx.clone())).await {
                                let _ = tx.send(TuiEvent::ScanError(e.to_string()));
                            } else {
                                let _ = tx.send(TuiEvent::ScanFinished);
                            }
                        });
                    }
                }
                events::UserAction::None => {}
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
