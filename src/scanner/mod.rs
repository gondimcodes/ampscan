//! Core scanning engine
//!
//! Manages concurrent network probes against CIDR prefixes or single IPs.
//!
//! # Memory model (v1.3.0)
//!
//! Prior to v1.3.0, all probe tasks were spawned upfront (e.g. 1.3M handles for a /16
//! with 20 ports), causing a large memory spike before any result was processed.
//!
//! v1.3.0 uses an **acquire-before-spawn** pattern: a semaphore permit is obtained
//! *before* spawning each task. This bounds the number of in-flight tasks to
//! `concurrency` at all times, capping peak memory regardless of scan size.
pub mod probes;
pub mod result;

use crate::db::models::{Port, Prefix};
use anyhow::{Context, Result};
use colored::Colorize;
use ipnet::IpNet;
use result::{PortStatus, ProbeResult, ScanReport};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use uuid::Uuid;

/// Configuration for a scan run.
pub struct ScanConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    pub retries: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 256,
            timeout: Duration::from_secs(3),
            retries: 2,
        }
    }
}

/// Run a full scan across all enabled prefixes and ports.
/// Returns a ScanReport with all results.
pub async fn run_scan(
    ports: Vec<Port>,
    prefixes: Vec<Prefix>,
    config: &ScanConfig,
) -> Result<ScanReport> {
    run_scan_with_channel(ports, prefixes, config, None).await
}

pub async fn run_scan_with_channel(
    ports: Vec<Port>,
    prefixes: Vec<Prefix>,
    config: &ScanConfig,
    tx: Option<tokio::sync::mpsc::UnboundedSender<crate::tui::app::TuiEvent>>,
) -> Result<ScanReport> {
    // ── 1. Expand prefixes into individual IPs ────────────────────────────
    let prefix_strings: Vec<String> = prefixes.iter().map(|p| p.prefix.clone()).collect();
    let mut all_ips: Vec<IpAddr> = Vec::new();

    for prefix in &prefixes {
        let net: IpNet = prefix
            .prefix
            .parse()
            .with_context(|| format!("Invalid prefix: {}", prefix.prefix))?;

        let hosts: Vec<IpAddr> = match net {
            IpNet::V4(net4) => {
                if net4.prefix_len() < 16 {
                    anyhow::bail!(
                        "IPv4 prefix {} is too large to scan (prefix /{}). \
                         The maximum allowed is /16 (65536 hosts).",
                        prefix.prefix,
                        net4.prefix_len()
                    );
                }
                let net_u32 = u32::from(net4.network());
                let bcast_u32 = u32::from(net4.broadcast());
                (net_u32..=bcast_u32)
                    .map(|ip_u32| IpAddr::V4(std::net::Ipv4Addr::from(ip_u32)))
                    .collect()
            }
            IpNet::V6(net6) => {
                if net6.prefix_len() < 112 {
                    anyhow::bail!(
                        "IPv6 prefix {} is too large to scan (prefix /{}). \
                         The maximum allowed is /112 (65536 hosts).",
                        prefix.prefix,
                        net6.prefix_len()
                    );
                }
                net6.hosts().map(IpAddr::V6).collect()
            }
        };
        all_ips.extend(hosts);
    }

    all_ips.sort();
    all_ips.dedup();

    let total_ips = all_ips.len();
    let total_probes = total_ips * ports.len();

    if let Some(ref sender) = tx {
        let _ = sender.send(crate::tui::app::TuiEvent::ScanStarted(total_probes));
    }

    let mut report = ScanReport::new(Uuid::new_v4().to_string(), prefix_strings);
    report.total_ips = total_ips;
    report.total_probes = total_probes;

    if total_ips == 0 {
        report.finalize();
        return Ok(report);
    }

    // ── 2. Convert ports to Arc<Port> — eliminates per-probe String cloning ──
    // With Vec<Arc<Port>>, each task only pays an atomic refcount increment
    // instead of heap-allocating clones of all String fields in Port.
    let ports: Vec<Arc<Port>> = ports.into_iter().map(Arc::new).collect();

    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let timeout = config.timeout;
    let retries = config.retries;

    let mut join_set = tokio::task::JoinSet::<ProbeResult>::new();
    let mut done: usize = 0;
    let mut fd_exhaustion_detected = false;
    let mut fd_error_msg = String::new();

    // ── 3. Streaming acquire-before-spawn ─────────────────────────────────
    //
    // Key invariant: we acquire a semaphore permit BEFORE spawning each task.
    // The task holds the permit until the probe completes.
    // This guarantees at most `concurrency` tasks are in-flight (alive in memory)
    // at any time — independent of total scan size.
    //
    // Contrast with the old approach: spawning all N×M tasks upfront caused a
    // memory spike proportional to N×M (e.g. ~300–500 MB for /16 × 20 ports).
    //
    // The acquire() await yields to Tokio, allowing running probes to complete
    // and release permits — no deadlock, no busy-wait.
    'outer: for ip in all_ips {
        for port_config in &ports {
            // Non-blocking drain: collect any probe results that finished
            // while we were processing the previous iteration.
            loop {
                match join_set.try_join_next() {
                    Some(Ok(probe_result)) => {
                        if let PortStatus::Error(ref e) = probe_result.status {
                            if e.contains("CRITICAL_FD_EXHAUSTION") {
                                fd_exhaustion_detected = true;
                                fd_error_msg = e.clone();
                                join_set.abort_all();
                                break 'outer;
                            }
                        }
                        if let Some(ref sender) = tx {
                            let _ = sender.send(crate::tui::app::TuiEvent::ProbeCompleted(probe_result.clone()));
                        }
                        report.results.push(probe_result);
                        done += 1;
                        draw_progress(done, total_probes, tx.is_some());
                    }
                    Some(Err(e)) if !e.is_cancelled() => {
                        eprintln!("\nTask error: {}", e);
                    }
                    _ => break, // No more completed tasks right now
                }
            }

            // Block (cooperatively) until a concurrency slot is available.
            // Tokio schedules other tasks while we wait, including running probes.
            let permit = Arc::clone(&semaphore)
                .acquire_owned()
                .await
                .map_err(|_| anyhow::anyhow!("Semaphore was closed unexpectedly during scan"))?;

            let port_config = Arc::clone(port_config);
            join_set.spawn(async move {
                let result =
                    probes::execute_probe(ip, &port_config, timeout, retries).await;
                drop(permit); // Release slot when probe completes
                result
            });
        }
    }

    // ── 4. Blocking drain of remaining in-flight tasks ────────────────────
    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(probe_result) => {
                if fd_exhaustion_detected {
                    continue; // Discard post-abort results
                }
                if let PortStatus::Error(ref e) = probe_result.status {
                    if e.contains("CRITICAL_FD_EXHAUSTION") {
                        fd_exhaustion_detected = true;
                        fd_error_msg = e.clone();
                        join_set.abort_all();
                        continue;
                    }
                }
                if let Some(ref sender) = tx {
                    let _ = sender.send(crate::tui::app::TuiEvent::ProbeCompleted(probe_result.clone()));
                }
                report.results.push(probe_result);
                done += 1;
                draw_progress(done, total_probes, tx.is_some());
            }
            Err(e) if !e.is_cancelled() => {
                eprintln!("\nTask error: {}", e);
            }
            _ => {}
        }
    }
    eprintln!(); // Newline after progress bar

    if fd_exhaustion_detected {
        eprintln!(
            "\n\n❌ {} Scan aborted due to resource exhaustion (Too many open files)!",
            "CRITICAL".red().bold()
        );
        eprintln!("   Error details: {}", fd_error_msg.yellow());
        eprintln!("   Please reduce '--concurrency' or increase 'ulimit -n' and try again.\n");
        anyhow::bail!("Scan aborted: OS limit reached (Too many open files).");
    }

    // ── 5. Post-process: infer closed ports on known-alive hosts ──────────
    // If a host responded on any port (Open or OpenProtected), all other
    // non-responding ports on that same host are marked Closed rather than
    // Inconclusive — the host is reachable, the port is just filtered.
    let mut alive_ips = std::collections::HashSet::new();
    for r in &report.results {
        if r.status == PortStatus::Open || r.status == PortStatus::OpenProtected {
            alive_ips.insert(r.ip);
        }
    }
    for r in &mut report.results {
        if alive_ips.contains(&r.ip) && r.status == PortStatus::Inconclusive {
            r.status = PortStatus::Closed;
        }
    }

    report.finalize();

    let is_tui = tx.is_some();
    if !is_tui {
        let vulnerable = report.vulnerable_results().len();
        let vuln_ips = report.vulnerable_ips().len();
        eprintln!(
            "\n{} Scan complete: {} vulnerable ports found on {} IPs (out of {} tested)",
            "✓".green().bold(),
            vulnerable.to_string().red().bold(),
            vuln_ips.to_string().red().bold(),
            report.total_ips.to_string().bold()
        );
    }

    Ok(report)
}

fn draw_progress(done: usize, total: usize, is_tui: bool) {
    if is_tui {
        return;
    }
    use std::io::Write;
    let width = 30;
    let ratio = if total > 0 {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    } else {
        1.0
    };
    let percent = ratio * 100.0;
    let filled = (ratio * width as f64).round() as usize;
    let empty = width - filled;
    let bar_filled = "█".repeat(filled).cyan();
    let bar_empty = "░".repeat(empty).bright_black();

    eprint!(
        "\r  Progress: [{}{}] {:.1}% ({}/{})",
        bar_filled,
        bar_empty,
        percent,
        done,
        total
    );
    let _ = std::io::stderr().flush();
}

pub async fn scan_single_ip(
    ip: IpAddr,
    ports: Vec<Port>,
    config: &ScanConfig,
) -> Result<Vec<ProbeResult>> {
    scan_single_ip_with_channel(ip, ports, config, None).await
}

pub async fn scan_single_ip_with_channel(
    ip: IpAddr,
    ports: Vec<Port>,
    config: &ScanConfig,
    tx: Option<tokio::sync::mpsc::UnboundedSender<crate::tui::app::TuiEvent>>,
) -> Result<Vec<ProbeResult>> {
    scan_target_with_channel(&ip.to_string(), ports, config, tx).await
}

pub async fn scan_target_with_channel(
    target: &str,
    ports: Vec<Port>,
    config: &ScanConfig,
    tx: Option<tokio::sync::mpsc::UnboundedSender<crate::tui::app::TuiEvent>>,
) -> Result<Vec<ProbeResult>> {
    let target = target.trim();
    let ips: Vec<IpAddr> = if let Ok(ip) = IpAddr::from_str(target) {
        vec![ip]
    } else if let Ok(net) = ipnet::IpNet::from_str(target) {
        match net {
            ipnet::IpNet::V4(net4) => {
                if net4.prefix_len() < 16 {
                    anyhow::bail!(
                        "IPv4 prefix {} is too large to scan (prefix /{}). The maximum allowed is /16 (65536 hosts).",
                        target,
                        net4.prefix_len()
                    );
                }
                net4.hosts().map(IpAddr::V4).collect()
            }
            ipnet::IpNet::V6(net6) => {
                if net6.prefix_len() < 112 {
                    anyhow::bail!(
                        "IPv6 prefix {} is too large to scan (prefix /{}). The maximum allowed is /112 (65536 hosts).",
                        target,
                        net6.prefix_len()
                    );
                }
                net6.hosts().map(IpAddr::V6).collect()
            }
        }
    } else {
        anyhow::bail!("Invalid target IP or CIDR prefix: {}", target);
    };

    if ips.is_empty() {
        return Ok(Vec::new());
    }

    let total_probes = ips.len() * ports.len();
    if let Some(ref sender) = tx {
        let _ = sender.send(crate::tui::app::TuiEvent::ScanStarted(total_probes));
    }

    let ip_ver = if ips.first().map(|ip| ip.is_ipv6()).unwrap_or(false) { 6 } else { 4 };

    let dummy_prefix = Prefix {
        id: 0,
        prefix: target.to_string(),
        description: "Target Scan".to_string(),
        ip_version: ip_ver,
        enabled: true,
        created_at: String::new(),
        updated_at: String::new(),
    };

    let report = run_scan_with_channel(ports, vec![dummy_prefix], config, tx).await?;
    Ok(report.results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    #[test]
    fn test_ipv4_prefix_expansion_includes_network_and_broadcast() {
        let prefix_str = "192.168.1.0/24";
        let net: IpNet = prefix_str.parse().unwrap();
        let hosts: Vec<IpAddr> = match net {
            IpNet::V4(net4) => {
                let start: u32 = net4.network().into();
                let end: u32 = net4.broadcast().into();
                (start..=end)
                    .map(|ip_u32| IpAddr::V4(std::net::Ipv4Addr::from(ip_u32)))
                    .collect()
            }
            IpNet::V6(net6) => net6.hosts().map(IpAddr::V6).collect(),
        };

        assert_eq!(hosts.len(), 256);
        assert_eq!(hosts[0], "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[255], "192.168.1.255".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_ipv6_prefix_expansion_includes_all() {
        let prefix_str = "fd00::/126";
        let net: IpNet = prefix_str.parse().unwrap();
        let hosts: Vec<IpAddr> = match net {
            IpNet::V4(net4) => {
                let start: u32 = net4.network().into();
                let end: u32 = net4.broadcast().into();
                (start..=end)
                    .map(|ip_u32| IpAddr::V4(std::net::Ipv4Addr::from(ip_u32)))
                    .collect()
            }
            IpNet::V6(net6) => net6.hosts().map(IpAddr::V6).collect(),
        };

        assert_eq!(hosts.len(), 4);
        assert_eq!(hosts[0], "fd00::".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[3], "fd00::3".parse::<IpAddr>().unwrap());
    }
}
