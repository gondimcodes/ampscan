//! Core scanning engine
//!
//! Manages concurrent network probes against CIDR prefixes or single IPs.
pub mod probes;
pub mod result;

use crate::db::models::{Port, Prefix};
use anyhow::{Context, Result};
use ipnet::IpNet;
use result::{ProbeResult, ScanReport};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use uuid::Uuid;
use colored::Colorize;

/// Configuration for a scan run.
pub struct ScanConfig {
    pub concurrency: usize,
    pub timeout: Duration,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 256,
            timeout: Duration::from_secs(3),
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
    // Expand prefixes into individual IPs
    let mut all_ips: Vec<IpAddr> = Vec::new();
    let prefix_strings: Vec<String> = prefixes.iter().map(|p| p.prefix.clone()).collect();

    for prefix in &prefixes {
        let net: IpNet = prefix
            .prefix
            .parse()
            .with_context(|| format!("Invalid prefix: {}", prefix.prefix))?;

        // Prevent memory exhaustion/panic on very large prefix ranges
        let max_hosts = 65536;
        let hosts: Vec<IpAddr> = match net {
            IpNet::V4(net4) => {
                let start: u32 = net4.network().into();
                let end: u32 = net4.broadcast().into();
                let hosts_count = (end as u64 - start as u64 + 1) as usize;
                if hosts_count > max_hosts {
                    anyhow::bail!(
                        "IPv4 prefix {} is too large to scan ({} hosts). The maximum allowed is {} hosts per prefix (e.g., /16).",
                        prefix.prefix,
                        hosts_count,
                        max_hosts
                    );
                }
                (start..=end)
                    .map(|ip_u32| IpAddr::V4(std::net::Ipv4Addr::from(ip_u32)))
                    .collect()
            }
            IpNet::V6(net6) => {
                if net6.prefix_len() < 112 {
                    anyhow::bail!(
                        "IPv6 prefix {} is too large to scan (prefix /{}). The maximum allowed is /112 (65536 hosts).",
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

    eprintln!(
        "{} Scanning {} IPs × {} ports = {} probes (concurrency: {})",
        "🌐".cyan().bold(),
        total_ips.to_string().bold(),
        ports.len().to_string().bold(),
        total_probes.to_string().bold(),
        config.concurrency.to_string().bold()
    );

    let mut report = ScanReport::new(Uuid::new_v4().to_string(), prefix_strings);
    report.total_ips = total_ips;
    report.total_probes = total_probes;

    // Shared state
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let ports = Arc::new(ports);
    let timeout = config.timeout;

    if total_ips > 0 {
        let mut join_set = tokio::task::JoinSet::new();

        for ip in all_ips {
            for port_config in ports.iter() {
                let sem = semaphore.clone();
                let port_config = port_config.clone();

                join_set.spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    probes::execute_probe(ip, &port_config, timeout, false).await
                });
            }
        }

        // Collect results in completion order
        let mut done = 0;
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(result) => {
                    report.results.push(result);
                    done += 1;
                    let step = (total_probes / 100).max(1);
                    if done % step == 0 || done == total_probes {
                        draw_progress(done, total_probes);
                    }
                }
                Err(e) => eprintln!("\nTask error: {}", e),
            }
        }
        eprintln!(); // Newline after progress

        // Post-process: if an IP has any Open or OpenProtected port, mark all other Inconclusive ports for that IP as Closed.
        let mut alive_ips = std::collections::HashSet::new();
        for r in &report.results {
            if r.status == result::PortStatus::Open || r.status == result::PortStatus::OpenProtected {
                alive_ips.insert(r.ip);
            }
        }
        for r in &mut report.results {
            if alive_ips.contains(&r.ip) && r.status == result::PortStatus::Inconclusive {
                r.status = result::PortStatus::Closed;
            }
        }
    }

    report.finalize();

    // Print summary
    let vulnerable = report.vulnerable_results().len();
    let vuln_ips = report.vulnerable_ips().len();

    eprintln!(
        "{} Scan complete: {} vulnerable ports found on {} IPs (out of {} tested)",
        "✓".green().bold(),
        vulnerable.to_string().red().bold(),
        vuln_ips.to_string().red().bold(),
        report.total_ips.to_string().bold()
    );

    Ok(report)
}

fn draw_progress(done: usize, total: usize) {
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
    let total = ports.len();
    let mut handles = Vec::with_capacity(total);

    // Track progress atomically
    let completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for port_config in ports {
        let completed = completed.clone();
        let timeout = config.timeout;

        let handle = tokio::spawn(async move {
            let result = probes::execute_probe(ip, &port_config, timeout, false).await;
            let done = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            draw_progress(done, total);
            result
        });
        handles.push(handle);
    }

    let mut results = Vec::with_capacity(total);
    for handle in handles {
        match handle.await {
            Ok(res) => results.push(res),
            Err(e) => eprintln!("\nTask error: {}", e),
        }
    }
    eprintln!();

    // Post-process: if any result is Open or OpenProtected, the host is alive.
    let is_alive = results.iter().any(|r| {
        r.status == result::PortStatus::Open || r.status == result::PortStatus::OpenProtected
    });

    if is_alive {
        for r in &mut results {
            if r.status == result::PortStatus::Inconclusive {
                r.status = result::PortStatus::Closed;
            }
        }
    }

    Ok(results)
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
            IpNet::V6(net6) => {
                net6.hosts().map(IpAddr::V6).collect()
            }
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
            IpNet::V6(net6) => {
                net6.hosts().map(IpAddr::V6).collect()
            }
        };

        assert_eq!(hosts.len(), 4);
        assert_eq!(hosts[0], "fd00::".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[3], "fd00::3".parse::<IpAddr>().unwrap());
    }
}

