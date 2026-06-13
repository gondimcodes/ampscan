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

/// Configuration for a scan run.
pub struct ScanConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    pub use_icmp: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 256,
            timeout: Duration::from_secs(3),
            use_icmp: true,
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
        match net {
            IpNet::V4(net4) => {
                let hosts_count = net4.hosts().count();
                if hosts_count > max_hosts {
                    anyhow::bail!(
                        "IPv4 prefix {} is too large to scan ({} hosts). The maximum allowed is {} hosts per prefix (e.g., /16).",
                        prefix.prefix,
                        hosts_count,
                        max_hosts
                    );
                }
            }
            IpNet::V6(net6) => {
                if net6.prefix_len() < 112 {
                    anyhow::bail!(
                        "IPv6 prefix {} is too large to scan (prefix /{}). The maximum allowed is /112 (65536 hosts).",
                        prefix.prefix,
                        net6.prefix_len()
                    );
                }
            }
        }

        let hosts: Vec<IpAddr> = net.hosts().collect();
        all_ips.extend(hosts);
    }

    all_ips.sort();
    all_ips.dedup();

    let total_ips = all_ips.len();
    let total_probes = total_ips * ports.len();

    eprintln!(
        "Scanning {} IPs × {} ports = {} probes (concurrency: {})",
        total_ips,
        ports.len(),
        total_probes,
        config.concurrency
    );

    let mut report = ScanReport::new(Uuid::new_v4().to_string(), prefix_strings);
    report.total_ips = total_ips;
    report.total_probes = total_probes;

    // Shared state
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let ports = Arc::new(ports);
    let timeout = config.timeout;
    let use_icmp = config.use_icmp;    // 1. Perform concurrent host discovery (liveness check)
    let mut liveness_set = tokio::task::JoinSet::new();
    for &ip in &all_ips {
        liveness_set.spawn(async move {
            let alive = probes::is_host_alive(ip, timeout, use_icmp).await;
            (ip, alive)
        });
    }

    let mut ip_liveness = std::collections::HashMap::with_capacity(all_ips.len());
    while let Some(res) = liveness_set.join_next().await {
        if let Ok((ip, alive)) = res {
            ip_liveness.insert(ip, alive);
        }
    }

    // 2. Separate IPs into alive and dead
    let mut alive_ips = Vec::new();
    for ip in all_ips {
        if *ip_liveness.get(&ip).unwrap_or(&false) {
            alive_ips.push(ip);
        } else {
            // For dead hosts, directly record Inconclusive results without sending any port probes
            for port_config in &*ports {
                report.results.push(result::ProbeResult {
                    ip,
                    port: port_config.port,
                    protocol: port_config.protocol.clone(),
                    service_name: port_config.name.clone(),
                    description: port_config.description.clone(),
                    status: result::PortStatus::Inconclusive,
                    response_time_ms: None,
                    timestamp: chrono::Utc::now(),
                });
            }
        }
    }

    let total_alive_ips = alive_ips.len();
    let total_alive_probes = total_alive_ips * ports.len();

    if total_alive_ips > 0 {
        let mut join_set = tokio::task::JoinSet::new();

        for ip in alive_ips {
            for port_config in ports.iter() {
                let sem = semaphore.clone();
                let port_config = port_config.clone();

                join_set.spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    probes::execute_probe(ip, &port_config, timeout, use_icmp).await
                });
            }
        }

        // Collect results in completion order for alive hosts
        let mut done = 0;
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(mut result) => {
                    // Since we know the host is alive, change Inconclusive status to Closed
                    if result.status == result::PortStatus::Inconclusive {
                        result.status = result::PortStatus::Closed;
                    }
                    report.results.push(result);
                    done += 1;
                    let step = (total_alive_probes / 100).max(1);
                    if done % step == 0 || done == total_alive_probes {
                        use std::io::Write;
                        eprint!("\r  Progress: {}/{} ({:.1}%)", done, total_alive_probes, (done as f64 / total_alive_probes as f64) * 100.0);
                        let _ = std::io::stderr().flush();
                    }
                }
                Err(e) => eprintln!("\nTask error: {}", e),
            }
        }
        eprintln!(); // Newline after progress
    }

    report.finalize();

    // Print summary
    let vulnerable = report.vulnerable_results().len();
    let vuln_ips = report.vulnerable_ips().len();
    eprintln!(
        "Scan complete: {} vulnerable ports found on {} IPs (out of {} tested)",
        vulnerable, vuln_ips, report.total_ips
    );

    Ok(report)
}

pub async fn scan_single_ip(
    ip: IpAddr,
    ports: Vec<Port>,
    config: &ScanConfig,
) -> Result<Vec<ProbeResult>> {
    use std::io::Write;
    let total = ports.len();
    let mut handles = Vec::with_capacity(total);

    // Track progress atomically
    let completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for port_config in ports {
        let completed = completed.clone();
        let timeout = config.timeout;
        let use_icmp = config.use_icmp;

        let handle = tokio::spawn(async move {
            let result = probes::execute_probe(ip, &port_config, timeout, use_icmp).await;
            let done = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            eprint!("\r  Progress: {}/{} ({:.1}%)", done, total, (done as f64 / total as f64) * 100.0);
            let _ = std::io::stderr().flush();
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
    // Otherwise, check if the host is alive exactly once.
    let any_alive = results.iter().any(|r| {
        r.status == result::PortStatus::Open || r.status == result::PortStatus::OpenProtected
    });
    let is_alive = if any_alive {
        true
    } else {
        probes::is_host_alive(ip, config.timeout, config.use_icmp).await
    };

    if is_alive {
        for r in &mut results {
            if r.status == result::PortStatus::Inconclusive {
                r.status = result::PortStatus::Closed;
            }
        }
    }

    Ok(results)
}
