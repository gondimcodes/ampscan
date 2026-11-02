//! Network probing engine and protocol dispatch
//!
//! Coordinates network transport, protocol-specific request generation,
//! and response validation across UDP and TCP services.

pub mod http;
pub mod payloads;
pub mod transport;
pub mod validate;

pub use payloads::build_payload;

use crate::db::models::Port;
use crate::scanner::result::{PortStatus, ProbeResult};
use chrono::Utc;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Execute a probe against a single IP:port and return the result.
pub async fn execute_probe(
    ip: IpAddr,
    port_config: &Port,
    timeout: Duration,
    retries: usize,
) -> ProbeResult {
    let (status, latency_ms, custom_desc) = match port_config.protocol.as_str() {
        "tcp" => {
            if port_config.probe_type == "php_http" {
                let (st, lat, desc) =
                    http::execute_php_probe(ip, port_config.port, false, timeout).await;
                (st, lat, Some(desc))
            } else if port_config.probe_type == "php_https" {
                let (st, lat, desc) =
                    http::execute_php_probe(ip, port_config.port, true, timeout).await;
                (st, lat, Some(desc))
            } else {
                let start = Instant::now();
                let st = transport::execute_tcp_probe(ip, port_config.port, timeout).await;
                let lat = if matches!(st, PortStatus::Open | PortStatus::OpenProtected) {
                    Some(start.elapsed().as_millis() as u64)
                } else {
                    None
                };
                (st, lat, None)
            }
        }
        "udp" => {
            let (st, lat) = if port_config.probe_type == "dns" {
                validate::execute_dns_probe(ip, port_config.port, timeout, retries).await
            } else if port_config.probe_type == "snmp" {
                validate::execute_snmp_probe(ip, port_config.port, timeout, retries).await
            } else {
                let payload = payloads::build_payload(
                    &port_config.probe_type,
                    port_config.probe_payload.as_deref(),
                );
                validate::execute_udp_probe(
                    ip,
                    port_config.port,
                    &port_config.probe_type,
                    &payload,
                    timeout,
                    retries,
                )
                .await
            };
            (st, lat, None)
        }
        other => (
            PortStatus::Error(format!("Unknown protocol: {}", other)),
            None,
            None,
        ),
    };

    let description = custom_desc.unwrap_or_else(|| port_config.description.clone());

    ProbeResult {
        ip,
        port: port_config.port,
        protocol: port_config.protocol.clone(),
        service_name: port_config.name.clone(),
        description,
        status,
        response_time_ms: latency_ms,
        timestamp: Utc::now(),
    }
}
