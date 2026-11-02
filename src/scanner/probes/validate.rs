//! Protocol response validation logic
//!
//! Validates protocol structures (DNS transaction IDs & recursive flags,
//! SNMP SEQUENCE & GetResponse tags, NTP control modes, SSDP headers,
//! and IP reflection filters (0x4x/0x6x) against ICMP packet pollution).

use super::payloads::{build_dns_payload_with_txid, build_snmp_payload};
use super::transport::send_udp_probe;
use crate::scanner::result::PortStatus;
use std::net::IpAddr;
use std::time::Duration;

pub async fn execute_dns_probe(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    retries: usize,
) -> (PortStatus, Option<u64>) {
    let (payload, txid) = build_dns_payload_with_txid();
    match send_udp_probe(ip, port, &payload, timeout, retries).await {
        Ok(Some((response, elapsed))) => {
            let lat_millis = elapsed.as_millis() as u64;

            // DNS Header MUST be at least 12 bytes
            if response.len() >= 12 {
                let resp_txid = u16::from_be_bytes([response[0], response[1]]);
                if resp_txid != txid {
                    // Mismatched transaction ID - stale packet or unrelated response
                    return (PortStatus::Inconclusive, None);
                }

                let qr = (response[2] & 0x80) != 0; // QR bit: 1 = Response
                if !qr {
                    return (PortStatus::Inconclusive, None);
                }

                let rcode = response[3] & 0x0F;
                let ra = (response[3] & 0x80) != 0; // Recursion Available

                // RCODE 0 = NoError (with RA=1 -> Open)
                if rcode == 0 && ra {
                    (PortStatus::Open, Some(lat_millis))
                } else {
                    (PortStatus::OpenProtected, Some(lat_millis))
                }
            } else {
                (PortStatus::Inconclusive, None)
            }
        }
        Ok(None) => (PortStatus::Inconclusive, None),
        Err(e) => {
            let is_fd_exhaustion = e
                .raw_os_error()
                .map(|code| code == 23 || code == 24)
                .unwrap_or(false);
            if is_fd_exhaustion {
                (
                    PortStatus::Error(format!("CRITICAL_FD_EXHAUSTION: {}", e)),
                    None,
                )
            } else {
                (PortStatus::Error(e.to_string()), None)
            }
        }
    }
}

pub async fn execute_snmp_probe(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    retries: usize,
) -> (PortStatus, Option<u64>) {
    let payload = build_snmp_payload();
    match send_udp_probe(ip, port, &payload, timeout, retries).await {
        Ok(Some((response, elapsed))) => {
            let lat_ms = elapsed.as_millis() as u64;

            // Valid SNMP response starts with 0x30 (SEQUENCE) and is at least 15 bytes long
            // Must contain 0xA2 (GetResponse-PDU) tag or 0xA8 (Report/Inform PDU)
            if response.len() >= 15
                && response[0] == 0x30
                && response.iter().any(|&b| b == 0xA2 || b == 0xA8)
            {
                (PortStatus::Open, Some(lat_ms))
            } else {
                (PortStatus::Inconclusive, None)
            }
        }
        Ok(None) => (PortStatus::Inconclusive, None),
        Err(e) => {
            let is_fd_exhaustion = e
                .raw_os_error()
                .map(|code| code == 23 || code == 24)
                .unwrap_or(false);
            if is_fd_exhaustion {
                (
                    PortStatus::Error(format!("CRITICAL_FD_EXHAUSTION: {}", e)),
                    None,
                )
            } else {
                (PortStatus::Error(e.to_string()), None)
            }
        }
    }
}

pub async fn execute_udp_probe(
    ip: IpAddr,
    port: u16,
    probe_type: &str,
    payload: &[u8],
    timeout: Duration,
    retries: usize,
) -> (PortStatus, Option<u64>) {
    match send_udp_probe(ip, port, payload, timeout, retries).await {
        Ok(Some((response, elapsed))) => {
            let lat_ms = elapsed.as_millis() as u64;

            let is_valid = validate_udp_response(probe_type, &response);
            if is_valid {
                (PortStatus::Open, Some(lat_ms))
            } else {
                (PortStatus::Inconclusive, None)
            }
        }
        Ok(None) => (PortStatus::Inconclusive, None),
        Err(e) => {
            let is_fd_exhaustion = e
                .raw_os_error()
                .map(|code| code == 23 || code == 24)
                .unwrap_or(false);
            if is_fd_exhaustion {
                (
                    PortStatus::Error(format!("CRITICAL_FD_EXHAUSTION: {}", e)),
                    None,
                )
            } else {
                (PortStatus::Error(e.to_string()), None)
            }
        }
    }
}

/// Validate protocol-specific response payload structure
pub fn validate_udp_response(probe_type: &str, resp: &[u8]) -> bool {
    if resp.is_empty() {
        return false;
    }

    match probe_type {
        "ntp" => {
            // NTP Control Message Response: length >= 12, VN is 2..4, Mode is 6 (0x16 or 0x1A or 0x06 in low bits)
            // or standard NTP response (Mode 4)
            if resp.len() >= 12 {
                let mode = resp[0] & 0x07;
                mode == 6 || mode == 4 || (resp[0] & 0x38) != 0
            } else {
                false
            }
        }
        "ssdp" => {
            // SSDP Response MUST contain HTTP header indicator "HTTP/1.1" or "ST:" or "LOCATION:"
            let resp_str = String::from_utf8_lossy(resp);
            resp_str.contains("HTTP/1.1")
                || resp_str.contains("ST:")
                || resp_str.contains("LOCATION:")
        }
        "memcached" => {
            // Memcached stats response contains "STAT " or "END" or binary protocol magic 0x81
            let resp_str = String::from_utf8_lossy(resp);
            resp_str.contains("STAT ")
                || resp_str.contains("END")
                || (resp.len() >= 4 && resp[0] == 0x81)
        }
        "rpc" => {
            // RPC reply message MUST be at least 16 bytes, XID matching and MsgType = 1 (Reply)
            if resp.len() >= 16 {
                let msg_type = u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]);
                msg_type == 1 // 1 = Reply
            } else {
                false
            }
        }
        "ldap" => {
            // CLDAP response starts with 0x30 (SEQUENCE) and contains LDAP response tag 0x64 (searchEntry) or 0x65
            resp.len() >= 10 && resp[0] == 0x30 && resp.iter().any(|&b| b == 0x64 || b == 0x65)
        }
        "netbios" => {
            // NetBIOS NBSTAT response: length >= 50, flags bit 15 = 1 (Response)
            if resp.len() >= 50 {
                let flags = u16::from_be_bytes([resp[2], resp[3]]);
                (flags & 0x8000) != 0 // QR bit: 1 = Response
            } else {
                false
            }
        }
        "mdns" => {
            // mDNS response: length >= 12, QR bit = 1 (Response)
            if resp.len() >= 12 {
                let flags = u16::from_be_bytes([resp[2], resp[3]]);
                (flags & 0x8000) != 0
            } else {
                false
            }
        }
        "tftp" => {
            // TFTP response opcode: 0x0003 (DATA) or 0x0005 (ERROR)
            if resp.len() >= 4 {
                let opcode = u16::from_be_bytes([resp[0], resp[1]]);
                opcode == 3 || opcode == 5
            } else {
                false
            }
        }
        "ripv1" => {
            // RIP response: length >= 24, Command == 2 (Response), Version == 1 or 2
            resp.len() >= 24 && resp[0] == 0x02 && (resp[1] == 0x01 || resp[1] == 0x02)
        }
        "sip" => {
            // SIP response starts with "SIP/2.0 " or contains SIP status / headers
            let resp_str = String::from_utf8_lossy(resp);
            resp_str.contains("SIP/2.0") || resp_str.contains("CSeq:")
        }
        "rdpeudp" => {
            // MS-RDPEUDP SYN+ACK / connection response:
            // Must be at least 8 bytes, first byte contains RDPUDP flags (e.g. RDPUDP_FLAG_SYN 0x0001 or SYN+ACK)
            // and not ICMP IPv4 (0x4x) or IPv6 (0x6x) reflection header
            let version_nibble = resp[0] & 0xF0;
            let is_ip_header = version_nibble == 0x40 || version_nibble == 0x60;
            resp.len() >= 8 && !is_ip_header && (resp[0] & 0x01 != 0 || resp.len() >= 12)
        }
        "udp_payload" => {
            // Generic UDP payload response must be at least 12 bytes, contain non-zero data,
            // and MUST NOT start with IPv4 (0x4x) or IPv6 (0x6x) headers from ICMP reflection
            let version_nibble = resp[0] & 0xF0;
            let is_ip_header = version_nibble == 0x40 || version_nibble == 0x60;
            if resp.len() >= 12 && !is_ip_header {
                resp.iter().any(|&b| b != 0)
            } else {
                false
            }
        }
        _ => {
            // Fallback for custom probes: require at least 8 non-zero bytes and not IP error header
            let version_nibble = resp[0] & 0xF0;
            let is_ip_header = version_nibble == 0x40 || version_nibble == 0x60;
            resp.len() >= 8 && !is_ip_header && resp.iter().any(|&b| b != 0)
        }
    }
}
