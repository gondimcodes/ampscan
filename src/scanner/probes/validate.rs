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

fn is_ip_reflection_header(resp: &[u8]) -> bool {
    !resp.is_empty() && matches!(resp[0] & 0xF0, 0x40 | 0x60)
}

fn map_udp_error(e: std::io::Error) -> (PortStatus, Option<u64>) {
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

/// Parse a single ASN.1/BER TLV element, supporting short and long-form lengths (0x81..=0x84).
/// Returns `(tag, value_slice, remaining_slice)`.
fn parse_ber_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let &tag = data.first()?;
    let &len_byte = data.get(1)?;
    let (len, hdr_len) = if len_byte < 0x80 {
        (len_byte as usize, 2usize)
    } else {
        let num_octets = (len_byte & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 || data.len() < 2 + num_octets {
            return None;
        }
        let mut len: usize = 0;
        for &b in &data[2..2 + num_octets] {
            len = (len << 8) | (b as usize);
        }
        (len, 2 + num_octets)
    };
    let end = hdr_len.checked_add(len)?;
    if data.len() < end {
        return None;
    }
    Some((tag, &data[hdr_len..end], &data[end..]))
}

/// Validate an NTP Control Message (Mode 6, OpCode 2 readvar) response.
pub fn assess_ntp_response(resp: &[u8]) -> PortStatus {
    if resp.len() < 12 || is_ip_reflection_header(resp) {
        return PortStatus::Inconclusive;
    }
    let vn = (resp[0] >> 3) & 0x07;
    let mode = resp[0] & 0x07;
    let is_response = (resp[1] & 0x80) != 0;
    let is_error = (resp[1] & 0x40) != 0;
    let opcode = resp[1] & 0x1F;

    if !(1..=4).contains(&vn) || mode != 6 || !is_response || opcode != 2 {
        return PortStatus::Inconclusive;
    }
    if is_error {
        PortStatus::OpenProtected
    } else if resp.len() > 12 {
        PortStatus::Open
    } else {
        PortStatus::Inconclusive
    }
}

pub async fn execute_ntp_probe(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    retries: usize,
) -> (PortStatus, Option<u64>) {
    let payload = super::payloads::build_ntp_payload();
    match send_udp_probe(ip, port, &payload, timeout, retries).await {
        Ok(Some((response, elapsed))) => {
            let lat_ms = elapsed.as_millis() as u64;
            let status = assess_ntp_response(&response);
            if matches!(status, PortStatus::Open | PortStatus::OpenProtected) {
                (status, Some(lat_ms))
            } else {
                (PortStatus::Inconclusive, None)
            }
        }
        Ok(None) => (PortStatus::Inconclusive, None),
        Err(e) => map_udp_error(e),
    }
}

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

            // Valid SNMPv2c response: SEQUENCE { version INTEGER, community OCTET STRING, PDU }
            // PDU tag must be 0xA2 (GetResponse-PDU) or 0xA8 (Report-PDU).
            let is_valid_snmp = (|| -> Option<bool> {
                let (seq_tag, seq_val, _) = parse_ber_tlv(&response)?;
                if seq_tag != 0x30 {
                    return Some(false);
                }
                let (ver_tag, _, rest) = parse_ber_tlv(seq_val)?;
                if ver_tag != 0x02 {
                    return Some(false);
                }
                let (comm_tag, _, rest) = parse_ber_tlv(rest)?;
                if comm_tag != 0x04 {
                    return Some(false);
                }
                let (pdu_tag, _, _) = parse_ber_tlv(rest)?;
                Some(pdu_tag == 0xA2 || pdu_tag == 0xA8)
            })()
            .unwrap_or(false);

            if response.len() >= 15 && is_valid_snmp {
                (PortStatus::Open, Some(lat_ms))
            } else {
                (PortStatus::Inconclusive, None)
            }
        }
        Ok(None) => (PortStatus::Inconclusive, None),
        Err(e) => map_udp_error(e),
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
        "ntp" => matches!(
            assess_ntp_response(resp),
            PortStatus::Open | PortStatus::OpenProtected
        ),
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
            // RPC reply message MUST be at least 16 bytes, match XID (0x00000001) and MsgType = 1 (Reply)
            if resp.len() >= 16 {
                let xid_ok = resp[0..4] == [0x00, 0x00, 0x00, 0x01];
                let msg_type = u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]);
                xid_ok && msg_type == 1
            } else {
                false
            }
        }
        "ldap" => {
            // CLDAP response: SEQUENCE { messageID INTEGER, protocolOp (0x64 SearchResultEntry | 0x65 SearchResultDone) }
            if resp.len() < 10 {
                return false;
            }
            (|| -> Option<bool> {
                let (seq_tag, seq_val, _) = parse_ber_tlv(resp)?;
                if seq_tag != 0x30 {
                    return Some(false);
                }
                let (msg_id_tag, _, rest) = parse_ber_tlv(seq_val)?;
                if msg_id_tag != 0x02 {
                    return Some(false);
                }
                let (op_tag, _, _) = parse_ber_tlv(rest)?;
                Some(op_tag == 0x64 || op_tag == 0x65)
            })()
            .unwrap_or(false)
        }
        "netbios" => {
            // NetBIOS NBSTAT response: length >= 50, TXID match (0x0001), flags bit 15 = 1 (Response)
            if resp.len() >= 50 && resp[0..2] == [0x00, 0x01] {
                let flags = u16::from_be_bytes([resp[2], resp[3]]);
                (flags & 0x8000) != 0 // QR bit: 1 = Response
            } else {
                false
            }
        }
        "mdns" => {
            // mDNS response: length >= 12, not ICMP reflection, QR = 1 (Response),
            // Opcode = 0 (Standard Query), RCODE = 0 (NoError), and at least 1 RR (AN/NS/AR).
            // Note: TXID is not locked per RFC 6762 §18.1.
            if resp.len() >= 12 && !is_ip_reflection_header(resp) {
                let flags = u16::from_be_bytes([resp[2], resp[3]]);
                let is_qr = (flags & 0x8000) != 0;
                let is_std_query = (flags & 0x7800) == 0;
                let is_noerror = (flags & 0x000F) == 0;
                let an_count = u16::from_be_bytes([resp[6], resp[7]]);
                let ns_count = u16::from_be_bytes([resp[8], resp[9]]);
                let ar_count = u16::from_be_bytes([resp[10], resp[11]]);
                is_qr
                    && is_std_query
                    && is_noerror
                    && (an_count > 0 || ns_count > 0 || ar_count > 0)
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
            // MS-RDPEUDP SYN+ACK response:
            // Must be at least 16 bytes (8B FEC_HEADER + 8B SYNDATA_PAYLOAD), not ICMP reflection (0x4x/0x6x),
            // and uFlags at bytes 6..8 (little-endian) must carry RDPUDP_FLAG_SYN (0x0001) or RDPUDP_FLAG_ACK (0x0004).
            if resp.len() < 16 || is_ip_reflection_header(resp) {
                return false;
            }
            let flags = u16::from_le_bytes([resp[6], resp[7]]);
            const RDPUDP_FLAG_SYN: u16 = 0x0001;
            const RDPUDP_FLAG_ACK: u16 = 0x0004;
            (flags & (RDPUDP_FLAG_SYN | RDPUDP_FLAG_ACK)) != 0
        }
        "udp_payload" => {
            // Generic UDP payload response must be at least 12 bytes, contain non-zero data,
            // and MUST NOT start with IPv4 (0x4x) or IPv6 (0x6x) headers from ICMP reflection
            if resp.len() >= 12 && !is_ip_reflection_header(resp) {
                resp.iter().any(|&b| b != 0)
            } else {
                false
            }
        }
        _ => {
            // Fallback for custom probes: require at least 8 non-zero bytes and not IP error header
            resp.len() >= 8 && !is_ip_reflection_header(resp) && resp.iter().any(|&b| b != 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_assessment_rejects_garbage_and_handles_error_bit() {
        // Arbitrary ASCII starting with 'H' (0x48) >= 12 bytes must NOT be Open
        assert_eq!(
            assess_ntp_response(b"HTTP/1.1 200 OK"),
            PortStatus::Inconclusive
        );
        // ICMPv6 reflection (0x68) must NOT be Open
        assert_eq!(assess_ntp_response(&[0x68; 16]), PortStatus::Inconclusive);
        // Valid NTP Mode 6 Control Response (VN=2, Mode=6 -> 0x16, R=1 E=0 OpCode=2 -> 0x82) with payload
        let mut vuln = vec![0x16, 0x82, 0, 1, 0, 0, 0, 0, 0, 0, 0, 8];
        vuln.extend_from_slice(b"version=");
        assert_eq!(assess_ntp_response(&vuln), PortStatus::Open);

        // Protected NTP Mode 6 Control Response with Error bit E=1 (0xC2)
        let prot = vec![0x16, 0xC2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(assess_ntp_response(&prot), PortStatus::OpenProtected);
    }

    #[test]
    fn test_rdpeudp_validation_checks_uflags_offset() {
        // Random 16-byte payload with uFlags=0x0000 at bytes 6..8 must fail
        let fake = [0x01u8, 0, 0, 0, 0, 0, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8];
        assert!(!validate_udp_response("rdpeudp", &fake));

        // Valid SYN+ACK flags (0x0005) at bytes 6..8 (LE) must pass
        let valid = [0x00u8, 0, 0, 0, 1, 0, 0x05, 0x00, 1, 2, 3, 4, 5, 6, 7, 8];
        assert!(validate_udp_response("rdpeudp", &valid));
    }

    #[test]
    fn test_rpc_netbios_and_ber_validators() {
        // RPC: wrong XID must fail, matching XID + Reply (1) must pass
        let bad_rpc = [0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(!validate_udp_response("rpc", &bad_rpc));
        let ok_rpc = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(validate_udp_response("rpc", &ok_rpc));

        // NetBIOS: wrong TXID must fail, matching TXID (0x0001) + QR=1 must pass
        let mut nb = vec![0u8; 50];
        nb[0] = 0x00;
        nb[1] = 0x02;
        nb[2] = 0x80;
        assert!(!validate_udp_response("netbios", &nb));
        nb[1] = 0x01;
        assert!(validate_udp_response("netbios", &nb));

        // LDAP: ASCII '0...d...e' must fail BER validation
        assert!(!validate_udp_response("ldap", b"0123456789de"));
        // Valid CLDAP SearchResultDone (0x65)
        let ok_ldap = [
            0x30, 0x0C, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        assert!(validate_udp_response("ldap", &ok_ldap));
    }

    #[test]
    fn test_mdns_validation_rejects_errors_empty_and_accepts_valid_response() {
        // Non-mDNS / REFUSED (QR=1, RCODE=5) with 1 answer must fail
        let refused = [0x00, 0x00, 0x84, 0x05, 0, 1, 0, 1, 0, 0, 0, 0];
        assert!(!validate_udp_response("mdns", &refused));

        // Empty mDNS response (QR=1, NOERROR, 0 answers/authority/additional) must fail
        let empty = [0x00, 0x00, 0x84, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        assert!(!validate_udp_response("mdns", &empty));

        // Non-standard opcode (Opcode=1, IQUERY) must fail
        let bad_opcode = [0x00, 0x00, 0x88, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
        assert!(!validate_udp_response("mdns", &bad_opcode));

        // Valid mDNS response (arbitrary TXID per RFC 6762 §18.1, QR=1 AA=1, NOERROR, ANCOUNT=1)
        let valid = [0x02, 0x08, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
        assert!(validate_udp_response("mdns", &valid));
    }
}
