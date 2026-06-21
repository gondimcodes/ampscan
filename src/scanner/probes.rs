use crate::db::models::Port;
use crate::scanner::result::{PortStatus, ProbeResult};
use chrono::Utc;
use rand::Rng;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};

// ═══════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════

/// Execute a probe against a single IP:port and return the result.
pub async fn execute_probe(
    ip: IpAddr,
    port_config: &Port,
    timeout: Duration,
    use_icmp: bool,
    retries: usize,
) -> ProbeResult {
    let start = Instant::now();

    let status = match port_config.protocol.as_str() {
        "tcp" => execute_tcp_probe(ip, port_config.port, timeout, use_icmp).await,
        "udp" => {
            if port_config.probe_type == "dns" {
                execute_dns_probe(ip, port_config.port, timeout, use_icmp, retries).await
            } else {
                let payload = build_payload(&port_config.probe_type, port_config.probe_payload.as_deref());
                execute_udp_probe(ip, port_config.port, &payload, timeout, use_icmp, retries).await
            }
        }
        other => PortStatus::Error(format!("Unknown protocol: {}", other)),
    };

    let elapsed = start.elapsed();

    ProbeResult {
        ip,
        port: port_config.port,
        protocol: port_config.protocol.clone(),
        service_name: port_config.name.clone(),
        description: port_config.description.clone(),
        status,
        response_time_ms: Some(elapsed.as_millis() as u64),
        timestamp: Utc::now(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// UDP probe execution
// ═══════════════════════════════════════════════════════════════════════════

async fn execute_dns_probe(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    _use_icmp: bool,
    retries: usize,
) -> PortStatus {
    let payload = build_dns_payload();
    match send_udp_probe(ip, port, &payload, timeout, retries).await {
        Ok(Some(response)) => {
            // Check if it's a DNS response and has RCODE = 5 (REFUSED) or RA = 0 (Recursion Available flag not set)
            if response.len() >= 4 {
                let rcode = response[3] & 0x0F;
                let ra = (response[3] & 0x80) != 0;
                if rcode == 5 || !ra {
                    PortStatus::OpenProtected
                } else {
                    PortStatus::Open
                }
            } else {
                PortStatus::Open
            }
        }
        Ok(None) => PortStatus::Inconclusive,
        Err(e) => {
            let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
            if is_fd_exhaustion {
                PortStatus::Error(format!("CRITICAL_FD_EXHAUSTION: {}", e))
            } else {
                PortStatus::Error(e.to_string())
            }
        }
    }
}

async fn execute_udp_probe(
    ip: IpAddr,
    port: u16,
    payload: &[u8],
    timeout: Duration,
    _use_icmp: bool,
    retries: usize,
) -> PortStatus {
    match send_udp_probe(ip, port, payload, timeout, retries).await {
        Ok(Some(_)) => PortStatus::Open,
        Ok(None) => PortStatus::Inconclusive,
        Err(e) => {
            let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
            if is_fd_exhaustion {
                PortStatus::Error(format!("CRITICAL_FD_EXHAUSTION: {}", e))
            } else {
                PortStatus::Error(e.to_string())
            }
        }
    }
}

async fn send_udp_probe(
    ip: IpAddr,
    port: u16,
    payload: &[u8],
    timeout: Duration,
    retries: usize,
) -> io::Result<Option<Vec<u8>>> {
    let bind_addr: SocketAddr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };

    let max_attempts = retries + 1;
    let attempt_timeout = Duration::from_millis(
        (timeout.as_millis() as u64 / 2).max(1000)
    );
    let mut last_err = None;

    for attempt in 1..=max_attempts {
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e);
                break; // Stop retries if we can't even bind the local socket (typically EMFILE/ENFILE)
            }
        };
        let dest = SocketAddr::new(ip, port);

        if let Err(e) = socket.send_to(payload, dest).await {
            last_err = Some(e);
            if attempt < max_attempts {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            continue;
        }

        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(attempt_timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n > 0 => {
                buf.truncate(n);
                return Ok(Some(buf));
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                last_err = Some(e);
            }
            Err(_) => {
                // Timeout on this attempt
            }
        }

        if attempt < max_attempts {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    if let Some(e) = last_err {
        Err(e)
    } else {
        Ok(None)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TCP probe execution
// ═══════════════════════════════════════════════════════════════════════════

async fn execute_tcp_probe(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    _use_icmp: bool,
) -> PortStatus {
    let dest = SocketAddr::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(dest)).await {
        Ok(Ok(_stream)) => PortStatus::Open, // Connection accepted
        Ok(Err(e)) => {
            let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
            if is_fd_exhaustion {
                PortStatus::Error(format!("CRITICAL_FD_EXHAUSTION: {}", e))
            } else if e.kind() == io::ErrorKind::ConnectionRefused {
                // Connection refused = host alive, port closed
                PortStatus::Closed
            } else {
                PortStatus::Inconclusive
            }
        }
        Err(_) => PortStatus::Inconclusive, // Timeout
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Payload builders — one per probe_type
// ═══════════════════════════════════════════════════════════════════════════

/// Build the probe payload for a given probe_type.
/// For "udp_payload" type, returns the raw bytes from the database.
/// For specific types (dns, snmp, etc.), constructs the protocol packet in code.
fn build_payload(probe_type: &str, db_payload: Option<&[u8]>) -> Vec<u8> {
    match probe_type {
        "dns" => build_dns_payload(),
        "mdns" => build_mdns_payload(),
        "snmp" => build_snmp_payload(),
        "ntp" => build_ntp_payload(),
        "ssdp" => build_ssdp_payload(),
        "tftp" => build_tftp_payload(),
        "netbios" => build_netbios_payload(),
        "rpc" => build_rpc_payload(),
        "ldap" => build_ldap_payload(),
        "memcached" => build_memcached_payload(),
        "udp_payload" => db_payload.unwrap_or(&[]).to_vec(),
        _ => db_payload.unwrap_or(&[]).to_vec(),
    }
}

// ── DNS (53/udp) ────────────────────────────────────────────────────────
// Standard DNS A query for google.com with recursion desired.
// Replicates: host -W 5 google.com $IP
fn build_dns_payload() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let txid: u16 = rng.gen();

    let mut pkt = Vec::with_capacity(33);
    // Header
    pkt.extend_from_slice(&txid.to_be_bytes()); // Transaction ID
    pkt.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, RD=1
    pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]); // Answers: 0
    pkt.extend_from_slice(&[0x00, 0x00]); // Authority: 0
    pkt.extend_from_slice(&[0x00, 0x00]); // Additional: 0
    // Question: google.com A IN
    pkt.push(6); // length of "google"
    pkt.extend_from_slice(b"google");
    pkt.push(3); // length of "com"
    pkt.extend_from_slice(b"com");
    pkt.push(0); // root label
    pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE: A
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
    pkt
}

// ── mDNS (5353/udp) ─────────────────────────────────────────────────────
// PTR query for _services._dns-sd._udp.local
// Replicates: dig +timeout=1 @$IP -p 5353 ptr _services._dns-sd._udp.local
fn build_mdns_payload() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    // Header
    pkt.extend_from_slice(&[0x00, 0x00]); // Transaction ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags: standard query
    pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]); // Answers: 0
    pkt.extend_from_slice(&[0x00, 0x00]); // Authority: 0
    pkt.extend_from_slice(&[0x00, 0x00]); // Additional: 0
    // Question: _services._dns-sd._udp.local PTR IN
    pkt.push(9);
    pkt.extend_from_slice(b"_services");
    pkt.push(7);
    pkt.extend_from_slice(b"_dns-sd");
    pkt.push(4);
    pkt.extend_from_slice(b"_udp");
    pkt.push(5);
    pkt.extend_from_slice(b"local");
    pkt.push(0); // root label
    pkt.extend_from_slice(&[0x00, 0x0C]); // QTYPE: PTR
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
    pkt
}

// ── SNMP (161/udp) ──────────────────────────────────────────────────────
// SNMPv2c GET with community "public", OID 1.3.6.1.2.1.1.1.0 (sysDescr)
// Replicates: snmpget -v 2c -c public $IP iso.3.6.1.2.1.1.1.0
fn build_snmp_payload() -> Vec<u8> {
    vec![
        // SEQUENCE (overall message)
        0x30, 0x29,
        // INTEGER: version = 1 (SNMPv2c)
        0x02, 0x01, 0x01,
        // OCTET STRING: community = "public"
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
        // GetRequest-PDU (context-specific, constructed, tag 0)
        0xA0, 0x1C,
        // INTEGER: request-id = 1
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
        // INTEGER: error-status = 0
        0x02, 0x01, 0x00,
        // INTEGER: error-index = 0
        0x02, 0x01, 0x00,
        // SEQUENCE OF varbinds
        0x30, 0x0E,
        // SEQUENCE (one varbind)
        0x30, 0x0C,
        // OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
        // NULL value
        0x05, 0x00,
    ]
}

// ── NTP (123/udp) ───────────────────────────────────────────────────────
// NTP Control Message (mode 6) with opcode 2 (readvar)
// Replicates: ntpq -c rv $IP
fn build_ntp_payload() -> Vec<u8> {
    vec![
        // LI=0, VN=2, Mode=6 (control) → 00 010 110 = 0x16
        0x16,
        // R=0, E=0, M=0, OpCode=2 (readvar) → 0 0 0 00010 = 0x02
        0x02,
        // Sequence number (16-bit)
        0x00, 0x01,
        // Status (16-bit)
        0x00, 0x00,
        // Association ID (16-bit)
        0x00, 0x00,
        // Offset (16-bit)
        0x00, 0x00,
        // Count (16-bit)
        0x00, 0x00,
    ]
}

// ── SSDP (1900/udp) ─────────────────────────────────────────────────────
// M-SEARCH request for UPnP root device
// Replicates the M-SEARCH from the bash script
fn build_ssdp_payload() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\n\
      Host:239.255.255.250:1900\r\n\
      ST:upnp:rootdevice\r\n\
      Man:\"ssdp:discover\"\r\n\
      MX:3\r\n\
      \r\n"
        .to_vec()
}

// ── TFTP (69/udp) ───────────────────────────────────────────────────────
// TFTP Read Request (RRQ) for "a.pdf" in octet mode
// Replicates: curl -m 3 tftp://$IP/a.pdf
fn build_tftp_payload() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(16);
    pkt.extend_from_slice(&[0x00, 0x01]); // Opcode: RRQ
    pkt.extend_from_slice(b"a.pdf");
    pkt.push(0); // null terminator
    pkt.extend_from_slice(b"octet");
    pkt.push(0); // null terminator
    pkt
}

// ── NETBIOS (137/udp) ───────────────────────────────────────────────────
// NetBIOS Node Status Request (NBSTAT) for wildcard name "*"
// Replicates: nmblookup -A $IP
fn build_netbios_payload() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    // Header
    pkt.extend_from_slice(&[0x00, 0x01]); // Transaction ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags
    pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]); // Answers: 0
    pkt.extend_from_slice(&[0x00, 0x00]); // Authority: 0
    pkt.extend_from_slice(&[0x00, 0x00]); // Additional: 0
    // Name: "*" encoded as CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    // '*' = 0x2A → first nibble (0x2) + 'A' = 'C', second nibble (0xA) + 'A' = 'K'
    // Remaining 15 null bytes → 30 'A's
    pkt.push(0x20); // Name length: 32
    pkt.push(b'C');
    pkt.push(b'K');
    for _ in 0..30 {
        pkt.push(b'A');
    }
    pkt.push(0x00); // Name terminator
    pkt.extend_from_slice(&[0x00, 0x21]); // Type: NBSTAT
    pkt.extend_from_slice(&[0x00, 0x01]); // Class: IN
    pkt
}

// ── RPC Portmapper (111/udp) ────────────────────────────────────────────
// RPC Call to Portmapper program (100000), version 2, procedure 4 (DUMP)
// Replicates: rpcinfo -T udp -p $IP
fn build_rpc_payload() -> Vec<u8> {
    vec![
        // XID (transaction ID)
        0x00, 0x00, 0x00, 0x01,
        // Message Type: Call (0)
        0x00, 0x00, 0x00, 0x00,
        // RPC Version: 2
        0x00, 0x00, 0x00, 0x02,
        // Program: 100000 (portmapper) = 0x000186A0
        0x00, 0x01, 0x86, 0xA0,
        // Program Version: 2
        0x00, 0x00, 0x00, 0x02,
        // Procedure: 4 (DUMP)
        0x00, 0x00, 0x00, 0x04,
        // Credentials: AUTH_NULL
        0x00, 0x00, 0x00, 0x00,
        // Credentials length: 0
        0x00, 0x00, 0x00, 0x00,
        // Verifier: AUTH_NULL
        0x00, 0x00, 0x00, 0x00,
        // Verifier length: 0
        0x00, 0x00, 0x00, 0x00,
    ]
}

// ── LDAP / CLDAP (389/udp) ──────────────────────────────────────────────
// CLDAP searchRequest: base scope, filter (objectClass present), no attributes
// Replicates: ldapsearch -x -h $IP -s base
fn build_ldap_payload() -> Vec<u8> {
    vec![
        // SEQUENCE
        0x30, 0x25,
        // INTEGER: messageID = 1
        0x02, 0x01, 0x01,
        // SearchRequest (APPLICATION 3)
        0x63, 0x20,
        // OCTET STRING: baseObject = "" (empty)
        0x04, 0x00,
        // ENUMERATED: scope = 0 (base)
        0x0A, 0x01, 0x00,
        // ENUMERATED: derefAliases = 0 (never)
        0x0A, 0x01, 0x00,
        // INTEGER: sizeLimit = 0
        0x02, 0x01, 0x00,
        // INTEGER: timeLimit = 0
        0x02, 0x01, 0x00,
        // BOOLEAN: typesOnly = FALSE
        0x01, 0x01, 0x00,
        // Filter: present "objectClass" (context [7])
        0x87, 0x0B,
        0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x43, 0x6C, 0x61, 0x73, 0x73,
        // SEQUENCE: attributes = [] (empty)
        0x30, 0x00,
    ]
}

// ── Memcached (11211/udp) ───────────────────────────────────────────────
// Memcached UDP "stats" command
// Replicates: printf '\x0\x0\x0\x0\x0\x1\x0\x0stats\n' | nc -w 3 -u $IP 11211
fn build_memcached_payload() -> Vec<u8> {
    vec![
        // UDP header for memcached
        0x00, 0x00, // Request ID
        0x00, 0x00, // Sequence number
        0x00, 0x01, // Total datagrams
        0x00, 0x00, // Reserved
        // "stats\n"
        0x73, 0x74, 0x61, 0x74, 0x73, 0x0A,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_payload_structure() {
        let pkt = build_dns_payload();
        assert!(pkt.len() >= 28);
        // Flags: standard query, RD=1
        assert_eq!(pkt[2], 0x01);
        assert_eq!(pkt[3], 0x00);
        // Questions: 1
        assert_eq!(pkt[4], 0x00);
        assert_eq!(pkt[5], 0x01);
        // "google" label
        assert_eq!(pkt[12], 6);
        assert_eq!(&pkt[13..19], b"google");
    }

    #[test]
    fn test_snmp_payload_structure() {
        let pkt = build_snmp_payload();
        assert_eq!(pkt.len(), 43);
        // First byte: SEQUENCE tag
        assert_eq!(pkt[0], 0x30);
        // Community string "public"
        assert_eq!(&pkt[7..13], b"public");
    }

    #[test]
    fn test_ntp_payload_structure() {
        let pkt = build_ntp_payload();
        assert_eq!(pkt.len(), 12);
        // LI=0, VN=2, Mode=6
        assert_eq!(pkt[0], 0x16);
        // Opcode=2 (readvar)
        assert_eq!(pkt[1], 0x02);
    }

    #[test]
    fn test_netbios_payload_structure() {
        let pkt = build_netbios_payload();
        // Name should start with 0x20 (length 32) followed by "CK" + 30 "A"s
        assert_eq!(pkt[12], 0x20);
        assert_eq!(pkt[13], b'C');
        assert_eq!(pkt[14], b'K');
        // Type: NBSTAT = 0x0021
        let type_offset = pkt.len() - 4;
        assert_eq!(pkt[type_offset], 0x00);
        assert_eq!(pkt[type_offset + 1], 0x21);
    }

    #[test]
    fn test_rpc_payload_structure() {
        let pkt = build_rpc_payload();
        assert_eq!(pkt.len(), 40);
        // Program: 100000 (portmapper) at bytes 12-15
        assert_eq!(&pkt[12..16], &[0x00, 0x01, 0x86, 0xA0]);
    }

    #[test]
    fn test_ssdp_payload_contains_msearch() {
        let pkt = build_ssdp_payload();
        let text = String::from_utf8_lossy(&pkt);
        assert!(text.contains("M-SEARCH"));
        assert!(text.contains("upnp:rootdevice"));
    }

    #[test]
    fn test_tftp_payload_structure() {
        let pkt = build_tftp_payload();
        // Opcode: RRQ = 0x0001
        assert_eq!(pkt[0], 0x00);
        assert_eq!(pkt[1], 0x01);
        // Filename "a.pdf"
        assert_eq!(&pkt[2..7], b"a.pdf");
    }

    #[test]
    fn test_ldap_payload_structure() {
        let pkt = build_ldap_payload();
        assert_eq!(pkt.len(), 39);
        // SEQUENCE tag
        assert_eq!(pkt[0], 0x30);
        // SearchRequest application tag
        assert_eq!(pkt[5], 0x63);
    }

    #[test]
    fn test_memcached_payload_contains_stats() {
        let pkt = build_memcached_payload();
        assert_eq!(pkt.len(), 14);
        // "stats\n" at end
        assert_eq!(&pkt[8..], b"stats\n");
    }

    #[test]
    fn test_build_payload_dispatch() {
        // Known probe types should build non-empty payloads
        for pt in &["dns", "mdns", "snmp", "ntp", "ssdp", "tftp", "netbios", "rpc", "ldap", "memcached"] {
            let payload = build_payload(pt, None);
            assert!(!payload.is_empty(), "Probe '{}' should produce non-empty payload", pt);
        }
        // udp_payload with no DB data should return empty
        let empty = build_payload("udp_payload", None);
        assert!(empty.is_empty());
        // udp_payload with DB data should return it
        let data = vec![0xFF, 0x01];
        let result = build_payload("udp_payload", Some(&data));
        assert_eq!(result, data);
    }
}
