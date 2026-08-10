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
    retries: usize,
) -> ProbeResult {
    let (status, latency_ms) = match port_config.protocol.as_str() {
        "tcp" => {
            let start = Instant::now();
            let st = execute_tcp_probe(ip, port_config.port, timeout).await;
            let lat = if matches!(st, PortStatus::Open | PortStatus::OpenProtected) {
                Some(start.elapsed().as_millis() as u64)
            } else {
                None
            };
            (st, lat)
        }
        "udp" => {
            if port_config.probe_type == "dns" {
                execute_dns_probe(ip, port_config.port, timeout, retries).await
            } else if port_config.probe_type == "snmp" {
                execute_snmp_probe(ip, port_config.port, timeout, retries).await
            } else {
                let payload = build_payload(&port_config.probe_type, port_config.probe_payload.as_deref());
                execute_udp_probe(ip, port_config.port, &port_config.probe_type, &payload, timeout, retries).await
            }
        }
        other => (PortStatus::Error(format!("Unknown protocol: {}", other)), None),
    };

    ProbeResult {
        ip,
        port: port_config.port,
        protocol: port_config.protocol.clone(),
        service_name: port_config.name.clone(),
        description: port_config.description.clone(),
        status,
        response_time_ms: latency_ms,
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
            let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
            if is_fd_exhaustion {
                (PortStatus::Error(format!("CRITICAL_FD_EXHAUSTION: {}", e)), None)
            } else {
                (PortStatus::Error(e.to_string()), None)
            }
        }
    }
}

async fn execute_udp_probe(
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
            let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
            if is_fd_exhaustion {
                (PortStatus::Error(format!("CRITICAL_FD_EXHAUSTION: {}", e)), None)
            } else {
                (PortStatus::Error(e.to_string()), None)
            }
        }
    }
}

/// Validate protocol-specific response payload structure
fn validate_udp_response(probe_type: &str, resp: &[u8]) -> bool {
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
            resp_str.contains("HTTP/1.1") || resp_str.contains("ST:") || resp_str.contains("LOCATION:")
        }
        "memcached" => {
            // Memcached stats response contains "STAT " or "END" or binary protocol magic 0x81
            let resp_str = String::from_utf8_lossy(resp);
            resp_str.contains("STAT ") || resp_str.contains("END") || (resp.len() >= 4 && resp[0] == 0x81)
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

async fn execute_snmp_probe(
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
            if response.len() >= 15 && response[0] == 0x30 && response.iter().any(|&b| b == 0xA2 || b == 0xA8) {
                (PortStatus::Open, Some(lat_ms))
            } else {
                (PortStatus::Inconclusive, None)
            }
        }
        Ok(None) => (PortStatus::Inconclusive, None),
        Err(e) => {
            let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
            if is_fd_exhaustion {
                (PortStatus::Error(format!("CRITICAL_FD_EXHAUSTION: {}", e)), None)
            } else {
                (PortStatus::Error(e.to_string()), None)
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
) -> io::Result<Option<(Vec<u8>, Duration)>> {
    let bind_addr: SocketAddr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };

    let max_attempts = retries + 1;
    let attempt_timeout = timeout;
    let mut last_err = None;

    for attempt in 1..=max_attempts {
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
                if is_fd_exhaustion {
                    return Err(e);
                }
                last_err = Some(e);
                break;
            }
        };
        let dest = SocketAddr::new(ip, port);

        // Connect socket to target (ip, port).
        // On Linux/Unix, a connected UDP socket:
        // 1. Filters out all incoming datagrams not from (ip, port) at kernel level.
        // 2. Delivers ICMP Port Unreachable / Refused errors as Err(ConnectionRefused) instead of raw packet data.
        if let Err(e) = socket.connect(dest).await {
            let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
            if is_fd_exhaustion {
                return Err(e);
            }
            last_err = Some(e);
            if attempt < max_attempts {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            continue;
        }

        let attempt_start = Instant::now();
        if let Err(e) = socket.send(payload).await {
            let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
            if is_fd_exhaustion {
                return Err(e);
            }
            last_err = Some(e);
            if attempt < max_attempts {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            continue;
        }

        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(attempt_timeout, socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let elapsed = attempt_start.elapsed();
                buf.truncate(n);
                return Ok(Some((buf, elapsed)));
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
                if is_fd_exhaustion {
                    return Err(e);
                }
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

    // ICMP Port Unreachable / Refused / Timeout on UDP indicate closed/filtered port (not scanner failure).
    // Only return Err for critical OS errors (e.g. FD exhaustion).
    if let Some(e) = last_err {
        let is_fd_exhaustion = e.raw_os_error().map(|code| code == 23 || code == 24).unwrap_or(false);
        if is_fd_exhaustion {
            Err(e)
        } else {
            Ok(None)
        }
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
        "ripv1" => build_ripv1_payload(),
        "udp_payload" => db_payload.unwrap_or(&[]).to_vec(),
        _ => db_payload.unwrap_or(&[]).to_vec(),
    }
}

// ── RIPv1 (520/udp) ─────────────────────────────────────────────────────
// RIPv1 Request for Full Routing Table (Command=1, Version=1, Metric=16)
fn build_ripv1_payload() -> Vec<u8> {
    vec![
        0x01, 0x01, 0x00, 0x00, // Command: Request (1), Version: RIPv1 (1), Must Be Zero (0)
        0x00, 0x00,             // Address Family Identifier: Unspecified (0)
        0x00, 0x00,             // Route Tag / Must Be Zero
        0x00, 0x00, 0x00, 0x00, // IP Address: 0.0.0.0
        0x00, 0x00, 0x00, 0x00, // Subnet Mask: 0.0.0.0
        0x00, 0x00, 0x00, 0x00, // Next Hop: 0.0.0.0
        0x00, 0x00, 0x00, 0x10, // Metric: 16 (Infinity - Request Full Table)
    ]
}

// ── DNS (53/udp) ────────────────────────────────────────────────────────
// Standard DNS A query for google.com with recursion desired.
// Replicates: host -W 5 google.com $IP
fn build_dns_payload_with_txid() -> (Vec<u8>, u16) {
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
    (pkt, txid)
}

fn build_dns_payload() -> Vec<u8> {
    build_dns_payload_with_txid().0
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
    fn test_ripv1_payload_structure() {
        let pkt = build_ripv1_payload();
        assert_eq!(pkt.len(), 24);
        // Command: 1 (Request), Version: 1 (RIPv1)
        assert_eq!(pkt[0], 0x01);
        assert_eq!(pkt[1], 0x01);
        // Metric: 16 (Infinity)
        assert_eq!(&pkt[20..24], &[0x00, 0x00, 0x00, 0x10]);
    }

    #[test]
    fn test_build_payload_dispatch() {
        // Known probe types should build non-empty payloads
        for pt in &["dns", "mdns", "snmp", "ntp", "ssdp", "tftp", "netbios", "rpc", "ldap", "memcached", "ripv1"] {
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
