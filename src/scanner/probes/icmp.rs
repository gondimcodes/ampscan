//! ICMP Echo Reachability Probe (IPv4 & IPv6)
//!
//! Used post-scan on hosts with 100% `Inconclusive` port results to determine
//! whether the target IP is actually UP (so silent ports can be classified as `Closed`)
//! or truly unreachable (`Inconclusive`).

use std::net::IpAddr;
use std::time::Duration;

/// Compute RFC 1071 Internet Checksum over a byte slice.
pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum = sum.wrapping_add(u16::from_be_bytes(*chunk) as u32);
    }
    if let Some(&rem) = remainder.first() {
        sum = sum.wrapping_add((rem as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an 8-byte ICMPv4 (type=8) or ICMPv6 (type=128) Echo Request packet.
pub fn build_icmp_echo_request(is_ipv6: bool, id: u16, seq: u16) -> [u8; 8] {
    let msg_type = if is_ipv6 { 128 } else { 8 };
    let mut pkt = [0u8; 8];
    pkt[0] = msg_type;
    pkt[1] = 0; // Code 0
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    if !is_ipv6 {
        let csum = icmp_checksum(&pkt);
        pkt[2..4].copy_from_slice(&csum.to_be_bytes());
    }
    pkt
}

/// Validate whether a received buffer is an ICMP Echo Reply matching `expected_seq`
/// (and `expected_id` when provided, e.g. for `SOCK_RAW`).
/// Handles both stripped ICMP payloads (Linux `SOCK_DGRAM`) and IPv4-prefixed payloads
/// (Linux `SOCK_RAW` / macOS `SOCK_DGRAM`).
pub fn is_icmp_echo_reply(
    is_ipv6: bool,
    buf: &[u8],
    expected_id: Option<u16>,
    expected_seq: u16,
) -> bool {
    let icmp = if !is_ipv6 && buf.len() >= 28 && (buf[0] & 0xF0) == 0x40 {
        let ihl = ((buf[0] & 0x0F) as usize) * 4;
        if ihl < 20 || buf.len() < ihl + 8 {
            return false;
        }
        &buf[ihl..]
    } else {
        buf
    };

    if icmp.len() < 8 {
        return false;
    }

    let expected_type = if is_ipv6 { 129 } else { 0 };
    if icmp[0] != expected_type || icmp[1] != 0 {
        return false;
    }

    if let Some(id) = expected_id {
        let resp_id = u16::from_be_bytes([icmp[4], icmp[5]]);
        if resp_id != id {
            return false;
        }
    }

    let resp_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    resp_seq == expected_seq
}

/// Probe a single IP with ICMP Echo Request. Returns `true` if an Echo Reply is received.
pub async fn probe_icmp_echo(ip: IpAddr, timeout: Duration) -> bool {
    #[cfg(unix)]
    {
        unix_impl::probe_icmp_echo_unix(ip, timeout).await
    }
    #[cfg(not(unix))]
    {
        let _ = (ip, timeout);
        false
    }
}

#[cfg(unix)]
mod unix_impl {
    use super::{build_icmp_echo_request, is_icmp_echo_reply};
    use std::net::{IpAddr, SocketAddr};
    use std::os::unix::io::FromRawFd;
    use std::time::Duration;

    pub async fn probe_icmp_echo_unix(ip: IpAddr, timeout: Duration) -> bool {
        let is_ipv6 = ip.is_ipv6();
        let domain = if is_ipv6 {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        let proto = if is_ipv6 {
            libc::IPPROTO_ICMPV6
        } else {
            libc::IPPROTO_ICMP
        };

        let seq: u16 = 1;
        let id: u16 = rand::random();

        // Prefer SOCK_DGRAM (non-blocking async via Tokio, works both as root and unprivileged).
        let dgram_fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, proto) };
        if dgram_fd >= 0 {
            let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(dgram_fd) };
            if std_sock.set_nonblocking(true).is_ok() {
                if let Ok(sock) = tokio::net::UdpSocket::from_std(std_sock) {
                    if sock.connect(SocketAddr::new(ip, 0)).await.is_ok() {
                        let pkt = build_icmp_echo_request(is_ipv6, id, seq);
                        if sock.send(&pkt).await.is_ok() {
                            let deadline = tokio::time::Instant::now() + timeout;
                            let mut buf = [0u8; 256];
                            loop {
                                let remaining =
                                    deadline.saturating_duration_since(tokio::time::Instant::now());
                                if remaining.is_zero() {
                                    break;
                                }
                                match tokio::time::timeout(remaining, sock.recv(&mut buf)).await {
                                    Ok(Ok(n)) if n >= 8 => {
                                        if is_icmp_echo_reply(is_ipv6, &buf[..n], None, seq) {
                                            return true;
                                        }
                                    }
                                    _ => break,
                                }
                            }
                        }
                    }
                    return false;
                }
            }
            // std_sock / dgram_fd dropped here if setup failed
            return false;
        }

        // Fallback to SOCK_RAW (requires root / CAP_NET_RAW) in blocking pool with poll().
        tokio::task::spawn_blocking(move || probe_icmp_raw_blocking(ip, is_ipv6, id, seq, timeout))
            .await
            .unwrap_or(false)
    }

    fn probe_icmp_raw_blocking(
        ip: IpAddr,
        is_ipv6: bool,
        id: u16,
        seq: u16,
        timeout: Duration,
    ) -> bool {
        let domain = if is_ipv6 {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        let proto = if is_ipv6 {
            libc::IPPROTO_ICMPV6
        } else {
            libc::IPPROTO_ICMP
        };

        let raw_fd = unsafe { libc::socket(domain, libc::SOCK_RAW, proto) };
        if raw_fd < 0 {
            return false;
        }
        // Wrap in UdpSocket purely for RAII close() on drop
        let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
        if std_sock.connect(SocketAddr::new(ip, 0)).is_err() {
            return false;
        }

        let pkt = build_icmp_echo_request(is_ipv6, id, seq);
        if std_sock.send(&pkt).is_err() {
            return false;
        }

        let deadline = std::time::Instant::now() + timeout;
        let mut buf = [0u8; 256];
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;
            let mut pfd = libc::pollfd {
                fd: raw_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if rc <= 0 || (pfd.revents & libc::POLLIN) == 0 {
                return false;
            }
            match std_sock.recv(&mut buf) {
                Ok(n) if n >= 8 => {
                    if is_icmp_echo_reply(is_ipv6, &buf[..n], Some(id), seq) {
                        return true;
                    }
                }
                _ => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_checksum_and_packet_construction() {
        let pkt = build_icmp_echo_request(false, 0x1234, 0x0001);
        assert_eq!(pkt[0], 8); // ICMPv4 Echo Request
        assert_eq!(pkt[1], 0);
        assert_eq!(icmp_checksum(&pkt), 0); // Valid RFC 1071 checksum verifies to 0

        let pkt6 = build_icmp_echo_request(true, 0x1234, 0x0001);
        assert_eq!(pkt6[0], 128); // ICMPv6 Echo Request
        assert_eq!(pkt6[1], 0);
    }

    #[test]
    fn test_is_icmp_echo_reply_dgram_and_raw() {
        // Linux SOCK_DGRAM ICMPv4 Echo Reply (no IP header)
        let dgram_reply = [0, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        assert!(is_icmp_echo_reply(false, &dgram_reply, None, 1));
        assert!(!is_icmp_echo_reply(false, &dgram_reply, None, 2));

        // Wrong ICMP type (Destination Unreachable = 3) must fail
        let unreach = [3, 3, 0, 0, 0x12, 0x34, 0x00, 0x01];
        assert!(!is_icmp_echo_reply(false, &unreach, None, 1));

        // SOCK_RAW / macOS IPv4 header (20 bytes, 0x45...) + ICMPv4 Echo Reply
        let mut raw_reply = vec![0u8; 28];
        raw_reply[0] = 0x45; // IPv4, IHL=5 (20 bytes)
        raw_reply[20] = 0; // Echo Reply
        raw_reply[21] = 0;
        raw_reply[24] = 0xAB;
        raw_reply[25] = 0xCD;
        raw_reply[26] = 0x00;
        raw_reply[27] = 0x01;
        assert!(is_icmp_echo_reply(false, &raw_reply, Some(0xABCD), 1));
        assert!(!is_icmp_echo_reply(false, &raw_reply, Some(0x9999), 1));

        // ICMPv6 Echo Reply (Type 129)
        let v6_reply = [129, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        assert!(is_icmp_echo_reply(true, &v6_reply, Some(0x1234), 1));
    }
}
