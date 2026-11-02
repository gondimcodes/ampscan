//! Network transport layer for UDP and TCP probes
//!
//! Handles connected UDP sockets (for kernel-level (ip, port) filtering and ICMP handling),
//! TCP connect probes, timeouts, retries and file descriptor exhaustion detection.

use crate::scanner::result::PortStatus;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};

/// Send a UDP probe using a connected socket with timeout and retries.
pub async fn send_udp_probe(
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
                let is_fd_exhaustion = e
                    .raw_os_error()
                    .map(|code| code == 23 || code == 24)
                    .unwrap_or(false);
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
            let is_fd_exhaustion = e
                .raw_os_error()
                .map(|code| code == 23 || code == 24)
                .unwrap_or(false);
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
            let is_fd_exhaustion = e
                .raw_os_error()
                .map(|code| code == 23 || code == 24)
                .unwrap_or(false);
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
                let is_fd_exhaustion = e
                    .raw_os_error()
                    .map(|code| code == 23 || code == 24)
                    .unwrap_or(false);
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
        let is_fd_exhaustion = e
            .raw_os_error()
            .map(|code| code == 23 || code == 24)
            .unwrap_or(false);
        if is_fd_exhaustion {
            Err(e)
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

/// Execute a TCP connection probe against a target IP and port.
pub async fn execute_tcp_probe(ip: IpAddr, port: u16, timeout: Duration) -> PortStatus {
    let dest = SocketAddr::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(dest)).await {
        Ok(Ok(_stream)) => PortStatus::Open, // Connection accepted
        Ok(Err(e)) => {
            let is_fd_exhaustion = e
                .raw_os_error()
                .map(|code| code == 23 || code == 24)
                .unwrap_or(false);
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
