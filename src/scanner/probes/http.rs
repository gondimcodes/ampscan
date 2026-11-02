//! HTTP and HTTPS banner grabber probe for PHP2Shell (CVE-2026-109618 / CVE-2026-109619) detection
//!
//! Executes non-intrusive HEAD requests on open ports 80 and 443, inspecting response
//! headers (X-Powered-By and Server) without sending memory corruption or exploit payloads.

use crate::scanner::result::PortStatus;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::{Certificate, ClientConfig, Error as RustlsError, ServerName};
use tokio_rustls::TlsConnector;

/// Null certificate verifier to allow scanning direct IP addresses over TLS
/// without failing due to Hostname/SAN mismatch.
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }
}

fn build_tls_connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[derive(Debug, PartialEq, Eq)]
pub enum PhpAssessment {
    Vulnerable {
        version: String,
        fixed_in: &'static str,
    },
    NotVulnerable {
        version: String,
    },
    NoPhpHeader,
}

/// Parse HTTP response headers searching for PHP signatures in X-Powered-By or Server headers.
pub fn parse_php_version_from_headers(headers: &str) -> PhpAssessment {
    for line in headers.lines() {
        let line_lower = line.to_ascii_lowercase();
        if line_lower.starts_with("x-powered-by:") || line_lower.starts_with("server:") {
            if let Some(pos) = line_lower.find("php/") {
                let after_php = &line[pos + 4..];
                let version_str: String = after_php
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if !version_str.is_empty() {
                    return assess_php_version(&version_str);
                }
            }
        }
    }
    PhpAssessment::NoPhpHeader
}

/// Assess vulnerability status based on PHP Foundation advisory criteria for
/// CVE-2026-109618 (Out-Of-Memory corruption) and CVE-2026-109619 (Use-After-Free worker).
pub fn assess_php_version(version: &str) -> PhpAssessment {
    let parts: Vec<u32> = version
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();

    if parts.is_empty() {
        return PhpAssessment::NoPhpHeader;
    }

    let major = parts[0];
    let minor = parts.get(1).copied().unwrap_or(0);
    let patch = parts.get(2).copied().unwrap_or(0);

    // Official Upstream Patch Thresholds:
    // - Branch 8.5: Vulnerable if < 8.5.12
    // - Branch 8.4: Vulnerable if < 8.4.27
    // - Branch 8.3: Vulnerable if < 8.3.36
    // - Branch 8.2: Vulnerable if < 8.2.35
    // - Versions 8.1, 7.x, 5.x: EOL / Unpatched upstream -> Critical Vulnerable
    // - Versions >= 8.6: Patched / Future safe branch
    if major == 8 {
        match minor {
            5 => {
                if patch < 12 {
                    PhpAssessment::Vulnerable {
                        version: version.to_string(),
                        fixed_in: "8.5.12",
                    }
                } else {
                    PhpAssessment::NotVulnerable {
                        version: version.to_string(),
                    }
                }
            }
            4 => {
                if patch < 27 {
                    PhpAssessment::Vulnerable {
                        version: version.to_string(),
                        fixed_in: "8.4.27",
                    }
                } else {
                    PhpAssessment::NotVulnerable {
                        version: version.to_string(),
                    }
                }
            }
            3 => {
                if patch < 36 {
                    PhpAssessment::Vulnerable {
                        version: version.to_string(),
                        fixed_in: "8.3.36",
                    }
                } else {
                    PhpAssessment::NotVulnerable {
                        version: version.to_string(),
                    }
                }
            }
            2 => {
                if patch < 35 {
                    PhpAssessment::Vulnerable {
                        version: version.to_string(),
                        fixed_in: "8.2.35",
                    }
                } else {
                    PhpAssessment::NotVulnerable {
                        version: version.to_string(),
                    }
                }
            }
            _ if minor <= 1 => {
                PhpAssessment::Vulnerable {
                    version: version.to_string(),
                    fixed_in: "8.2.35+ (8.1 is EOL)",
                }
            }
            _ => PhpAssessment::NotVulnerable {
                version: version.to_string(),
            },
        }
    } else if major < 8 {
        PhpAssessment::Vulnerable {
            version: version.to_string(),
            fixed_in: "8.2.35+ (Legacy EOL)",
        }
    } else {
        // major > 8
        PhpAssessment::NotVulnerable {
            version: version.to_string(),
        }
    }
}

/// Execute a two-phase non-intrusive HTTP/HTTPS probe:
/// Phase 1: Fast TCP connect with capped timeout (max 1500ms).
/// Phase 2: Send HEAD / request (plaintext or TLS) and parse headers.
pub async fn execute_php_probe(
    ip: IpAddr,
    port: u16,
    is_tls: bool,
    timeout: Duration,
) -> (PortStatus, Option<u64>, String) {
    let start = Instant::now();
    let dest = SocketAddr::new(ip, port);

    // Fast TCP connect capped at 1500ms to prevent semaphore starvation
    let connect_timeout = timeout.min(Duration::from_millis(1500));
    let stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(dest)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let is_fd = e.raw_os_error().map(|c| c == 23 || c == 24).unwrap_or(false);
            if is_fd {
                return (
                    PortStatus::Error(format!("CRITICAL_FD_EXHAUSTION: {}", e)),
                    None,
                    String::new(),
                );
            } else if e.kind() == io::ErrorKind::ConnectionRefused {
                return (PortStatus::Closed, None, "Connection refused".to_string());
            } else {
                return (
                    PortStatus::Inconclusive,
                    None,
                    "Connection unreachable".to_string(),
                );
            }
        }
        Err(_) => {
            return (
                PortStatus::Inconclusive,
                None,
                "Connection timeout".to_string(),
            );
        }
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    // Send non-intrusive HEAD request
    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: ampscan/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        ip,
        env!("CARGO_PKG_VERSION")
    );

    let read_timeout = Duration::from_millis(1500);

    let raw_response = if !is_tls {
        let mut stream = stream;
        if let Err(e) = stream.write_all(req.as_bytes()).await {
            return (
                PortStatus::OpenProtected,
                Some(latency_ms),
                format!("HTTP open, write error: {}", e),
            );
        }
        let mut buf = vec![0u8; 4096];
        let n = match tokio::time::timeout(read_timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        buf.truncate(n);
        String::from_utf8_lossy(&buf).to_string()
    } else {
        let connector = build_tls_connector();
        let server_name = match ServerName::try_from(ip.to_string().as_str()) {
            Ok(sn) => sn,
            Err(_) => match ServerName::try_from("target") {
                Ok(sn) => sn,
                Err(_) => {
                    return (
                        PortStatus::OpenProtected,
                        Some(latency_ms),
                        "HTTPS open (TLS hostname error)".to_string(),
                    );
                }
            },
        };

        match tokio::time::timeout(read_timeout, connector.connect(server_name, stream)).await {
            Ok(Ok(mut tls_stream)) => {
                if let Err(e) = tls_stream.write_all(req.as_bytes()).await {
                    return (
                        PortStatus::OpenProtected,
                        Some(latency_ms),
                        format!("HTTPS open, write error: {}", e),
                    );
                }
                let mut buf = vec![0u8; 4096];
                let n = match tokio::time::timeout(read_timeout, tls_stream.read(&mut buf)).await {
                    Ok(Ok(n)) => n,
                    _ => 0,
                };
                buf.truncate(n);
                String::from_utf8_lossy(&buf).to_string()
            }
            _ => {
                return (
                    PortStatus::OpenProtected,
                    Some(latency_ms),
                    "HTTPS open (TLS handshake failed / non-standard)".to_string(),
                );
            }
        }
    };

    let assessment = parse_php_version_from_headers(&raw_response);
    match assessment {
        PhpAssessment::Vulnerable { version, fixed_in } => (
            PortStatus::Open,
            Some(latency_ms),
            format!(
                "PHP2Shell: PHP {} vulnerable (< {}) - CVE-2026-109618/19",
                version, fixed_in
            ),
        ),
        PhpAssessment::NotVulnerable { version } => (
            PortStatus::OpenProtected,
            Some(latency_ms),
            format!("PHP {} (patched against CVE-2026-109618/19)", version),
        ),
        PhpAssessment::NoPhpHeader => (
            PortStatus::OpenProtected,
            Some(latency_ms),
            "Web server open, PHP banner not exposed (expose_php = Off)".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_php_version_vulnerable_cases() {
        assert_eq!(
            assess_php_version("8.5.11"),
            PhpAssessment::Vulnerable {
                version: "8.5.11".to_string(),
                fixed_in: "8.5.12"
            }
        );
        assert_eq!(
            assess_php_version("8.4.26"),
            PhpAssessment::Vulnerable {
                version: "8.4.26".to_string(),
                fixed_in: "8.4.27"
            }
        );
        assert_eq!(
            assess_php_version("8.3.35"),
            PhpAssessment::Vulnerable {
                version: "8.3.35".to_string(),
                fixed_in: "8.3.36"
            }
        );
        assert_eq!(
            assess_php_version("8.2.34"),
            PhpAssessment::Vulnerable {
                version: "8.2.34".to_string(),
                fixed_in: "8.2.35"
            }
        );
        assert_eq!(
            assess_php_version("8.2.20"),
            PhpAssessment::Vulnerable {
                version: "8.2.20".to_string(),
                fixed_in: "8.2.35"
            }
        );
        assert_eq!(
            assess_php_version("8.1.2"),
            PhpAssessment::Vulnerable {
                version: "8.1.2".to_string(),
                fixed_in: "8.2.35+ (8.1 is EOL)"
            }
        );
        assert_eq!(
            assess_php_version("7.4.33"),
            PhpAssessment::Vulnerable {
                version: "7.4.33".to_string(),
                fixed_in: "8.2.35+ (Legacy EOL)"
            }
        );
        assert_eq!(
            assess_php_version("5.6.40"),
            PhpAssessment::Vulnerable {
                version: "5.6.40".to_string(),
                fixed_in: "8.2.35+ (Legacy EOL)"
            }
        );
    }

    #[test]
    fn test_php_version_patched_cases() {
        assert_eq!(
            assess_php_version("8.5.12"),
            PhpAssessment::NotVulnerable {
                version: "8.5.12".to_string()
            }
        );
        assert_eq!(
            assess_php_version("8.4.27"),
            PhpAssessment::NotVulnerable {
                version: "8.4.27".to_string()
            }
        );
        assert_eq!(
            assess_php_version("8.3.36"),
            PhpAssessment::NotVulnerable {
                version: "8.3.36".to_string()
            }
        );
        assert_eq!(
            assess_php_version("8.2.35"),
            PhpAssessment::NotVulnerable {
                version: "8.2.35".to_string()
            }
        );
        assert_eq!(
            assess_php_version("8.6.0"),
            PhpAssessment::NotVulnerable {
                version: "8.6.0".to_string()
            }
        );
    }

    #[test]
    fn test_parse_headers() {
        let headers_x_powered = "HTTP/1.1 200 OK\r\nDate: Sun, 01 Nov 2026\r\nX-Powered-By: PHP/8.2.20\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(
            parse_php_version_from_headers(headers_x_powered),
            PhpAssessment::Vulnerable {
                version: "8.2.20".to_string(),
                fixed_in: "8.2.35"
            }
        );

        let headers_server = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.62 (Debian) PHP/8.3.36\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(
            parse_php_version_from_headers(headers_server),
            PhpAssessment::NotVulnerable {
                version: "8.3.36".to_string()
            }
        );

        let headers_no_php = "HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(
            parse_php_version_from_headers(headers_no_php),
            PhpAssessment::NoPhpHeader
        );
    }
}

