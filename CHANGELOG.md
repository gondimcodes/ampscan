# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.2] - 2026-11-04

### Fixed
- **Reactive Port Database & Statistics Synchronization in TUI**:
  - Resolved state desynchronization bug where dynamically toggling PHP2Shell (`P` key in Settings tab) did not update the registered signatures in the Port Database tab or the side-by-side Port Statistics panel.
  - Added `sync_php_ports()` and `toggle_check_php()` to `App` to dynamically insert or remove `80/tcp` (`php_http`) and `443/tcp` (`php_https`) in real time, keeping ports sorted by port number.
  - Added dedicated regression unit test `test_toggle_check_php_updates_port_database_dynamically`.

## [1.5.1] - 2026-11-03

### Added
- **Custom Virtual Host & TLS SNI Routing (`--http-host`)**:
  - Added `--http-host <HOST>` parameter to `scan single`, `scan run`, and `tui` commands.
  - Injects the specified domain into the `Host: <HOST>` HTTP header and into the TLS `Client Hello` Server Name Indication (SNI) extension via `tokio-rustls`.
  - Enables non-intrusive auditing of backends protected by CDNs (Cloudflare, Fastly, Akamai) or shared reverse proxies, bypassing default vhost fallback (HTTP 400/403).
  - RFC 6066 compliance: automatically strips port numbers from the SNI extension if supplied (e.g., `domain.com:8443` -> SNI `domain.com`).
  - Integrated into PDF executive reports, CLI summary displays, and TUI Settings and Single Target tabs.

### Changed
- **Zero-DB Mode for Ad-hoc Inspection (`scan single` and `scan run --prefix`)**:
  - Removed mandatory `--db-path`, `AMPSCAN_DB_KEY`, and user authentication for ad-hoc diagnostics on single target IPs (`scan single`) or manual subnets (`scan run --prefix`).
  - Loads the built-in 23 DDoS amplification signatures (`DEFAULT_PORTS`) directly in memory with zero disk I/O.
  - Automatically injects ports `80/tcp` (HTTP) and `443/tcp` (HTTPS) when `--check-php` is enabled.
  - Preserves optional `--db-path` usage to test custom/database-enabled ports when explicitly provided.

### Security
- **Strict CRLF / Header Injection Defense**:
  - Added `validate_http_host` to enforce RFC 1123/3986 compliance and reject any `\r`, `\n`, control characters, spaces, or malformed characters before socket creation.

## [1.5.0] - 2026-11-01

### Added
- **Passive HTTP/HTTPS PHP2Shell Vulnerability Auditing (`--check-php`)**:
  - Added non-intrusive banner inspection for ports `80/tcp` (HTTP) and `443/tcp` (HTTPS) to detect critical PHP vulnerabilities:
    - **CVE-2026-109618**: Out-Of-Memory memory corruption.
    - **CVE-2026-109619**: Worker process Use-After-Free condition.
  - **Two-Phase Probing Model** (`src/scanner/probes/http.rs`):
    - Fast TCP connection check capped at 1,500ms preventing semaphore starvation on silent firewall `DROP` packets.
    - Zero active exploit payloads: inspects `X-Powered-By` and `Server` headers via RFC-compliant `HEAD / HTTP/1.1`.
    - Integrated pure Rust TLS client (`tokio-rustls` with permissive IP certificate verifier) for HTTPS inspection on direct IP addresses.
  - **SemVer Vulnerability Assessment**:
    - Validates PHP versions against upstream PHP Foundation fixes: Branch 8.5 (< 8.5.12), Branch 8.4 (< 8.4.27), Branch 8.3 (< 8.3.36), Branch 8.2 (< 8.2.35), and legacy EOL branches (<= 8.1).
  - **CLI & TUI Integration**:
    - Global `--check-php` CLI parameter available on `scan run`, `scan single`, and `tui`.
    - Live dynamic toggle in TUI: press `P` in the Settings tab to toggle PHP2Shell checking on the fly.
  - **Executive PDF Reporting & Client Mitigation**:
    - Automatic generation of dedicated PHP2Shell advisory section in PDF reports.
    - Documented guidance on Linux distribution backports (Debian, Ubuntu, RHEL) and actionable client mitigations: `pm.max_requests = 1` in PHP-FPM (`www.conf`) and `expose_php = Off` in `php.ini`.

## [1.4.8] - 2026-10-17

### Changed
- **Architectural Modularization & Decoupling**:
  - Refactored large monolithic source files into clean, domain-driven submodules with strict Single Responsibility Principle (SRP):
    - `src/main.rs` (reduced from 913 to 96 lines): Trimmed into a clean entrypoint and command dispatcher. CLI argument schemas, authentication helpers, and subcommand handlers moved to `src/cli/` (`args.rs`, `auth_helper.rs`, and `commands/`).
    - `src/report.rs` (860 lines) decomposed into `src/report/`:
      - `config.rs`: `AppConfig`, `CompanyConfig`, and configuration loader.
      - `writer.rs`: `PdfWriter` primitives, layout constants, and cursor coordination.
      - `text.rs`: Transliteration (`sanitize`), command and text wrapping with dedicated unit tests.
      - `procedures.rs`: Protocol-to-CLI manual verification command dictionary (`get_manual_command`).
      - `mod.rs`: High-level executive report orchestrator (`generate_pdf`).
    - `src/scanner/probes.rs` (856 lines) decomposed into `src/scanner/probes/`:
      - `transport.rs`: Low-level connected socket networking (`send_udp_probe`, `execute_tcp_probe`) and file descriptor exhaustion detection.
      - `validate.rs`: Protocol response validators, Transaction ID validation, and IP version reflection filters (`0x4x`/`0x6x`).
      - `payloads.rs`: All 13 protocol binary payload constructors and comprehensive unit tests.
      - `mod.rs`: Main probe execution dispatcher (`execute_probe`).
    - `src/tui/ui.rs` (560 lines) decomposed into `src/tui/ui/`:
      - Dedicated view components for each tab: `dashboard.rs`, `results.rs` (with 68%/32% split), `cidr_scan.rs`, `single_target.rs`, `port_database.rs`, and `settings.rs`.
      - `mod.rs`: Frame orchestrator, tabs header, and hotkey footer.
    - `src/db/port_repo.rs` (reduced from 274 to 136 lines):
      - Isolated static definition of 23 amplification ports into `src/db/default_ports.rs`, leaving `port_repo.rs` focused strictly on SQL CRUD operations.
  - Zero functional regressions or breaking API changes: all public interfaces re-exported via `pub use`.

## [1.4.7] - 2026-08-23

### Added
- **Shadowserver & CISA Amplification Vectors**:
  - **MS-RDPEUDP (`3389/udp`)**: Added SYN datagram probe construction (`RDPUDP_FLAG_SYN 0x0001` + `snSourcePackets` + `uUpStreamMtu`), testing for volumetric amplification up to 85.9x.
  - **SIP (`5060/udp`)**: Added RFC 3261-compliant `OPTIONS` ping probe to detect exposed PBX/VoIP systems vulnerable to 15x–30x reflection and brute-force scanning.
  - Expanded amplification vector coverage to **23 ports** (21 UDP and 2 TCP).
  - Added CLI manual validation commands (`printf` + `nc` + `xxd`) for `MS-RDPEUDP` and `SIP` to PDF executive reports.

## [1.4.6] - 2026-08-11

### Optimized
- **TUI Performance & CPU Usage**:
  - Reduced Results Viewer rendering complexity from $O(42N)$ to **$O(1)$ constant time** using indexed `filtered_log_indices` and `port_stats` hash maps.
  - Capped frame rate at 60 FPS (16ms rest between ticks), reducing idle CPU usage from ~100% to ~1–3%.
  - Batch event processing (up to 2,000 events/tick) on `mpsc` queue for fluid rendering and keyboard responsiveness under high concurrency scans.
- **Results Viewer Redesign**:
  - Horizontal split layout: 68% scrollable verified findings table and 32% live `Port Statistics` panel with real-time `VULNERABLE` and `Open/Protected` counters.

## [1.4.5] - 2026-08-10

### Fixed
- **Target Scan Input Handling**:
  - Fixed keyboard event handling so `s`/`S` and `q`/`Q`/`Esc` keys trigger actions without corrupting the target IP text input.
  - Added strict input character filtering allowing only valid IP/CIDR characters.
  - Added automatic fallback to `/32` (IPv4) and `/128` (IPv6) for standalone IP targets in subnet scanner.

## [1.4.4] - 2026-08-08

### Fixed
- **Network Engine & Dual-Stack Resiliency**:
  - Implemented connected UDP sockets (`socket.connect`) for IPv4 and IPv6 to filter responses strictly by `(ip, port)` tuple at the Linux kernel level.
  - Added IP version signature filters (`0x4x` / `0x6x`) to eliminate false positives from ICMP/ICMPv6 error reflection under high concurrency.
  - Removed static 1000ms latency cap, allowing scans to honor configured probe timeouts dynamically.
