# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.7] - 2026-11-26

### Added
- **Unified Host Reachability & Alive-IP Closure (`CLI` + `TUI`)**:
  - Added `ensure_root_privileges()` in `src/sys_limits.rs` / `src/main.rs` to abort immediately with a clear error if executed without root privileges (`euid != 0` on Unix).
  - `apply_alive_ip_closure` now recognizes `PortStatus::Closed` (TCP RST / `ConnectionRefused`) as proof that the host is UP, closing silent UDP ports on that host instead of leaving them `Inconclusive`.
  - Added streaming **per-IP ICMP Echo (IPv4 & IPv6)** reachability fallback (`src/scanner/probes/icmp.rs`, `SOCK_DGRAM` async with `SOCK_RAW` fallback) triggered immediately as each silent IP finishes its port probes—running in parallel with the rest of the scan instead of stalling at 100%; hosts responding to ICMP Echo are marked `Closed` across both CLI and TUI (`TuiEvent::HostsAlive`). Hosts with zero port and zero ICMP responses remain `Inconclusive`.

### Fixed
- **mDNS Validator Hardening (`5353/udp`)**:
  - Updated `validate_udp_response("mdns", ...)` in `src/scanner/probes/validate.rs` to require `QR = 1`, `Opcode = 0`, `RCODE = 0` (`NoError`), and at least one response record (`ANCOUNT + NSCOUNT + ARCOUNT > 0`) while keeping `TXID` unlocked per RFC 6762 §18.1.
  - Added regression test `test_mdns_validation_rejects_errors_empty_and_accepts_valid_response`.
- **PDF Manual Verification Commands (`src/report/procedures.rs`)**:
  - Updated `mDNS` command to include `+norecurse +noedns` (`dig +short +norecurse +noedns -p 5353 @<IP> -t PTR _services._dns-sd._udp.local`), matching `ampscan`'s RFC 6762 probe and avoiding silent drops on strict embedded responders.
  - Updated `DNS` command from `-t ANY` to `-t A` to match `ampscan`'s `A google.com` probe and avoid RFC 8482 `HINFO` minimal responses.
  - Updated `DVR-DHCPDiscover` (`37810/udp`) command from bash-specific `echo -ne` to POSIX-portable `printf '\\xff'`.

## [1.5.6] - 2026-11-26

### Added
- **TUI Dashboard & Results Viewer Enhancements**:
  - Added live/final `Scan Duration` (`HH:MM:SS`) to the Dashboard `Findings Summary`.
  - Added conditional `HTTP/HTTPS Open (No PHP)` counter in Dashboard (visible when `--check-php` / `P` is enabled or findings exist).
  - Added `Protocol` column (`TCP`/`UDP`) to the Results Viewer table and isolated `port_stats` by `(port, protocol)` while excluding `OpenNoPhp` from `Vuln`/`Prot` counters.

### Fixed
- **Protocol Validators Hardening**:
  - Added dedicated `execute_ntp_probe` / `assess_ntp_response` rejecting arbitrary payloads and ICMP reflections (`0x4x`/`0x6x`) and mapping `E=1` refusals to `OpenProtected`.
  - Fixed MS-RDPEUDP validator to inspect `uFlags` at bytes `6..8` (`RDPUDP_FLAG_SYN` / `RDPUDP_FLAG_ACK`) instead of byte 0 / length fallback.
  - Added `XID`/`TXID` matching for `rpc`/`netbios` and structural ASN.1/BER TLV parsing (with long-form length support) for `snmp`/`ldap`.
- **HTTP/HTTPS Probe & TUI/CLI Consistency**:
  - Implemented bounded header read loop (`\r\n\r\n`, 8 KB cap) and full multi-header PHP evaluation prioritizing `Vulnerable`.
  - Removed silent `"target"` SNI fallback; invalid TLS hostnames now report `OpenNoPhp`.
  - Synchronized `alive_ips` closure and `last_scanned_prefixes` in TUI; enforced `protocol == "tcp"` on 80/443 injection; aligned CLI limits (`concurrency` `1..=10000`, `timeout` `1..=60`, `retries` `0..=10`).
  - Removed dead code (`custom_prefix_input`, `has_php_findings`, unused `truncate`, `_USABLE_W`, duplicate `ScanStarted`).

## [1.5.5] - 2026-11-24

### Changed
- **Strict Web Classification (Protected vs. No PHP Detected)**:
  - Introduced canonical probe status `PortStatus::OpenNoPhp` (`OPEN (NO PHP DETECTED)`).
  - Web ports 80/tcp and 443/tcp responding without an explicit PHP version header are now classified as `Open (No PHP detected)` and are never declared as `OpenProtected`.
  - Only responses exposing explicit patched PHP versions ($\ge 8.2.36, 8.3.37, 8.4.28, 8.5.13$) are marked as `Protected`.
  - CLI `scan single` output updated with detailed finding suffixes and clean zero-protected counts when no PHP is identified.
  - TUI Findings table and Dashboard render `Open (No PHP)` without inflating protected or vulnerable statistics.
  - PDF Report: PHP Security Advisory and details are generated **strictly when vulnerable PHP is identified** (`has_vulnerable_php()`), ensuring non-vulnerable web ports never pollute executive reports.

## [1.5.4] - 2026-11-22

### Changed
- **PDF Report Layout Reorganization**:
  - Removed the legacy flat column table `"Detailed Results - Vulnerable Ports"`.
  - Removed obsolete column positioning constants (`COL_IP`, `COL_PORT`, `COL_PROTO`, `COL_SVC`, `COL_DESC`, `DESC_MAX_CHARS`) from `src/report/writer.rs`.
  - Introduced new `"Vulnerable Port Details"` section grouping open amplification results by port:
    - Bold subheading with formatted port, protocol, service and description: `Port: {port}/{protocol} ({service}) - {description}`.
    - Bulleted listing of affected IP addresses (`* <IP>`) under each port header without latency metrics, matching the inverted format of the `"Vulnerable IP Details"` section.
  - Retained `"Vulnerable IP Details"` section intact.
  - Added dedicated unit regression test `test_generate_pdf_vulnerable_port_and_ip_details`.

### Fixed
- **PDF Report PHP Advisory Heading Truncation**:
  - Restructured long PHP Security Advisory heading to prevent horizontal clipping off the right margin of the A4 page. Split into main section heading `PHP Security Advisory` (16pt bold) and descriptive CVE subheading `CVE-2026-109618 / CVE-2026-109619 / CVE-2026-126714` (12pt bold).
- **TUI Results Viewer Cursor Navigation & Viewport Scrolling**:
  - Eliminated cursor locking at screen midpoint (`half_view` centering artifact) in the Results Viewer tab. Cursor now navigates freely top-to-bottom across the full visible viewport height, only triggering viewport scroll when crossing viewport boundaries.
  - Added full PageUp (`PageUp`, `Ctrl+B`, `Ctrl+U`) and PageDown (`PageDown`, `Ctrl+F`, `Ctrl+D`) pagination using the dynamic visible viewport row count.
  - Added `Home` (jump to first finding) and `End` (jump to last finding) navigation support.
  - Isolated global `[F]` (Full Scan) and `[S]` (Single Scan) trigger keys to prevent conflict with terminal control combinations (`Ctrl+F`).
  - Added dedicated regression unit test `test_findings_viewport_free_scrolling_and_page_nav`.

## [1.5.3] - 2026-11-21

### Added
- **Detection of CVE-2026-126714 (phpAfterShell)**:
  - Updated passive HTTP/HTTPS PHP probe (`--check-php`) to detect CVE-2026-126714 ("phpAfterShell" - session file corruption RCE, CVSS 9.2).
  - Elevated patch thresholds across all active branches to match official upstream PHP Foundation security fixes:
    - Branch 8.5: Patched in `8.5.13` (vulnerable if `< 8.5.13`).
    - Branch 8.4: Patched in `8.4.28` (vulnerable if `< 8.4.28`).
    - Branch 8.3: Patched in `8.3.37` (vulnerable if `< 8.3.37`).
    - Branch 8.2: Patched in `8.2.36` (vulnerable if `< 8.2.36`).
    - Legacy branches ($\le$ 8.1) remain EOL and permanently vulnerable.
  - Added dedicated regression unit test `test_cve_2026_126714_phpaftershell_regression` to verify intermediate versions (8.5.12, 8.4.27, 8.3.36, 8.2.35) are strictly reported as `Vulnerable`.
  - Updated PDF executive advisory section, CLI diagnostic profiles, and TUI labels to reflect both PHP2Shell and phpAfterShell CVEs.

### Security
- **SQLite / SQLCipher Upstream Security Remediation**:
  - Upgraded `rusqlite` to `0.43.0` and `sqlcipher-src` to `420.0.0`, eliminating C SQLite vulnerabilities RUSTSEC-2026-0459 and RUSTSEC-2026-0502 (CVE-2026-119375) with zero known security advisories remaining on `cargo audit`.

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
