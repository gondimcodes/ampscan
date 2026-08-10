# Technology Stack & Architecture — AmpScan

This document provides a comprehensive overview of the technology stack, external crates, system libraries, and architectural decisions powering **ampscan** (v1.4.1).

---

## 1. Core Language & Runtime

* **Language**: **Rust (2021 Edition)**
  * **Rationale**: Guarantees memory safety without garbage collection overhead, prevents data races during high-concurrency network scans, ensures predictable resource utilization, and delivers high-performance network I/O.
* **Async Runtime**: `tokio 1.x` (`features = ["full"]`)
  * **Usage**: Non-blocking orchestration of packet transmission/reception (UDP & TCP), fine-grained concurrency control via asynchronous semaphores (`tokio::sync::Semaphore`), and thread yield management.

---

## 2. Interactive Terminal User Interface (TUI)

* **TUI Rendering Engine**: `ratatui 0.30`
  * **Usage**: Rich terminal UI layout orchestration, responsive gauges, tab navigation, styled tables with auto-wrapping, border frames, and real-time finding feeds.
* **Terminal Control & Input**: `crossterm 0.28`
  * **Usage**: Raw terminal mode initialization, mouse capture, alternate screen switching, and non-blocking key event processing (`PageUp`, `PageDown`, `Up`, `Down`, `Tab`, digits).

---

## 3. Encrypted Database & Data-at-Rest Security

* **Storage Engine**: **SQLite3 + SQLCipher** via `rusqlite 0.32`
  * **Encryption**: Transparent AES-256-CBC encryption at rest for the entire database (storing users, subnets, ports, and scan report history).
  * **Static & Cross-Platform Builds**:
    * On **Windows** & **Linux ARM64**: Built using `bundled-sqlcipher-vendored-openssl` (compiles SQLCipher and OpenSSL statically from source).
    * On other Unix/Linux/macOS platforms: Built using `bundled-sqlcipher`.
* **Password Hashing & Authentication**: `argon2 0.5` (**Argon2id**)
  * **Usage**: Secure password hashing and key derivation for local administrator authentication.
* **Heap Memory Hygiene**: `zeroize 1.9`
  * **Usage**: Immediate zero-overwriting of raw encryption keys in heap memory (`AMPSCAN_DB_KEY`) right after opening the encrypted database, reducing memory dump exposure windows.

---

## 4. Command Line Interface (CLI) & User Experience

* **Argument Parsing**: `clap 4.x` (`features = ["derive", "env"]`)
  * **Usage**: Declarative subcommand parsing (`init`, `tui`, `scan run`, `port list`, etc.), execution flags (`--concurrency`, `--retries`, `--pdf`, `--db-path`), and non-interactive automation support via environment variables (`AMPSCAN_PASS`, `AMPSCAN_DB_PATH`).
* **Table Formatting**: `comfy-table 7.x`
  * **Usage**: Rendering clean terminal tables with borders and alignment for CLI output (port listings, IP subnets, and summary scan results).
* **Console Styling**: `colored 2.x`
  * **Usage**: Color-coded CLI output by severity (e.g., bold yellow for `Open/Protected` status, green/yellow/red for latency ranges).
* **Masked Password Prompt**: `rpassword 7.x`
  * **Usage**: Capturing administrator passwords without echoing characters in the terminal.

---

## 5. Scanning Engine & Network Protocols

* **IP Subnet Management**: `ipnet 2.x`
  * **Usage**: Strict validation and parsing of IPv4 and IPv6 CIDR blocks, supporting full range host expansion.
* **Amplification Probes & Strict Packet Validation**: Internal module `src/scanner/probes.rs`
  * **Source IP Verification**: Strict filtering requiring `src_addr.ip() == target_ip` to reject cross-talk packets.
  * **DNS (53)**: Random 16-bit Transaction ID (TXID) matching per probe, `QR=1` bit verification, and RCODE/RA status evaluation.
  * **SNMP (161)**: ASN.1/DER sequence verification (`0x30`) and GetResponse PDU tag matching (`0xA2` / `0xA8`).
  * **Protocol Payloads**: Tailored parsers for NTP, SSDP, Memcached, RPC Portmapper, CLDAP, NetBIOS, mDNS, TFTP, RIPv1 (520/udp), and generic `udp_payload` signatures with strict length/magic-byte checks to prevent false positives.

---

## 6. Report Generation & Image Processing

* **PDF Engine**: `printpdf 0.12` (`features = ["png", "jpeg"]`)
  * **Usage**: Low-level 2D vector PDF creation without third-party system dependencies (such as wkhtmltopdf or C graphics libraries).
* **Image Processing**: `image 0.24`
  * **Usage**: Decoding, magic byte verification (PNG/JPEG), and rendering of auditor company logos in PDF headers.

---

## 7. Operating System Integration & System Limits

* **Resource Limit Tuning**: `libc 0.2`
  * **Usage**: Unix system calls (`rlimit`/`getrlimit`/`setrlimit`) for automatic self-elevation of socket file descriptors (*soft limit* to *hard limit*), preventing file exhaustion errors (`EMFILE`).
* **Timestamps & Identifiers**: `chrono 0.4` and `uuid 1.x`
  * **Usage**: Date formatting in reports and generating UUIDv4 for unique scan session tracking.
* **Configuration Deserialization**: `toml 0.8` and `serde 1.x`
  * **Usage**: Parsing and managing local configuration settings (`config.toml`).

---

## 8. Multi-Platform CI/CD Infrastructure & Code Mirroring

* **GitHub Actions Workflows**:
  * **Continuous Integration (`ci.yml`)**: Automated `cargo check` and `cargo test` runs across Linux and macOS runners on pushes and pull requests.
  * **Continuous Delivery (`release.yml`)**: Multi-platform release automation triggered by `v*` tags to compile and publish static binary assets for:
    * Linux x86_64 (`x86_64-unknown-linux-gnu`)
    * Linux ARM64 (`aarch64-unknown-linux-gnu`) via `cross` (Docker container)
    * Windows x86_64 (`x86_64-pc-windows-msvc`)
    * macOS Intel & Apple Silicon (`x86_64-apple-darwin` / `aarch64-apple-darwin`)
    * FreeBSD x86_64 (`x86_64-unknown-freebsd`) via VM (`freebsd-vm`)
* **Codeberg Pipeline (`.woodpecker.yml`)**:
  * **Woodpecker CI**: Automated testing (`cargo test`) and standalone Linux release packaging (`ampscan-<tag>-x86_64-unknown-linux-gnu.tar.gz`) integrated directly with Codeberg Releases on tag events via `woodpeckerci/plugin-release`.

