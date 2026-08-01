# Technology Stack & Architecture — AmpScan

This document provides a comprehensive overview of the technology stack, external crates, system libraries, and architectural decisions powering **ampscan** (v1.3.2).

---

## 1. Core Language & Runtime

* **Language**: **Rust (2021 Edition)**
  * **Rationale**: Guarantees memory safety without garbage collection overhead, prevents data races during high-concurrency network scans, ensures predictable resource utilization, and delivers high-performance network I/O.
* **Async Runtime**: [`tokio 1.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L13) (`features = ["full"]`)
  * **Usage**: Non-blocking orchestration of packet transmission/reception (UDP & TCP), fine-grained concurrency control via asynchronous semaphores (`tokio::sync::Semaphore`), and thread yield management (`yield_now`).

---

## 2. Encrypted Database & Data-at-Rest Security

* **Storage Engine**: **SQLite3 + SQLCipher** via [`rusqlite 0.32`](file:///home/gondim/projetos/ampscan/Cargo.toml#L58-L64)
  * **Encryption**: Transparent AES-256-CBC encryption at rest for the entire database (storing users, subnets, ports, and scan report history).
  * **Static & Cross-Platform Builds**:
    * On **Windows** & **Linux ARM64**: Built using `bundled-sqlcipher-vendored-openssl` (compiles SQLCipher and OpenSSL statically from source).
    * On other Unix/Linux/macOS platforms: Built using `bundled-sqlcipher`.
* **Password Hashing & Authentication**: [`argon2 0.5`](file:///home/gondim/projetos/ampscan/Cargo.toml#L16) (**Argon2id**)
  * **Usage**: Secure password hashing and key derivation for local administrator authentication.
* **Heap Memory Hygiene**: [`zeroize 1.9`](file:///home/gondim/projetos/ampscan/Cargo.toml#L55)
  * **Usage**: Immediate zero-overwriting of raw encryption keys in heap memory (`AMPSCAN_DB_KEY`) right after opening the encrypted database, reducing memory dump exposure windows.

---

## 3. Command Line Interface (CLI) & User Experience

* **Argument Parsing**: [`clap 4.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L10) (`features = ["derive", "env"]`)
  * **Usage**: Declarative subcommand parsing (`init`, `scan run`, `port list`, etc.), execution flags (`--concurrency`, `--retries`, `--pdf`), and non-interactive automation support via environment variables (`AMPSCAN_PASS`).
* **Table Formatting**: [`comfy-table 7.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L49)
  * **Usage**: Rendering clean terminal tables with borders and alignment for port listings, IP subnets, and summary scan results.
* **Console Styling**: [`colored 2.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L40)
  * **Usage**: Color-coded output by severity (e.g., bold yellow for `Open/Protected` status, green/yellow/red for latency ranges).
* **Masked Password Prompt**: [`rpassword 7.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L43)
  * **Usage**: Capturing administrator passwords without echoing characters in the terminal.

---

## 4. Scanning Engine & Network Protocols

* **IP Subnet Management**: [`ipnet 2.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L19)
  * **Usage**: Strict validation and parsing of IPv4 and IPv6 CIDR blocks, supporting full range host expansion.
* **Amplification Probes**: Internal module [`src/scanner/probes.rs`](file:///home/gondim/projetos/ampscan/src/scanner/probes.rs)
  * **Usage**: Manual construction and serialization of binary protocol payloads (DNS, NTP, SNMP, Memcached, SSDP, TFTP, LDAP, NetBIOS, SLP, RPC, MikroTik, etc.) dispatched over Tokio UDP/TCP sockets.

---

## 5. Report Generation & Image Processing

* **PDF Engine**: [`printpdf 0.12`](file:///home/gondim/projetos/ampscan/Cargo.toml#L22) (`features = ["png", "jpeg"]`)
  * **Usage**: Low-level 2D vector PDF creation without third-party system dependencies (such as wkhtmltopdf or C graphics libraries).
* **Image Processing**: [`image 0.24`](file:///home/gondim/projetos/ampscan/Cargo.toml#L23)
  * **Usage**: Decoding, magic byte verification (PNG/JPEG), and rendering of auditor company logos in PDF headers.

---

## 6. Operating System Integration & System Limits

* **Resource Limit Tuning**: [`libc 0.2`](file:///home/gondim/projetos/ampscan/Cargo.toml#L52)
  * **Usage**: Unix system calls (`rlimit`/`getrlimit`/`setrlimit`) for automatic self-elevation of socket file descriptors (*soft limit* to *hard limit*), preventing file exhaustion errors (`EMFILE`).
* **Timestamps & Identifiers**: [`chrono 0.4`](file:///home/gondim/projetos/ampscan/Cargo.toml#L34) and [`uuid 1.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L46)
  * **Usage**: Date formatting in reports and generating UUIDv4 for unique scan session tracking.
* **Configuration Deserialization**: [`toml 0.8`](file:///home/gondim/projetos/ampscan/Cargo.toml#L28) and [`serde 1.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L26)
  * **Usage**: Parsing and managing local configuration settings (`config.toml`).

---

## 7. CI/CD Pipeline & Cross-Platform Infrastructure

* **Continuous Integration (CI)**: GitHub Actions (`ci.yml`) running `cargo check` and `cargo test` across Linux and macOS environments.
* **Continuous Delivery (CD)**: GitHub Actions (`release.yml`) triggered by `v*` tags to cross-compile static binaries for:
  * Linux x86_64 (`x86_64-unknown-linux-gnu`)
  * Linux ARM64 (`aarch64-unknown-linux-gnu`) via `cross` (Docker container)
  * Windows x86_64 (`x86_64-pc-windows-msvc`)
  * macOS Intel & Apple Silicon (`x86_64-apple-darwin` / `aarch64-apple-darwin`)
  * FreeBSD x86_64 (`x86_64-unknown-freebsd`) via VM (`freebsd-vm`)
