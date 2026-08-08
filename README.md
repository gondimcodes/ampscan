# AmpScan — Usage Manual and User Guide

**AmpScan** is a high-performance command-line (CLI) tool written in Rust, designed to audit networks and identify open and misconfigured ports that could be exploited in **DDoS amplification** attacks across IPv4 and IPv6 protocols.

---

## 🔒 Security First

AmpScan was designed with security at rest in mind. The local SQLite database (`ampscan.db`) is **completely encrypted using SQLCipher (AES-256)**.

### Crucial Environment Variables

Before running any subcommand, you must define the following variables in your environment:

*   `AMPSCAN_DB_KEY`: **[Required]** The secret key used to encrypt/decrypt the database (a long string with more than 32 characters is recommended).
*   `AMPSCAN_DB_PATH`: *(Optional)* Custom path for the database file (default: `ampscan.db`).
*   `AMPSCAN_USER`: *(Optional)* Defines the administrator user to prevent the terminal from interactively prompting for the username on each command.
*   `AMPSCAN_PASS`: *(Optional)* Defines the administrator password to prevent the terminal from interactively prompting for the password. Extremely useful for automation/cron scans.

Environment preparation example:
```bash
export AMPSCAN_DB_KEY="a_very_secure_and_long_secret_key_for_the_db"
export AMPSCAN_USER="admin"
export AMPSCAN_PASS="my_secure_admin_password"
```

---

## 🛠️ Installation and Compilation

To compile the project on your machine (requires the Rust / Cargo toolchain installed):

```bash
# Clone the repository or navigate to the folder
cd ampscan

# Compile in Release mode for maximum scanning performance
cargo build --release
```

The compiled binary will be located at `target/release/ampscan`.

---

## 🧭 Quick Start Workflow

### 1. Initialize the Database
On the first run, initialize the database to create the encrypted schema, register the 20 default ports, and configure the initial administrator user password:

```bash
./target/release/ampscan init
```
*Enter the desired username and set a strong password when prompted interactively.*

### 2. Register a Network Prefix (CIDR)
For full scanning to work, you need to register which network prefixes you own/manage to be tested:

```bash
./target/release/ampscan prefix add --prefix "192.168.1.0/24" --description "Corporate Office Network"
```

### 3. List Registered Ports
Check the amplification ports registered in the system:

```bash
./target/release/ampscan port list
```

### 4. Launch the Interactive TUI
Launch the Terminal User Interface to monitor scans, inspect results, or run target checks interactively:

```bash
# Mandatory: --db-path must be specified to load prefixes and ports
./target/release/ampscan tui --db-path /opt/ampscan/ampscan.db -c 512 -t 2
```

---

## 🖥️ Terminal User Interface (TUI) Overview

AmpScan includes a rich **Terminal User Interface (TUI)** built with `ratatui` and `crossterm`. It provides real-time visual feedback, live progress bars, finding filters, and keyboard-driven configuration.

> ⚠️ **Requirement:** The TUI requires the `--db-path` argument to be explicitly specified upon execution. The application will not load without a valid database file.

### Quick TUI Commands:

```bash
# 1. Standard TUI launch with database
./target/release/ampscan tui --db-path /path/to/ampscan.db

# 2. Custom concurrency (1024 threads) and probe timeout (2s)
./target/release/ampscan tui --db-path /path/to/ampscan.db -c 1024 -t 2

# 3. TUI launch with automatic PDF report generation upon scan completion
./target/release/ampscan tui --db-path /path/to/ampscan.db -c 512 -t 2 --pdf --recipient "SOC Team" -o /var/reports/audit.pdf
```

---

## 📸 TUI Screens & Features

### 1. Dashboard (`[Tab]` View 1)
Displays live scan metrics, a progress bar, overall statistics (Vulnerable, Open/Protected, Closed/Filtered), active parameters, and a real-time stream of incoming probes.

![Dashboard Screen](tui_dashboard.png)

*   **Key Controls:** Press `[F]` to start a Full CIDR scan, `[Space]` to pause/resume, and `[Q]` to quit.

### 2. Results Viewer (`[Tab]` View 2)
Dedicated viewer listing all detected findings (**VULNERABLE** and **Open/Protected**). Supports smooth keyboard scrolling.

![Results Viewer Screen](tui_results.png)

*   **Key Controls:** Use `[UP]`, `[DOWN]`, `[PageUp]` (`PgUp`), and `[PageDown]` (`PgDn`) to scroll through findings.

### 3. CIDR Scan (`[Tab]` View 3)
Shows the list of network subnets (CIDR prefixes) registered in the database, along with their active status and descriptions.

![CIDR Scan Screen](tui_cidr_scan.png)

### 4. Target Scan (`[Tab]` View 4)
Allows instant scanning of a single IP address (e.g., `192.168.1.1`) or specific sub-network CIDR prefix (e.g., `192.168.1.0/24`). Real-time input validation provides green/red border feedback.

![Target Scan Screen](tui_target_scan.png)

*   **Key Controls:** Type the IP/CIDR target and press `[Enter]` or `[S]` to start an immediate diagnostic scan.

### 5. Port Database (`[Tab]` View 5)
Lists all 20+ DDoS amplification signatures (DNS, NTP, SNMP, Memcached, SSDP, CLDAP, etc.) registered in the system, including protocol type, probe method, and amplification factors.

![Port Database Screen](tui_port_database.png)

### 6. Settings (`[Tab]` View 6)
Allows real-time tweaking of scanner runtime parameters: **Max Concurrency** (up to 10,000 threads), **Probe Timeout** (up to 60s), and **UDP Retries** (up to 10 attempts).

![Settings Screen](tui_settings.png)

*   **Key Controls:** Use `[UP]` and `[DOWN]` setas to cycle between fields, and type digits directly to edit parameters.

---

## 📖 CLI Command Reference

### `ampscan init`
Initializes the encrypted database structure, populates it with the 20 default amplification ports, and creates the system's master user.

### Port Management (`port`)
Allows you to manage which ports and payloads will be tested during the scan:

*   **List:**
    ```bash
    ./target/release/ampscan --db-path ampscan.db port list
    ```
    ![Port List Output](ampscan_port_list.png)
*   **Disable / Enable a specific port:**
    ```bash
    ./target/release/ampscan --db-path ampscan.db port disable <ID>
    ./target/release/ampscan --db-path ampscan.db port enable <ID>
    ```

### Prefix Management (`prefix`)
Defines the targets for batch scanning (accepts IPv4 and IPv6 ranges):

*   **List:**
    ```bash
    ./target/release/ampscan --db-path ampscan.db prefix list
    ```
    ![Prefix List Output](ampscan_prefix_list.png)
*   **Add:**
    ```bash
    ./target/release/ampscan --db-path ampscan.db prefix add --prefix "2001:db8::/120" --description "IPv6 Staging Hosts"
    ```
*   **Disable / Enable:**
    ```bash
    ./target/release/ampscan --db-path ampscan.db prefix disable <ID>
    ./target/release/ampscan --db-path ampscan.db prefix enable <ID>
    ```

### User Management (`user`)
*   **Add new administrator:**
    ```bash
    ./target/release/ampscan --db-path ampscan.db user add --username new_admin
    ```
*   **Change password:**
    ```bash
    ./target/release/ampscan --db-path ampscan.db user change-password --username admin
    ```

### Running Scans (`scan`)

AmpScan has two execution modes:

#### 1. Batch Scan Mode (`scan run`)
Fetches all prefixes and ports marked as active (`enabled`) in the database and performs parallel testing directly on all hosts.

**Supported parameters:**
*   `--concurrency <N>`: Number of probes sent simultaneously (default: `256`).
*   `--timeout <S>`: Timeout for each probe's response in seconds (default: `3`).
*   `--output <PATH>`: Name of the PDF file to be generated (default: `ampscan_report.pdf`).
*   `--prefix <CIDR>`: Manual network prefix to scan (e.g.: `192.168.1.0/24`). **Ignores database-configured prefixes and skips PDF report generation**.
*   `--pdf`: Enable automatic PDF report generation.

Robust execution example:
```bash
./target/release/ampscan --db-path ampscan.db scan run --concurrency 500 --timeout 2 --pdf --output scan_june.pdf
```
![Scan Run CLI Output](ampscan_report_cli.png)

Example with manual prefix:
```bash
./target/release/ampscan --db-path ampscan.db scan run --prefix "10.0.0.0/29"
```

#### 2. Single IP Mode (`scan single`)
Tests all active ports against a single destination IP, printing real-time responses and timings to the console:

```bash
./target/release/ampscan --db-path ampscan.db scan single 1.1.1.1 --timeout 2
```

---

## 📈 Understanding the Results

During each port scan, the status can be classified as:

1.  🔴 **Open (Vulnerable):** The target responded to the sent probe. It means the amplification port is open and publicly responds to external requests without filtering.
2.  🟢 **Closed:** The host responded to at least one of the active probes, but the amplification service on this specific port yielded no response.
3.  🔵 **Inconclusive:** The tested host did not respond to any of the sent probes, suggesting the host might be offline or entirely blocking diagnostic traffic.
4.  🟡 **Protected:** The port is open, but it is not vulnerable.

---

## 🚀 CI/CD & Release Automation (Codeberg)

This repository supports build and test automation via **Woodpecker CI** hosted on Codeberg:

* **Continuous Integration (CI):** On every `push` or `pull_request` sent to the `main` branch, the complete unit and integration test suite is executed automatically (with parallelism limited to `-j 1` to respect Codeberg's shared resource guidelines).
* **Continuous Delivery (CD):** When creating and pushing a version tag (e.g., `v1.4.0`), the pipeline compiles the binary (`ampscan`) in production mode (Release) for Linux x86_64, compresses it into a `.tar.gz` file, and attaches the final file directly to the Releases page on Codeberg.

