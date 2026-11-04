//! Command line interface argument definitions via clap
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "ampscan",
    about = "AmpScan — DDoS Amplification Port Testing Tool",
    long_about = "Tests DDoS amplification ports across IPv4/IPv6 prefixes.\n\
                  Requires AMPSCAN_DB_KEY as an environment variable for database encryption.",
    version
)]
pub struct Cli {
    /// Database file path (obrigatorio)
    #[arg(long, global = true, env = "AMPSCAN_DB_PATH")]
    pub db_path: Option<String>,

    /// Admin user (or set AMPSCAN_USER environment variable)
    #[arg(short, long, global = true, env = "AMPSCAN_USER")]
    pub user: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize database and create administrator user
    Init,

    /// Manage amplification ports
    #[command(subcommand)]
    Port(PortCommands),

    /// Manage network prefixes (CIDR)
    #[command(subcommand)]
    Prefix(PrefixCommands),

    /// Manage administrator users
    #[command(subcommand)]
    User(UserCommands),

    /// Execute amplification scan
    #[command(subcommand)]
    Scan(ScanCommands),

    /// Launch interactive Terminal User Interface (TUI)
    Tui {
        /// Maximum number of simultaneous probes
        #[arg(short, long, default_value = "256")]
        concurrency: usize,
        /// Timeout per probe in seconds
        #[arg(short, long, default_value = "3")]
        timeout: u64,
        /// Number of retries for UDP probes (default is 2)
        #[arg(short, long, default_value = "2")]
        retries: usize,
        /// Request PDF report generation when scan finishes
        #[arg(long)]
        pdf: bool,
        /// Output PDF report file path
        #[arg(short, long, default_value = "ampscan_report.pdf")]
        output: String,
        /// Company/client name for the report
        #[arg(long)]
        client_name: Option<String>,
        /// PDF report recipient (e.g., manager or department name)
        #[arg(long)]
        recipient: Option<String>,
        /// Audit HTTP (80) and HTTPS (443) for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
        #[arg(long)]
        check_php: bool,
        /// Custom Host header and TLS SNI for --check-php probes (e.g. example.com)
        #[arg(long)]
        http_host: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum PortCommands {
    /// List all registered ports
    List,
    /// Enable a port for testing
    Enable {
        /// Port ID
        id: i64,
    },
    /// Disable a port (will not be tested)
    Disable {
        /// Port ID
        id: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum PrefixCommands {
    /// List all registered prefixes
    List,
    /// Add a new network prefix
    Add {
        /// CIDR Prefix (e.g., 192.168.0.0/24 or 2001:db8::/120)
        #[arg(short, long)]
        prefix: String,
        /// Description (e.g., client name, AS)
        #[arg(short, long, default_value = "")]
        description: String,
    },
    /// Edit an existing prefix
    Edit {
        /// Prefix ID
        id: i64,
        /// New CIDR Prefix
        #[arg(short, long)]
        prefix: Option<String>,
        /// New description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Remove a prefix
    Remove {
        /// Prefix ID
        id: i64,
    },
    /// Enable a prefix for scanning
    Enable {
        /// Prefix ID
        id: i64,
    },
    /// Disable a prefix (will not be scanned)
    Disable {
        /// Prefix ID
        id: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum UserCommands {
    /// List users
    List,
    /// Add a new administrator user
    Add {
        /// Username
        #[arg(short = 'n', long)]
        username: String,
    },
    /// Change a user's password
    ChangePassword {
        /// Username
        #[arg(short = 'n', long)]
        username: String,
    },
    /// Remove a user
    Remove {
        /// User ID
        id: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum ScanCommands {
    /// Run a full scan on all enabled prefixes
    Run {
        /// Maximum number of simultaneous probes
        #[arg(short, long, default_value = "256")]
        concurrency: usize,
        /// Timeout per probe in seconds
        #[arg(short, long, default_value = "3")]
        timeout: u64,
        /// Number of retries for UDP probes (default is 2, giving 3 total attempts)
        #[arg(short, long, default_value = "2")]
        retries: usize,
        /// Output PDF report file path
        #[arg(short, long, default_value = "ampscan_report.pdf")]
        output: String,
        /// Manual CIDR prefix to test directly (ignores database and skips PDF)
        #[arg(long)]
        prefix: Option<String>,
        /// Request PDF report generation
        #[arg(long)]
        pdf: bool,
        /// Company/client name for the report
        #[arg(long)]
        client_name: Option<String>,
        /// PDF report recipient (e.g., manager or department name)
        #[arg(long)]
        recipient: Option<String>,
        /// Audit HTTP (80) and HTTPS (443) for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
        #[arg(long)]
        check_php: bool,
        /// Custom Host header and TLS SNI for --check-php probes (e.g. example.com)
        #[arg(long)]
        http_host: Option<String>,
    },
    /// Test a single IP against all enabled ports
    Single {
        /// IP Address (IPv4 or IPv6)
        ip: String,
        /// Timeout per probe in seconds
        #[arg(short, long, default_value = "3")]
        timeout: u64,
        /// Maximum number of simultaneous probes
        #[arg(short, long, default_value = "1")]
        concurrency: usize,
        /// Number of retries for UDP probes (default is 2, giving 3 total attempts)
        #[arg(short, long, default_value = "2")]
        retries: usize,
        /// Audit HTTP (80) and HTTPS (443) for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
        #[arg(long)]
        check_php: bool,
        /// Custom Host header and TLS SNI for --check-php probes (e.g. example.com)
        #[arg(long)]
        http_host: Option<String>,
    },
}
