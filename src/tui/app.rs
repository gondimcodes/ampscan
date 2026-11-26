use crate::db::models::{Port, Prefix};
use crate::scanner::result::ProbeResult;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Results,
    CidrScan,
    SingleTarget,
    PortDatabase,
    Settings,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Dashboard,
        Tab::Results,
        Tab::CidrScan,
        Tab::SingleTarget,
        Tab::PortDatabase,
        Tab::Settings,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Results => "Results Viewer",
            Tab::CidrScan => "CIDR Scan",
            Tab::SingleTarget => "Target Scan",
            Tab::PortDatabase => "Port Database",
            Tab::Settings => "Settings",
        }
    }
}

pub enum TuiEvent {
    ScanStarted(usize),
    ProbeCompleted(ProbeResult),
    HostsAlive(Vec<std::net::IpAddr>),
    ScanFinished,
    ScanError(String),
}

#[derive(Default)]
pub struct ScanStats {
    pub total_probes: usize,
    pub completed_probes: usize,
    pub vulnerable_count: usize,
    pub protected_count: usize,
    pub open_no_php_count: usize,
    pub closed_count: usize,
    pub start_time: Option<Instant>,
    pub elapsed_duration: Option<std::time::Duration>,
}

impl ScanStats {
    /// Returns the frozen final duration after completion, or live elapsed time while scanning.
    pub fn scan_duration(&self) -> Option<std::time::Duration> {
        self.elapsed_duration
            .or_else(|| self.start_time.map(|t| t.elapsed()))
    }
}

pub struct App {
    pub active_tab: Tab,
    pub should_quit: bool,
    pub is_scanning: bool,

    // Scan Data & Logs
    pub stats: ScanStats,
    pub logs: Vec<ProbeResult>,
    pub filtered_log_indices: Vec<usize>,
    pub port_stats: std::collections::HashMap<(u16, String), (usize, usize)>,
    pub selected_log_index: usize,
    pub findings_scroll_offset: std::cell::Cell<usize>,
    pub visible_findings_rows: std::cell::Cell<usize>,

    // DB Data Cache for TUI
    pub prefixes: Vec<Prefix>,
    pub ports: Vec<Port>,
    pub last_scanned_prefixes: Vec<String>,
    pub selected_prefix_index: usize,
    pub selected_port_index: usize,

    // Form inputs
    pub db_path: String,
    pub db_key: String,
    pub single_ip_input: String,
    pub concurrency_input: String,
    pub timeout_input: String,
    pub retries_input: String,
    pub focused_field: usize,

    pub pdf_export: bool,
    pub pdf_output: String,
    pub pdf_client_name: Option<String>,
    pub pdf_recipient: Option<String>,
    pub check_php: bool,
    pub http_host: Option<String>,

    // Status message for notification bar
    pub status_message: Option<String>,
}

impl App {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db_path: String,
        db_key: String,
        concurrency: usize,
        timeout: u64,
        retries: usize,
        pdf_export: bool,
        pdf_output: String,
        pdf_client_name: Option<String>,
        pdf_recipient: Option<String>,
        check_php: bool,
        http_host: Option<String>,
    ) -> Self {
        Self {
            active_tab: Tab::Dashboard,
            should_quit: false,
            is_scanning: false,
            stats: ScanStats::default(),
            logs: Vec::new(),
            filtered_log_indices: Vec::new(),
            port_stats: std::collections::HashMap::new(),
            selected_log_index: 0,
            findings_scroll_offset: std::cell::Cell::new(0),
            visible_findings_rows: std::cell::Cell::new(25),
            prefixes: Vec::new(),
            ports: Vec::new(),
            last_scanned_prefixes: Vec::new(),
            selected_prefix_index: 0,
            selected_port_index: 0,
            db_path,
            db_key,
            single_ip_input: String::new(),
            concurrency_input: concurrency.to_string(),
            timeout_input: timeout.to_string(),
            retries_input: retries.to_string(),
            focused_field: 0,
            pdf_export,
            pdf_output,
            pdf_client_name,
            pdf_recipient,
            check_php,
            http_host,
            status_message: None,
        }
    }

    pub fn next_tab(&mut self) {
        let current_idx = Tab::ALL
            .iter()
            .position(|t| t == &self.active_tab)
            .unwrap_or(0);
        let next_idx = (current_idx + 1) % Tab::ALL.len();
        self.active_tab = Tab::ALL[next_idx];
    }

    pub fn prev_tab(&mut self) {
        let current_idx = Tab::ALL
            .iter()
            .position(|t| t == &self.active_tab)
            .unwrap_or(0);
        let prev_idx = if current_idx == 0 {
            Tab::ALL.len() - 1
        } else {
            current_idx - 1
        };
        self.active_tab = Tab::ALL[prev_idx];
    }

    pub fn clear_scan_data(&mut self) {
        self.logs.clear();
        self.filtered_log_indices.clear();
        self.port_stats.clear();
        self.selected_log_index = 0;
        self.findings_scroll_offset.set(0);
        self.stats = ScanStats::default();
        self.stats.start_time = Some(std::time::Instant::now());
    }

    pub fn get_filtered_findings_count(&self) -> usize {
        self.filtered_log_indices.len()
    }

    pub fn add_probe_result(&mut self, result: ProbeResult) {
        let is_finding = matches!(
            result.status,
            crate::scanner::result::PortStatus::Open
                | crate::scanner::result::PortStatus::OpenProtected
                | crate::scanner::result::PortStatus::OpenNoPhp
        );

        match &result.status {
            crate::scanner::result::PortStatus::Open => {
                self.stats.vulnerable_count += 1;
                let entry = self
                    .port_stats
                    .entry((result.port, result.protocol.clone()))
                    .or_default();
                entry.0 += 1;
            }
            crate::scanner::result::PortStatus::OpenProtected => {
                self.stats.protected_count += 1;
                let entry = self
                    .port_stats
                    .entry((result.port, result.protocol.clone()))
                    .or_default();
                entry.1 += 1;
            }
            crate::scanner::result::PortStatus::OpenNoPhp => {
                // Open web port without PHP: counted only in Dashboard summary, never in Vuln/Prot stats
                self.stats.open_no_php_count += 1;
            }
            _ => self.stats.closed_count += 1,
        }
        self.stats.completed_probes += 1;

        let new_idx = self.logs.len();
        self.logs.push(result);

        if is_finding {
            self.filtered_log_indices.push(new_idx);
        }
    }

    /// Synchronize app.ports with current check_php state
    pub fn sync_php_ports(&mut self) {
        if self.check_php {
            if !self
                .ports
                .iter()
                .any(|p| p.port == 80 && p.probe_type == "php_http")
            {
                self.ports.push(crate::db::models::Port {
                    id: 80,
                    port: 80,
                    protocol: "tcp".to_string(),
                    name: "HTTP".to_string(),
                    description: "HTTP - PHP RCE check (PHP2Shell / phpAfterShell)".to_string(),
                    probe_type: "php_http".to_string(),
                    probe_payload: None,
                    enabled: true,
                    created_at: String::new(),
                    updated_at: String::new(),
                });
            }
            if !self
                .ports
                .iter()
                .any(|p| p.port == 443 && p.probe_type == "php_https")
            {
                self.ports.push(crate::db::models::Port {
                    id: 443,
                    port: 443,
                    protocol: "tcp".to_string(),
                    name: "HTTPS".to_string(),
                    description: "HTTPS - PHP RCE check (PHP2Shell / phpAfterShell)".to_string(),
                    probe_type: "php_https".to_string(),
                    probe_payload: None,
                    enabled: true,
                    created_at: String::new(),
                    updated_at: String::new(),
                });
            }
            self.ports.sort_by_key(|p| p.port);
        } else {
            self.ports
                .retain(|p| !(p.probe_type == "php_http" || p.probe_type == "php_https"));
        }
    }

    /// Toggle PHP2Shell checking and synchronize port list in real time
    pub fn toggle_check_php(&mut self) {
        self.check_php = !self.check_php;
        self.sync_php_ports();
    }

    /// Synchronize TUI logs with the scanner's post-scan alive-IP closure rule.
    pub fn apply_alive_ip_closure(&mut self) {
        crate::scanner::apply_alive_ip_closure(&mut self.logs);
    }

    /// Mark hosts confirmed alive via out-of-band checks (e.g. ICMP Echo) so `Inconclusive` becomes `Closed`.
    pub fn mark_hosts_alive(&mut self, ips: &[std::net::IpAddr]) {
        let extra: std::collections::HashSet<std::net::IpAddr> = ips.iter().copied().collect();
        crate::scanner::apply_alive_ip_closure_with_extra(&mut self.logs, &extra);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::Port;

    #[test]
    fn test_toggle_check_php_updates_port_database_dynamically() {
        let mut app = App::new(
            "test.db".to_string(),
            "test_key".to_string(),
            256,
            3,
            2,
            false,
            "report.pdf".to_string(),
            None,
            None,
            false,
            None,
        );

        // Populate with baseline amplification ports
        app.ports = vec![
            Port {
                id: 1,
                port: 53,
                protocol: "udp".to_string(),
                name: "DNS".to_string(),
                description: "DNS check".to_string(),
                probe_type: "dns".to_string(),
                probe_payload: None,
                enabled: true,
                created_at: String::new(),
                updated_at: String::new(),
            },
            Port {
                id: 2,
                port: 123,
                protocol: "udp".to_string(),
                name: "NTP".to_string(),
                description: "NTP check".to_string(),
                probe_type: "ntp".to_string(),
                probe_payload: None,
                enabled: true,
                created_at: String::new(),
                updated_at: String::new(),
            },
        ];

        // Initially disabled: only 53 and 123
        app.sync_php_ports();
        assert_eq!(app.ports.len(), 2);
        assert!(!app.ports.iter().any(|p| p.port == 80 || p.port == 443));

        // Toggle ON (pressing 'P' in settings)
        app.toggle_check_php();
        assert!(app.check_php);
        assert_eq!(app.ports.len(), 4);
        assert!(app
            .ports
            .iter()
            .any(|p| p.port == 80 && p.probe_type == "php_http"));
        assert!(app
            .ports
            .iter()
            .any(|p| p.port == 443 && p.probe_type == "php_https"));
        // Check sorting: 53, 80, 123, 443
        let port_numbers: Vec<u16> = app.ports.iter().map(|p| p.port).collect();
        assert_eq!(port_numbers, vec![53, 80, 123, 443]);

        // Toggle OFF (pressing 'P' in settings again)
        app.toggle_check_php();
        assert!(!app.check_php);
        assert_eq!(app.ports.len(), 2);
        assert!(!app.ports.iter().any(|p| p.port == 80 || p.port == 443));
        assert!(app.ports.iter().any(|p| p.port == 53));
        assert!(app.ports.iter().any(|p| p.port == 123));
    }

    #[test]
    fn test_findings_viewport_free_scrolling_and_page_nav() {
        let mut app = App::new(
            "test.db".to_string(),
            "test_key".to_string(),
            256,
            3,
            2,
            false,
            "report.pdf".to_string(),
            None,
            None,
            false,
            None,
        );

        // Simulate 100 findings
        app.filtered_log_indices = (0..100).collect();
        let visible_height = 30;
        app.visible_findings_rows.set(visible_height);

        let calculate_start_idx = |app: &App, visible_height: usize| -> usize {
            let total = app.filtered_log_indices.len();
            let selected_idx = app.selected_log_index.min(total.saturating_sub(1));
            let max_start = total.saturating_sub(visible_height);
            let mut offset = app.findings_scroll_offset.get();

            if selected_idx < offset {
                offset = selected_idx;
            } else if selected_idx >= offset + visible_height {
                offset = selected_idx.saturating_sub(visible_height.saturating_sub(1));
            }
            let clamped = offset.min(max_start);
            app.findings_scroll_offset.set(clamped);
            clamped
        };

        // 1. Initially at index 0, start_idx must be 0
        assert_eq!(calculate_start_idx(&app, visible_height), 0);

        // 2. Cursor moves down to middle of screen (index 15) — must NOT scroll or lock in middle
        app.selected_log_index = 15;
        assert_eq!(calculate_start_idx(&app, visible_height), 0);
        assert_eq!(app.findings_scroll_offset.get(), 0);

        // 3. Cursor reaches bottom edge of screen (index 29) — still at start_idx 0
        app.selected_log_index = 29;
        assert_eq!(calculate_start_idx(&app, visible_height), 0);

        // 4. Cursor goes beyond bottom edge (index 30) — viewport scrolls by 1
        app.selected_log_index = 30;
        assert_eq!(calculate_start_idx(&app, visible_height), 1);
        assert_eq!(app.findings_scroll_offset.get(), 1);

        // 5. PageDown jumps by visible_height (30 rows): index goes to 60
        let page = app.visible_findings_rows.get().max(10);
        app.selected_log_index = (app.selected_log_index + page).min(100 - 1);
        assert_eq!(app.selected_log_index, 60);
        assert_eq!(calculate_start_idx(&app, visible_height), 31);

        // 6. PageUp recedes by visible_height (30 rows): index goes back to 30
        app.selected_log_index = app.selected_log_index.saturating_sub(page);
        assert_eq!(app.selected_log_index, 30);
        assert_eq!(calculate_start_idx(&app, visible_height), 30);

        // 7. Cursor moves UP within visible viewport (index 25)
        app.selected_log_index = 25;
        assert_eq!(calculate_start_idx(&app, visible_height), 25);
    }

    #[test]
    fn test_tui_alive_ip_closure_and_protocol_stats_isolation() {
        use crate::scanner::result::PortStatus;
        use chrono::Utc;
        use std::net::IpAddr;

        let mut app = App::new(
            "test.db".to_string(),
            "test_key".to_string(),
            256,
            3,
            2,
            false,
            "report.pdf".to_string(),
            None,
            None,
            false,
            None,
        );

        let ip_alive: IpAddr = "192.0.2.10".parse().unwrap();
        let ip_dead: IpAddr = "192.0.2.20".parse().unwrap();

        app.add_probe_result(ProbeResult {
            ip: ip_alive,
            port: 53,
            protocol: "udp".to_string(),
            service_name: "DNS".to_string(),
            description: "DNS".to_string(),
            status: PortStatus::Open,
            response_time_ms: Some(5),
            timestamp: Utc::now(),
        });
        app.add_probe_result(ProbeResult {
            ip: ip_alive,
            port: 53,
            protocol: "tcp".to_string(),
            service_name: "DNS-TCP".to_string(),
            description: "DNS TCP".to_string(),
            status: PortStatus::Inconclusive,
            response_time_ms: None,
            timestamp: Utc::now(),
        });
        app.add_probe_result(ProbeResult {
            ip: ip_dead,
            port: 53,
            protocol: "udp".to_string(),
            service_name: "DNS".to_string(),
            description: "DNS".to_string(),
            status: PortStatus::Inconclusive,
            response_time_ms: None,
            timestamp: Utc::now(),
        });

        app.apply_alive_ip_closure();

        assert_eq!(app.logs[0].status, PortStatus::Open);
        assert_eq!(app.logs[1].status, PortStatus::Closed);
        assert_eq!(app.logs[2].status, PortStatus::Inconclusive);
        assert_eq!(app.port_stats.get(&(53, "udp".to_string())), Some(&(1, 0)));
        assert_eq!(app.port_stats.get(&(53, "tcp".to_string())), None);
    }
}
