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
    ScanFinished,
    ScanError(String),
}

pub struct ScanStats {
    pub total_probes: usize,
    pub completed_probes: usize,
    pub vulnerable_count: usize,
    pub protected_count: usize,
    pub closed_count: usize,
    pub start_time: Option<Instant>,
}

impl Default for ScanStats {
    fn default() -> Self {
        Self {
            total_probes: 0,
            completed_probes: 0,
            vulnerable_count: 0,
            protected_count: 0,
            closed_count: 0,
            start_time: None,
        }
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
    pub port_stats: std::collections::HashMap<u16, (usize, usize)>,
    pub selected_log_index: usize,
    
    // DB Data Cache for TUI
    pub prefixes: Vec<Prefix>,
    pub ports: Vec<Port>,
    pub selected_prefix_index: usize,
    pub selected_port_index: usize,

    // Form inputs
    pub db_path: String,
    pub db_key: String,
    pub single_ip_input: String,
    pub custom_prefix_input: String,
    pub concurrency_input: String,
    pub timeout_input: String,
    pub retries_input: String,
    pub focused_field: usize,
    
    pub pdf_export: bool,
    pub pdf_output: String,
    pub pdf_client_name: Option<String>,
    pub pdf_recipient: Option<String>,

    // Status message for notification bar
    pub status_message: Option<String>,
}

impl App {
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
            prefixes: Vec::new(),
            ports: Vec::new(),
            selected_prefix_index: 0,
            selected_port_index: 0,
            db_path,
            db_key,
            single_ip_input: String::new(),
            custom_prefix_input: String::new(),
            concurrency_input: concurrency.to_string(),
            timeout_input: timeout.to_string(),
            retries_input: retries.to_string(),
            focused_field: 0,
            pdf_export,
            pdf_output,
            pdf_client_name,
            pdf_recipient,
            status_message: None,
        }
    }

    pub fn next_tab(&mut self) {
        let current_idx = Tab::ALL.iter().position(|t| t == &self.active_tab).unwrap_or(0);
        let next_idx = (current_idx + 1) % Tab::ALL.len();
        self.active_tab = Tab::ALL[next_idx];
    }

    pub fn prev_tab(&mut self) {
        let current_idx = Tab::ALL.iter().position(|t| t == &self.active_tab).unwrap_or(0);
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
        self.stats = ScanStats::default();
        self.stats.start_time = Some(std::time::Instant::now());
    }

    pub fn get_filtered_findings_count(&self) -> usize {
        self.filtered_log_indices.len()
    }

    pub fn add_probe_result(&mut self, result: ProbeResult) {
        let is_finding = matches!(
            result.status,
            crate::scanner::result::PortStatus::Open | crate::scanner::result::PortStatus::OpenProtected
        );

        match &result.status {
            crate::scanner::result::PortStatus::Open => {
                self.stats.vulnerable_count += 1;
                let entry = self.port_stats.entry(result.port).or_default();
                entry.0 += 1;
            }
            crate::scanner::result::PortStatus::OpenProtected => {
                self.stats.protected_count += 1;
                let entry = self.port_stats.entry(result.port).or_default();
                entry.1 += 1;
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
}
