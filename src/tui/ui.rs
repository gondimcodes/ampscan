use std::str::FromStr;
use crate::scanner::result::PortStatus;
use crate::tui::app::{App, Tab};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Paragraph, Row, Table, Tabs, Wrap,
    },
    Frame,
};

pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header & Tabs
            Constraint::Min(0),    // Main Content
            Constraint::Length(3), // Footer / Status bar
        ])
        .split(frame.area());

    render_tabs(frame, app, chunks[0]);

    match app.active_tab {
        Tab::Dashboard => render_dashboard(frame, app, chunks[1]),
        Tab::Results => render_results_viewer(frame, app, chunks[1]),
        Tab::CidrScan => render_cidr_scan(frame, app, chunks[1]),
        Tab::SingleTarget => render_single_target(frame, app, chunks[1]),
        Tab::PortDatabase => render_port_database(frame, app, chunks[1]),
        Tab::Settings => render_settings(frame, app, chunks[1]),
    }

    render_footer(frame, app, chunks[2]);
}

fn render_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles = Tab::ALL
        .iter()
        .map(|t| {
            let title = t.title();
            Span::styled(title, Style::default().fg(Color::Cyan))
        })
        .collect::<Vec<_>>();

    let selected_index = Tab::ALL.iter().position(|t| t == &app.active_tab).unwrap_or(0);

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" ampscan v1.4.1 ")
                .style(Style::default().fg(Color::DarkGray)),
        )
        .select(selected_index)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .divider(Span::raw(" | "));

    frame.render_widget(tabs, area);
}

fn render_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // Left Panel: Stats & Gauges
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Progress Gauge
            Constraint::Length(6), // Metrics Summary
            Constraint::Min(0),    // Info Panel
        ])
        .split(main_chunks[0]);

    // Hacker Style Custom Progress Bar
    let pct_float = if app.stats.total_probes > 0 {
        ((app.stats.completed_probes as f64 / app.stats.total_probes as f64) * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };

    let inner_width = (left_chunks[0].width as usize).saturating_sub(18); // space for percent text and borders
    let filled_len = ((pct_float / 100.0) * inner_width as f64).round() as usize;
    let empty_len = inner_width.saturating_sub(filled_len);

    let filled_bar = "█".repeat(filled_len);
    let empty_bar = "░".repeat(empty_len);

    let progress_line = Line::from(vec![
        Span::styled("[ ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(filled_bar, Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
        Span::styled(empty_bar, Style::default().fg(Color::DarkGray)),
        Span::styled(" ] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:>5.1}%", pct_float), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ]);

    let progress_widget = Paragraph::new(vec![Line::from(""), progress_line])
        .block(Block::default().borders(Borders::ALL).title(" 💀 SCAN PROGRESS "));
    frame.render_widget(progress_widget, left_chunks[0]);

    // Metrics Summary
    let stats_text = vec![
        Line::from(vec![
            Span::raw("Vulnerable (Open): "),
            Span::styled(
                app.stats.vulnerable_count.to_string(),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("Open / Protected:  "),
            Span::styled(
                app.stats.protected_count.to_string(),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("Closed / Filtered: "),
            Span::styled(
                app.stats.closed_count.to_string(),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    let stats_paragraph = Paragraph::new(stats_text)
        .block(Block::default().borders(Borders::ALL).title(" Findings Summary "));
    frame.render_widget(stats_paragraph, left_chunks[1]);

    // System & Scanner Info
    let info_text = vec![
        Line::from(Span::styled("Scan Overview", Style::default().add_modifier(Modifier::UNDERLINED))),
        Line::from(format!("Status: {}", if app.is_scanning { "SCANNING" } else { "IDLE" })),
        Line::from(format!("Probes Completed: {} / {}", app.stats.completed_probes, app.stats.total_probes)),
        Line::from(format!("Concurrency Limit: {}", app.concurrency_input)),
        Line::from(format!("Timeout Per Probe: {}s", app.timeout_input)),
    ];
    let info_paragraph = Paragraph::new(info_text)
        .block(Block::default().borders(Borders::ALL).title(" Parameters "))
        .wrap(Wrap { trim: true });
    frame.render_widget(info_paragraph, left_chunks[2]);

    // Right Panel: Live Streaming Logs Table
    render_logs_table(frame, app, main_chunks[1]);
}

fn render_logs_table(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["IP Address", "Port", "Service", "Status", "Latency"]
        .iter()
        .map(|h| Span::styled(*h, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = app.logs.iter().rev().take(100).map(|log| {
        let (status_str, status_style) = match &log.status {
            PortStatus::Open => ("Vulnerable", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            PortStatus::OpenProtected => ("Open/Protected", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            PortStatus::Closed => ("Closed", Style::default().fg(Color::DarkGray)),
            PortStatus::Inconclusive => ("Inconclusive", Style::default().fg(Color::DarkGray)),
            PortStatus::Error(_) => ("Error", Style::default().fg(Color::Red)),
        };

        let latency_str = log.response_time_ms.map(|ms| format!("{} ms", ms)).unwrap_or_else(|| "-".to_string());

        Row::new(vec![
            Span::raw(log.ip.to_string()),
            Span::raw(log.port.to_string()),
            Span::raw(log.service_name.clone()),
            Span::styled(status_str, status_style),
            Span::raw(latency_str),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(15),
            Constraint::Percentage(20),
            Constraint::Percentage(25),
            Constraint::Percentage(15),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Live Probing Activity "));

    frame.render_widget(table, area);
}

fn render_results_viewer(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["#", "IP Address", "Port", "Service", "Status", "Latency"]
        .iter()
        .map(|h| Span::styled(*h, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    // Filter logs to ONLY show Vulnerable (Open) and Open/Protected findings
    let filtered_logs: Vec<_> = app
        .logs
        .iter()
        .filter(|log| log.status == PortStatus::Open || log.status == PortStatus::OpenProtected)
        .collect();

    let total_findings = filtered_logs.len();

    // Dynamically calculate visible rows based on component height
    let visible_height = (area.height as usize).saturating_sub(4); // subtract header, borders and margin
    let half_view = visible_height / 2;

    let selected_idx = if total_findings == 0 {
        0
    } else {
        app.selected_log_index.min(total_findings.saturating_sub(1))
    };

    let start_idx = if total_findings <= visible_height {
        0
    } else {
        let max_start = total_findings - visible_height;
        let ideal_start = selected_idx.saturating_sub(half_view);
        ideal_start.min(max_start)
    };

    let rows = filtered_logs.iter().enumerate().skip(start_idx).take(visible_height).map(|(idx, log)| {
        let is_selected = idx == selected_idx;
        let (status_str, status_style) = match &log.status {
            PortStatus::Open => ("VULNERABLE", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            PortStatus::OpenProtected => ("Open/Protected", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            _ => ("Other", Style::default().fg(Color::DarkGray)),
        };

        let latency_str = log.response_time_ms.map(|ms| format!("{} ms", ms)).unwrap_or_else(|| "-".to_string());

        let row_style = if is_selected {
            Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        Row::new(vec![
            Span::raw((idx + 1).to_string()),
            Span::raw(log.ip.to_string()),
            Span::raw(log.port.to_string()),
            Span::raw(log.service_name.clone()),
            Span::styled(status_str, status_style),
            Span::raw(latency_str),
        ]).style(row_style)
    });

    let display_counter = if total_findings == 0 { 0 } else { selected_idx + 1 };
    let title_text = if total_findings == 0 {
        " Verified Findings (0 Vulnerable / OpenProtected Detected) ".to_string()
    } else {
        format!(" Verified Findings ({}/{} entries - Use UP/DOWN/PgUp/PgDn to Scroll) ", display_counter, total_findings)
    };

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(8),
            Constraint::Percentage(22),
            Constraint::Percentage(12),
            Constraint::Percentage(20),
            Constraint::Percentage(23),
            Constraint::Percentage(15),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title_text));

    frame.render_widget(table, area);
}

fn render_cidr_scan(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["ID", "CIDR Prefix", "Description", "Status"]
        .iter()
        .map(|h| Span::styled(*h, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = app.prefixes.iter().map(|p| {
        let status = if p.enabled { "Enabled" } else { "Disabled" };
        let style = if p.enabled { Style::default().fg(Color::Green) } else { Style::default().fg(Color::DarkGray) };
        Row::new(vec![
            Span::raw(p.id.to_string()),
            Span::styled(p.prefix.clone(), Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(p.description.clone()),
            Span::styled(status, style),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(10),
            Constraint::Percentage(30),
            Constraint::Percentage(45),
            Constraint::Percentage(15),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Registered Subnet Prefixes (Database) "));

    frame.render_widget(table, area);
}

fn render_single_target(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Input box for target IP or CIDR Prefix
            Constraint::Length(6), // Instructions & status (compact height)
        ])
        .split(area);

    let trimmed = app.single_ip_input.trim();
    let is_valid_target = trimmed.is_empty() 
        || std::net::IpAddr::from_str(trimmed).is_ok()
        || ipnet::IpNet::from_str(trimmed).is_ok();

    let (input_display, style, border_color) = if app.single_ip_input.is_empty() {
        ("Type IP or CIDR prefix here (e.g. 192.168.1.1 or 192.168.1.0/24)", Style::default().fg(Color::DarkGray), Color::White)
    } else if is_valid_target {
        (app.single_ip_input.as_str(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD), Color::Green)
    } else {
        (app.single_ip_input.as_str(), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD), Color::Red)
    };

    let title_str = if !app.single_ip_input.is_empty() && !is_valid_target {
        " Target IP / CIDR Prefix [INVALID FORMAT] "
    } else if !app.single_ip_input.is_empty() {
        " Target IP / CIDR Prefix [VALID TARGET] "
    } else {
        " Target IP / CIDR Prefix "
    };

    let p_input = Paragraph::new(input_display)
        .style(style)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title_str)
                .border_style(Style::default().fg(border_color)),
        );
    frame.render_widget(p_input, chunks[0]);

    let text = vec![
        Line::from(Span::styled("Instructions:", Style::default().add_modifier(Modifier::UNDERLINED))),
        Line::from("• Type an IP address (e.g. 192.168.1.1) or CIDR subnet (e.g. 192.168.1.0/24) directly in this view."),
        Line::from("• Press [Enter] or [S] to launch an immediate scan against the specified target."),
        Line::from("• Switch to Dashboard [Tab] to see live progress and results."),
    ];
    let p_info = Paragraph::new(text).block(
        Block::default().borders(Borders::ALL).title(" Target Inspection "),
    );
    frame.render_widget(p_info, chunks[1]);
}

fn render_port_database(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Port", "Proto", "Name", "Probe Type", "Description"]
        .iter()
        .map(|h| Span::styled(*h, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = app.ports.iter().map(|p| {
        Row::new(vec![
            Span::raw(p.port.to_string()),
            Span::raw(p.protocol.to_uppercase()),
            Span::styled(p.name.clone(), Style::default().fg(Color::Yellow)),
            Span::raw(p.probe_type.clone()),
            Span::raw(p.description.clone()),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Min(30),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Registered Amplification Signatures "));

    frame.render_widget(table, area);
}



fn render_settings(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Concurrency
            Constraint::Length(3), // Timeout
            Constraint::Length(3), // Retries
            Constraint::Length(6), // Instructions (compact height)
        ])
        .split(area);

    let conc_style = if app.focused_field == 0 {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };

    let timeout_style = if app.focused_field == 1 {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };

    let retries_style = if app.focused_field == 2 {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };

    let p_conc = Paragraph::new(app.concurrency_input.as_str())
        .block(Block::default().borders(Borders::ALL).title(" Max Concurrency (Threads) ").style(conc_style));
    frame.render_widget(p_conc, chunks[0]);

    let p_timeout = Paragraph::new(app.timeout_input.as_str())
        .block(Block::default().borders(Borders::ALL).title(" Probe Timeout (Seconds) ").style(timeout_style));
    frame.render_widget(p_timeout, chunks[1]);

    let p_retries = Paragraph::new(app.retries_input.as_str())
        .block(Block::default().borders(Borders::ALL).title(" UDP Probe Retries ").style(retries_style));
    frame.render_widget(p_retries, chunks[2]);

    let help_text = vec![
        Line::from(Span::styled("Scanner Settings Instructions:", Style::default().add_modifier(Modifier::UNDERLINED))),
        Line::from("• Use UP/DOWN arrows to navigate between setting fields."),
        Line::from("• Type directly to edit max concurrency, timeout or retries per probe."),
        Line::from("• Database Path: ") + Span::styled(&app.db_path, Style::default().fg(Color::Cyan)),
    ];
    let p_help = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title(" Global Configuration "));
    frame.render_widget(p_help, chunks[3]);
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let default_status = if app.single_ip_input.trim().is_empty() {
        "Press [F] for Full Scan | [S] for Single Target Scan"
    } else {
        "Press [S] to scan target IP | [F] for Full CIDR Scan"
    };

    let status = app
        .status_message
        .as_deref()
        .unwrap_or(default_status);

    let footer_text = vec![Line::from(vec![
        Span::styled(" HOTKEYS: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw("[Tab] Switch View  |  [F] Full Scan  |  [S] Single Target  |  [Q] Quit    --    "),
        Span::styled(status, Style::default().fg(Color::Green)),
    ])];

    let p = Paragraph::new(footer_text).block(Block::default().borders(Borders::ALL));
    frame.render_widget(p, area);
}
