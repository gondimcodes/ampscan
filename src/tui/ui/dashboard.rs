//! Dashboard tab rendering: progress gauges, findings summary and live probing activity
use crate::scanner::result::PortStatus;
use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, Wrap},
    Frame,
};

pub fn render_dashboard(frame: &mut Frame, app: &App, area: Rect) {
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
        ((app.stats.completed_probes as f64 / app.stats.total_probes as f64) * 100.0)
            .clamp(0.0, 100.0)
    } else {
        0.0
    };

    let inner_width = (left_chunks[0].width as usize).saturating_sub(18); // space for percent text and borders
    let filled_len = ((pct_float / 100.0) * inner_width as f64).round() as usize;
    let empty_len = inner_width.saturating_sub(filled_len);

    let filled_bar = "█".repeat(filled_len);
    let empty_bar = "░".repeat(empty_len);

    let progress_line = Line::from(vec![
        Span::styled(
            "[ ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            filled_bar,
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(empty_bar, Style::default().fg(Color::DarkGray)),
        Span::styled(
            " ] ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:>5.1}%", pct_float),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let progress_widget = Paragraph::new(vec![Line::from(""), progress_line]).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" 💀 SCAN PROGRESS "),
    );
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
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
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

    let stats_paragraph = Paragraph::new(stats_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Findings Summary "),
    );
    frame.render_widget(stats_paragraph, left_chunks[1]);

    // System & Scanner Info
    let info_text = vec![
        Line::from(Span::styled(
            "Scan Overview",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from(format!(
            "Status: {}",
            if app.is_scanning { "SCANNING" } else { "IDLE" }
        )),
        Line::from(format!(
            "Probes Completed: {} / {}",
            app.stats.completed_probes, app.stats.total_probes
        )),
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
        .map(|h| {
            Span::styled(
                *h,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = app.logs.iter().rev().take(100).map(|log| {
        let (status_str, status_style) = match &log.status {
            PortStatus::Open => (
                "Vulnerable",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            PortStatus::OpenProtected => (
                "Open/Protected",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            PortStatus::Closed => ("Closed", Style::default().fg(Color::DarkGray)),
            PortStatus::Inconclusive => ("Inconclusive", Style::default().fg(Color::DarkGray)),
            PortStatus::Error(_) => ("Error", Style::default().fg(Color::Red)),
        };

        let latency_str = log
            .response_time_ms
            .map(|ms| format!("{} ms", ms))
            .unwrap_or_else(|| "-".to_string());

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
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Live Probing Activity "),
    );

    frame.render_widget(table, area);
}
