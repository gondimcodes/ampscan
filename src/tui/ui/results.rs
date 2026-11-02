//! Results viewer tab rendering: verified findings table and real-time port statistics panel
use crate::scanner::result::PortStatus;
use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Row, Table},
    Frame,
};

pub fn render_results_viewer(frame: &mut Frame, app: &App, area: Rect) {
    // Horizontal layout split: 68% Findings Table, 32% Port Statistics
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(68), Constraint::Percentage(32)])
        .split(area);

    let left_area = chunks[0];
    let right_area = chunks[1];

    // ── 1. Left Panel: Verified Findings Table ─────────────────────────────
    let header_cells = ["#", "IP Address", "Port", "Service", "Status", "Latency"]
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

    let total_findings = app.filtered_log_indices.len();

    // Dynamically calculate visible rows based on left component height
    let visible_height = (left_area.height as usize).saturating_sub(4);
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

    let rows = app
        .filtered_log_indices
        .iter()
        .skip(start_idx)
        .take(visible_height)
        .enumerate()
        .map(|(rel_idx, &log_idx)| {
            let abs_idx = start_idx + rel_idx;
            let is_selected = abs_idx == selected_idx;
            let log = &app.logs[log_idx];
            let (status_str, status_style) = match &log.status {
                PortStatus::Open => (
                    "VULNERABLE",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                PortStatus::OpenProtected => (
                    "Open/Protected",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                _ => ("Other", Style::default().fg(Color::DarkGray)),
            };

            let latency_str = log
                .response_time_ms
                .map(|ms| format!("{} ms", ms))
                .unwrap_or_else(|| "-".to_string());

            let row_style = if is_selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            Row::new(vec![
                Span::raw((abs_idx + 1).to_string()),
                Span::raw(log.ip.to_string()),
                Span::raw(log.port.to_string()),
                Span::raw(log.service_name.clone()),
                Span::styled(status_str, status_style),
                Span::raw(latency_str),
            ])
            .style(row_style)
        });

    let display_counter = if total_findings == 0 {
        0
    } else {
        selected_idx + 1
    };
    let title_text = if total_findings == 0 {
        " Verified Findings (0 Detected) ".to_string()
    } else {
        format!(
            " Verified Findings ({}/{} entries) ",
            display_counter, total_findings
        )
    };

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(8),
            Constraint::Percentage(26),
            Constraint::Percentage(12),
            Constraint::Percentage(18),
            Constraint::Percentage(22),
            Constraint::Percentage(14),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title_text));

    frame.render_widget(table, left_area);

    // ── 2. Right Panel: Port Statistics Table ──────────────────────────────
    let stat_header_cells = ["Service (Port)", "Vuln", "Prot"].iter().map(|h| {
        Span::styled(
            *h,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    });
    let stat_header = Row::new(stat_header_cells).height(1).bottom_margin(1);

    struct PortStat {
        display_name: String,
        vulnerable: usize,
        protected: usize,
    }

    let mut stats_list: Vec<PortStat> = Vec::new();

    if !app.ports.is_empty() {
        for port in &app.ports {
            let (vuln, prot) = app.port_stats.get(&port.port).copied().unwrap_or((0, 0));
            stats_list.push(PortStat {
                display_name: format!("{} ({}/{})", port.name, port.port, port.protocol),
                vulnerable: vuln,
                protected: prot,
            });
        }
    } else {
        use std::collections::BTreeMap;
        let mut map: BTreeMap<(u16, String, String), (usize, usize)> = BTreeMap::new();
        for log in &app.logs {
            let entry = map
                .entry((log.port, log.service_name.clone(), log.protocol.clone()))
                .or_insert((0, 0));
            if log.status == PortStatus::Open {
                entry.0 += 1;
            } else if log.status == PortStatus::OpenProtected {
                entry.1 += 1;
            }
        }
        for ((port, name, proto), (vuln, prot)) in map {
            stats_list.push(PortStat {
                display_name: format!("{} ({}/{})", name, port, proto),
                vulnerable: vuln,
                protected: prot,
            });
        }
    }

    let stat_rows = stats_list.iter().map(|stat| {
        let vuln_style = if stat.vulnerable > 0 {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let prot_style = if stat.protected > 0 {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        Row::new(vec![
            Span::raw(stat.display_name.clone()),
            Span::styled(stat.vulnerable.to_string(), vuln_style),
            Span::styled(stat.protected.to_string(), prot_style),
        ])
    });

    let stat_title = format!(" Port Statistics ({} Ports) ", stats_list.len());

    let stat_table = Table::new(
        stat_rows,
        [
            Constraint::Percentage(58),
            Constraint::Percentage(21),
            Constraint::Percentage(21),
        ],
    )
    .header(stat_header)
    .block(Block::default().borders(Borders::ALL).title(stat_title));

    frame.render_widget(stat_table, right_area);
}
