//! Single target scan tab rendering: IP/CIDR input field and instructions
use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use std::str::FromStr;

pub fn render_single_target(frame: &mut Frame, app: &App, area: Rect) {
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
        (
            "Type IP or CIDR prefix here (e.g. 192.168.1.1 or 192.168.1.0/24)",
            Style::default().fg(Color::DarkGray),
            Color::White,
        )
    } else if is_valid_target {
        (
            app.single_ip_input.as_str(),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            Color::Green,
        )
    } else {
        (
            app.single_ip_input.as_str(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            Color::Red,
        )
    };

    let title_str = if !app.single_ip_input.is_empty() && !is_valid_target {
        " Target IP / CIDR Prefix [INVALID FORMAT] "
    } else if !app.single_ip_input.is_empty() {
        " Target IP / CIDR Prefix [VALID TARGET] "
    } else {
        " Target IP / CIDR Prefix "
    };

    let p_input = Paragraph::new(input_display).style(style).block(
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
        Block::default()
            .borders(Borders::ALL)
            .title(" Target Inspection "),
    );
    frame.render_widget(p_info, chunks[1]);
}
