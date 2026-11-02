//! Settings tab rendering: scanner parameters and concurrency controls
use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn render_settings(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Concurrency
            Constraint::Length(3), // Timeout
            Constraint::Length(3), // Retries
            Constraint::Length(8), // Instructions
        ])
        .split(area);

    let conc_style = if app.focused_field == 0 {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };

    let timeout_style = if app.focused_field == 1 {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };

    let retries_style = if app.focused_field == 2 {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };

    let p_conc = Paragraph::new(app.concurrency_input.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Max Concurrency (Threads) ")
            .style(conc_style),
    );
    frame.render_widget(p_conc, chunks[0]);

    let p_timeout = Paragraph::new(app.timeout_input.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Probe Timeout (Seconds) ")
            .style(timeout_style),
    );
    frame.render_widget(p_timeout, chunks[1]);

    let p_retries = Paragraph::new(app.retries_input.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" UDP Probe Retries ")
            .style(retries_style),
    );
    frame.render_widget(p_retries, chunks[2]);

    let help_text = vec![
        Line::from(Span::styled(
            "Scanner Settings Instructions:",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from("• Use UP/DOWN arrows to navigate between setting fields."),
        Line::from("• Type directly to edit max concurrency, timeout or retries per probe."),
        Line::from(vec![
            Span::raw("• PHP2Shell Audit (80/443): "),
            if app.check_php {
                Span::styled(
                    "ENABLED (Press 'P' to toggle)",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    "DISABLED (Press 'P' to toggle)",
                    Style::default().fg(Color::DarkGray),
                )
            },
        ]),
        Line::from("• Database Path: ")
            + Span::styled(&app.db_path, Style::default().fg(Color::Cyan)),
    ];
    let p_help = Paragraph::new(help_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Global Configuration "),
    );
    frame.render_widget(p_help, chunks[3]);
}
