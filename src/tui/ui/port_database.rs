//! Port database tab rendering: registered amplification signatures table
use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Row, Table},
    Frame,
};

pub fn render_port_database(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Port", "Proto", "Name", "Probe Type", "Description"]
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
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Registered Amplification Signatures "),
    );

    frame.render_widget(table, area);
}
