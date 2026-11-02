//! CIDR scan tab rendering: registered subnet prefixes table
use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Row, Table},
    Frame,
};

pub fn render_cidr_scan(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["ID", "CIDR Prefix", "Description", "Status"]
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

    let rows = app.prefixes.iter().map(|p| {
        let status = if p.enabled { "Enabled" } else { "Disabled" };
        let style = if p.enabled {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        Row::new(vec![
            Span::raw(p.id.to_string()),
            Span::styled(
                p.prefix.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
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
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Registered Subnet Prefixes (Database) "),
    );

    frame.render_widget(table, area);
}
