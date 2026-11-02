//! TUI Layout and UI Orchestration
//!
//! Renders the overall TUI frame, tabs, footer status bar and dispatches
//! tab contents to modular view components.

pub mod cidr_scan;
pub mod dashboard;
pub mod port_database;
pub mod results;
pub mod settings;
pub mod single_target;

pub use cidr_scan::render_cidr_scan;
pub use dashboard::render_dashboard;
pub use port_database::render_port_database;
pub use results::render_results_viewer;
pub use settings::render_settings;
pub use single_target::render_single_target;

use crate::tui::app::{App, Tab};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
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

    let selected_index = Tab::ALL
        .iter()
        .position(|t| t == &app.active_tab)
        .unwrap_or(0);

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(concat!(" ampscan v", env!("CARGO_PKG_VERSION"), " "))
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

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let default_status = if app.single_ip_input.trim().is_empty() {
        "Press [F] for Full Scan | [S] for Single Target Scan"
    } else {
        "Press [S] to scan target IP | [F] for Full CIDR Scan"
    };

    let status = app.status_message.as_deref().unwrap_or(default_status);

    let footer_text = vec![Line::from(vec![
        Span::styled(
            " HOTKEYS: ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(
            "[Tab] Switch View  |  [F] Full Scan  |  [S] Single Target  |  [Q] Quit    --    ",
        ),
        Span::styled(status, Style::default().fg(Color::Green)),
    ])];

    let p = Paragraph::new(footer_text).block(Block::default().borders(Borders::ALL));
    frame.render_widget(p, area);
}
