use crate::tui::app::{App, Tab};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use std::io;
use std::time::Duration;

pub enum UserAction {
    None,
    StartSingleScan,
    StartFullScan,
}

pub fn handle_events(app: &mut App) -> io::Result<UserAction> {
    if event::poll(Duration::from_millis(50))? {
        if let Event::Key(key) = event::read()? {
            if key.kind == event::KeyEventKind::Press {
                // Handle text input on SingleTarget and Settings tabs
                if app.active_tab == Tab::SingleTarget {
                    match key.code {
                        KeyCode::Char('s') | KeyCode::Char('S') => {
                            return Ok(UserAction::StartSingleScan);
                        }
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                            app.should_quit = true;
                            return Ok(UserAction::None);
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() || c == '.' || c == ':' || c == '/' || c.is_ascii_hexdigit() => {
                            app.single_ip_input.push(c);
                            return Ok(UserAction::None);
                        }
                        KeyCode::Backspace => {
                            app.single_ip_input.pop();
                            return Ok(UserAction::None);
                        }
                        KeyCode::Enter => {
                            return Ok(UserAction::StartSingleScan);
                        }
                        _ => {}
                    }
                } else if app.active_tab == Tab::Settings {
                    match key.code {
                        KeyCode::Char(c) => {
                            if c.is_ascii_digit() {
                                if app.focused_field == 0 {
                                    let candidate = format!("{}{}", app.concurrency_input, c);
                                    if let Ok(val) = candidate.parse::<usize>() {
                                        if val <= 10000 {
                                            app.concurrency_input = candidate;
                                        }
                                    }
                                } else if app.focused_field == 1 {
                                    let candidate = format!("{}{}", app.timeout_input, c);
                                    if let Ok(val) = candidate.parse::<u64>() {
                                        if val <= 60 {
                                            app.timeout_input = candidate;
                                        }
                                    }
                                } else if app.focused_field == 2 {
                                    let candidate = format!("{}{}", app.retries_input, c);
                                    if let Ok(val) = candidate.parse::<usize>() {
                                        if val <= 10 {
                                            app.retries_input = candidate;
                                        }
                                    }
                                }
                            }
                            return Ok(UserAction::None);
                        }
                        KeyCode::Backspace => {
                            if app.focused_field == 0 {
                                app.concurrency_input.pop();
                            } else if app.focused_field == 1 {
                                app.timeout_input.pop();
                            } else if app.focused_field == 2 {
                                app.retries_input.pop();
                            }
                            return Ok(UserAction::None);
                        }
                        KeyCode::Down => {
                            app.focused_field = (app.focused_field + 1) % 3;
                            return Ok(UserAction::None);
                        }
                        KeyCode::Up => {
                            app.focused_field = if app.focused_field == 0 { 2 } else { app.focused_field - 1 };
                            return Ok(UserAction::None);
                        }
                        _ => {}
                    }
                }

                match key.code {
                    // Quit application
                    KeyCode::Char('q') | KeyCode::Esc => {
                        app.should_quit = true;
                    }
                    // Tab navigation
                    KeyCode::Tab => {
                        if key.modifiers.contains(KeyModifiers::SHIFT) {
                            app.prev_tab();
                        } else {
                            app.next_tab();
                        }
                    }
                    KeyCode::Right => app.next_tab(),
                    KeyCode::Left => app.prev_tab(),

                    // Global Actions
                    KeyCode::Char('f') | KeyCode::Char('F') => return Ok(UserAction::StartFullScan),
                    KeyCode::Char('s') | KeyCode::Char('S') => return Ok(UserAction::StartSingleScan),

                    // List navigation & Scrolling
                    KeyCode::Down => {
                        let total = app.get_filtered_findings_count();
                        if total > 0 && app.selected_log_index < total.saturating_sub(1) {
                            app.selected_log_index += 1;
                        }
                    }
                    KeyCode::Up => {
                        if app.selected_log_index > 0 {
                            app.selected_log_index -= 1;
                        }
                    }
                    KeyCode::PageDown => {
                        let total = app.get_filtered_findings_count();
                        if total > 0 {
                            app.selected_log_index = (app.selected_log_index + 15).min(total.saturating_sub(1));
                        }
                    }
                    KeyCode::PageUp => {
                        app.selected_log_index = app.selected_log_index.saturating_sub(15);
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(UserAction::None)
}
