//! CLI port command implementation
use crate::cli::args::PortCommands;
use crate::db::{port_repo, DbConn};
use anyhow::Result;
use colored::Colorize;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};

pub fn cmd_port(db: &DbConn, cmd: &PortCommands) -> Result<()> {
    match cmd {
        PortCommands::List => {
            let ports = port_repo::list_ports(db)?;
            if ports.is_empty() {
                println!("No registered ports.");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    Cell::new("ID"),
                    Cell::new("Port"),
                    Cell::new("Proto"),
                    Cell::new("Name"),
                    Cell::new("Probe"),
                    Cell::new("Enabled"),
                    Cell::new("Description"),
                ]);

            for p in &ports {
                let status = if p.enabled {
                    Cell::new("✓").fg(Color::Green)
                } else {
                    Cell::new("✗").fg(Color::Red)
                };
                table.add_row(vec![
                    Cell::new(p.id),
                    Cell::new(p.port),
                    Cell::new(&p.protocol),
                    Cell::new(&p.name),
                    Cell::new(&p.probe_type),
                    status,
                    Cell::new(&p.description),
                ]);
            }
            println!("{}", table);
            println!("Total: {} ports", ports.len());
        }

        PortCommands::Enable { id } => {
            port_repo::toggle_port(db, *id, true)?;
            println!("{} Port ID {} enabled", "✓".green(), id);
        }

        PortCommands::Disable { id } => {
            port_repo::toggle_port(db, *id, false)?;
            println!("{} Port ID {} disabled", "✓".green(), id);
        }
    }
    Ok(())
}
