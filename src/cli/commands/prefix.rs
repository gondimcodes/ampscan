//! CLI prefix command implementation
use crate::cli::args::PrefixCommands;
use crate::db::{prefix_repo, DbConn};
use anyhow::Result;
use colored::Colorize;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};

pub fn cmd_prefix(db: &DbConn, cmd: &PrefixCommands) -> Result<()> {
    match cmd {
        PrefixCommands::List => {
            let prefixes = prefix_repo::list_prefixes(db)?;
            if prefixes.is_empty() {
                println!("No registered prefixes. Use 'ampscan prefix add' to add one.");
                return Ok(());
            }

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    Cell::new("ID"),
                    Cell::new("Prefix"),
                    Cell::new("IPv"),
                    Cell::new("Enabled"),
                    Cell::new("Description"),
                ]);

            for p in &prefixes {
                let status = if p.enabled {
                    Cell::new("✓").fg(Color::Green)
                } else {
                    Cell::new("✗").fg(Color::Red)
                };
                table.add_row(vec![
                    Cell::new(p.id),
                    Cell::new(&p.prefix),
                    Cell::new(format!("v{}", p.ip_version)),
                    status,
                    Cell::new(&p.description),
                ]);
            }
            println!("{}", table);
        }

        PrefixCommands::Add {
            prefix,
            description,
        } => {
            let id = prefix_repo::insert_prefix(db, prefix, description)?;
            println!("{} Prefix {} added with ID {}", "✓".green(), prefix, id);
        }

        PrefixCommands::Edit {
            id,
            prefix,
            description,
        } => {
            prefix_repo::update_prefix(db, *id, prefix.as_deref(), description.as_deref())?;
            println!("{} Prefix ID {} updated", "✓".green(), id);
        }

        PrefixCommands::Remove { id } => {
            prefix_repo::delete_prefix(db, *id)?;
            println!("{} Prefix ID {} removed", "✓".green(), id);
        }

        PrefixCommands::Enable { id } => {
            prefix_repo::toggle_prefix(db, *id, true)?;
            println!("{} Prefix ID {} enabled", "✓".green(), id);
        }

        PrefixCommands::Disable { id } => {
            prefix_repo::toggle_prefix(db, *id, false)?;
            println!("{} Prefix ID {} disabled", "✓".green(), id);
        }
    }
    Ok(())
}
