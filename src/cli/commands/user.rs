//! CLI user command implementation
use crate::auth;
use crate::cli::args::UserCommands;
use crate::db::{user_repo, DbConn};
use anyhow::Result;
use colored::Colorize;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Table};

pub fn cmd_user(db: &DbConn, cmd: &UserCommands) -> Result<()> {
    match cmd {
        UserCommands::List => {
            let users = user_repo::list_users(db)?;
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    Cell::new("ID"),
                    Cell::new("Username"),
                    Cell::new("Created at"),
                ]);

            for u in &users {
                table.add_row(vec![
                    Cell::new(u.id),
                    Cell::new(&u.username),
                    Cell::new(&u.created_at),
                ]);
            }
            println!("{}", table);
        }

        UserCommands::Add { username } => {
            let password = auth::prompt_new_password()?;
            let id = user_repo::create_user(db, username, &password)?;
            println!("{} User '{}' created with ID {}", "✓".green(), username, id);
        }

        UserCommands::ChangePassword { username } => {
            println!("Changing password for '{}':", username);
            let new_password = auth::prompt_new_password()?;
            user_repo::change_password(db, username, &new_password)?;
            println!("{} Password successfully changed", "✓".green());
        }

        UserCommands::Remove { id } => {
            user_repo::delete_user(db, *id)?;
            println!("{} User ID {} removed", "✓".green(), id);
        }
    }
    Ok(())
}
