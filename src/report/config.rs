//! Report configuration structures and loader
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyConfig {
    pub name: Option<String>,
    pub cnpj: Option<String>,
    pub address: Option<String>,
    pub logo_path: Option<String>,
    pub logo_scale: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub company: Option<CompanyConfig>,
}

impl AppConfig {
    pub fn load() -> Self {
        find_config_file()
            .and_then(|path| std::fs::read_to_string(&path).ok())
            .and_then(|content| toml::from_str(&content).ok())
            .unwrap_or_default()
    }
}

/// Search for `config.toml` in priority order:
/// 1. Directory containing the running executable (typical install layout)
/// 2. Current working directory (development / explicit run-from-dir)
///
/// Returns `None` if neither location has the file, suppressing any error silently
/// (missing config is a valid state — the tool works without it).
fn find_config_file() -> Option<std::path::PathBuf> {
    // 1. Alongside the binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let candidate = exe_dir.join("config.toml");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    // 2. Current working directory
    let cwd = std::path::PathBuf::from("config.toml");
    if cwd.exists() {
        return Some(cwd);
    }
    None
}
