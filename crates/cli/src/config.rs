use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub server_url: String,
    pub auth_token: Option<String>,
    pub config_dir: PathBuf,
    pub log_level: String,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:3000".to_string(),
            auth_token: None,
            config_dir: dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("brankas"),
            log_level: "info".to_string(),
        }
    }
}

impl CliConfig {
    pub fn load() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("brankas");

        let config_file = config_dir.join("config.toml");
        
        if config_file.exists() {
            let content = std::fs::read_to_string(&config_file)?;
            let config: CliConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        let config_file = self.config_dir.join("config.toml");
        let content = toml::to_string_pretty(self)?;
        std::fs::write(config_file, content)?;
        Ok(())
    }
}
