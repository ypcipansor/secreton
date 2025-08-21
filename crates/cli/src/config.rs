use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub server_url: String,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8200".to_string(),
        }
    }
}

impl CliConfig {
    pub async fn load_from_file(path: &str) -> Result<Self> {
        let content = tokio::fs::read_to_string(path).await?;
        let config: CliConfig = toml::from_str(&content)?;
        Ok(config)
    }
}
