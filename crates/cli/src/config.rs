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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_server_url() {
        let config = CliConfig::default();
        assert_eq!(config.server_url, "http://127.0.0.1:8200");
    }

    #[tokio::test]
    async fn test_load_from_file() {
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        tokio::fs::write(tmp.path(), "server_url = \"https://vault.example.com\"")
            .await
            .expect("write config");

        let loaded = CliConfig::load_from_file(tmp.path().to_str().unwrap())
            .await
            .expect("load config");
        assert_eq!(loaded.server_url, "https://vault.example.com");
    }
}
