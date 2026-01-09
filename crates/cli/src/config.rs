use secreton_config::Config;
use secreton_errors::{Result as SecretonResult, SecretonError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub server_url: String,
    pub token: Option<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8200".to_string(),
            token: None,
        }
    }
}

impl Config for CliConfig {
    fn validate(&self) -> SecretonResult<()> {
        if self.server_url.is_empty() {
            return Err(SecretonError::Configuration {
                message: "server_url cannot be empty".to_string(),
            });
        }
        // Basic URL validation
        if !self.server_url.starts_with("http://") && !self.server_url.starts_with("https://") {
            return Err(SecretonError::Configuration {
                message: "server_url must start with http:// or https://".to_string(),
            });
        }
        Ok(())
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
        tokio::fs::write(tmp.path(), "server_url = \"https://secreton.example.com\"")
            .await
            .expect("write config");

        let loaded = CliConfig::load_from_file(tmp.path()).expect("load config");
        assert_eq!(loaded.server_url, "https://secreton.example.com");
    }
}
