//! CLI configuration.

use std::path::Path;

use secreton_domain::{Result as SecretonResult, SecretonError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub server_url: String,
    /// Bearer token. Written to the config file only if the user asks; otherwise it is
    /// read from `SECRETON_TOKEN` so a token need not sit on disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            // The server listens on 3000 now that one process serves the UI, the REST API
            // and gRPC together. This used to default to 8200, which was never a port
            // this project listened on.
            server_url: "http://127.0.0.1:3000/api/v1".to_string(),
            token: None,
        }
    }
}

impl CliConfig {
    /// Read configuration from `path`, then let the environment override it.
    pub fn load_from_file(path: impl AsRef<Path>) -> SecretonResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&content)?;
        config.apply_environment();
        config.validate()?;
        Ok(config)
    }

    /// Defaults plus environment, for when no file exists.
    pub fn from_environment() -> Self {
        let mut config = Self::default();
        config.apply_environment();
        config
    }

    fn apply_environment(&mut self) {
        if let Ok(url) = std::env::var("SECRETON_ADDR") {
            self.server_url = url;
        }
        // Preferred over storing the token in the file: an environment variable does not
        // survive on disk with the wrong permissions.
        if let Ok(token) = std::env::var("SECRETON_TOKEN") {
            self.token = Some(token);
        }
    }

    pub fn validate(&self) -> SecretonResult<()> {
        if self.server_url.is_empty() {
            return Err(SecretonError::Configuration {
                message: "server_url cannot be empty".to_string(),
            });
        }
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

    #[test]
    fn the_default_points_at_the_port_the_server_actually_listens_on() {
        assert!(CliConfig::default().server_url.contains(":3000"));
        assert!(CliConfig::default().validate().is_ok());
    }

    #[test]
    fn a_url_without_a_scheme_is_rejected() {
        let config = CliConfig {
            server_url: "secreton.example.com".into(),
            token: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_empty_url_is_rejected() {
        let config = CliConfig {
            server_url: String::new(),
            token: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_token_is_omitted_from_the_serialised_file_when_absent() {
        let toml = toml::to_string(&CliConfig::default()).expect("serialise");
        assert!(
            !toml.contains("token"),
            "an absent token must not be written to disk as an empty value: {toml}"
        );
    }

    #[test]
    fn loading_a_file_reads_the_url() {
        let dir = std::env::temp_dir().join("secreton-cli-config-test");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("config.toml");
        std::fs::write(&path, r#"server_url = "https://secreton.example.com""#).expect("write");

        let loaded = CliConfig::load_from_file(&path).expect("load");
        assert_eq!(loaded.server_url, "https://secreton.example.com");
    }
}
