//! Agent configuration management

//! The agent is a sidecar with its own lifecycle, so its configuration is defined here
//! rather than shared with the server. Previously these were type aliases onto the
//! server's config crate — including `MonitoringConfig = CoreConfig`, which handed the
//! agent the *entire* server configuration surface, most of it meaningless to a sidecar.

use secreton_domain::SecretonError;
use serde::{Deserialize, Serialize};

/// Main agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Unique agent identifier
    pub agent_id: String,

    /// Agent name/description
    pub name: String,

    /// Monitoring configuration
    pub monitoring: MonitoringConfig,

    /// Alerting configuration
    pub alerting: AlertingConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// Health checking configuration
    pub health: HealthConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Metrics configuration
    pub metrics: MetricsConfig,

    /// Vault/Secreton connection configuration
    #[serde(default)]
    pub vault: Option<VaultConfig>,

    /// Template rendering configuration
    #[serde(default)]
    pub templates: Vec<TemplateConfig>,
}

/// Vault/Secreton connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Secreton server URL
    pub server_url: String,

    /// Authentication token (optional, can be loaded from file/env)
    pub token: Option<String>,

    /// Path to token file (like ~/.secreton-token)
    pub token_file: Option<String>,
}

/// Template rendering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    /// Source template file path
    pub source: String,

    /// Destination file path
    pub destination: String,

    /// Optional command to run after rendering (e.g. reload service)
    pub command: Option<String>,

    /// Refresh interval in seconds (default: 300)
    #[serde(default = "default_template_interval")]
    pub refresh_interval_seconds: u64,
}

fn default_template_interval() -> u64 {
    300
}

/// Health checking configuration (agent-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Health check interval in seconds
    pub check_interval_seconds: u64,

    /// Enable agent health checks
    pub agent_enabled: bool,

    /// Health check timeout in seconds
    pub timeout_seconds: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval_seconds: 60,
            agent_enabled: true,
            timeout_seconds: 30,
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: uuid::Uuid::new_v4().to_string(),
            name: "Secreton Security Agent".to_string(),
            monitoring: MonitoringConfig::default(),
            alerting: AlertingConfig::default(),
            security: SecurityConfig::default(),
            health: HealthConfig::default(),
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            vault: None,
            templates: Vec::new(),
        }
    }
}

/// What the agent watches on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitoringConfig {
    pub enabled: bool,
    /// Seconds between samples.
    pub interval_seconds: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 60,
        }
    }
}

/// Where the agent sends alerts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertingConfig {
    pub enabled: bool,
    /// Webhook to POST alerts to. No credentials are read from configuration; put a
    /// token in the URL's own auth mechanism or in the environment.
    pub webhook_url: Option<String>,
}

/// Agent-side security posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Verify the server's TLS certificate. Turning this off is a downgrade to an
    /// unauthenticated channel and is never appropriate outside a local test.
    pub verify_tls: bool,
    /// Refuse to write a rendered template to a world-readable path.
    pub strict_file_permissions: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            verify_tls: true,
            strict_file_permissions: true,
        }
    }
}

/// Prometheus exposition from the agent itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub prometheus_port: u16,
    pub collection_interval_seconds: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prometheus_port: 9100,
            collection_interval_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    /// Emit JSON rather than human-readable lines.
    pub json: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json: false,
        }
    }
}

impl AgentConfig {
    /// Load configuration from environment variables
    pub async fn load_from_env() -> Result<Self, SecretonError> {
        let mut config = AgentConfig::default();

        // Override with environment variables
        if let Ok(agent_id) = std::env::var("SECRETON_AGENT_ID") {
            config.agent_id = agent_id;
        }

        if let Ok(name) = std::env::var("SECRETON_AGENT_NAME") {
            config.name = name;
        }

        if let Ok(log_level) = std::env::var("SECRETON_LOG_LEVEL") {
            config.logging.level = log_level;
        }

        Ok(config)
    }

    /// Load configuration from file
    pub async fn load_from_file(path: &str) -> Result<Self, SecretonError> {
        let content = std::fs::read_to_string(path)?;
        let config: AgentConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Convenience method to load config - tries file first, then env
    pub async fn load() -> Result<Self, SecretonError> {
        // Try to load from common config file locations
        let config_paths = [
            "agent.toml",
            "config/agent.toml",
            "/etc/secreton/agent.toml",
        ];

        for path in &config_paths {
            if std::path::Path::new(path).exists() {
                return Self::load_from_file(path).await;
            }
        }

        // Fall back to environment variables
        Self::load_from_env().await
    }

    /// Get metrics port (convenience method)
    pub fn metrics_port(&self) -> u16 {
        self.metrics.prometheus_port
    }

    /// Get collection interval (convenience method)
    pub fn collection_interval(&self) -> u64 {
        self.metrics.collection_interval_seconds
    }

    /// Get report interval (convenience method) - alias for collection_interval
    pub fn report_interval(&self) -> u64 {
        self.collection_interval()
    }
}


impl AgentConfig {
    /// Reject a configuration that would make the agent unsafe or useless.
    pub fn validate(&self) -> Result<(), SecretonError> {
        if let Some(vault) = &self.vault {
            if vault.server_url.is_empty() {
                return Err(SecretonError::Configuration {
                    message: "vault.server_url cannot be empty".into(),
                });
            }
            // Refusing TLS verification against a non-local server means the agent will
            // hand its token to anything that answers.
            if !self.security.verify_tls && !is_loopback(&vault.server_url) {
                return Err(SecretonError::Configuration {
                    message: format!(
                        "security.verify_tls is disabled for a non-local server ({}). \
                         That sends the agent's token to any host that answers.",
                        vault.server_url
                    ),
                });
            }
        }

        for template in &self.templates {
            if template.refresh_interval_seconds == 0 {
                return Err(SecretonError::Configuration {
                    message: format!(
                        "templates[{}].refresh_interval_seconds is 0, which would spin \
                         the render loop without pausing",
                        template.source
                    ),
                });
            }
        }
        Ok(())
    }
}

fn is_loopback(url: &str) -> bool {
    url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
        || url.starts_with("http://[::1]")
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    fn with_vault(url: &str) -> AgentConfig {
        AgentConfig {
            vault: Some(VaultConfig {
                server_url: url.to_string(),
                token: None,
                token_file: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn the_default_configuration_is_valid() {
        assert!(AgentConfig::default().validate().is_ok());
    }

    #[test]
    fn disabling_tls_verification_against_a_remote_server_is_rejected() {
        let mut config = with_vault("https://secreton.example.com");
        config.security.verify_tls = false;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("verify_tls"), "{err}");
    }

    #[test]
    fn disabling_tls_verification_is_allowed_against_loopback_only() {
        let mut config = with_vault("http://127.0.0.1:3000");
        config.security.verify_tls = false;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_zero_refresh_interval_is_rejected() {
        let mut config = AgentConfig::default();
        config.templates.push(TemplateConfig {
            source: "app.tmpl".into(),
            destination: "/etc/app.conf".into(),
            command: None,
            refresh_interval_seconds: 0,
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_empty_server_url_is_rejected() {
        assert!(with_vault("").validate().is_err());
    }
}
