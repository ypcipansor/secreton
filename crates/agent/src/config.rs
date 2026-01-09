//! Agent configuration management

use secreton_config::{AlertingConfig, LoggingConfig, MetricsConfig, SecurityConfig};
use secreton_errors::SecretonError;
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

/// Monitoring configuration
pub type MonitoringConfig = secreton_config::CoreConfig;

/// Alert severity thresholds
pub type SeverityThresholds = secreton_config::CoreConfig;

/// Email alert configuration
pub type EmailConfig = secreton_config::EmailConfig;

/// SMS alert configuration
pub type SmsConfig = secreton_config::SmsConfig;

/// Webhook alert configuration
pub type WebhookConfig = secreton_config::WebhookConfig;

/// Slack alert configuration
pub type SlackConfig = secreton_config::SlackConfig;

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
        let content = std::fs::read_to_string(path).map_err(secreton_core::CoreError::Io)?;

        let config: AgentConfig =
            toml::from_str(&content).map_err(|e| secreton_core::CoreError::Configuration {
                message: format!("Failed to parse config: {}", e),
            })?;

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
