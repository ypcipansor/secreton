//! Agent configuration management

use serde::{Deserialize, Serialize};
use std::time::Duration;
use brankas_core::CoreResult;

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
    
    /// Metrics configuration
    pub metrics: MetricsConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: uuid::Uuid::new_v4().to_string(),
            name: "Brankas Security Agent".to_string(),
            monitoring: MonitoringConfig::default(),
            alerting: AlertingConfig::default(),
            security: SecurityConfig::default(),
            health: HealthConfig::default(),
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Check interval in seconds
    pub check_interval_seconds: u64,
    
    /// Enable file system monitoring
    pub filesystem_enabled: bool,
    
    /// Enable network monitoring
    pub network_enabled: bool,
    
    /// Enable process monitoring
    pub process_enabled: bool,
    
    /// Enable log file monitoring
    pub logs_enabled: bool,
    
    /// Maximum events to buffer
    pub max_events_buffer: usize,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            check_interval_seconds: 30,
            filesystem_enabled: true,
            network_enabled: true,
            process_enabled: true,
            logs_enabled: true,
            max_events_buffer: 1000,
        }
    }
}

/// Alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    /// Processing interval in seconds
    pub processing_interval_seconds: u64,
    
    /// Enable email alerts
    pub email_enabled: bool,
    
    /// Enable webhook alerts
    pub webhook_enabled: bool,
    
    /// Enable Slack alerts
    pub slack_enabled: bool,
    
    /// Maximum alerts per minute
    pub rate_limit: u32,
    
    /// Alert severity thresholds
    pub severity_thresholds: SeverityThresholds,
    
    /// Email settings
    pub email: EmailConfig,
    
    /// Webhook settings
    pub webhook: WebhookConfig,
    
    /// Slack settings
    pub slack: SlackConfig,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            processing_interval_seconds: 10,
            email_enabled: false,
            webhook_enabled: false,
            slack_enabled: false,
            rate_limit: 60,
            severity_thresholds: SeverityThresholds::default(),
            email: EmailConfig::default(),
            webhook: WebhookConfig::default(),
            slack: SlackConfig::default(),
        }
    }
}

/// Alert severity thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityThresholds {
    /// CPU usage threshold for warning (percentage)
    pub cpu_warning_threshold: f64,
    
    /// CPU usage threshold for critical (percentage)
    pub cpu_critical_threshold: f64,
    
    /// Memory usage threshold for warning (percentage)
    pub memory_warning_threshold: f64,
    
    /// Memory usage threshold for critical (percentage)
    pub memory_critical_threshold: f64,
    
    /// Disk usage threshold for warning (percentage)
    pub disk_warning_threshold: f64,
    
    /// Disk usage threshold for critical (percentage)
    pub disk_critical_threshold: f64,
    
    /// Failed login attempts threshold
    pub failed_login_threshold: u32,
    
    /// Suspicious activity threshold
    pub suspicious_activity_threshold: u32,
}

impl Default for SeverityThresholds {
    fn default() -> Self {
        Self {
            cpu_warning_threshold: 80.0,
            cpu_critical_threshold: 95.0,
            memory_warning_threshold: 85.0,
            memory_critical_threshold: 95.0,
            disk_warning_threshold: 90.0,
            disk_critical_threshold: 98.0,
            failed_login_threshold: 5,
            suspicious_activity_threshold: 3,
        }
    }
}

/// Email alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server
    pub smtp_server: String,
    
    /// SMTP port
    pub smtp_port: u16,
    
    /// Username
    pub username: String,
    
    /// Password
    pub password: String,
    
    /// From address
    pub from_address: String,
    
    /// To addresses
    pub to_addresses: Vec<String>,
    
    /// Use TLS
    pub use_tls: bool,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            smtp_server: "localhost".to_string(),
            smtp_port: 587,
            username: "".to_string(),
            password: "".to_string(),
            from_address: "secreton-agent@localhost".to_string(),
            to_addresses: Vec::new(),
            use_tls: true,
        }
    }
}

/// Webhook alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,
    
    /// HTTP method
    pub method: String,
    
    /// Headers to include
    pub headers: std::collections::HashMap<String, String>,
    
    /// Request timeout in seconds
    pub timeout_seconds: u64,
    
    /// Retry attempts
    pub retry_attempts: u32,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: "".to_string(),
            method: "POST".to_string(),
            headers: std::collections::HashMap::new(),
            timeout_seconds: 30,
            retry_attempts: 3,
        }
    }
}

/// Slack alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    /// Slack webhook URL
    pub webhook_url: String,
    
    /// Channel to post to
    pub channel: String,
    
    /// Username for the bot
    pub username: String,
    
    /// Icon emoji for the bot
    pub icon_emoji: String,
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            webhook_url: "".to_string(),
            channel: "#security-alerts".to_string(),
            username: "Brankas Agent".to_string(),
            icon_emoji: ":shield:".to_string(),
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Security scan interval in seconds
    pub scan_interval_seconds: u64,
    
    /// Enable intrusion detection
    pub intrusion_detection_enabled: bool,
    
    /// Enable malware scanning
    pub malware_scan_enabled: bool,
    
    /// Enable vulnerability scanning
    pub vulnerability_scan_enabled: bool,
    
    /// Enable compliance checking
    pub compliance_check_enabled: bool,
    
    /// Quarantine suspicious files
    pub auto_quarantine: bool,
    
    /// Block suspicious IPs
    pub auto_block_ips: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            scan_interval_seconds: 300, // 5 minutes
            intrusion_detection_enabled: true,
            malware_scan_enabled: true,
            vulnerability_scan_enabled: true,
            compliance_check_enabled: true,
            auto_quarantine: false, // Require manual confirmation
            auto_block_ips: false,  // Require manual confirmation
        }
    }
}

/// Health checking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Health check interval in seconds
    pub check_interval_seconds: u64,
    
    /// Enable database health checks
    pub database_enabled: bool,
    
    /// Enable API health checks
    pub api_enabled: bool,
    
    /// Enable external service health checks
    pub external_services_enabled: bool,
    
    /// Health check timeout in seconds
    pub timeout_seconds: u64,
    
    /// External services to check
    pub external_services: Vec<ExternalServiceConfig>,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval_seconds: 60,
            database_enabled: true,
            api_enabled: true,
            external_services_enabled: true,
            timeout_seconds: 30,
            external_services: Vec::new(),
        }
    }
}

/// External service health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalServiceConfig {
    /// Service name
    pub name: String,
    
    /// Service URL
    pub url: String,
    
    /// Expected HTTP status code
    pub expected_status: u16,
    
    /// Request timeout in seconds
    pub timeout_seconds: u64,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Metrics collection interval in seconds
    pub collection_interval_seconds: u64,
    
    /// Enable Prometheus metrics
    pub prometheus_enabled: bool,
    
    /// Prometheus metrics port
    pub prometheus_port: u16,
    
    /// Enable StatsD metrics
    pub statsd_enabled: bool,
    
    /// StatsD server address
    pub statsd_address: String,
    
    /// Metrics retention period in seconds
    pub retention_seconds: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            collection_interval_seconds: 60,
            prometheus_enabled: true,
            prometheus_port: 9090,
            statsd_enabled: false,
            statsd_address: "localhost:8125".to_string(),
            retention_seconds: 86400 * 7, // 7 days
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    
    /// Log format (json or text)
    pub format: String,
    
    /// Enable file logging
    pub file_enabled: bool,
    
    /// Log file path
    pub file_path: String,
    
    /// Maximum log file size in MB
    pub max_file_size_mb: u64,
    
    /// Number of log files to retain
    pub max_files: u32,
    
    /// Enable structured logging
    pub structured: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "text".to_string(),
            file_enabled: true,
            file_path: "/var/log/secreton-agent.log".to_string(),
            max_file_size_mb: 100,
            max_files: 10,
            structured: true,
        }
    }
}

impl AgentConfig {
    /// Load configuration from environment variables
    pub async fn load_from_env() -> CoreResult<Self> {
        let mut config = AgentConfig::default();
        
        // Override with environment variables
        if let Ok(agent_id) = std::env::var("BRANKAS_AGENT_ID") {
            config.agent_id = agent_id;
        }
        
        if let Ok(name) = std::env::var("BRANKAS_AGENT_NAME") {
            config.name = name;
        }
        
        if let Ok(interval) = std::env::var("BRANKAS_MONITOR_INTERVAL") {
            if let Ok(interval_val) = interval.parse::<u64>() {
                config.monitoring.check_interval_seconds = interval_val;
            }
        }
        
        if let Ok(log_level) = std::env::var("BRANKAS_LOG_LEVEL") {
            config.logging.level = log_level;
        }
        
        Ok(config)
    }
    
    /// Load configuration from file
    pub async fn load_from_file(path: &str) -> CoreResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| brankas_core::CoreError::Io(e))?;
            
        let config: AgentConfig = toml::from_str(&content)
            .map_err(|e| brankas_core::CoreError::configuration(format!("Failed to parse config: {}", e)))?;
            
        Ok(config)
    }
    
    /// Save configuration to file
    pub async fn save_to_file(&self, path: &str) -> CoreResult<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| brankas_core::CoreError::configuration(format!("Failed to serialize config: {}", e)))?;
            
        std::fs::write(path, content)
            .map_err(|e| brankas_core::CoreError::Io(e))?;
            
        Ok(())
    }
    
    /// Validate configuration
    pub fn validate(&self) -> CoreResult<()> {
        if self.agent_id.is_empty() {
            return Err(brankas_core::CoreError::configuration("Agent ID cannot be empty"));
        }
        
        if self.monitoring.check_interval_seconds == 0 {
            return Err(brankas_core::CoreError::configuration("Monitoring interval must be greater than 0"));
        }
        
        if self.alerting.processing_interval_seconds == 0 {
            return Err(brankas_core::CoreError::configuration("Alerting interval must be greater than 0"));
        }
        
        if self.security.scan_interval_seconds == 0 {
            return Err(brankas_core::CoreError::configuration("Security scan interval must be greater than 0"));
        }
        
        Ok(())
    }
}
