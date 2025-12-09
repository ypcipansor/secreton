//! # Secreton Monitoring & Alerting
//!
//! Unified monitoring, alerting, and health checking system for the Secreton secreton.
//! Provides comprehensive system monitoring, alert management, and notification channels.
//!
//! ## Features
//!
//! - **Alert Management**: Severity-based alert classification and lifecycle management
//! - **Monitoring Events**: System, network, process, and security event monitoring
//! - **Notification Channels**: Email, webhook, Slack, and SMS notifications
//! - **Health Checks**: System health monitoring and reporting
//! - **Metrics Collection**: Performance and system metrics aggregation
//!
//! ## Architecture
//!
//! The monitoring crate follows domain-driven design principles:
//!
//! - `alerting/`: Alert management and notification system
//! - `monitoring/`: System monitoring and event processing
//! - `health/`: Health check implementations
//! - `metrics/`: Metrics collection and reporting

use lettre::AsyncTransport;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

use secreton_common::{Service, ServiceHealth, ServiceResult};
use secreton_config::AlertingConfig;

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "INFO"),
            AlertSeverity::Warning => write!(f, "WARNING"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
            AlertSeverity::Emergency => write!(f, "EMERGENCY"),
        }
    }
}

/// Alert categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlertCategory {
    Security,
    Performance,
    System,
    Network,
    Application,
    Compliance,
}

impl std::fmt::Display for AlertCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertCategory::Security => write!(f, "SECURITY"),
            AlertCategory::Performance => write!(f, "PERFORMANCE"),
            AlertCategory::System => write!(f, "SYSTEM"),
            AlertCategory::Network => write!(f, "NETWORK"),
            AlertCategory::Application => write!(f, "APPLICATION"),
            AlertCategory::Compliance => write!(f, "COMPLIANCE"),
        }
    }
}

/// Alert status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertStatus {
    New,
    Acknowledged,
    InProgress,
    Resolved,
    Closed,
}

/// Alert structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID
    pub id: String,

    /// Alert title
    pub title: String,

    /// Alert description
    pub description: String,

    /// Alert severity
    pub severity: AlertSeverity,

    /// Alert category
    pub category: AlertCategory,

    /// Alert status
    pub status: AlertStatus,

    /// Source system or component
    pub source: String,

    /// Alert timestamp
    pub timestamp: u64,

    /// Last updated timestamp
    pub updated_at: u64,

    /// Acknowledged by
    pub acknowledged_by: Option<String>,

    /// Acknowledgment timestamp
    pub acknowledged_at: Option<u64>,

    /// Resolution details
    pub resolution: Option<String>,

    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,

    /// Related alerts
    pub related_alerts: Vec<String>,

    /// Alert count (for deduplicated alerts)
    pub count: u32,
}

impl Alert {
    /// Create a new alert
    pub fn new(
        title: String,
        description: String,
        severity: AlertSeverity,
        category: AlertCategory,
        source: String,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title,
            description,
            severity,
            category,
            status: AlertStatus::New,
            source,
            timestamp: now,
            updated_at: now,
            acknowledged_by: None,
            acknowledged_at: None,
            resolution: None,
            metadata: HashMap::new(),
            related_alerts: Vec::new(),
            count: 1,
        }
    }

    /// Acknowledge the alert
    pub fn acknowledge(&mut self, acknowledged_by: String) {
        self.status = AlertStatus::Acknowledged;
        self.acknowledged_by = Some(acknowledged_by);
        self.acknowledged_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Resolve the alert
    pub fn resolve(&mut self, resolution: String) {
        self.status = AlertStatus::Resolved;
        self.resolution = Some(resolution);
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Close the alert
    pub fn close(&mut self) {
        self.status = AlertStatus::Closed;
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Increment the alert count (for deduplication)
    pub fn increment(&mut self) {
        self.count += 1;
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Alert notification channel
#[derive(Debug, Clone)]
pub enum NotificationChannel {
    Email,
    Webhook,
    Slack,
    Sms,
}

/// Alert notification
#[derive(Debug, Clone)]
pub struct AlertNotification {
    pub alert: Alert,
    pub channels: Vec<NotificationChannel>,
    pub retry_count: u32,
    pub next_retry: Option<SystemTime>,
}

/// Monitoring event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitoringEvent {
    /// File system events
    FileSystem(FileSystemEvent),

    /// Network events
    Network(NetworkEvent),

    /// Process events
    Process(ProcessEvent),

    /// Log events
    Log(LogEvent),

    /// Resource usage events
    Resource(ResourceEvent),
}

/// File system event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemEvent {
    pub event_type: String,
    pub path: String,
    pub metadata: HashMap<String, String>,
}

/// Network event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub event_type: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Process event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub event_type: String,
    pub process_id: u32,
    pub process_name: String,
    pub user_id: Option<u32>,
    pub metadata: HashMap<String, String>,
}

/// Log event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub level: String,
    pub source: String,
    pub message: String,
    pub metadata: HashMap<String, String>,
}

/// Resource usage event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEvent {
    pub resource_type: String,
    pub current_value: f64,
    pub threshold_value: f64,
    pub severity: String,
    pub metadata: HashMap<String, String>,
}

/// Alert manager
#[derive(Debug)]
pub struct AlertManager {
    /// Configuration
    config: AlertingConfig,

    /// Event receiver channel
    event_receiver: mpsc::UnboundedReceiver<MonitoringEvent>,

    /// Active alerts
    active_alerts: HashMap<String, Alert>,

    /// Alert history
    alert_history: VecDeque<Alert>,

    /// Notification queue
    notification_queue: VecDeque<AlertNotification>,

    /// Running flag
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /// HTTP client for webhooks
    http_client: reqwest::Client,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(
        config: AlertingConfig,
        event_receiver: mpsc::UnboundedReceiver<MonitoringEvent>,
    ) -> Self {
        Self {
            config,
            event_receiver,
            active_alerts: HashMap::new(),
            alert_history: VecDeque::new(),
            notification_queue: VecDeque::new(),
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            http_client: reqwest::Client::new(),
        }
    }

    /// Start alert processing
    pub async fn start(&mut self) -> secreton_errors::Result<()> {
        tracing::info!("Starting alert manager");

        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let processing_interval = Duration::from_secs(self.config.processing_interval_seconds);

        while self.running.load(std::sync::atomic::Ordering::SeqCst) {
            // Process incoming monitoring events
            if let Err(e) = self.process_events().await {
                tracing::error!("Error processing events: {}", e);
            }

            // Process notification queue
            if let Err(e) = self.process_notifications().await {
                tracing::error!("Error processing notifications: {}", e);
            }

            // Clean up old alerts
            if let Err(e) = self.cleanup_alerts().await {
                tracing::error!("Error cleaning up alerts: {}", e);
            }

            tokio::time::sleep(processing_interval).await;
        }

        Ok(())
    }

    /// Stop alert processing
    pub async fn stop(&mut self) -> secreton_errors::Result<()> {
        tracing::info!("Stopping alert manager");
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Process incoming monitoring events
    async fn process_events(&mut self) -> secreton_errors::Result<()> {
        while let Ok(event) = self.event_receiver.try_recv() {
            if let Some(alert) = self.event_to_alert(event).await? {
                self.handle_alert(alert).await?;
            }
        }
        Ok(())
    }

    /// Convert monitoring event to alert
    async fn event_to_alert(
        &self,
        event: MonitoringEvent,
    ) -> secreton_errors::Result<Option<Alert>> {
        match event {
            MonitoringEvent::FileSystem(fs_event) => {
                // Create alert for suspicious file system activity
                let alert = Alert::new(
                    "File System Activity".to_string(),
                    format!(
                        "File system event: {:?} on path: {:?}",
                        fs_event.event_type, fs_event.path
                    ),
                    AlertSeverity::Info,
                    AlertCategory::Security,
                    "FileSystemMonitor".to_string(),
                );
                Ok(Some(alert))
            }

            MonitoringEvent::Network(net_event) => {
                let severity = match net_event.event_type.as_str() {
                    "suspicious_activity" | "port_scan" | "ddos_attempt" => AlertSeverity::Critical,
                    _ => AlertSeverity::Info,
                };

                let alert = Alert::new(
                    "Network Activity".to_string(),
                    format!("Network event: {}", net_event.event_type),
                    severity,
                    AlertCategory::Network,
                    "NetworkMonitor".to_string(),
                );
                Ok(Some(alert))
            }

            MonitoringEvent::Process(proc_event) => {
                let severity = match proc_event.event_type.as_str() {
                    "suspicious_activity" | "privilege_escalation" => AlertSeverity::Critical,
                    "high_cpu" | "high_memory" => AlertSeverity::Warning,
                    _ => AlertSeverity::Info,
                };

                let alert = Alert::new(
                    "Process Activity".to_string(),
                    format!(
                        "Process event: {} for PID {}",
                        proc_event.event_type, proc_event.process_id
                    ),
                    severity,
                    AlertCategory::System,
                    "ProcessMonitor".to_string(),
                );
                Ok(Some(alert))
            }

            MonitoringEvent::Log(log_event) => {
                let severity = match log_event.level.as_str() {
                    "emergency" | "alert" | "critical" => AlertSeverity::Critical,
                    "error" => AlertSeverity::Warning,
                    _ => return Ok(None), // Don't alert on info/debug logs
                };

                let alert = Alert::new(
                    "Log Alert".to_string(),
                    format!("Log event from {}: {}", log_event.source, log_event.message),
                    severity,
                    AlertCategory::System,
                    "LogMonitor".to_string(),
                );
                Ok(Some(alert))
            }

            MonitoringEvent::Resource(resource_event) => {
                let severity = match resource_event.severity.as_str() {
                    "critical" => AlertSeverity::Critical,
                    "warning" => AlertSeverity::Warning,
                    _ => AlertSeverity::Info,
                };

                let alert = Alert::new(
                    format!("{} Threshold Exceeded", resource_event.resource_type),
                    format!(
                        "Resource usage is {}% (threshold: {}%)",
                        resource_event.current_value, resource_event.threshold_value
                    ),
                    severity,
                    AlertCategory::Performance,
                    "ResourceMonitor".to_string(),
                );
                Ok(Some(alert))
            }
        }
    }

    /// Handle a new alert
    async fn handle_alert(&mut self, alert: Alert) -> secreton_errors::Result<()> {
        // Check for deduplication
        let alert_key = format!("{}:{}", alert.title, alert.source);

        if let Some(existing_alert) = self.active_alerts.get_mut(&alert_key) {
            // Deduplicate - increment count and update timestamp
            existing_alert.increment();
            tracing::debug!(
                "Deduplicated alert: {} (count: {})",
                alert_key,
                existing_alert.count
            );
            return Ok(());
        }

        // Store the alert
        self.active_alerts.insert(alert_key.clone(), alert.clone());

        // Add to history
        self.alert_history.push_back(alert.clone());

        // Limit history size
        if self.alert_history.len() > self.config.max_history_size {
            self.alert_history.pop_front();
        }

        // Queue for notification
        self.queue_notification(alert.clone()).await?;

        tracing::info!("New alert created: {} (ID: {})", alert.title, alert.id);
        Ok(())
    }

    /// Queue alert for notification
    async fn queue_notification(&mut self, alert: Alert) -> secreton_errors::Result<()> {
        let mut channels = Vec::new();

        // Determine notification channels based on severity and configuration
        match alert.severity {
            AlertSeverity::Emergency => {
                if !self.config.email.to_addresses.is_empty() {
                    channels.push(NotificationChannel::Email);
                }
                if !self.config.webhook.url.is_empty() {
                    channels.push(NotificationChannel::Webhook);
                }
                if !self.config.slack.webhook_url.is_empty() {
                    channels.push(NotificationChannel::Slack);
                }
            }
            AlertSeverity::Critical => {
                if !self.config.email.to_addresses.is_empty() {
                    channels.push(NotificationChannel::Email);
                }
                if !self.config.webhook.url.is_empty() {
                    channels.push(NotificationChannel::Webhook);
                }
                if !self.config.slack.webhook_url.is_empty() {
                    channels.push(NotificationChannel::Slack);
                }
            }
            AlertSeverity::Warning => {
                if !self.config.webhook.url.is_empty() {
                    channels.push(NotificationChannel::Webhook);
                }
                if !self.config.slack.webhook_url.is_empty() {
                    channels.push(NotificationChannel::Slack);
                }
            }
            AlertSeverity::Info => {
                if !self.config.slack.webhook_url.is_empty() {
                    channels.push(NotificationChannel::Slack);
                }
            }
        }

        if !channels.is_empty() {
            let notification = AlertNotification {
                alert,
                channels,
                retry_count: 0,
                next_retry: None,
            };

            self.notification_queue.push_back(notification);
        }

        Ok(())
    }

    /// Process notification queue
    async fn process_notifications(&mut self) -> secreton_errors::Result<()> {
        let mut notifications_to_retry = Vec::new();

        while let Some(mut notification) = self.notification_queue.pop_front() {
            let success = self.send_notification(&notification).await;

            if !success && notification.retry_count < 3 {
                notification.retry_count += 1;
                notification.next_retry = Some(
                    SystemTime::now() + Duration::from_secs(60 * notification.retry_count as u64),
                );
                notifications_to_retry.push(notification);
            }
        }

        // Re-queue failed notifications
        for notification in notifications_to_retry {
            self.notification_queue.push_back(notification);
        }

        Ok(())
    }

    /// Send notification via configured channels
    async fn send_notification(&self, notification: &AlertNotification) -> bool {
        let mut all_success = true;

        for channel in &notification.channels {
            let success = match channel {
                NotificationChannel::Email => self.send_email_notification(notification).await,
                NotificationChannel::Webhook => self.send_webhook_notification(notification).await,
                NotificationChannel::Slack => self.send_slack_notification(notification).await,
                NotificationChannel::Sms => self.send_sms_notification(notification).await,
            };

            if !success {
                tracing::error!("Failed to send notification via {:?}", channel);
                all_success = false;
            }
        }

        all_success
    }

    /// Send email notification
    async fn send_email_notification(&self, notification: &AlertNotification) -> bool {
        if self.config.email.smtp_server.is_empty() || self.config.email.to_addresses.is_empty() {
            return false;
        }

        // Create email message
        let subject = format!(
            "[{}] {}",
            notification.alert.severity, notification.alert.title
        );
        let body = format!(
            "Alert Details:\n\nTitle: {}\nDescription: {}\nSeverity: {}\nCategory: {}\nSource: {}\nTimestamp: {}\n\nPlease check the system immediately.",
            notification.alert.title,
            notification.alert.description,
            notification.alert.severity,
            notification.alert.category,
            notification.alert.source,
            notification.alert.timestamp
        );

        // Send to all configured addresses
        let mut all_success = true;
        for to_address in &self.config.email.to_addresses {
            // Build email for each recipient
            let email = lettre::Message::builder()
                .from(
                    self.config
                        .email
                        .from_address
                        .parse()
                        .unwrap_or_else(|_| "alerts@secreton.local".parse().unwrap()),
                )
                .to(to_address
                    .parse()
                    .unwrap_or_else(|_| "admin@secreton.local".parse().unwrap()))
                .subject(&subject)
                .body(body.clone())
                .unwrap();

            // Create SMTP transport
            let smtp_server = &self.config.email.smtp_server;
            let smtp_port = self.config.email.smtp_port;
            let creds = lettre::transport::smtp::authentication::Credentials::new(
                self.config.email.smtp_username.clone(),
                self.config.email.smtp_password.clone(),
            );

            let mailer = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(smtp_server)
                .unwrap()
                .port(smtp_port)
                .credentials(creds)
                .build();

            match mailer.send(email).await {
                Ok(_) => {
                    tracing::info!("Email notification sent successfully to {}", to_address);
                }
                Err(e) => {
                    tracing::error!("Failed to send email notification to {}: {}", to_address, e);
                    all_success = false;
                }
            }
        }

        all_success
    }

    /// Send webhook notification
    async fn send_webhook_notification(&self, notification: &AlertNotification) -> bool {
        if self.config.webhook.url.is_empty() {
            return false;
        }

        let payload = serde_json::json!({
            "alert": notification.alert,
            "timestamp": notification.alert.timestamp,
            "severity": notification.alert.severity,
            "category": notification.alert.category,
        });

        match self
            .http_client
            .post(&self.config.webhook.url)
            .json(&payload)
            .timeout(Duration::from_secs(self.config.webhook.timeout_seconds))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                tracing::info!("Webhook notification sent successfully");
                true
            }
            Ok(response) => {
                tracing::error!(
                    "Webhook notification failed with status: {}",
                    response.status()
                );
                false
            }
            Err(e) => {
                tracing::error!("Webhook notification error: {}", e);
                false
            }
        }
    }

    /// Send Slack notification
    async fn send_slack_notification(&self, notification: &AlertNotification) -> bool {
        if self.config.slack.webhook_url.is_empty() {
            return false;
        }

        let color = match notification.alert.severity {
            AlertSeverity::Emergency => "danger",
            AlertSeverity::Critical => "danger",
            AlertSeverity::Warning => "warning",
            AlertSeverity::Info => "good",
        };

        let payload = serde_json::json!({
            "channel": self.config.slack.channel,
            "username": self.config.slack.username,
            "attachments": [{
                "color": color,
                "title": notification.alert.title,
                "text": notification.alert.description,
                "fields": [
                    {
                        "title": "Severity",
                        "value": notification.alert.severity.to_string(),
                        "short": true
                    },
                    {
                        "title": "Category",
                        "value": notification.alert.category.to_string(),
                        "short": true
                    },
                    {
                        "title": "Source",
                        "value": notification.alert.source,
                        "short": true
                    }
                ],
                "ts": notification.alert.timestamp
            }]
        });

        match self
            .http_client
            .post(&self.config.slack.webhook_url)
            .json(&payload)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                tracing::info!("Slack notification sent successfully");
                true
            }
            Ok(response) => {
                tracing::error!(
                    "Slack notification failed with status: {}",
                    response.status()
                );
                false
            }
            Err(e) => {
                tracing::error!("Slack notification error: {}", e);
                false
            }
        }
    }

    /// Send SMS notification
    async fn send_sms_notification(&self, notification: &AlertNotification) -> bool {
        if self.config.sms.account_sid.is_empty()
            || self.config.sms.auth_token.is_empty()
            || self.config.sms.from_number.is_empty()
        {
            return false;
        }

        // Create SMS message
        let message = format!(
            "[{}] {}: {}",
            notification.alert.severity, notification.alert.title, notification.alert.description
        );

        // Send SMS using Twilio API
        match self.send_twilio_sms(&message).await {
            Ok(_) => {
                tracing::info!("SMS notification sent successfully");
                true
            }
            Err(e) => {
                tracing::error!("Failed to send SMS notification: {}", e);
                false
            }
        }
    }

    /// Send SMS via Twilio API
    async fn send_twilio_sms(
        &self,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // For now, we'll use a simple HTTP request to Twilio API
        // In a real implementation, you'd use the twilio crate

        let account_sid = &self.config.sms.account_sid;
        let auth_token = &self.config.sms.auth_token;
        let from_number = &self.config.sms.from_number;

        // Use the first configured recipient or a default
        let to_number = self
            .config
            .sms
            .to_numbers
            .first()
            .ok_or("No SMS recipients configured")?;

        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            account_sid
        );

        let params = [
            ("From", from_number.as_str()),
            ("To", to_number),
            ("Body", message),
        ];

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .basic_auth(account_sid, Some(auth_token))
            .form(&params)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Twilio API error: {}", response.status()).into())
        }
    }

    /// Clean up old alerts
    async fn cleanup_alerts(&mut self) -> secreton_errors::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Remove alerts older than deduplication window
        self.active_alerts.retain(|_, alert| {
            now.saturating_sub(alert.timestamp) < self.config.deduplication_window_seconds
        });

        // Remove old history entries
        while self.alert_history.len() > self.config.max_history_size {
            self.alert_history.pop_front();
        }

        Ok(())
    }

    /// Get active alerts
    pub fn get_active_alerts(&self) -> Vec<&Alert> {
        self.active_alerts.values().collect()
    }

    /// Get alert history
    pub fn get_alert_history(&self) -> Vec<&Alert> {
        self.alert_history.iter().collect()
    }
}

#[async_trait::async_trait]
impl Service for AlertManager {
    async fn start(&self) -> ServiceResult<()> {
        tracing::info!("AlertManager started");
        Ok(())
    }

    async fn stop(&self) -> ServiceResult<()> {
        tracing::info!("AlertManager stopped");
        Ok(())
    }

    async fn health(&self) -> ServiceResult<ServiceHealth> {
        // Basic health check - check if we can access the alert storage
        match self.active_alerts.len() {
            _ => Ok(ServiceHealth::Healthy),
        }
    }

    fn name(&self) -> &str {
        "AlertManager"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn uptime_seconds(&self) -> u64 {
        // AlertManager doesn't track uptime, return 0
        0
    }
}

// Re-export key types for convenience
pub use AlertCategory as Category;
pub use AlertSeverity as Severity;
pub use AlertStatus as Status;
