//! Alert management module for the Brankas agent

use crate::config::AlertingConfig;
use crate::monitoring::MonitoringEvent;
use secreton_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

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
    pub async fn start(&mut self) -> CoreResult<()> {
        tracing::info!("Starting alert manager");

        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let processing_interval = Duration::from_secs(self.config.processing_interval_seconds);

        while self.running.load(std::sync::atomic::Ordering::SeqCst) {
            // Process incoming monitoring events
            self.process_events().await?;

            // Process notification queue
            self.process_notifications().await?;

            // Clean up old alerts
            self.cleanup_alerts().await?;

            tokio::time::sleep(processing_interval).await;
        }

        Ok(())
    }

    /// Stop alert processing
    pub async fn stop(&mut self) -> CoreResult<()> {
        tracing::info!("Stopping alert manager");
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Process incoming monitoring events
    async fn process_events(&mut self) -> CoreResult<()> {
        while let Ok(event) = self.event_receiver.try_recv() {
            if let Some(alert) = self.event_to_alert(event).await? {
                self.handle_alert(alert).await?;
            }
        }
        Ok(())
    }

    /// Convert monitoring event to alert
    async fn event_to_alert(&self, event: MonitoringEvent) -> CoreResult<Option<Alert>> {
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
                let severity = match net_event.event_type {
                    crate::monitoring::NetworkEventType::SuspiciousActivity
                    | crate::monitoring::NetworkEventType::PortScan
                    | crate::monitoring::NetworkEventType::DdosAttempt => AlertSeverity::Critical,
                    _ => AlertSeverity::Info,
                };

                let alert = Alert::new(
                    "Network Activity".to_string(),
                    format!("Network event: {:?}", net_event.event_type),
                    severity,
                    AlertCategory::Network,
                    "NetworkMonitor".to_string(),
                );
                Ok(Some(alert))
            }

            MonitoringEvent::Process(proc_event) => {
                let severity = match proc_event.event_type {
                    crate::monitoring::ProcessEventType::SuspiciousActivity
                    | crate::monitoring::ProcessEventType::PrivilegeEscalation => {
                        AlertSeverity::Critical
                    }
                    crate::monitoring::ProcessEventType::HighCpuUsage
                    | crate::monitoring::ProcessEventType::HighMemoryUsage => {
                        AlertSeverity::Warning
                    }
                    _ => AlertSeverity::Info,
                };

                let alert = Alert::new(
                    "Process Activity".to_string(),
                    format!(
                        "Process event: {:?} for PID {}",
                        proc_event.event_type, proc_event.process_id
                    ),
                    severity,
                    AlertCategory::System,
                    "ProcessMonitor".to_string(),
                );
                Ok(Some(alert))
            }

            MonitoringEvent::Log(log_event) => {
                let severity = match log_event.level {
                    crate::monitoring::LogLevel::Emergency => AlertSeverity::Emergency,
                    crate::monitoring::LogLevel::Alert | crate::monitoring::LogLevel::Critical => {
                        AlertSeverity::Critical
                    }
                    crate::monitoring::LogLevel::Error => AlertSeverity::Warning,
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
                let alert = Alert::new(
                    format!("{:?} Threshold Exceeded", resource_event.resource_type),
                    format!(
                        "Resource usage is {}% (threshold: {}%)",
                        resource_event.current_value, resource_event.threshold_value
                    ),
                    match resource_event.severity {
                        crate::monitoring::ResourceSeverity::Critical => AlertSeverity::Critical,
                        crate::monitoring::ResourceSeverity::Warning => AlertSeverity::Warning,
                        crate::monitoring::ResourceSeverity::Info => AlertSeverity::Info,
                    },
                    AlertCategory::Performance,
                    "ResourceMonitor".to_string(),
                );
                Ok(Some(alert))
            }
        }
    }

    /// Handle a new alert
    async fn handle_alert(&mut self, alert: Alert) -> CoreResult<()> {
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
        if self.alert_history.len() > 1000 {
            self.alert_history.pop_front();
        }

        // Queue for notification
        self.queue_notification(alert.clone()).await?;

        tracing::info!("New alert created: {} (ID: {})", alert.title, alert.id);
        Ok(())
    }

    /// Queue alert for notification
    async fn queue_notification(&mut self, alert: Alert) -> CoreResult<()> {
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
    async fn process_notifications(&mut self) -> CoreResult<()> {
        let mut processed = Vec::new();
        let mut failed = Vec::new();

        while let Some(mut notification) = self.notification_queue.pop_front() {
            // Check if it's time to retry
            if let Some(next_retry) = notification.next_retry {
                if SystemTime::now() < next_retry {
                    failed.push(notification);
                    continue;
                }
            }

            let mut success = true;

            for channel in &notification.channels {
                match self.send_notification(&notification.alert, channel).await {
                    Ok(_) => {
                        tracing::info!(
                            "Alert notification sent via {:?}: {}",
                            channel,
                            notification.alert.id
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to send alert notification via {:?}: {}",
                            channel,
                            e
                        );
                        success = false;
                    }
                }
            }

            if success {
                processed.push(notification);
            } else {
                // Retry logic
                notification.retry_count += 1;
                if notification.retry_count < 3 {
                    notification.next_retry = Some(
                        SystemTime::now()
                            + Duration::from_secs(60 * notification.retry_count as u64),
                    );
                    failed.push(notification);
                } else {
                    tracing::error!(
                        "Failed to send alert notification after 3 retries: {}",
                        notification.alert.id
                    );
                }
            }
        }

        // Re-queue failed notifications
        for notification in failed {
            self.notification_queue.push_back(notification);
        }

        Ok(())
    }

    /// Send notification via specific channel
    async fn send_notification(
        &self,
        alert: &Alert,
        channel: &NotificationChannel,
    ) -> CoreResult<()> {
        match channel {
            NotificationChannel::Email => {
                if !self.config.email.to_addresses.is_empty() {
                    self.send_email_notification(alert).await?;
                }
            }
            NotificationChannel::Webhook => {
                if !self.config.webhook.url.is_empty() {
                    self.send_webhook_notification(alert).await?;
                }
            }
            NotificationChannel::Slack => {
                if !self.config.slack.webhook_url.is_empty() {
                    self.send_slack_notification(alert).await?;
                }
            }
            NotificationChannel::Sms => {
                if self.config.sms_enabled {
                    self.send_sms_notification(alert).await?;
                }
            }
        }

        Ok(())
    }

    /// Send email notification
    async fn send_email_notification(&self, alert: &Alert) -> CoreResult<()> {
        // This is a simplified implementation
        // In a real implementation, you would use a proper email library
        tracing::info!("Sending email notification for alert: {}", alert.id);

        let subject = format!("[{}] {} - {}", alert.severity, alert.category, alert.title);
        let body = format!(
            "Alert ID: {}\nSeverity: {:?}\nCategory: {:?}\nSource: {}\nTimestamp: {}\n\nDescription:\n{}",
            alert.id,
            alert.severity,
            alert.category,
            alert.source,
            chrono::DateTime::<chrono::Utc>::from_timestamp(alert.timestamp as i64, 0)
                .unwrap_or_default()
                .format("%Y-%m-%d %H:%M:%S UTC"),
            alert.description
        );

        tracing::debug!("Email subject: {}", subject);
        tracing::debug!("Email body: {}", body);

        Ok(())
    }

    /// Send SMS notification
    async fn send_sms_notification(&self, alert: &Alert) -> CoreResult<()> {
        if self.config.sms.account_sid.is_empty() || self.config.sms.auth_token.is_empty() {
            return Err(Box::new(CoreError::Configuration {
                message: "SMS credentials not configured".to_string(),
            }));
        }

        if self.config.sms.to_numbers.is_empty() {
            return Err(Box::new(CoreError::Configuration {
                message: "No SMS recipients configured".to_string(),
            }));
        }

        tracing::info!("Sending SMS notification for alert: {}", alert.id);

        let message = format!(
            "[{}] {}: {}",
            alert.severity,
            alert.title,
            alert.description.chars().take(140).collect::<String>() // SMS length limit
        );

        // For each recipient, send SMS
        for to_number in &self.config.sms.to_numbers {
            match self.config.sms.provider.as_str() {
                "twilio" => {
                    self.send_twilio_sms(to_number, &message).await?;
                }
                "aws-sns" => {
                    self.send_aws_sns_sms(to_number, &message).await?;
                }
                _ => {
                    tracing::warn!("Unsupported SMS provider: {}", self.config.sms.provider);
                }
            }
        }

        Ok(())
    }

    /// Send webhook notification
    async fn send_webhook_notification(&self, alert: &Alert) -> CoreResult<()> {
        if self.config.webhook.url.is_empty() {
            return Err(Box::new(CoreError::Configuration {
                message: "Webhook URL not configured".to_string(),
            }));
        }

        let payload = serde_json::json!({
            "alert_id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "category": alert.category,
            "status": alert.status,
            "source": alert.source,
            "timestamp": alert.timestamp,
            "metadata": alert.metadata
        });

        let mut request = self
            .http_client
            .post(&self.config.webhook.url)
            .json(&payload)
            .timeout(Duration::from_secs(self.config.webhook.timeout_seconds));

        // Add custom headers
        for (key, value) in &self.config.webhook.headers {
            request = request.header(key, value);
        }

        let response = request.send().await.map_err(|e| {
            Box::new(CoreError::Network {
                message: format!("Webhook request failed: {}", e),
            })
        })?;

        if !response.status().is_success() {
            return Err(Box::new(CoreError::Network {
                message: format!("Webhook returned status: {}", response.status()),
            }));
        }

        tracing::info!("Webhook notification sent for alert: {}", alert.id);
        Ok(())
    }

    /// Send Slack notification
    async fn send_slack_notification(&self, alert: &Alert) -> CoreResult<()> {
        if self.config.slack.webhook_url.is_empty() {
            return Err(Box::new(CoreError::Configuration {
                message: "Slack webhook URL not configured".to_string(),
            }));
        }

        let color = match alert.severity {
            AlertSeverity::Emergency => "#ff0000",
            AlertSeverity::Critical => "#ff6600",
            AlertSeverity::Warning => "#ffaa00",
            AlertSeverity::Info => "#36a64f",
        };

        let payload = serde_json::json!({
            "channel": self.config.slack.channel,
            "username": self.config.slack.username,
            "icon_emoji": self.config.slack.icon_emoji,
            "attachments": [{
                "color": color,
                "title": format!("{:?} Alert: {}", alert.severity, alert.title),
                "text": alert.description,
                "fields": [
                    {
                        "title": "Category",
                        "value": format!("{:?}", alert.category),
                        "short": true
                    },
                    {
                        "title": "Source",
                        "value": alert.source,
                        "short": true
                    },
                    {
                        "title": "Alert ID",
                        "value": alert.id,
                        "short": true
                    },
                    {
                        "title": "Timestamp",
                        "value": chrono::DateTime::<chrono::Utc>::from_timestamp(alert.timestamp as i64, 0)
                            .unwrap_or_default()
                            .format("%Y-%m-%d %H:%M:%S UTC")
                            .to_string(),
                        "short": true
                    }
                ],
                "ts": alert.timestamp
            }]
        });

        let response = self
            .http_client
            .post(&self.config.slack.webhook_url)
            .json(&payload)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| {
                Box::new(CoreError::Network {
                    message: format!("Slack webhook request failed: {}", e),
                })
            })?;

        if !response.status().is_success() {
            return Err(Box::new(CoreError::Network {
                message: format!("Slack webhook returned status: {}", response.status()),
            }));
        }

        tracing::info!("Slack notification sent for alert: {}", alert.id);
        Ok(())
    }

    /// Clean up old alerts
    async fn cleanup_alerts(&mut self) -> CoreResult<()> {
        let cutoff_time = SystemTime::now() - Duration::from_secs(24 * 60 * 60); // 24 hours

        // Remove resolved alerts older than 24 hours
        self.active_alerts.retain(|_, alert| {
            if matches!(alert.status, AlertStatus::Resolved | AlertStatus::Closed) {
                let alert_time = UNIX_EPOCH + Duration::from_secs(alert.updated_at);
                alert_time > cutoff_time
            } else {
                true
            }
        });

        Ok(())
    }

    /// Get active alerts
    pub fn get_active_alerts(&self) -> Vec<&Alert> {
        self.active_alerts.values().collect()
    }

    /// Get alert by ID
    pub fn get_alert(&self, alert_id: &str) -> Option<&Alert> {
        self.active_alerts
            .values()
            .find(|alert| alert.id == alert_id)
    }

    /// Acknowledge an alert
    pub fn acknowledge_alert(&mut self, alert_id: &str, acknowledged_by: String) -> CoreResult<()> {
        for alert in self.active_alerts.values_mut() {
            if alert.id == alert_id {
                alert.acknowledge(acknowledged_by);
                return Ok(());
            }
        }

        Err(Box::new(CoreError::NotFound {
            resource: format!("alert:{}", alert_id),
        }))
    }

    /// Resolve an alert
    pub fn resolve_alert(&mut self, alert_id: &str, resolution: String) -> CoreResult<()> {
        for alert in self.active_alerts.values_mut() {
            if alert.id == alert_id {
                alert.resolve(resolution);
                return Ok(());
            }
        }

        Err(Box::new(CoreError::NotFound {
            resource: format!("alert:{}", alert_id),
        }))
    }

    /// Check if alert manager is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Send SMS via Twilio
    async fn send_twilio_sms(&self, to: &str, message: &str) -> CoreResult<()> {
        let url = format!(
            "https://api.twilio.com/2010-04-04/Accounts/{}/Messages.json",
            self.config.sms.account_sid
        );

        let params = [
            ("From", self.config.sms.from_number.clone()),
            ("To", to.to_string()),
            ("Body", message.to_string()),
        ];

        let response = self
            .http_client
            .post(&url)
            .basic_auth(
                &self.config.sms.account_sid,
                Some(&self.config.sms.auth_token),
            )
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                Box::new(CoreError::Network {
                    message: format!("Twilio API request failed: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(Box::new(CoreError::Network {
                message: format!("Twilio SMS send failed: {}", error_text),
            }));
        }

        tracing::debug!("SMS sent successfully to {}", to);
        Ok(())
    }

    /// Send SMS via AWS SNS
    async fn send_aws_sns_sms(&self, _to: &str, _message: &str) -> CoreResult<()> {
        // This would require AWS SDK integration
        // For now, just log that AWS SNS SMS is not implemented
        tracing::warn!("AWS SNS SMS provider not yet implemented");
        Ok(())
    }
}
