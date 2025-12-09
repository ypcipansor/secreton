// Webhook System - Enhanced webhook notifications for secreton events
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("Webhook error: {0}")]
    WebhookError(String),
    #[error("Webhook not found: {0}")]
    WebhookNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Delivery error: {0}")]
    DeliveryError(String),
}

pub type Result<T> = std::result::Result<T, WebhookError>;

/// Event type for webhooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WebhookEventType {
    SecretRead,
    SecretWrite,
    SecretDelete,
    PolicyChange,
    AuthSuccess,
    AuthFailure,
    TokenCreate,
    TokenRevoke,
    ConfigChange,
    SystemStartup,
    SystemShutdown,
}

/// Delivery _status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Retrying,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub id: String,
    pub url: String,
    pub _secret: String, // For HMAC signature
    pub headers: HashMap<String, String>,
    pub retry_attempts: u32,
    pub timeout_ms: u64,
    pub enabled: bool,
}

/// Webhook event _data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub event_id: String,
    pub event_type: WebhookEventType,
    pub timestamp: DateTime<Utc>,
    pub principal: String,
    pub _path: String,
    pub metadata: HashMap<String, String>,
    pub request_id: String,
}

/// Webhook delivery record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub delivery_id: String,
    pub webhook_id: String,
    pub event: WebhookEvent,
    pub _status: DeliveryStatus,
    pub attempts: u32,
    pub last_attempt: DateTime<Utc>,
    pub next_retry: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub response_code: Option<u16>,
}

/// Webhook system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSystemConfig {
    pub webhooks: Vec<WebhookConfig>,
    pub event_types: Vec<WebhookEventType>,
    pub buffer_size: usize,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
}

/// Webhook notification system
pub struct WebhookSystem {
    _config: Arc<RwLock<WebhookSystemConfig>>,
    webhooks: Arc<RwLock<HashMap<String, WebhookConfig>>>,
    events: Arc<RwLock<Vec<WebhookEvent>>>,
    deliveries: Arc<RwLock<Vec<WebhookDelivery>>>,
}

impl WebhookSystem {
    pub fn new(_config: WebhookSystemConfig) -> Self {
        let webhooks = _config
            .webhooks
            .iter()
            .map(|w| (w.id.clone(), w.clone()))
            .collect();

        Self {
            _config: Arc::new(RwLock::new(_config)),
            webhooks: Arc::new(RwLock::new(webhooks)),
            events: Arc::new(RwLock::new(Vec::new())),
            deliveries: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add webhook
    pub async fn add_webhook(&self, webhook: WebhookConfig) -> Result<()> {
        if webhook.url.is_empty() {
            return Err(WebhookError::ConfigError("URL is required".to_string()));
        }

        let mut webhooks = self.webhooks.write().await;
        webhooks.insert(webhook.id.clone(), webhook);

        Ok(())
    }

    /// Remove webhook
    pub async fn remove_webhook(&self, webhook_id: &str) -> Result<()> {
        let mut webhooks = self.webhooks.write().await;
        webhooks
            .remove(webhook_id)
            .ok_or_else(|| WebhookError::WebhookNotFound(webhook_id.to_string()))?;
        Ok(())
    }

    /// Emit event to all configured webhooks
    pub async fn emit_event(&self, mut event: WebhookEvent) -> Result<()> {
        // Assign event ID if not set
        if event.event_id.is_empty() {
            event.event_id = uuid::Uuid::new_v4().to_string();
        }

        // Store event
        let mut events = self.events.write().await;
        events.push(event.clone());
        drop(events);

        // Check if event type is configured
        let _config = self._config.read().await;
        if !_config.event_types.contains(&event.event_type) {
            return Ok(()); // Event type not subscribed
        }
        drop(_config);

        // Deliver to all enabled webhooks
        let webhooks = self.webhooks.read().await;
        for webhook in webhooks.values() {
            if webhook.enabled {
                self.deliver_to_webhook(&event, webhook).await?;
            }
        }

        Ok(())
    }

    /// Deliver event to specific webhook
    async fn deliver_to_webhook(
        &self,
        event: &WebhookEvent,
        webhook: &WebhookConfig,
    ) -> Result<()> {
        let delivery_id = uuid::Uuid::new_v4().to_string();

        // Create payload
        let payload = serde_json::to_string(event)
            .map_err(|_e| WebhookError::WebhookError(_e.to_string()))?;

        // Generate HMAC signature
        let signature = self.generate_hmac_signature(&payload, &webhook._secret);

        // Mock HTTP POST delivery
        // Real implementation would use reqwest
        let (_status, response_code) = self.mock_http_post(webhook, &payload, &signature).await;

        let delivery = WebhookDelivery {
            delivery_id: delivery_id.clone(),
            webhook_id: webhook.id.clone(),
            event: event.clone(),
            _status,
            attempts: 1,
            last_attempt: Utc::now(),
            next_retry: None,
            error_message: None,
            response_code: Some(response_code),
        };

        let mut deliveries = self.deliveries.write().await;
        deliveries.push(delivery);

        Ok(())
    }

    /// Generate HMAC-SHA256 signature
    fn generate_hmac_signature(&self, payload: &str, _secret: &str) -> String {
        // Mock HMAC generation
        // Real implementation would use hmac crate with sha2
        format!("sha256={}", self.mock_hash(payload, _secret))
    }

    fn mock_hash(&self, payload: &str, _secret: &str) -> String {
        // Simple mock hash
        format!("{:x}", (payload.len() + _secret.len()) * 123456789)
    }

    /// Mock HTTP POST
    async fn mock_http_post(
        &self,
        _webhook: &WebhookConfig,
        _payload: &str,
        _signature: &str,
    ) -> (DeliveryStatus, u16) {
        // Mock successful delivery
        // Real implementation would use reqwest to POST
        (DeliveryStatus::Delivered, 200)
    }

    /// Validate HMAC signature (for incoming webhooks)
    pub fn validate_webhook(&self, payload: &str, signature: &str, _secret: &str) -> bool {
        let expected = self.generate_hmac_signature(payload, _secret);
        expected == signature
    }

    /// Retry failed deliveries
    pub async fn retry_delivery(&self) -> Result<usize> {
        let _config = self._config.read().await;
        let max_retries = _config.max_retries;
        let retry_delay = Duration::milliseconds(_config.retry_delay_ms as i64);
        drop(_config);

        let mut deliveries = self.deliveries.write().await;
        let mut retry_count = 0;
        let now = Utc::now();

        for delivery in deliveries.iter_mut() {
            if delivery._status == DeliveryStatus::Failed
                && delivery.attempts < max_retries
                && delivery.next_retry.map(|t| t <= now).unwrap_or(true)
            {
                delivery._status = DeliveryStatus::Retrying;
                delivery.attempts += 1;
                delivery.last_attempt = now;
                delivery.next_retry = Some(now + retry_delay * (delivery.attempts as i32));
                retry_count += 1;

                // Mock retry logic
                // Real implementation would actually retry delivery
            }
        }

        Ok(retry_count)
    }

    /// List events with optional filtering
    pub async fn list_events(&self, event_type: Option<WebhookEventType>) -> Vec<WebhookEvent> {
        let events = self.events.read().await;

        if let Some(filter_type) = event_type {
            events
                .iter()
                .filter(|_e| _e.event_type == filter_type)
                .cloned()
                .collect()
        } else {
            events.clone()
        }
    }

    /// Get delivery _status for webhook
    pub async fn get_delivery_status(&self, webhook_id: &str) -> Vec<WebhookDelivery> {
        let deliveries = self.deliveries.read().await;
        deliveries
            .iter()
            .filter(|d| d.webhook_id == webhook_id)
            .cloned()
            .collect()
    }

    /// Get delivery metrics
    pub async fn get_delivery_metrics(&self) -> HashMap<String, serde_json::Value> {
        let deliveries = self.deliveries.read().await;

        let total = deliveries.len();
        let delivered = deliveries
            .iter()
            .filter(|d| d._status == DeliveryStatus::Delivered)
            .count();
        let failed = deliveries
            .iter()
            .filter(|d| d._status == DeliveryStatus::Failed)
            .count();
        let retrying = deliveries
            .iter()
            .filter(|d| d._status == DeliveryStatus::Retrying)
            .count();

        let mut metrics = HashMap::new();
        metrics.insert("total_deliveries".to_string(), serde_json::json!(total));
        metrics.insert("delivered".to_string(), serde_json::json!(delivered));
        metrics.insert("failed".to_string(), serde_json::json!(failed));
        metrics.insert("retrying".to_string(), serde_json::json!(retrying));

        if total > 0 {
            metrics.insert(
                "success_rate".to_string(),
                serde_json::json!((delivered as f64 / total as f64) * 100.0),
            );
        }

        metrics
    }

    /// Clear old events
    pub async fn clear_old_events(&self, older_than_hours: i64) -> usize {
        let cutoff = Utc::now() - Duration::hours(older_than_hours);

        let mut events = self.events.write().await;
        let original_len = events.len();
        events.retain(|_e| _e.timestamp > cutoff);

        original_len - events.len()
    }

    /// Get webhook by ID
    pub async fn get_webhook(&self, webhook_id: &str) -> Result<WebhookConfig> {
        let webhooks = self.webhooks.read().await;
        webhooks
            .get(webhook_id)
            .cloned()
            .ok_or_else(|| WebhookError::WebhookNotFound(webhook_id.to_string()))
    }

    /// List all webhooks
    pub async fn list_webhooks(&self) -> Vec<WebhookConfig> {
        let webhooks = self.webhooks.read().await;
        webhooks.values().cloned().collect()
    }
}

impl Default for WebhookSystem {
    fn default() -> Self {
        Self::new(WebhookSystemConfig {
            webhooks: vec![],
            event_types: vec![],
            buffer_size: 1000,
            max_retries: 3,
            retry_delay_ms: 5000,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_webhook() -> WebhookConfig {
        WebhookConfig {
            id: "webhook-1".to_string(),
            url: "https://hooks.example.com/secreton".to_string(),
            _secret: "test_secret_key".to_string(),
            headers: HashMap::new(),
            retry_attempts: 3,
            timeout_ms: 5000,
            enabled: true,
        }
    }

    fn create_test_event() -> WebhookEvent {
        let mut metadata = HashMap::new();
        metadata.insert("user_agent".to_string(), "secreton-cli/1.0".to_string());

        WebhookEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: WebhookEventType::SecretRead,
            timestamp: Utc::now(),
            principal: "_user@example.com".to_string(),
            _path: "/_secret/_data/myapp".to_string(),
            metadata,
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    #[tokio::test]
    async fn test_emit_event_to_webhook() {
        let webhook = create_test_webhook();
        let _config = WebhookSystemConfig {
            webhooks: vec![webhook],
            event_types: vec![WebhookEventType::SecretRead, WebhookEventType::SecretWrite],
            buffer_size: 100,
            max_retries: 3,
            retry_delay_ms: 1000,
        };

        let system = WebhookSystem::new(_config);
        let event = create_test_event();

        system.emit_event(event).await.unwrap();

        let metrics = system.get_delivery_metrics().await;
        assert_eq!(metrics["total_deliveries"], 1);
    }

    #[tokio::test]
    async fn test_hmac_signature_validation() {
        let system = WebhookSystem::default();

        let payload = r#"{"event":"test"}"#;
        let _secret = "my_secret_key";

        let signature = system.generate_hmac_signature(payload, _secret);

        assert!(system.validate_webhook(payload, &signature, _secret));
        assert!(!system.validate_webhook(payload, "wrong_signature", _secret));
    }

    #[tokio::test]
    async fn test_retry_failed_deliveries() {
        let webhook = create_test_webhook();
        let _config = WebhookSystemConfig {
            webhooks: vec![webhook],
            event_types: vec![WebhookEventType::SecretRead],
            buffer_size: 100,
            max_retries: 3,
            retry_delay_ms: 100,
        };

        let system = WebhookSystem::new(_config);

        // Manually create failed delivery
        let event = create_test_event();
        let delivery = WebhookDelivery {
            delivery_id: uuid::Uuid::new_v4().to_string(),
            webhook_id: "webhook-1".to_string(),
            event: event.clone(),
            _status: DeliveryStatus::Failed,
            attempts: 1,
            last_attempt: Utc::now(),
            next_retry: Some(Utc::now()),
            error_message: Some("Connection timeout".to_string()),
            response_code: None,
        };

        let mut deliveries = system.deliveries.write().await;
        deliveries.push(delivery);
        drop(deliveries);

        // Retry
        let retry_count = system.retry_delivery().await.unwrap();
        assert_eq!(retry_count, 1);
    }

    #[tokio::test]
    async fn test_event_filtering_by_type() {
        let _config = WebhookSystemConfig {
            webhooks: vec![],
            event_types: vec![WebhookEventType::SecretRead, WebhookEventType::SecretWrite],
            buffer_size: 100,
            max_retries: 3,
            retry_delay_ms: 1000,
        };

        let system = WebhookSystem::new(_config);

        // Emit different types of events
        let mut event1 = create_test_event();
        event1.event_type = WebhookEventType::SecretRead;

        let mut event2 = create_test_event();
        event2.event_type = WebhookEventType::SecretWrite;

        let mut event3 = create_test_event();
        event3.event_type = WebhookEventType::TokenCreate;

        let mut events = system.events.write().await;
        events.push(event1);
        events.push(event2);
        events.push(event3);
        drop(events);

        // Filter by type
        let read_events = system.list_events(Some(WebhookEventType::SecretRead)).await;
        assert_eq!(read_events.len(), 1);

        let write_events = system
            .list_events(Some(WebhookEventType::SecretWrite))
            .await;
        assert_eq!(write_events.len(), 1);
    }

    #[tokio::test]
    async fn test_delivery_status_tracking() {
        let webhook = create_test_webhook();
        let webhook_id = webhook.id.clone();

        let _config = WebhookSystemConfig {
            webhooks: vec![webhook],
            event_types: vec![WebhookEventType::SecretRead],
            buffer_size: 100,
            max_retries: 3,
            retry_delay_ms: 1000,
        };

        let system = WebhookSystem::new(_config);
        let event = create_test_event();

        system.emit_event(event).await.unwrap();

        let deliveries = system.get_delivery_status(&webhook_id).await;
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].webhook_id, webhook_id);
    }

    #[tokio::test]
    async fn test_batch_events() {
        let webhook = create_test_webhook();
        let _config = WebhookSystemConfig {
            webhooks: vec![webhook],
            event_types: vec![WebhookEventType::SecretRead],
            buffer_size: 100,
            max_retries: 3,
            retry_delay_ms: 1000,
        };

        let system = WebhookSystem::new(_config);

        // Emit multiple events
        for _ in 0..5 {
            let event = create_test_event();
            system.emit_event(event).await.unwrap();
        }

        let all_events = system.list_events(None).await;
        assert_eq!(all_events.len(), 5);

        let metrics = system.get_delivery_metrics().await;
        assert_eq!(metrics["total_deliveries"], 5);
    }

    #[tokio::test]
    async fn test_webhook_crud() {
        let system = WebhookSystem::default();

        let webhook = create_test_webhook();
        let webhook_id = webhook.id.clone();

        // Add
        system.add_webhook(webhook).await.unwrap();

        // Get
        let retrieved = system.get_webhook(&webhook_id).await.unwrap();
        assert_eq!(retrieved.id, webhook_id);

        // List
        let webhooks = system.list_webhooks().await;
        assert_eq!(webhooks.len(), 1);

        // Remove
        system.remove_webhook(&webhook_id).await.unwrap();
        assert!(system.get_webhook(&webhook_id).await.is_err());
    }
}
