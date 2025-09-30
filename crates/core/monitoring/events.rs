/// Events System - Event Streaming and Webhook Notifications
/// 
/// Provides event streaming capabilities and webhook notifications for Secreton

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Event type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Secret created
    SecretCreated,
    /// Secret read
    SecretRead,
    /// Secret updated
    SecretUpdated,
    /// Secret deleted
    SecretDeleted,
    /// Authentication success
    AuthSuccess,
    /// Authentication failure
    AuthFailure,
    /// Policy violation
    PolicyViolation,
    /// Audit log entry
    AuditLog,
    /// System health change
    HealthChange,
    /// Configuration change
    ConfigChange,
}

/// Event severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Event data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event ID
    pub id: Uuid,
    /// Event type
    pub event_type: EventType,
    /// Event severity
    pub severity: EventSeverity,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Source of the event
    pub source: String,
    /// Event message
    pub message: String,
    /// Event metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// User/actor who triggered the event
    pub actor: Option<String>,
    /// Resource affected
    pub resource: Option<String>,
}

impl Event {
    /// Create a new event
    pub fn new(
        event_type: EventType,
        severity: EventSeverity,
        source: String,
        message: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type,
            severity,
            timestamp: Utc::now(),
            source,
            message,
            metadata: HashMap::new(),
            actor: None,
            resource: None,
        }
    }

    /// Add metadata to event
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set actor
    pub fn with_actor(mut self, actor: String) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Set resource
    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
        self
    }
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,
    /// Event types to subscribe to
    pub event_types: Vec<EventType>,
    /// HTTP headers
    pub headers: HashMap<String, String>,
    /// Retry configuration
    pub max_retries: u32,
    /// Timeout in seconds
    pub timeout_seconds: u64,
    /// Enable webhook
    pub enabled: bool,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            event_types: vec![],
            headers: HashMap::new(),
            max_retries: 3,
            timeout_seconds: 30,
            enabled: true,
        }
    }
}

/// Event subscriber trait
#[async_trait::async_trait]
pub trait EventSubscriber: Send + Sync {
    /// Handle an event
    async fn handle_event(&self, event: &Event) -> Result<(), String>;
    
    /// Get subscriber name
    fn name(&self) -> &str;
    
    /// Check if subscriber is interested in event type
    fn is_interested(&self, event_type: EventType) -> bool;
}

/// Webhook subscriber
pub struct WebhookSubscriber {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookSubscriber {
    /// Create new webhook subscriber
    pub fn new(config: WebhookConfig) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        Ok(Self { config, client })
    }
}

#[async_trait::async_trait]
impl EventSubscriber for WebhookSubscriber {
    async fn handle_event(&self, event: &Event) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut request = self.client.post(&self.config.url)
            .json(event);

        // Add custom headers
        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }

        // Retry logic
        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= self.config.max_retries {
            match request.try_clone().unwrap().send().await {
                Ok(response) if response.status().is_success() => {
                    return Ok(());
                }
                Ok(response) => {
                    last_error = Some(format!("HTTP {}", response.status()));
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                }
            }

            attempts += 1;
            if attempts <= self.config.max_retries {
                tokio::time::sleep(std::time::Duration::from_millis(100 * attempts as u64)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| "Unknown error".to_string()))
    }

    fn name(&self) -> &str {
        "webhook"
    }

    fn is_interested(&self, event_type: EventType) -> bool {
        self.config.event_types.is_empty() || self.config.event_types.contains(&event_type)
    }
}

/// Event manager
pub struct EventManager {
    /// Event subscribers
    subscribers: Arc<RwLock<Vec<Arc<dyn EventSubscriber>>>>,
    /// Event history (for debugging)
    history: Arc<RwLock<Vec<Event>>>,
    /// Maximum history size
    max_history_size: usize,
}

impl EventManager {
    /// Create new event manager
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(RwLock::new(Vec::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            max_history_size: 1000,
        }
    }

    /// Add a subscriber
    pub async fn subscribe(&self, subscriber: Arc<dyn EventSubscriber>) {
        let mut subscribers = self.subscribers.write().await;
        subscribers.push(subscriber);
    }

    /// Remove a subscriber by name
    pub async fn unsubscribe(&self, name: &str) -> bool {
        let mut subscribers = self.subscribers.write().await;
        let len_before = subscribers.len();
        subscribers.retain(|s| s.name() != name);
        subscribers.len() < len_before
    }

    /// Publish an event
    pub async fn publish(&self, event: Event) {
        // Store in history
        {
            let mut history = self.history.write().await;
            history.push(event.clone());
            
            // Trim history if needed
            if history.len() > self.max_history_size {
                history.drain(0..history.len() - self.max_history_size);
            }
        }

        // Notify subscribers
        let subscribers = self.subscribers.read().await;
        for subscriber in subscribers.iter() {
            if subscriber.is_interested(event.event_type) {
                let event_clone = event.clone();
                let subscriber_clone = Arc::clone(subscriber);
                
                // Spawn task to handle event asynchronously
                tokio::spawn(async move {
                    if let Err(e) = subscriber_clone.handle_event(&event_clone).await {
                        tracing::error!("Subscriber '{}' failed to handle event: {}", 
                            subscriber_clone.name(), e);
                    }
                });
            }
        }
    }

    /// Get event history
    pub async fn get_history(&self, limit: Option<usize>) -> Vec<Event> {
        let history = self.history.read().await;
        let limit = limit.unwrap_or(history.len());
        history.iter().rev().take(limit).cloned().collect()
    }

    /// Get event count by type
    pub async fn get_event_count(&self, event_type: Option<EventType>) -> usize {
        let history = self.history.read().await;
        match event_type {
            Some(et) => history.iter().filter(|e| e.event_type == et).count(),
            None => history.len(),
        }
    }

    /// Clear history
    pub async fn clear_history(&self) {
        let mut history = self.history.write().await;
        history.clear();
    }
}

impl Default for EventManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = Event::new(
            EventType::SecretCreated,
            EventSeverity::Info,
            "test".to_string(),
            "Test event".to_string(),
        );

        assert_eq!(event.event_type, EventType::SecretCreated);
        assert_eq!(event.severity, EventSeverity::Info);
        assert_eq!(event.message, "Test event");
    }

    #[test]
    fn test_event_with_metadata() {
        let event = Event::new(
            EventType::SecretCreated,
            EventSeverity::Info,
            "test".to_string(),
            "Test event".to_string(),
        )
        .with_metadata("key".to_string(), serde_json::json!("value"))
        .with_actor("user1".to_string())
        .with_resource("secret/path".to_string());

        assert_eq!(event.metadata.get("key").unwrap(), &serde_json::json!("value"));
        assert_eq!(event.actor.as_ref().unwrap(), "user1");
        assert_eq!(event.resource.as_ref().unwrap(), "secret/path");
    }

    #[tokio::test]
    async fn test_event_manager_creation() {
        let manager = EventManager::new();
        assert_eq!(manager.get_event_count(None).await, 0);
    }

    #[tokio::test]
    async fn test_publish_event() {
        let manager = EventManager::new();
        
        let event = Event::new(
            EventType::SecretCreated,
            EventSeverity::Info,
            "test".to_string(),
            "Test event".to_string(),
        );

        manager.publish(event).await;
        
        assert_eq!(manager.get_event_count(None).await, 1);
    }

    #[tokio::test]
    async fn test_event_history() {
        let manager = EventManager::new();
        
        for i in 0..5 {
            let event = Event::new(
                EventType::SecretCreated,
                EventSeverity::Info,
                "test".to_string(),
                format!("Event {}", i),
            );
            manager.publish(event).await;
        }

        let history = manager.get_history(Some(3)).await;
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].message, "Event 4"); // Most recent first
    }

    #[tokio::test]
    async fn test_event_count_by_type() {
        let manager = EventManager::new();
        
        manager.publish(Event::new(
            EventType::SecretCreated,
            EventSeverity::Info,
            "test".to_string(),
            "Event 1".to_string(),
        )).await;

        manager.publish(Event::new(
            EventType::SecretDeleted,
            EventSeverity::Warning,
            "test".to_string(),
            "Event 2".to_string(),
        )).await;

        manager.publish(Event::new(
            EventType::SecretCreated,
            EventSeverity::Info,
            "test".to_string(),
            "Event 3".to_string(),
        )).await;

        assert_eq!(manager.get_event_count(Some(EventType::SecretCreated)).await, 2);
        assert_eq!(manager.get_event_count(Some(EventType::SecretDeleted)).await, 1);
        assert_eq!(manager.get_event_count(None).await, 3);
    }

    #[tokio::test]
    async fn test_clear_history() {
        let manager = EventManager::new();
        
        manager.publish(Event::new(
            EventType::SecretCreated,
            EventSeverity::Info,
            "test".to_string(),
            "Event".to_string(),
        )).await;

        assert_eq!(manager.get_event_count(None).await, 1);
        
        manager.clear_history().await;
        assert_eq!(manager.get_event_count(None).await, 0);
    }

    #[test]
    fn test_webhook_config_default() {
        let config = WebhookConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.timeout_seconds, 30);
        assert!(config.enabled);
    }
}
