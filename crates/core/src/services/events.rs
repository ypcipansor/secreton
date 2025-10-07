//! Event System
//!
//! Webhook and event subscription system for audit and monitoring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Event errors
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("Subscription not found: {0}")]
    SubscriptionNotFound(String),
    
    #[error("Invalid webhook URL: {0}")]
    InvalidWebhookUrl(String),
    
    #[error("Webhook delivery failed: {0}")]
    WebhookDeliveryFailed(String),
    
    #[error("Invalid event filter: {0}")]
    InvalidFilter(String),
}

/// Event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    /// Authentication events
    AuthSuccess,
    AuthFailure,
    
    /// Secret access events
    SecretRead,
    SecretWrite,
    SecretDelete,
    
    /// Token events
    TokenCreated,
    TokenRevoked,
    TokenRenewed,
    
    /// Policy events
    PolicyUpdated,
    PolicyViolation,
    
    /// System events
    SealStatusChanged,
    ConfigUpdated,
    
    /// Audit events
    AuditLogGenerated,
    
    /// Custom event
    Custom(String),
}

/// Event severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event ID
    pub id: String,
    
    /// Event type
    pub event_type: EventType,
    
    /// Severity
    pub severity: EventSeverity,
    
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Source (service/component)
    pub source: String,
    
    /// Event metadata
    pub metadata: HashMap<String, serde_json::Value>,
    
    /// Related entity (path, token ID, etc.)
    pub entity: Option<String>,
}

impl Event {
    /// Create new event
    pub fn new(event_type: EventType, source: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            event_type,
            severity: EventSeverity::Info,
            timestamp: Utc::now(),
            source,
            metadata: HashMap::new(),
            entity: None,
        }
    }
    
    /// Set severity
    pub fn with_severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }
    
    /// Set entity
    pub fn with_entity(mut self, entity: String) -> Self {
        self.entity = Some(entity);
        self
    }
    
    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Event filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    /// Event types to match (empty = all)
    pub event_types: Vec<EventType>,
    
    /// Minimum severity
    pub min_severity: Option<EventSeverity>,
    
    /// Source pattern (wildcard supported)
    pub source_pattern: Option<String>,
    
    /// Entity pattern
    pub entity_pattern: Option<String>,
}

impl EventFilter {
    /// Check if event matches filter
    pub fn matches(&self, event: &Event) -> bool {
        // Check event type
        if !self.event_types.is_empty() && !self.event_types.contains(&event.event_type) {
            return false;
        }
        
        // Check severity
        if let Some(min_sev) = &self.min_severity {
            let sev_level = |s: &EventSeverity| match s {
                EventSeverity::Info => 0,
                EventSeverity::Warning => 1,
                EventSeverity::Error => 2,
                EventSeverity::Critical => 3,
            };
            
            if sev_level(&event.severity) < sev_level(min_sev) {
                return false;
            }
        }
        
        // Check source pattern
        if let Some(pattern) = &self.source_pattern {
            if !self.matches_pattern(&event.source, pattern) {
                return false;
            }
        }
        
        // Check entity pattern
        if let Some(pattern) = &self.entity_pattern {
            if let Some(entity) = &event.entity {
                if !self.matches_pattern(entity, pattern) {
                    return false;
                }
            } else {
                return false;
            }
        }
        
        true
    }
    
    fn matches_pattern(&self, value: &str, pattern: &str) -> bool {
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            value.starts_with(prefix)
        } else {
            value == pattern
        }
    }
}

/// Event subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSubscription {
    /// Subscription ID
    pub id: String,
    
    /// Webhook URL
    pub webhook_url: String,
    
    /// Event filter
    pub filter: EventFilter,
    
    /// Enabled
    pub enabled: bool,
    
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    
    /// Description
    pub description: Option<String>,
}

/// Webhook delivery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// Delivery ID
    pub id: String,
    
    /// Event ID
    pub event_id: String,
    
    /// Subscription ID
    pub subscription_id: String,
    
    /// Success status
    pub success: bool,
    
    /// HTTP status code
    pub status_code: Option<u16>,
    
    /// Error message
    pub error: Option<String>,
    
    /// Attempt count
    pub attempt: u32,
    
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Event service
pub struct EventService {
    subscriptions: Arc<RwLock<HashMap<String, EventSubscription>>>,
    event_history: Arc<RwLock<Vec<Event>>>,
    delivery_history: Arc<RwLock<Vec<WebhookDelivery>>>,
}

impl EventService {
    /// Create new event service
    pub fn new() -> Self {
        Self {
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            event_history: Arc::new(RwLock::new(Vec::new())),
            delivery_history: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Create subscription
    pub async fn subscribe(&self, subscription: EventSubscription) -> Result<String, EventError> {
        // Validate webhook URL
        if !subscription.webhook_url.starts_with("http://") 
            && !subscription.webhook_url.starts_with("https://") {
            return Err(EventError::InvalidWebhookUrl(subscription.webhook_url.clone()));
        }
        
        let id = subscription.id.clone();
        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.insert(id.clone(), subscription);
        
        Ok(id)
    }
    
    /// Get subscription
    pub async fn get_subscription(&self, id: &str) -> Option<EventSubscription> {
        let subscriptions = self.subscriptions.read().await;
        subscriptions.get(id).cloned()
    }
    
    /// List subscriptions
    pub async fn list_subscriptions(&self) -> Vec<EventSubscription> {
        let subscriptions = self.subscriptions.read().await;
        subscriptions.values().cloned().collect()
    }
    
    /// Update subscription
    pub async fn update_subscription(
        &self,
        id: &str,
        subscription: EventSubscription,
    ) -> Result<(), EventError> {
        let mut subscriptions = self.subscriptions.write().await;
        if !subscriptions.contains_key(id) {
            return Err(EventError::SubscriptionNotFound(id.to_string()));
        }
        
        subscriptions.insert(id.to_string(), subscription);
        Ok(())
    }
    
    /// Delete subscription
    pub async fn unsubscribe(&self, id: &str) -> Result<(), EventError> {
        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.remove(id)
            .ok_or_else(|| EventError::SubscriptionNotFound(id.to_string()))?;
        Ok(())
    }
    
    /// Publish event
    pub async fn publish(&self, event: Event) -> Result<(), EventError> {
        // Store event in history
        let mut history = self.event_history.write().await;
        history.push(event.clone());
        
        // Keep only last 1000 events
        if history.len() > 1000 {
            let excess = history.len() - 1000;
            history.drain(0..excess);
        }
        drop(history);
        
        // Find matching subscriptions
        let subscriptions = self.subscriptions.read().await;
        let matching: Vec<_> = subscriptions.values()
            .filter(|sub| sub.enabled && sub.filter.matches(&event))
            .cloned()
            .collect();
        drop(subscriptions);
        
        // Deliver to webhooks
        for subscription in matching {
            self.deliver_webhook(&event, &subscription).await;
        }
        
        Ok(())
    }
    
    /// Deliver webhook (simulated)
    async fn deliver_webhook(&self, event: &Event, subscription: &EventSubscription) {
        // In production, this would make an actual HTTP POST request
        // For now, we simulate delivery
        
        let delivery = WebhookDelivery {
            id: uuid::Uuid::new_v4().to_string(),
            event_id: event.id.clone(),
            subscription_id: subscription.id.clone(),
            success: true, // Simulated success
            status_code: Some(200),
            error: None,
            attempt: 1,
            timestamp: Utc::now(),
        };
        
        let mut history = self.delivery_history.write().await;
        history.push(delivery);
        
        // Keep only last 500 deliveries
        if history.len() > 500 {
            let excess = history.len() - 500;
            history.drain(0..excess);
        }
    }
    
    /// Get event history
    pub async fn get_event_history(&self, limit: usize) -> Vec<Event> {
        let history = self.event_history.read().await;
        history.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
    
    /// Get delivery history for subscription
    pub async fn get_delivery_history(&self, subscription_id: &str, limit: usize) -> Vec<WebhookDelivery> {
        let history = self.delivery_history.read().await;
        history.iter()
            .filter(|d| d.subscription_id == subscription_id)
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

impl Default for EventService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_publish_and_subscribe() {
        let service = EventService::new();
        
        let subscription = EventSubscription {
            id: "sub1".to_string(),
            webhook_url: "https://example.com/webhook".to_string(),
            filter: EventFilter {
                event_types: vec![EventType::AuthSuccess],
                min_severity: None,
                source_pattern: None,
                entity_pattern: None,
            },
            enabled: true,
            created_at: Utc::now(),
            description: Some("Test subscription".to_string()),
        };
        
        service.subscribe(subscription).await.unwrap();
        
        let event = Event::new(EventType::AuthSuccess, "auth-service".to_string());
        service.publish(event).await.unwrap();
        
        let history = service.get_event_history(10).await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].event_type, EventType::AuthSuccess);
    }
    
    #[tokio::test]
    async fn test_event_filtering() {
        let filter = EventFilter {
            event_types: vec![EventType::SecretRead, EventType::SecretWrite],
            min_severity: Some(EventSeverity::Warning),
            source_pattern: Some("secret-*".to_string()),
            entity_pattern: None,
        };
        
        // Matching event
        let event1 = Event::new(EventType::SecretRead, "secret-engine".to_string())
            .with_severity(EventSeverity::Warning);
        assert!(filter.matches(&event1));
        
        // Non-matching event type
        let event2 = Event::new(EventType::AuthSuccess, "secret-engine".to_string())
            .with_severity(EventSeverity::Warning);
        assert!(!filter.matches(&event2));
        
        // Non-matching severity
        let event3 = Event::new(EventType::SecretRead, "secret-engine".to_string())
            .with_severity(EventSeverity::Info);
        assert!(!filter.matches(&event3));
        
        // Non-matching source
        let event4 = Event::new(EventType::SecretRead, "auth-engine".to_string())
            .with_severity(EventSeverity::Warning);
        assert!(!filter.matches(&event4));
    }
    
    #[tokio::test]
    async fn test_webhook_delivery() {
        let service = EventService::new();
        
        let subscription = EventSubscription {
            id: "sub1".to_string(),
            webhook_url: "https://example.com/webhook".to_string(),
            filter: EventFilter {
                event_types: Vec::new(), // Match all
                min_severity: None,
                source_pattern: None,
                entity_pattern: None,
            },
            enabled: true,
            created_at: Utc::now(),
            description: None,
        };
        
        service.subscribe(subscription).await.unwrap();
        
        let event = Event::new(EventType::SecretWrite, "kv-engine".to_string());
        service.publish(event).await.unwrap();
        
        let deliveries = service.get_delivery_history("sub1", 10).await;
        assert_eq!(deliveries.len(), 1);
        assert!(deliveries[0].success);
    }
    
    #[tokio::test]
    async fn test_subscription_management() {
        let service = EventService::new();
        
        let subscription = EventSubscription {
            id: "test-sub".to_string(),
            webhook_url: "https://example.com/webhook".to_string(),
            filter: EventFilter {
                event_types: Vec::new(),
                min_severity: None,
                source_pattern: None,
                entity_pattern: None,
            },
            enabled: true,
            created_at: Utc::now(),
            description: None,
        };
        
        service.subscribe(subscription.clone()).await.unwrap();
        
        let retrieved = service.get_subscription("test-sub").await.unwrap();
        assert_eq!(retrieved.id, "test-sub");
        
        let all = service.list_subscriptions().await;
        assert_eq!(all.len(), 1);
        
        service.unsubscribe("test-sub").await.unwrap();
        assert!(service.get_subscription("test-sub").await.is_none());
    }
}
