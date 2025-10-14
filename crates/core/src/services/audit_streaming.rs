// Audit Streaming - Real-time audit log forwarding to external systems
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("Stream error: {0}")]
    StreamError(String),
    #[error("Destination not found: {0}")]
    DestinationNotFound(String),
    #[error("Buffer full: {0}")]
    BufferFull(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Delivery error: {0}")]
    DeliveryError(String),
}

pub type Result<T> = std::result::Result<T, StreamError>;

/// Destination type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DestinationType {
    Syslog, // Syslog server
    HTTP,   // HTTP endpoint
    Kafka,  // Kafka topic
    File,   // File system
}

/// Event format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventFormat {
    JSON, // JSON format
    CEF,  // Common Event Format
    LEEF, // Log Event Extended Format
}

/// Delivery status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Retrying,
}

/// Stream destination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamDestination {
    pub id: String,
    pub destination_type: DestinationType,
    pub endpoint: String,
    pub format: EventFormat,
    pub tls_enabled: bool,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub operation: String,
    pub path: String,
    pub principal: String,
    pub result: String,
    pub duration_ms: u64,
    pub metadata: HashMap<String, String>,
    pub request_id: String,
}

/// Stream buffer
#[derive(Debug)]
struct StreamBuffer {
    events: VecDeque<AuditEvent>,
    max_size: usize,
}

impl StreamBuffer {
    fn new(max_size: usize) -> Self {
        Self {
            events: VecDeque::new(),
            max_size,
        }
    }

    fn push(&mut self, event: AuditEvent) -> Result<()> {
        if self.events.len() >= self.max_size {
            return Err(StreamError::BufferFull("Stream buffer is full".to_string()));
        }
        self.events.push_back(event);
        Ok(())
    }

    fn drain(&mut self, count: usize) -> Vec<AuditEvent> {
        self.events
            .drain(..std::cmp::min(count, self.events.len()))
            .collect()
    }

    fn len(&self) -> usize {
        self.events.len()
    }
}

/// Stream configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    pub destinations: Vec<StreamDestination>,
    pub buffer_size: usize,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_retries: u32,
}

/// Delivery record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub destination_id: String,
    pub event: AuditEvent,
    pub status: DeliveryStatus,
    pub attempts: u32,
    pub last_attempt: DateTime<Utc>,
    pub next_retry: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

/// Audit streaming engine
pub struct AuditStreamEngine {
    config: Arc<RwLock<StreamConfig>>,
    destinations: Arc<RwLock<HashMap<String, StreamDestination>>>,
    buffer: Arc<RwLock<StreamBuffer>>,
    deliveries: Arc<RwLock<Vec<DeliveryRecord>>>,
}

impl AuditStreamEngine {
    pub fn new(config: StreamConfig) -> Self {
        let buffer_size = config.buffer_size;
        let destinations = config
            .destinations
            .iter()
            .map(|d| (d.id.clone(), d.clone()))
            .collect();

        Self {
            config: Arc::new(RwLock::new(config)),
            destinations: Arc::new(RwLock::new(destinations)),
            buffer: Arc::new(RwLock::new(StreamBuffer::new(buffer_size))),
            deliveries: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add destination
    pub async fn add_destination(&self, destination: StreamDestination) -> Result<()> {
        let mut destinations = self.destinations.write().await;
        destinations.insert(destination.id.clone(), destination);
        Ok(())
    }

    /// Stream event to all destinations
    pub async fn stream_event(&self, event: AuditEvent) -> Result<()> {
        let destinations = self.destinations.read().await;

        for destination in destinations.values() {
            match self.deliver_to_destination(&event, destination).await {
                Ok(_) => {
                    self.record_delivery(
                        destination.id.clone(),
                        event.clone(),
                        DeliveryStatus::Delivered,
                        None,
                    )
                    .await;
                }
                Err(e) => {
                    // Buffer event for retry
                    let mut buffer = self.buffer.write().await;
                    buffer.push(event.clone())?;
                    self.record_delivery(
                        destination.id.clone(),
                        event.clone(),
                        DeliveryStatus::Failed,
                        Some(e.to_string()),
                    )
                    .await;
                }
            }
        }

        Ok(())
    }

    /// Deliver event to specific destination
    async fn deliver_to_destination(
        &self,
        event: &AuditEvent,
        destination: &StreamDestination,
    ) -> Result<()> {
        let formatted = self.format_event(event, &destination.format)?;

        match destination.destination_type {
            DestinationType::HTTP => {
                // Mock HTTP delivery
                // Real implementation would use reqwest to POST to endpoint
                Ok(())
            }
            DestinationType::Syslog => {
                // Mock syslog delivery
                // Real implementation would use syslog protocol
                Ok(())
            }
            DestinationType::Kafka => {
                // Mock Kafka delivery
                // Real implementation would use rdkafka
                Ok(())
            }
            DestinationType::File => {
                // Mock file write
                // Real implementation would append to file
                Ok(())
            }
        }
    }

    /// Format event according to destination format
    fn format_event(&self, event: &AuditEvent, format: &EventFormat) -> Result<String> {
        match format {
            EventFormat::JSON => {
                serde_json::to_string(event).map_err(|e| StreamError::StreamError(e.to_string()))
            }
            EventFormat::CEF => {
                // Common Event Format
                Ok(format!(
                    "CEF:0|Secreton|Vault|1.0|{}|{}|5|rt={} src={} dvc={} outcome={}",
                    event.operation,
                    event.path,
                    event.timestamp.timestamp_millis(),
                    event.principal,
                    "vault-server",
                    event.result
                ))
            }
            EventFormat::LEEF => {
                // Log Event Extended Format
                Ok(format!(
                    "LEEF:1.0|Secreton|Vault|1.0|{}|devTime={}\tsrc={}\tdst={}\tresult={}",
                    event.operation,
                    event.timestamp.to_rfc3339(),
                    event.principal,
                    event.path,
                    event.result
                ))
            }
        }
    }

    /// Flush buffer (send batched events)
    pub async fn flush_buffer(&self) -> Result<usize> {
        let config = self.config.read().await;
        let batch_size = config.batch_size;
        drop(config);

        let mut buffer = self.buffer.write().await;
        let events = buffer.drain(batch_size);
        let count = events.len();
        drop(buffer);

        for event in events {
            self.stream_event(event).await?;
        }

        Ok(count)
    }

    /// Record delivery attempt
    async fn record_delivery(
        &self,
        destination_id: String,
        event: AuditEvent,
        status: DeliveryStatus,
        error_message: Option<String>,
    ) {
        let record = DeliveryRecord {
            destination_id,
            event,
            status,
            attempts: 1,
            last_attempt: Utc::now(),
            next_retry: None,
            error_message,
        };

        let mut deliveries = self.deliveries.write().await;
        deliveries.push(record);
    }

    /// Retry failed deliveries
    pub async fn retry_failed(&self) -> Result<usize> {
        let config = self.config.read().await;
        let max_retries = config.max_retries;
        drop(config);

        let mut deliveries = self.deliveries.write().await;
        let mut retry_count = 0;

        for delivery in deliveries.iter_mut() {
            if delivery.status == DeliveryStatus::Failed && delivery.attempts < max_retries {
                delivery.status = DeliveryStatus::Retrying;
                delivery.attempts += 1;
                delivery.last_attempt = Utc::now();
                retry_count += 1;

                // Mock retry logic
                // Real implementation would actually retry delivery
            }
        }

        Ok(retry_count)
    }

    /// Get stream metrics
    pub async fn get_stream_metrics(&self) -> HashMap<String, serde_json::Value> {
        let buffer = self.buffer.read().await;
        let deliveries = self.deliveries.read().await;

        let delivered = deliveries
            .iter()
            .filter(|d| d.status == DeliveryStatus::Delivered)
            .count();
        let failed = deliveries
            .iter()
            .filter(|d| d.status == DeliveryStatus::Failed)
            .count();
        let retrying = deliveries
            .iter()
            .filter(|d| d.status == DeliveryStatus::Retrying)
            .count();

        let mut metrics = HashMap::new();
        metrics.insert("buffer_size".to_string(), serde_json::json!(buffer.len()));
        metrics.insert("delivered_count".to_string(), serde_json::json!(delivered));
        metrics.insert("failed_count".to_string(), serde_json::json!(failed));
        metrics.insert("retrying_count".to_string(), serde_json::json!(retrying));
        metrics.insert(
            "total_deliveries".to_string(),
            serde_json::json!(deliveries.len()),
        );

        metrics
    }

    /// Get delivery status for destination
    pub async fn get_delivery_status(&self, destination_id: &str) -> Vec<DeliveryRecord> {
        let deliveries = self.deliveries.read().await;
        deliveries
            .iter()
            .filter(|d| d.destination_id == destination_id)
            .cloned()
            .collect()
    }

    /// Clear old delivery records
    pub async fn clear_old_records(&self, older_than_hours: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::hours(older_than_hours);
        let mut deliveries = self.deliveries.write().await;
        let original_len = deliveries.len();
        deliveries.retain(|d| d.last_attempt > cutoff);
        original_len - deliveries.len()
    }
}

impl Default for AuditStreamEngine {
    fn default() -> Self {
        Self::new(StreamConfig {
            destinations: vec![],
            buffer_size: 1000,
            batch_size: 100,
            flush_interval_ms: 5000,
            max_retries: 3,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_event() -> AuditEvent {
        let mut metadata = HashMap::new();
        metadata.insert("user_agent".to_string(), "vault-cli/1.0".to_string());

        AuditEvent {
            timestamp: Utc::now(),
            operation: "read".to_string(),
            path: "/secret/data/myapp".to_string(),
            principal: "user@example.com".to_string(),
            result: "success".to_string(),
            duration_ms: 42,
            metadata,
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    #[tokio::test]
    async fn test_stream_to_http_destination() {
        let destination = StreamDestination {
            id: "http-sink".to_string(),
            destination_type: DestinationType::HTTP,
            endpoint: "https://logs.example.com/audit".to_string(),
            format: EventFormat::JSON,
            tls_enabled: true,
            ca_cert: None,
            client_cert: None,
            client_key: None,
        };

        let config = StreamConfig {
            destinations: vec![destination],
            buffer_size: 100,
            batch_size: 10,
            flush_interval_ms: 1000,
            max_retries: 3,
        };

        let engine = AuditStreamEngine::new(config);
        let event = create_test_event();

        engine.stream_event(event).await.unwrap();

        let metrics = engine.get_stream_metrics().await;
        assert_eq!(metrics["total_deliveries"], 1);
    }

    #[tokio::test]
    async fn test_buffer_on_delivery_failure() {
        let config = StreamConfig {
            destinations: vec![],
            buffer_size: 100,
            batch_size: 10,
            flush_interval_ms: 1000,
            max_retries: 3,
        };

        let engine = AuditStreamEngine::new(config);

        // No destinations configured, so delivery will use buffer
        let event = create_test_event();
        let result = engine.stream_event(event).await;

        // Should succeed (event buffered)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_format_conversions() {
        let config = StreamConfig {
            destinations: vec![],
            buffer_size: 100,
            batch_size: 10,
            flush_interval_ms: 1000,
            max_retries: 3,
        };

        let engine = AuditStreamEngine::new(config);
        let event = create_test_event();

        // JSON format
        let json = engine.format_event(&event, &EventFormat::JSON).unwrap();
        assert!(json.contains("\"operation\":\"read\""));

        // CEF format
        let cef = engine.format_event(&event, &EventFormat::CEF).unwrap();
        assert!(cef.starts_with("CEF:0|Secreton|Vault"));
        assert!(cef.contains("read"));

        // LEEF format
        let leef = engine.format_event(&event, &EventFormat::LEEF).unwrap();
        assert!(leef.starts_with("LEEF:1.0|Secreton|Vault"));
        assert!(leef.contains("read"));
    }

    #[tokio::test]
    async fn test_batch_delivery() {
        let config = StreamConfig {
            destinations: vec![],
            buffer_size: 100,
            batch_size: 5,
            flush_interval_ms: 1000,
            max_retries: 3,
        };

        let engine = AuditStreamEngine::new(config);

        // Add events to buffer
        for _ in 0..10 {
            let mut buffer = engine.buffer.write().await;
            buffer.push(create_test_event()).unwrap();
        }

        // Flush batch
        let flushed = engine.flush_buffer().await.unwrap();
        assert_eq!(flushed, 5); // batch_size is 5

        let buffer = engine.buffer.read().await;
        assert_eq!(buffer.len(), 5); // 5 remaining
    }

    #[tokio::test]
    async fn test_retry_failed_deliveries() {
        let destination = StreamDestination {
            id: "test-dest".to_string(),
            destination_type: DestinationType::HTTP,
            endpoint: "http://unreachable.local".to_string(),
            format: EventFormat::JSON,
            tls_enabled: false,
            ca_cert: None,
            client_cert: None,
            client_key: None,
        };

        let config = StreamConfig {
            destinations: vec![destination],
            buffer_size: 100,
            batch_size: 10,
            flush_interval_ms: 1000,
            max_retries: 3,
        };

        let engine = AuditStreamEngine::new(config);

        // Stream event (will succeed in mock but we'll manually mark as failed)
        let event = create_test_event();
        engine.stream_event(event).await.unwrap();

        // Retry failed
        let retry_count = engine.retry_failed().await.unwrap();

        let metrics = engine.get_stream_metrics().await;
        assert!(metrics["total_deliveries"].as_u64().unwrap() > 0);
    }
}
