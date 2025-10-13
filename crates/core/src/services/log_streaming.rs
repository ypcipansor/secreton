// Log Streaming Advanced - Structured logging to Fluentd/Logstash
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum LogStreamError {
    #[error("Log streaming error: {0}")]
    StreamError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Buffer full")]
    BufferFull,
    #[error("Destination not found: {0}")]
    DestinationNotFound(String),
}

pub type Result<T> = std::result::Result<T, LogStreamError>;

/// Log level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

/// Log format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogFormat {
    JSON,
    Logstash,
    Fluentd,
}

/// Destination type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DestinationType {
    Fluentd,
    Logstash,
    HTTP,
    File,
}

/// Log streaming configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStreamConfig {
    pub destinations: Vec<LogDestination>,
    pub format: LogFormat,
    pub buffer_size: usize,
    pub batch_size: usize,
    pub enrichment_enabled: bool,
    pub enable_sampling: bool,
    pub sample_rate: f64, // 0.0 to 1.0
}

/// Log destination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogDestination {
    pub id: String,
    pub destination_type: DestinationType,
    pub endpoint: String, // URL or file path
    pub tag: String,      // For Fluentd
    pub index: Option<String>, // For Logstash (ES index)
    pub enabled: bool,
}

/// Log event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub context: HashMap<String, String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub service: String,
    pub hostname: Option<String>,
    pub pod_name: Option<String>,
    pub namespace: Option<String>,
}

/// Log enrichment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEnrichment {
    pub add_hostname: bool,
    pub add_pod_info: bool,
    pub add_trace_context: bool,
    pub add_environment: bool,
    pub custom_fields: HashMap<String, String>,
}

/// Log buffer
#[derive(Debug)]
struct LogBuffer {
    events: VecDeque<LogEvent>,
    max_size: usize,
}

impl LogBuffer {
    fn new(max_size: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    fn push(&mut self, event: LogEvent) -> Result<()> {
        if self.events.len() >= self.max_size {
            return Err(LogStreamError::BufferFull);
        }
        self.events.push_back(event);
        Ok(())
    }

    fn drain(&mut self, count: usize) -> Vec<LogEvent> {
        self.events.drain(..count.min(self.events.len())).collect()
    }

    fn len(&self) -> usize {
        self.events.len()
    }
}

/// Advanced Log Streaming
pub struct LogStreaming {
    config: Arc<RwLock<LogStreamConfig>>,
    enrichment: Arc<RwLock<LogEnrichment>>,
    buffer: Arc<RwLock<LogBuffer>>,
    destinations: Arc<RwLock<HashMap<String, LogDestination>>>,
    metrics: Arc<RwLock<StreamMetrics>>,
}

#[derive(Debug, Default)]
struct StreamMetrics {
    total_events: u64,
    buffered_events: u64,
    delivered_events: u64,
    dropped_events: u64,
    errors: u64,
}

impl LogStreaming {
    pub fn new(config: LogStreamConfig, enrichment: LogEnrichment) -> Self {
        let destinations = config
            .destinations
            .iter()
            .map(|d| (d.id.clone(), d.clone()))
            .collect();

        let buffer = LogBuffer::new(config.buffer_size);

        Self {
            config: Arc::new(RwLock::new(config)),
            enrichment: Arc::new(RwLock::new(enrichment)),
            buffer: Arc::new(RwLock::new(buffer)),
            destinations: Arc::new(RwLock::new(destinations)),
            metrics: Arc::new(RwLock::new(StreamMetrics::default())),
        }
    }

    /// Stream log event
    pub async fn stream_log(&self, mut event: LogEvent) -> Result<()> {
        // Apply enrichment
        let enrichment = self.enrichment.read().await;
        self.enrich_log(&mut event, &enrichment).await;
        drop(enrichment);

        // Apply sampling
        let config = self.config.read().await;
        if config.enable_sampling && !self.should_sample(config.sample_rate) {
            return Ok(());
        }
        drop(config);

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.total_events += 1;
        drop(metrics);

        // Try to stream to destinations
        let destinations = self.destinations.read().await;
        let mut success = false;

        for destination in destinations.values() {
            if destination.enabled {
                match self.deliver_to_destination(&event, destination).await {
                    Ok(_) => {
                        success = true;
                        let mut metrics = self.metrics.write().await;
                        metrics.delivered_events += 1;
                    }
                    Err(_) => {
                        // Buffer on failure
                        let mut metrics = self.metrics.write().await;
                        metrics.errors += 1;
                    }
                }
            }
        }

        // Buffer if no successful delivery
        if !success {
            let mut buffer = self.buffer.write().await;
            match buffer.push(event) {
                Ok(_) => {
                    let mut metrics = self.metrics.write().await;
                    metrics.buffered_events += 1;
                }
                Err(_) => {
                    let mut metrics = self.metrics.write().await;
                    metrics.dropped_events += 1;
                }
            }
        }

        Ok(())
    }

    /// Enrich log with additional context
    async fn enrich_log(&self, event: &mut LogEvent, enrichment: &LogEnrichment) {
        if enrichment.add_hostname && event.hostname.is_none() {
            event.hostname = Some("vault-server-1".to_string());
        }

        if enrichment.add_pod_info && event.pod_name.is_none() {
            event.pod_name = Some("vault-0".to_string());
            event.namespace = Some("default".to_string());
        }

        if enrichment.add_trace_context && event.trace_id.is_none() {
            event.trace_id = Some(uuid::Uuid::new_v4().to_string());
        }

        // Add custom fields to context
        for (key, value) in &enrichment.custom_fields {
            event.context.insert(key.clone(), value.clone());
        }
    }

    /// Deliver event to destination
    async fn deliver_to_destination(
        &self,
        event: &LogEvent,
        destination: &LogDestination,
    ) -> Result<()> {
        let config = self.config.read().await;
        let formatted = self.format_event(event, &config.format, destination).await?;
        drop(config);

        // Mock delivery based on destination type
        match destination.destination_type {
            DestinationType::Fluentd => self.mock_send_to_fluentd(&formatted, destination).await,
            DestinationType::Logstash => self.mock_send_to_logstash(&formatted, destination).await,
            DestinationType::HTTP => self.mock_send_to_http(&formatted, destination).await,
            DestinationType::File => self.mock_write_to_file(&formatted, destination).await,
        }
    }

    /// Format event for destination
    async fn format_event(
        &self,
        event: &LogEvent,
        format: &LogFormat,
        destination: &LogDestination,
    ) -> Result<String> {
        match format {
            LogFormat::JSON => {
                serde_json::to_string(event)
                    .map_err(|e| LogStreamError::StreamError(e.to_string()))
            }
            LogFormat::Fluentd => self.format_for_fluentd(event, &destination.tag),
            LogFormat::Logstash => self.format_for_logstash(event, destination),
        }
    }

    /// Format for Fluentd (tag + JSON)
    fn format_for_fluentd(&self, event: &LogEvent, tag: &str) -> Result<String> {
        let timestamp = event.timestamp.timestamp();
        let json = serde_json::to_string(event)
            .map_err(|e| LogStreamError::StreamError(e.to_string()))?;

        Ok(format!("[{}, {}, {}]", tag, timestamp, json))
    }

    /// Format for Logstash (JSON with @timestamp and @metadata)
    fn format_for_logstash(&self, event: &LogEvent, destination: &LogDestination) -> Result<String> {
        let mut logstash_event = serde_json::json!({
            "@timestamp": event.timestamp.to_rfc3339(),
            "@version": "1",
            "message": event.message,
            "level": format!("{:?}", event.level),
            "service": event.service,
        });

        if let Some(index) = &destination.index {
            logstash_event["@metadata"] = serde_json::json!({
                "index": index
            });
        }

        if let Some(hostname) = &event.hostname {
            logstash_event["hostname"] = serde_json::json!(hostname);
        }

        if let Some(trace_id) = &event.trace_id {
            logstash_event["trace_id"] = serde_json::json!(trace_id);
        }

        // Add context fields
        for (key, value) in &event.context {
            logstash_event[key] = serde_json::json!(value);
        }

        serde_json::to_string(&logstash_event)
            .map_err(|e| LogStreamError::StreamError(e.to_string()))
    }

    /// Flush buffered events
    pub async fn flush_buffer(&self) -> Result<usize> {
        let config = self.config.read().await;
        let batch_size = config.batch_size;
        drop(config);

        let mut buffer = self.buffer.write().await;
        let drain_count = batch_size.min(buffer.events.len());
        let events: Vec<_> = buffer.events.drain(0..drain_count).collect();
        let count = events.len();
        drop(buffer);

        // Send buffered events directly to destinations (don't re-buffer)
        let destinations = self.destinations.read().await;
        for event in events {
            for destination in destinations.values() {
                if destination.enabled {
                    let _ = self.deliver_to_destination(&event, destination).await;
                }
            }
        }

        Ok(count)
    }

    /// Add destination
    pub async fn add_destination(&self, destination: LogDestination) -> Result<()> {
        let mut destinations = self.destinations.write().await;
        destinations.insert(destination.id.clone(), destination);
        Ok(())
    }

    /// Remove destination
    pub async fn remove_destination(&self, destination_id: &str) -> Result<()> {
        let mut destinations = self.destinations.write().await;
        destinations
            .remove(destination_id)
            .ok_or_else(|| LogStreamError::DestinationNotFound(destination_id.to_string()))?;
        Ok(())
    }

    /// Get metrics
    pub async fn get_metrics(&self) -> HashMap<String, u64> {
        let metrics = self.metrics.read().await;
        let buffer = self.buffer.read().await;

        let mut result = HashMap::new();
        result.insert("total_events".to_string(), metrics.total_events);
        result.insert("buffered_events".to_string(), buffer.len() as u64);
        result.insert("delivered_events".to_string(), metrics.delivered_events);
        result.insert("dropped_events".to_string(), metrics.dropped_events);
        result.insert("errors".to_string(), metrics.errors);

        result
    }

    fn should_sample(&self, rate: f64) -> bool {
        use rand::Rng;
        rand::thread_rng().r#gen::<f64>() < rate
    }

    // Mock delivery methods
    async fn mock_send_to_fluentd(&self, _data: &str, _dest: &LogDestination) -> Result<()> {
        Ok(())
    }

    async fn mock_send_to_logstash(&self, _data: &str, _dest: &LogDestination) -> Result<()> {
        Ok(())
    }

    async fn mock_send_to_http(&self, _data: &str, _dest: &LogDestination) -> Result<()> {
        Ok(())
    }

    async fn mock_write_to_file(&self, _data: &str, _dest: &LogDestination) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> LogStreamConfig {
        LogStreamConfig {
            destinations: vec![],
            format: LogFormat::JSON,
            buffer_size: 100,
            batch_size: 10,
            enrichment_enabled: true,
            enable_sampling: false,
            sample_rate: 1.0,
        }
    }

    fn create_test_enrichment() -> LogEnrichment {
        LogEnrichment {
            add_hostname: true,
            add_pod_info: true,
            add_trace_context: true,
            add_environment: false,
            custom_fields: HashMap::new(),
        }
    }

    fn create_test_event() -> LogEvent {
        let mut context = HashMap::new();
        context.insert("user_id".to_string(), "123".to_string());

        LogEvent {
            timestamp: Utc::now(),
            level: LogLevel::Info,
            message: "Test log message".to_string(),
            context,
            trace_id: None,
            span_id: None,
            service: "vault".to_string(),
            hostname: None,
            pod_name: None,
            namespace: None,
        }
    }

    #[tokio::test]
    async fn test_stream_log_with_enrichment() {
        let config = create_test_config();
        let enrichment = create_test_enrichment();
        let streaming = LogStreaming::new(config, enrichment);

        let event = create_test_event();

        streaming.stream_log(event).await.unwrap();

        let metrics = streaming.get_metrics().await;
        assert_eq!(metrics["total_events"], 1);
    }

    #[tokio::test]
    async fn test_fluentd_format() {
        let config = LogStreamConfig {
            format: LogFormat::Fluentd,
            ..create_test_config()
        };
        let enrichment = create_test_enrichment();
        let streaming = LogStreaming::new(config, enrichment);

        let destination = LogDestination {
            id: "fluentd-1".to_string(),
            destination_type: DestinationType::Fluentd,
            endpoint: "tcp://localhost:24224".to_string(),
            tag: "vault.logs".to_string(),
            index: None,
            enabled: true,
        };

        let event = create_test_event();
        let formatted = streaming
            .format_for_fluentd(&event, &destination.tag)
            .unwrap();

        assert!(formatted.starts_with("[vault.logs,"));
        assert!(formatted.contains("Test log message"));
    }

    #[tokio::test]
    async fn test_logstash_format() {
        let config = LogStreamConfig {
            format: LogFormat::Logstash,
            ..create_test_config()
        };
        let enrichment = create_test_enrichment();
        let streaming = LogStreaming::new(config, enrichment);

        let destination = LogDestination {
            id: "logstash-1".to_string(),
            destination_type: DestinationType::Logstash,
            endpoint: "tcp://localhost:5044".to_string(),
            tag: "".to_string(),
            index: Some("vault-logs".to_string()),
            enabled: true,
        };

        let event = create_test_event();
        let formatted = streaming
            .format_for_logstash(&event, &destination)
            .unwrap();

        assert!(formatted.contains("@timestamp"));
        assert!(formatted.contains("@version"));
        assert!(formatted.contains("Test log message"));
        assert!(formatted.contains("vault-logs"));
    }

    #[tokio::test]
    async fn test_buffer_and_flush() {
        let config = LogStreamConfig {
            batch_size: 5,
            ..create_test_config()
        };
        let enrichment = create_test_enrichment();
        let streaming = LogStreaming::new(config, enrichment);

        // Add events to buffer
        for _ in 0..10 {
            let event = create_test_event();
            streaming.stream_log(event).await.unwrap();
        }

        let metrics_before = streaming.get_metrics().await;
        assert_eq!(metrics_before["buffered_events"], 10);

        // Flush batch (flushes batch_size=5 events)
        let flushed = streaming.flush_buffer().await.unwrap();
        assert_eq!(flushed, 5); // batch_size events flushed

        let metrics_after = streaming.get_metrics().await;
        assert_eq!(metrics_after["buffered_events"], 5); // 5 remaining in buffer
    }

    #[tokio::test]
    async fn test_enrichment() {
        let config = create_test_config();
        let mut enrichment = create_test_enrichment();
        enrichment.custom_fields.insert("environment".to_string(), "production".to_string());

        let streaming = LogStreaming::new(config, enrichment.clone());

        let mut event = create_test_event();
        streaming.enrich_log(&mut event, &enrichment).await;

        assert!(event.hostname.is_some());
        assert!(event.pod_name.is_some());
        assert!(event.trace_id.is_some());
        assert_eq!(event.context.get("environment"), Some(&"production".to_string()));
    }
}
