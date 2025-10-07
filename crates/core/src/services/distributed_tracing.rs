// Distributed Tracing Integration - OpenTelemetry and Jaeger/Zipkin export
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum TracingError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Tracing error: {0}")]
    TracingError(String),
    #[error("Export error: {0}")]
    ExportError(String),
}

pub type Result<T> = std::result::Result<T, TracingError>;

/// Trace exporter type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExporterType {
    Jaeger,
    Zipkin,
    OTLP,
}

/// Span status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SpanStatus {
    Ok,
    Error,
}

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub exporter: ExporterType,
    pub endpoint: String,
    pub sample_rate: f64, // 0.0 - 1.0
    pub service_name: String,
}

/// Trace span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    pub span_id: String,
    pub trace_id: String,
    pub parent_span_id: Option<String>,
    pub operation_name: String,
    pub started_at: DateTime<Utc>,
    pub duration_ms: Option<u64>,
    pub tags: HashMap<String, String>,
    pub status: SpanStatus,
    pub error_message: Option<String>,
}

/// Trace context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub baggage: HashMap<String, String>,
}

/// Performance metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetric {
    pub operation: String,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub avg_ms: f64,
    pub count: u64,
}

/// Trace batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBatch {
    pub traces: Vec<TraceSpan>,
    pub exported_at: DateTime<Utc>,
}

/// Distributed Tracing Integration
pub struct DistributedTracing {
    config: Arc<RwLock<TracingConfig>>,
    spans: Arc<RwLock<Vec<TraceSpan>>>,
    active_spans: Arc<RwLock<HashMap<String, TraceSpan>>>,
}

impl DistributedTracing {
    pub fn new(config: TracingConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            spans: Arc::new(RwLock::new(Vec::new())),
            active_spans: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start a new span
    pub async fn start_span(
        &self,
        operation_name: String,
        parent_span_id: Option<String>,
    ) -> Result<TraceSpan> {
        let config = self.config.read().await;
        if !config.enabled {
            return Err(TracingError::ConfigError("Tracing is disabled".to_string()));
        }
        drop(config);

        let span_id = uuid::Uuid::new_v4().to_string();
        let trace_id = if let Some(parent_id) = &parent_span_id {
            // Inherit trace_id from parent
            let active_spans = self.active_spans.read().await;
            active_spans
                .get(parent_id)
                .map(|s| s.trace_id.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
        } else {
            uuid::Uuid::new_v4().to_string()
        };

        let span = TraceSpan {
            span_id: span_id.clone(),
            trace_id,
            parent_span_id,
            operation_name,
            started_at: Utc::now(),
            duration_ms: None,
            tags: HashMap::new(),
            status: SpanStatus::Ok,
            error_message: None,
        };

        let mut active_spans = self.active_spans.write().await;
        active_spans.insert(span_id.clone(), span.clone());

        Ok(span)
    }

    /// Finish a span
    pub async fn finish_span(&self, span_id: &str) -> Result<TraceSpan> {
        let mut active_spans = self.active_spans.write().await;
        let mut span = active_spans
            .remove(span_id)
            .ok_or_else(|| TracingError::TracingError("Span not found".to_string()))?;

        drop(active_spans);

        let duration = (Utc::now() - span.started_at).num_milliseconds() as u64;
        span.duration_ms = Some(duration);

        let mut spans = self.spans.write().await;
        spans.push(span.clone());

        Ok(span)
    }

    /// Add tag to span
    pub async fn add_span_tag(&self, span_id: &str, key: String, value: String) -> Result<()> {
        let mut active_spans = self.active_spans.write().await;
        let span = active_spans
            .get_mut(span_id)
            .ok_or_else(|| TracingError::TracingError("Span not found".to_string()))?;

        span.tags.insert(key, value);

        Ok(())
    }

    /// Set span error
    pub async fn set_span_error(&self, span_id: &str, error_message: String) -> Result<()> {
        let mut active_spans = self.active_spans.write().await;
        let span = active_spans
            .get_mut(span_id)
            .ok_or_else(|| TracingError::TracingError("Span not found".to_string()))?;

        span.status = SpanStatus::Error;
        span.error_message = Some(error_message);

        Ok(())
    }

    /// Propagate context (for distributed tracing across services)
    pub async fn propagate_context(&self, span_id: &str) -> Result<String> {
        let active_spans = self.active_spans.read().await;
        let span = active_spans
            .get(span_id)
            .ok_or_else(|| TracingError::TracingError("Span not found".to_string()))?;

        // W3C traceparent format: version-trace_id-span_id-flags
        let traceparent = format!("00-{}-{}-01", span.trace_id, span.span_id);

        Ok(traceparent)
    }

    /// Extract context from traceparent header
    pub async fn extract_context(&self, traceparent: &str) -> Result<TraceContext> {
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() != 4 {
            return Err(TracingError::TracingError(
                "Invalid traceparent format".to_string(),
            ));
        }

        Ok(TraceContext {
            trace_id: parts[1].to_string(),
            span_id: parts[2].to_string(),
            baggage: HashMap::new(),
        })
    }

    /// Export traces
    pub async fn export_traces(&self) -> Result<TraceBatch> {
        let config = self.config.read().await;
        let exporter = config.exporter.clone();
        let endpoint = config.endpoint.clone();
        drop(config);

        let spans = self.spans.read().await;
        let batch = TraceBatch {
            traces: spans.clone(),
            exported_at: Utc::now(),
        };
        drop(spans);

        // Mock: Export to configured backend
        self.mock_export_to_backend(&exporter, &endpoint, &batch)
            .await?;

        // Clear exported spans
        let mut spans = self.spans.write().await;
        spans.clear();

        Ok(batch)
    }

    /// Get performance metrics
    pub async fn get_performance_metrics(&self, operation: &str) -> Option<PerformanceMetric> {
        let spans = self.spans.read().await;

        let operation_spans: Vec<_> = spans
            .iter()
            .filter(|s| s.operation_name == operation && s.duration_ms.is_some())
            .collect();

        if operation_spans.is_empty() {
            return None;
        }

        let mut durations: Vec<u64> = operation_spans
            .iter()
            .map(|s| s.duration_ms.unwrap())
            .collect();
        durations.sort();

        let count = durations.len() as u64;
        let sum: u64 = durations.iter().sum();
        let avg_ms = sum as f64 / count as f64;

        let p50_index = (count as f64 * 0.50) as usize;
        let p95_index = (count as f64 * 0.95) as usize;
        let p99_index = (count as f64 * 0.99) as usize;

        Some(PerformanceMetric {
            operation: operation.to_string(),
            p50_ms: durations.get(p50_index).copied().unwrap_or(0) as f64,
            p95_ms: durations.get(p95_index).copied().unwrap_or(0) as f64,
            p99_ms: durations.get(p99_index).copied().unwrap_or(0) as f64,
            avg_ms,
            count,
        })
    }

    /// Correlate request across services
    pub async fn correlate_request(&self, trace_id: &str) -> Vec<TraceSpan> {
        let spans = self.spans.read().await;
        spans
            .iter()
            .filter(|s| s.trace_id == trace_id)
            .cloned()
            .collect()
    }

    /// List spans
    pub async fn list_spans(&self, operation: Option<&str>) -> Vec<TraceSpan> {
        let spans = self.spans.read().await;

        if let Some(op) = operation {
            spans
                .iter()
                .filter(|s| s.operation_name == op)
                .cloned()
                .collect()
        } else {
            spans.clone()
        }
    }

    // Helper methods

    async fn mock_export_to_backend(
        &self,
        exporter: &ExporterType,
        _endpoint: &str,
        _batch: &TraceBatch,
    ) -> Result<()> {
        // Mock export based on exporter type
        match exporter {
            ExporterType::Jaeger => {
                // Mock Jaeger HTTP export
                Ok(())
            }
            ExporterType::Zipkin => {
                // Mock Zipkin export
                Ok(())
            }
            ExporterType::OTLP => {
                // Mock OTLP export
                Ok(())
            }
        }
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> TracingStatistics {
        let spans = self.spans.read().await;
        let active_spans = self.active_spans.read().await;

        let total_spans = spans.len() + active_spans.len();
        let completed_spans = spans.len();
        let active_spans_count = active_spans.len();
        let error_spans = spans.iter().filter(|s| s.status == SpanStatus::Error).count();

        let total_duration_ms: u64 = spans
            .iter()
            .filter_map(|s| s.duration_ms)
            .sum();

        let avg_duration_ms = if completed_spans > 0 {
            total_duration_ms as f64 / completed_spans as f64
        } else {
            0.0
        };

        TracingStatistics {
            total_spans,
            completed_spans,
            active_spans: active_spans_count,
            error_spans,
            avg_duration_ms,
        }
    }
}

/// Tracing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingStatistics {
    pub total_spans: usize,
    pub completed_spans: usize,
    pub active_spans: usize,
    pub error_spans: usize,
    pub avg_duration_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> TracingConfig {
        TracingConfig {
            enabled: true,
            exporter: ExporterType::Jaeger,
            endpoint: "http://jaeger:14268/api/traces".to_string(),
            sample_rate: 1.0,
            service_name: "secreton".to_string(),
        }
    }

    #[tokio::test]
    async fn test_start_finish_span() {
        let tracing = DistributedTracing::new(create_test_config());

        let span = tracing
            .start_span("secret_read".to_string(), None)
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let finished = tracing.finish_span(&span.span_id).await.unwrap();

        assert!(finished.duration_ms.is_some());
        assert!(finished.duration_ms.unwrap() >= 10);
    }

    #[tokio::test]
    async fn test_add_span_tag() {
        let tracing = DistributedTracing::new(create_test_config());

        let span = tracing
            .start_span("secret_write".to_string(), None)
            .await
            .unwrap();

        tracing
            .add_span_tag(
                &span.span_id,
                "secret_path".to_string(),
                "secret/db/password".to_string(),
            )
            .await
            .unwrap();

        tracing
            .add_span_tag(&span.span_id, "operation".to_string(), "write".to_string())
            .await
            .unwrap();

        let finished = tracing.finish_span(&span.span_id).await.unwrap();
        assert_eq!(finished.tags.len(), 2);
        assert_eq!(
            finished.tags.get("secret_path"),
            Some(&"secret/db/password".to_string())
        );
    }

    #[tokio::test]
    async fn test_propagate_context() {
        let tracing = DistributedTracing::new(create_test_config());

        let span = tracing
            .start_span("api_call".to_string(), None)
            .await
            .unwrap();

        let traceparent = tracing.propagate_context(&span.span_id).await.unwrap();

        assert!(traceparent.starts_with("00-"));
        assert!(traceparent.contains(&span.trace_id));
        assert!(traceparent.contains(&span.span_id));
    }

    #[tokio::test]
    async fn test_export_traces() {
        let tracing = DistributedTracing::new(create_test_config());

        let span = tracing
            .start_span("test_op".to_string(), None)
            .await
            .unwrap();
        tracing.finish_span(&span.span_id).await.unwrap();

        let batch = tracing.export_traces().await.unwrap();
        assert_eq!(batch.traces.len(), 1);
    }

    #[tokio::test]
    async fn test_performance_metrics() {
        let tracing = DistributedTracing::new(create_test_config());

        for _ in 0..10 {
            let span = tracing
                .start_span("db_query".to_string(), None)
                .await
                .unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            tracing.finish_span(&span.span_id).await.unwrap();
        }

        let metrics = tracing.get_performance_metrics("db_query").await.unwrap();
        assert_eq!(metrics.count, 10);
        assert!(metrics.p95_ms > 0.0);
        assert!(metrics.avg_ms >= 50.0);
    }
}
