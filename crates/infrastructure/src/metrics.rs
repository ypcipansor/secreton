//! Metrics System
//!
//! Observability metrics collection and export for monitoring
//! system performance and health.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Metric type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MetricType {
    /// Counter (monotonically increasing)
    Counter,

    /// Gauge (can increase or decrease)
    Gauge,

    /// Histogram (distribution of values)
    Histogram,
}

/// Metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(Vec<f64>),
}

/// Metric metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    /// Metric _name
    pub _name: String,

    /// Metric type
    pub metric_type: MetricType,

    /// Value
    pub value: MetricValue,

    /// Labels
    pub labels: HashMap<String, String>,

    /// Help text
    pub help: String,

    /// Last updated
    pub updated_at: DateTime<Utc>,
}

impl Metric {
    /// Create counter metric
    pub fn counter(_name: String, help: String) -> Self {
        Self {
            _name,
            metric_type: MetricType::Counter,
            value: MetricValue::Counter(0),
            labels: HashMap::new(),
            help,
            updated_at: Utc::now(),
        }
    }

    /// Create gauge metric
    pub fn gauge(_name: String, help: String) -> Self {
        Self {
            _name,
            metric_type: MetricType::Gauge,
            value: MetricValue::Gauge(0.0),
            labels: HashMap::new(),
            help,
            updated_at: Utc::now(),
        }
    }

    /// Create histogram metric
    pub fn histogram(_name: String, help: String) -> Self {
        Self {
            _name,
            metric_type: MetricType::Histogram,
            value: MetricValue::Histogram(Vec::new()),
            labels: HashMap::new(),
            help,
            updated_at: Utc::now(),
        }
    }

    /// Add label
    pub fn with_label(mut self, _key: String, value: String) -> Self {
        self.labels.insert(_key, value);
        self
    }
}

/// Metrics registry
pub struct MetricsRegistry {
    metrics: Arc<RwLock<HashMap<String, Metric>>>,
}

impl MetricsRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register metric
    pub async fn register(&self, metric: Metric) {
        let mut metrics = self.metrics.write().await;
        metrics.insert(metric._name.clone(), metric);
    }

    /// Increment counter
    pub async fn increment_counter(&self, _name: &str, delta: u64) {
        let mut metrics = self.metrics.write().await;

        if let Some(metric) = metrics.get_mut(_name) {
            if let MetricValue::Counter(ref mut value) = metric.value {
                *value += delta;
                metric.updated_at = Utc::now();
            }
        }
    }

    /// Set gauge value
    pub async fn set_gauge(&self, _name: &str, value: f64) {
        let mut metrics = self.metrics.write().await;

        if let Some(metric) = metrics.get_mut(_name) {
            if let MetricValue::Gauge(ref mut current) = metric.value {
                *current = value;
                metric.updated_at = Utc::now();
            }
        }
    }

    /// Increment gauge
    pub async fn increment_gauge(&self, _name: &str, delta: f64) {
        let mut metrics = self.metrics.write().await;

        if let Some(metric) = metrics.get_mut(_name) {
            if let MetricValue::Gauge(ref mut value) = metric.value {
                *value += delta;
                metric.updated_at = Utc::now();
            }
        }
    }

    /// Decrement gauge
    pub async fn decrement_gauge(&self, _name: &str, delta: f64) {
        let mut metrics = self.metrics.write().await;

        if let Some(metric) = metrics.get_mut(_name) {
            if let MetricValue::Gauge(ref mut value) = metric.value {
                *value -= delta;
                metric.updated_at = Utc::now();
            }
        }
    }

    /// Record histogram observation
    pub async fn observe_histogram(&self, _name: &str, value: f64) {
        let mut metrics = self.metrics.write().await;

        if let Some(metric) = metrics.get_mut(_name) {
            if let MetricValue::Histogram(ref mut values) = metric.value {
                values.push(value);
                metric.updated_at = Utc::now();

                // Keep only last 1000 observations
                if values.len() > 1000 {
                    values.drain(0..values.len() - 1000);
                }
            }
        }
    }

    /// Get metric
    pub async fn get(&self, _name: &str) -> Option<Metric> {
        let metrics = self.metrics.read().await;
        metrics.get(_name).cloned()
    }

    /// Get all metrics
    pub async fn get_all(&self) -> Vec<Metric> {
        let metrics = self.metrics.read().await;
        metrics.values().cloned().collect()
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let metrics = self.metrics.read().await;
        let mut output = String::new();

        for metric in metrics.values() {
            // Help text
            output.push_str(&format!("# HELP {} {}\n", metric._name, metric.help));

            // Type
            let type_str = match metric.metric_type {
                MetricType::Counter => "counter",
                MetricType::Gauge => "gauge",
                MetricType::Histogram => "histogram",
            };
            output.push_str(&format!("# TYPE {} {}\n", metric._name, type_str));

            // Labels
            let labels = if metric.labels.is_empty() {
                String::new()
            } else {
                let label_str = metric
                    .labels
                    .iter()
                    .map(|(k, v)| format!("{}=\"{}\"", k, v))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{{{}}}", label_str)
            };

            // Value
            match &metric.value {
                MetricValue::Counter(v) => {
                    output.push_str(&format!("{}{} {}\n", metric._name, labels, v));
                }
                MetricValue::Gauge(v) => {
                    output.push_str(&format!("{}{} {}\n", metric._name, labels, v));
                }
                MetricValue::Histogram(values) => {
                    if !values.is_empty() {
                        let sum: f64 = values.iter().sum();
                        let count = values.len();

                        output.push_str(&format!("{}_sum{} {}\n", metric._name, labels, sum));
                        output.push_str(&format!("{}_count{} {}\n", metric._name, labels, count));

                        // Calculate quantiles
                        let mut sorted = values.clone();
                        sorted
                            .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

                        for (quantile, label) in &[(0.5, "0.5"), (0.9, "0.9"), (0.99, "0.99")] {
                            let idx = ((sorted.len() as f64) * quantile) as usize;
                            let value = sorted.get(idx.min(sorted.len() - 1)).unwrap_or(&0.0);
                            output.push_str(&format!(
                                "{}{{quantile=\"{}\"}}{} {}\n",
                                metric._name, label, labels, value
                            ));
                        }
                    }
                }
            }

            output.push('\n');
        }

        output
    }

    /// Clear all metrics
    pub async fn clear(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.clear();
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard metrics
pub struct StandardMetrics {
    registry: Arc<MetricsRegistry>,
}

impl StandardMetrics {
    /// Create and register standard metrics
    pub async fn new(registry: Arc<MetricsRegistry>) -> Self {
        // Request metrics
        registry
            .register(Metric::counter(
                "secreton_requests_total".to_string(),
                "Total number of requests".to_string(),
            ))
            .await;

        registry
            .register(Metric::histogram(
                "secreton_request_duration_seconds".to_string(),
                "Request duration in seconds".to_string(),
            ))
            .await;

        // Secret metrics
        registry
            .register(Metric::counter(
                "secreton_secrets_read_total".to_string(),
                "Total number of _secret reads".to_string(),
            ))
            .await;

        registry
            .register(Metric::counter(
                "secreton_secrets_written_total".to_string(),
                "Total number of _secret writes".to_string(),
            ))
            .await;

        // Token metrics
        registry
            .register(Metric::gauge(
                "secreton_tokens_active".to_string(),
                "Number of active tokens".to_string(),
            ))
            .await;

        registry
            .register(Metric::counter(
                "secreton_tokens_created_total".to_string(),
                "Total number of tokens created".to_string(),
            ))
            .await;

        // Lease metrics
        registry
            .register(Metric::gauge(
                "secreton_leases_active".to_string(),
                "Number of active leases".to_string(),
            ))
            .await;

        Self { registry }
    }

    /// Record _request
    pub async fn record_request(&self, duration_seconds: f64) {
        self.registry
            .increment_counter("secreton_requests_total", 1)
            .await;
        self.registry
            .observe_histogram("secreton_request_duration_seconds", duration_seconds)
            .await;
    }

    /// Record _secret read
    pub async fn record_secret_read(&self) {
        self.registry
            .increment_counter("secreton_secrets_read_total", 1)
            .await;
    }

    /// Record _secret write
    pub async fn record_secret_write(&self) {
        self.registry
            .increment_counter("secreton_secrets_written_total", 1)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_counter() {
        let registry = MetricsRegistry::new();

        registry
            .register(Metric::counter(
                "test_counter".to_string(),
                "Test counter".to_string(),
            ))
            .await;

        registry.increment_counter("test_counter", 5).await;
        registry.increment_counter("test_counter", 3).await;

        let metric = registry.get("test_counter").await.unwrap();
        assert!(matches!(metric.value, MetricValue::Counter(8)));
    }

    #[tokio::test]
    async fn test_gauge() {
        let registry = MetricsRegistry::new();

        registry
            .register(Metric::gauge(
                "test_gauge".to_string(),
                "Test gauge".to_string(),
            ))
            .await;

        registry.set_gauge("test_gauge", 10.5).await;
        registry.increment_gauge("test_gauge", 2.5).await;
        registry.decrement_gauge("test_gauge", 1.0).await;

        let metric = registry.get("test_gauge").await.unwrap();
        if let MetricValue::Gauge(value) = metric.value {
            assert!((value - 12.0).abs() < 0.01);
        } else {
            panic!("Expected gauge value");
        }
    }

    #[tokio::test]
    async fn test_histogram() {
        let registry = MetricsRegistry::new();

        registry
            .register(Metric::histogram(
                "test_histogram".to_string(),
                "Test histogram".to_string(),
            ))
            .await;

        registry.observe_histogram("test_histogram", 1.0).await;
        registry.observe_histogram("test_histogram", 2.0).await;
        registry.observe_histogram("test_histogram", 3.0).await;

        let metric = registry.get("test_histogram").await.unwrap();
        if let MetricValue::Histogram(values) = metric.value {
            assert_eq!(values.len(), 3);
        } else {
            panic!("Expected histogram value");
        }
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let registry = MetricsRegistry::new();

        registry
            .register(Metric::counter(
                "test_total".to_string(),
                "Test counter".to_string(),
            ))
            .await;

        registry.increment_counter("test_total", 42).await;

        let output = registry.export_prometheus().await;
        assert!(output.contains("# HELP test_total Test counter"));
        assert!(output.contains("# TYPE test_total counter"));
        assert!(output.contains("test_total 42"));
    }
}
