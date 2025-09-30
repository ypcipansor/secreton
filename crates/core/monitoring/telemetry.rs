/// Telemetry Integration for Secreton
/// Supports Prometheus, StatsD, and Datadog metrics

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Enable telemetry
    pub enabled: bool,
    /// Prometheus configuration
    pub prometheus: Option<PrometheusConfig>,
    /// StatsD configuration
    pub statsd: Option<StatsDConfig>,
    /// Datadog configuration
    pub datadog: Option<DatadogConfig>,
}

/// Prometheus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusConfig {
    /// Enable Prometheus exporter
    pub enabled: bool,
    /// Prometheus metrics endpoint path
    pub path: String,
    /// Prometheus listen address
    pub listen_address: String,
    /// Metrics prefix
    pub prefix: String,
}

/// StatsD configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsDConfig {
    /// Enable StatsD
    pub enabled: bool,
    /// StatsD server address
    pub address: String,
    /// Metrics prefix
    pub prefix: String,
}

/// Datadog configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatadogConfig {
    /// Enable Datadog
    pub enabled: bool,
    /// Datadog agent address
    pub address: String,
    /// Datadog API key
    pub api_key: String,
    /// Metrics prefix
    pub prefix: String,
    /// Tags
    pub tags: Vec<String>,
}

/// Metric type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

/// Metric data
#[derive(Debug, Clone)]
pub struct Metric {
    pub name: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Telemetry engine
pub struct TelemetryEngine {
    config: TelemetryConfig,
    metrics: Arc<RwLock<HashMap<String, Metric>>>,
    prometheus_registry: Arc<RwLock<PrometheusRegistry>>,
}

/// Prometheus registry
struct PrometheusRegistry {
    metrics: HashMap<String, PrometheusMetric>,
}

/// Prometheus metric
struct PrometheusMetric {
    name: String,
    metric_type: MetricType,
    help: String,
    values: HashMap<String, f64>,
}

impl TelemetryEngine {
    /// Create new telemetry engine
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(RwLock::new(HashMap::new())),
            prometheus_registry: Arc::new(RwLock::new(PrometheusRegistry {
                metrics: HashMap::new(),
            })),
        }
    }

    /// Record a counter metric
    pub async fn counter(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        if !self.config.enabled {
            return;
        }

        let metric = Metric {
            name: name.to_string(),
            metric_type: MetricType::Counter,
            value,
            labels: labels.clone(),
            timestamp: chrono::Utc::now(),
        };

        // Store metric
        let mut metrics = self.metrics.write().await;
        metrics.insert(name.to_string(), metric.clone());

        // Send to backends
        self.send_to_prometheus(&metric).await;
        self.send_to_statsd(&metric).await;
        self.send_to_datadog(&metric).await;
    }

    /// Record a gauge metric
    pub async fn gauge(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        if !self.config.enabled {
            return;
        }

        let metric = Metric {
            name: name.to_string(),
            metric_type: MetricType::Gauge,
            value,
            labels: labels.clone(),
            timestamp: chrono::Utc::now(),
        };

        let mut metrics = self.metrics.write().await;
        metrics.insert(name.to_string(), metric.clone());

        self.send_to_prometheus(&metric).await;
        self.send_to_statsd(&metric).await;
        self.send_to_datadog(&metric).await;
    }

    /// Record a histogram metric
    pub async fn histogram(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        if !self.config.enabled {
            return;
        }

        let metric = Metric {
            name: name.to_string(),
            metric_type: MetricType::Histogram,
            value,
            labels: labels.clone(),
            timestamp: chrono::Utc::now(),
        };

        let mut metrics = self.metrics.write().await;
        metrics.insert(name.to_string(), metric.clone());

        self.send_to_prometheus(&metric).await;
        self.send_to_statsd(&metric).await;
        self.send_to_datadog(&metric).await;
    }

    /// Get Prometheus metrics in text format
    pub async fn get_prometheus_metrics(&self) -> String {
        let registry = self.prometheus_registry.read().await;
        let mut output = String::new();

        for (_, metric) in &registry.metrics {
            // Add HELP line
            output.push_str(&format!("# HELP {} {}\n", metric.name, metric.help));
            
            // Add TYPE line
            let type_str = match metric.metric_type {
                MetricType::Counter => "counter",
                MetricType::Gauge => "gauge",
                MetricType::Histogram => "histogram",
                MetricType::Summary => "summary",
            };
            output.push_str(&format!("# TYPE {} {}\n", metric.name, type_str));

            // Add metric values
            for (labels, value) in &metric.values {
                if labels.is_empty() {
                    output.push_str(&format!("{} {}\n", metric.name, value));
                } else {
                    output.push_str(&format!("{}{{{}}} {}\n", metric.name, labels, value));
                }
            }
        }

        output
    }

    /// Send metric to Prometheus
    async fn send_to_prometheus(&self, metric: &Metric) {
        if let Some(prom_config) = &self.config.prometheus {
            if !prom_config.enabled {
                return;
            }

            let mut registry = self.prometheus_registry.write().await;
            let full_name = format!("{}_{}", prom_config.prefix, metric.name);

            // Format labels
            let labels_str = metric.labels.iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect::<Vec<_>>()
                .join(",");

            let prom_metric = registry.metrics.entry(full_name.clone()).or_insert(PrometheusMetric {
                name: full_name.clone(),
                metric_type: metric.metric_type,
                help: format!("Secreton metric: {}", metric.name),
                values: HashMap::new(),
            });

            prom_metric.values.insert(labels_str, metric.value);
        }
    }

    /// Send metric to StatsD
    async fn send_to_statsd(&self, metric: &Metric) {
        if let Some(statsd_config) = &self.config.statsd {
            if !statsd_config.enabled {
                return;
            }

            // Format StatsD metric
            let full_name = format!("{}.{}", statsd_config.prefix, metric.name);
            let metric_str = match metric.metric_type {
                MetricType::Counter => format!("{}:{}|c", full_name, metric.value),
                MetricType::Gauge => format!("{}:{}|g", full_name, metric.value),
                MetricType::Histogram => format!("{}:{}|h", full_name, metric.value),
                MetricType::Summary => format!("{}:{}|ms", full_name, metric.value),
            };

            // Send to StatsD (UDP)
            // In production, you'd use a proper StatsD client
            tracing::debug!("StatsD metric: {}", metric_str);
        }
    }

    /// Send metric to Datadog
    async fn send_to_datadog(&self, metric: &Metric) {
        if let Some(dd_config) = &self.config.datadog {
            if !dd_config.enabled {
                return;
            }

            // Format Datadog metric
            let full_name = format!("{}.{}", dd_config.prefix, metric.name);
            
            // In production, you'd use the Datadog API
            tracing::debug!("Datadog metric: {} = {}", full_name, metric.value);
        }
    }

    /// Get all metrics
    pub async fn get_metrics(&self) -> HashMap<String, Metric> {
        self.metrics.read().await.clone()
    }

    /// Clear all metrics
    pub async fn clear_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.clear();

        let mut registry = self.prometheus_registry.write().await;
        registry.metrics.clear();
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            prometheus: Some(PrometheusConfig {
                enabled: false,
                path: "/metrics".to_string(),
                listen_address: "0.0.0.0:9090".to_string(),
                prefix: "secreton".to_string(),
            }),
            statsd: Some(StatsDConfig {
                enabled: false,
                address: "localhost:8125".to_string(),
                prefix: "secreton".to_string(),
            }),
            datadog: Some(DatadogConfig {
                enabled: false,
                address: "localhost:8126".to_string(),
                api_key: String::new(),
                prefix: "secreton".to_string(),
                tags: vec![],
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_telemetry_engine_creation() {
        let config = TelemetryConfig::default();
        let engine = TelemetryEngine::new(config);
        
        let metrics = engine.get_metrics().await;
        assert_eq!(metrics.len(), 0);
    }

    #[tokio::test]
    async fn test_counter_metric() {
        let mut config = TelemetryConfig::default();
        config.enabled = true;
        
        let engine = TelemetryEngine::new(config);
        
        let mut labels = HashMap::new();
        labels.insert("operation".to_string(), "read".to_string());
        
        engine.counter("requests_total", 1.0, labels).await;
        
        let metrics = engine.get_metrics().await;
        assert_eq!(metrics.len(), 1);
        assert!(metrics.contains_key("requests_total"));
    }

    #[tokio::test]
    async fn test_gauge_metric() {
        let mut config = TelemetryConfig::default();
        config.enabled = true;
        
        let engine = TelemetryEngine::new(config);
        
        engine.gauge("active_connections", 42.0, HashMap::new()).await;
        
        let metrics = engine.get_metrics().await;
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics.get("active_connections").unwrap().value, 42.0);
    }

    #[tokio::test]
    async fn test_prometheus_output() {
        let mut config = TelemetryConfig::default();
        config.enabled = true;
        config.prometheus = Some(PrometheusConfig {
            enabled: true,
            path: "/metrics".to_string(),
            listen_address: "0.0.0.0:9090".to_string(),
            prefix: "test".to_string(),
        });
        
        let engine = TelemetryEngine::new(config);
        
        engine.counter("requests", 10.0, HashMap::new()).await;
        
        let output = engine.get_prometheus_metrics().await;
        assert!(output.contains("test_requests"));
        assert!(output.contains("# TYPE"));
        assert!(output.contains("# HELP"));
    }

    #[tokio::test]
    async fn test_clear_metrics() {
        let mut config = TelemetryConfig::default();
        config.enabled = true;
        
        let engine = TelemetryEngine::new(config);
        
        engine.counter("test", 1.0, HashMap::new()).await;
        assert_eq!(engine.get_metrics().await.len(), 1);
        
        engine.clear_metrics().await;
        assert_eq!(engine.get_metrics().await.len(), 0);
    }
}
