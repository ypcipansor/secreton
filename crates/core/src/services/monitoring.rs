// Advanced Monitoring Engine - Prometheus metrics and health checks
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum MonitoringError {
    #[error("Monitoring error: {0}")]
    MonitoringError(String),
    #[error("Metric not found: {0}")]
    MetricNotFound(String),
    #[error("Health check not found: {0}")]
    HealthCheckNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, MonitoringError>;

/// Metric type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MetricType {
    Counter,   // Monotonically increasing counter
    Gauge,     // Value that can go up or down
    Histogram, // Distribution of observations
    Summary,   // Similar to histogram with quantiles
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enable_prometheus: bool,
    pub metrics_port: u16,
    pub health_check_interval_secs: u64,
    pub retention_period_hours: u64,
    pub enable_detailed_metrics: bool,
}

/// Metric definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
    pub help: String,
}

/// Health check definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthStatus,
    pub message: String,
    pub last_check: DateTime<Utc>,
    pub check_interval_secs: u64,
}

/// Prometheus exposition format
#[derive(Debug, Clone)]
pub struct PrometheusMetric {
    pub name: String,
    pub metric_type: String,
    pub help: String,
    pub samples: Vec<(HashMap<String, String>, f64, Option<i64>)>,
}

/// Advanced monitoring engine
pub struct MonitoringEngine {
    config: Arc<RwLock<MonitoringConfig>>,
    metrics: Arc<RwLock<HashMap<String, Vec<Metric>>>>,
    health_checks: Arc<RwLock<HashMap<String, HealthCheck>>>,
}

impl MonitoringEngine {
    pub fn new(config: MonitoringConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            metrics: Arc::new(RwLock::new(HashMap::new())),
            health_checks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a metric
    pub async fn record_metric(
        &self,
        name: String,
        metric_type: MetricType,
        value: f64,
        labels: HashMap<String, String>,
        help: String,
    ) -> Result<()> {
        let metric = Metric {
            name: name.clone(),
            metric_type,
            value,
            labels,
            timestamp: Utc::now(),
            help,
        };

        let mut metrics = self.metrics.write().await;
        metrics.entry(name).or_insert_with(Vec::new).push(metric);

        Ok(())
    }

    /// Increment counter
    pub async fn increment_counter(
        &self,
        name: &str,
        labels: HashMap<String, String>,
        amount: f64,
    ) -> Result<()> {
        let metrics = self.metrics.read().await;
        let current_value = metrics
            .get(name)
            .and_then(|m| m.last())
            .map(|m| m.value)
            .unwrap_or(0.0);

        drop(metrics);

        self.record_metric(
            name.to_string(),
            MetricType::Counter,
            current_value + amount,
            labels,
            format!("Counter: {}", name),
        )
        .await
    }

    /// Set gauge value
    pub async fn set_gauge(
        &self,
        name: &str,
        value: f64,
        labels: HashMap<String, String>,
    ) -> Result<()> {
        self.record_metric(
            name.to_string(),
            MetricType::Gauge,
            value,
            labels,
            format!("Gauge: {}", name),
        )
        .await
    }

    /// Observe histogram value
    pub async fn observe_histogram(
        &self,
        name: &str,
        value: f64,
        labels: HashMap<String, String>,
    ) -> Result<()> {
        self.record_metric(
            name.to_string(),
            MetricType::Histogram,
            value,
            labels,
            format!("Histogram: {}", name),
        )
        .await
    }

    /// Register health check
    pub async fn register_health_check(
        &self,
        name: String,
        check_interval_secs: u64,
    ) -> Result<()> {
        let health_check = HealthCheck {
            name: name.clone(),
            status: HealthStatus::Healthy,
            message: "Not yet checked".to_string(),
            last_check: Utc::now(),
            check_interval_secs,
        };

        let mut checks = self.health_checks.write().await;
        checks.insert(name, health_check);

        Ok(())
    }

    /// Update health check status
    pub async fn update_health_check(
        &self,
        name: &str,
        status: HealthStatus,
        message: String,
    ) -> Result<()> {
        let mut checks = self.health_checks.write().await;
        let check = checks
            .get_mut(name)
            .ok_or_else(|| MonitoringError::HealthCheckNotFound(name.to_string()))?;

        check.status = status;
        check.message = message;
        check.last_check = Utc::now();

        Ok(())
    }

    /// Run all health checks
    pub async fn run_health_checks(&self) -> HashMap<String, HealthStatus> {
        let checks = self.health_checks.read().await;
        checks
            .iter()
            .map(|(name, check)| (name.clone(), check.status.clone()))
            .collect()
    }

    /// Get overall health status
    pub async fn get_overall_health(&self) -> HealthStatus {
        let checks = self.health_checks.read().await;

        if checks.is_empty() {
            return HealthStatus::Healthy;
        }

        let statuses: Vec<HealthStatus> = checks.values().map(|c| c.status.clone()).collect();

        if statuses
            .iter()
            .any(|s| matches!(s, HealthStatus::Unhealthy))
        {
            HealthStatus::Unhealthy
        } else if statuses.iter().any(|s| matches!(s, HealthStatus::Degraded)) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let metrics = self.metrics.read().await;
        let mut output = String::new();

        for (name, metric_series) in metrics.iter() {
            if metric_series.is_empty() {
                continue;
            }

            let first_metric = &metric_series[0];

            // Write help
            output.push_str(&format!("# HELP {} {}\n", name, first_metric.help));

            // Write type
            let type_str = match first_metric.metric_type {
                MetricType::Counter => "counter",
                MetricType::Gauge => "gauge",
                MetricType::Histogram => "histogram",
                MetricType::Summary => "summary",
            };
            output.push_str(&format!("# TYPE {} {}\n", name, type_str));

            // Write samples
            for metric in metric_series.iter().rev().take(1) {
                let labels_str = if metric.labels.is_empty() {
                    String::new()
                } else {
                    let labels: Vec<String> = metric
                        .labels
                        .iter()
                        .map(|(k, v)| format!("{}=\"{}\"", k, v))
                        .collect();
                    format!("{{{}}}", labels.join(","))
                };

                output.push_str(&format!(
                    "{}{} {} {}\n",
                    name,
                    labels_str,
                    metric.value,
                    metric.timestamp.timestamp_millis()
                ));
            }
        }

        output
    }

    /// Get metrics summary
    pub async fn get_metrics_summary(&self) -> HashMap<String, serde_json::Value> {
        let metrics = self.metrics.read().await;
        let mut summary = HashMap::new();

        for (name, metric_series) in metrics.iter() {
            if let Some(latest) = metric_series.last() {
                summary.insert(
                    name.clone(),
                    serde_json::json!({
                        "type": format!("{:?}", latest.metric_type),
                        "value": latest.value,
                        "labels": latest.labels,
                        "timestamp": latest.timestamp.to_rfc3339(),
                    }),
                );
            }
        }

        summary
    }

    /// Query metrics by name and labels
    pub async fn query_metrics(
        &self,
        name: &str,
        label_filter: Option<HashMap<String, String>>,
    ) -> Vec<Metric> {
        let metrics = self.metrics.read().await;

        if let Some(metric_series) = metrics.get(name) {
            if let Some(filter) = label_filter {
                metric_series
                    .iter()
                    .filter(|m| {
                        filter
                            .iter()
                            .all(|(k, v)| m.labels.get(k).map(|val| val == v).unwrap_or(false))
                    })
                    .cloned()
                    .collect()
            } else {
                metric_series.clone()
            }
        } else {
            vec![]
        }
    }

    /// Clean up old metrics
    pub async fn cleanup_old_metrics(&self) -> usize {
        let config = self.config.read().await;
        let retention = chrono::Duration::hours(config.retention_period_hours as i64);
        let cutoff = Utc::now() - retention;

        let mut metrics = self.metrics.write().await;
        let mut removed_count = 0;

        for metric_series in metrics.values_mut() {
            let original_len = metric_series.len();
            metric_series.retain(|m| m.timestamp > cutoff);
            removed_count += original_len - metric_series.len();
        }

        removed_count
    }

    /// Get metric names
    pub async fn list_metric_names(&self) -> Vec<String> {
        let metrics = self.metrics.read().await;
        metrics.keys().cloned().collect()
    }

    /// Get health check names
    pub async fn list_health_checks(&self) -> Vec<String> {
        let checks = self.health_checks.read().await;
        checks.keys().cloned().collect()
    }
}

impl Default for MonitoringEngine {
    fn default() -> Self {
        Self::new(MonitoringConfig {
            enable_prometheus: true,
            metrics_port: 9090,
            health_check_interval_secs: 30,
            retention_period_hours: 24,
            enable_detailed_metrics: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> MonitoringConfig {
        MonitoringConfig {
            enable_prometheus: true,
            metrics_port: 9090,
            health_check_interval_secs: 30,
            retention_period_hours: 24,
            enable_detailed_metrics: true,
        }
    }

    #[tokio::test]
    async fn test_record_counter_metric() {
        let engine = MonitoringEngine::new(create_test_config());

        let mut labels = HashMap::new();
        labels.insert("endpoint".to_string(), "/api/secrets".to_string());
        labels.insert("method".to_string(), "GET".to_string());

        engine
            .record_metric(
                "http_requests_total".to_string(),
                MetricType::Counter,
                100.0,
                labels.clone(),
                "Total HTTP requests".to_string(),
            )
            .await
            .unwrap();

        let metrics = engine
            .query_metrics("http_requests_total", Some(labels))
            .await;

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].value, 100.0);
    }

    #[tokio::test]
    async fn test_increment_counter() {
        let engine = MonitoringEngine::new(create_test_config());

        let labels = HashMap::new();

        engine
            .increment_counter("requests", labels.clone(), 1.0)
            .await
            .unwrap();
        engine
            .increment_counter("requests", labels.clone(), 1.0)
            .await
            .unwrap();
        engine
            .increment_counter("requests", labels.clone(), 1.0)
            .await
            .unwrap();

        let metrics = engine.query_metrics("requests", None).await;
        let last_value = metrics.last().unwrap().value;

        assert_eq!(last_value, 3.0); // 0 + 1 + 1 + 1 = 3
    }

    #[tokio::test]
    async fn test_health_checks() {
        let engine = MonitoringEngine::new(create_test_config());

        engine
            .register_health_check("database".to_string(), 30)
            .await
            .unwrap();
        engine
            .register_health_check("storage".to_string(), 60)
            .await
            .unwrap();

        // Initially healthy
        let status = engine.get_overall_health().await;
        assert_eq!(status, HealthStatus::Healthy);

        // Update one to degraded
        engine
            .update_health_check(
                "database",
                HealthStatus::Degraded,
                "High latency".to_string(),
            )
            .await
            .unwrap();

        let status = engine.get_overall_health().await;
        assert_eq!(status, HealthStatus::Degraded);

        // Update one to unhealthy
        engine
            .update_health_check(
                "storage",
                HealthStatus::Unhealthy,
                "Connection failed".to_string(),
            )
            .await
            .unwrap();

        let status = engine.get_overall_health().await;
        assert_eq!(status, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let engine = MonitoringEngine::new(create_test_config());

        let mut labels = HashMap::new();
        labels.insert("status".to_string(), "200".to_string());

        engine
            .record_metric(
                "http_requests_total".to_string(),
                MetricType::Counter,
                42.0,
                labels,
                "Total HTTP requests".to_string(),
            )
            .await
            .unwrap();

        let output = engine.export_prometheus().await;

        assert!(output.contains("# HELP http_requests_total"));
        assert!(output.contains("# TYPE http_requests_total counter"));
        assert!(output.contains("http_requests_total{status=\"200\"}"));
        assert!(output.contains("42"));
    }

    #[tokio::test]
    async fn test_query_metrics_with_labels() {
        let engine = MonitoringEngine::new(create_test_config());

        let mut labels1 = HashMap::new();
        labels1.insert("region".to_string(), "us-east-1".to_string());

        let mut labels2 = HashMap::new();
        labels2.insert("region".to_string(), "eu-west-1".to_string());

        engine
            .set_gauge("active_connections", 10.0, labels1.clone())
            .await
            .unwrap();
        engine
            .set_gauge("active_connections", 20.0, labels2)
            .await
            .unwrap();

        let metrics = engine
            .query_metrics("active_connections", Some(labels1))
            .await;

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].value, 10.0);
    }

    #[tokio::test]
    async fn test_metrics_summary() {
        let engine = MonitoringEngine::new(create_test_config());

        engine
            .set_gauge("memory_usage", 75.5, HashMap::new())
            .await
            .unwrap();
        engine
            .increment_counter("api_calls", HashMap::new(), 100.0)
            .await
            .unwrap();

        let summary = engine.get_metrics_summary().await;

        assert!(summary.contains_key("memory_usage"));
        assert!(summary.contains_key("api_calls"));
    }
}
