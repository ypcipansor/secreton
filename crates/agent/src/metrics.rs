//! Metrics collection module for the Brankas agent

use crate::config::MetricsConfig;
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use secreton_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tokio::sync::mpsc;

/// Metrics server for serving Prometheus metrics
pub struct MetricsServer {
    config: MetricsConfig,
    metrics: Arc<RwLock<HashMap<String, MetricSeries>>>,
}

/// Shared state for the metrics server
#[derive(Clone)]
struct AppState {
    metrics: Arc<RwLock<HashMap<String, MetricSeries>>>,
}

impl MetricsServer {
    /// Create a new metrics server
    pub async fn new(port: u16) -> CoreResult<Self> {
        let mut config = MetricsConfig::default();
        config.prometheus_port = port;

        Ok(Self {
            config,
            metrics: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Serve metrics via HTTP
    pub async fn serve(self) -> CoreResult<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.prometheus_port));

        let app_state = AppState {
            metrics: self.metrics.clone(),
        };

        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .with_state(app_state);

        tracing::info!("Starting metrics server on {}", addr);

        let listener =
            tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| CoreError::Internal {
                    message: format!("Failed to bind to address: {}", e),
                })?;

        axum::serve(listener, app)
            .await
            .map_err(|e| CoreError::Internal {
                message: format!("Server error: {}", e),
            })?;

        Ok(())
    }
}

/// Metric types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

/// Metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    /// Metric name
    pub name: String,

    /// Metric type
    pub metric_type: MetricType,

    /// Metric value
    pub value: f64,

    /// Timestamp
    pub timestamp: u64,

    /// Labels/tags
    pub labels: HashMap<String, String>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl MetricPoint {
    /// Create a new metric point
    pub fn new(name: String, metric_type: MetricType, value: f64) -> Self {
        Self {
            name,
            metric_type,
            value,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            labels: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Metric series (time series data for a metric)
#[derive(Debug, Clone)]
pub struct MetricSeries {
    /// Metric name
    pub name: String,

    /// Metric type
    pub metric_type: MetricType,

    /// Data points
    pub points: VecDeque<MetricPoint>,
}

/// Metrics collector
#[derive(Debug)]
pub struct MetricsCollector {
    /// Configuration
    config: MetricsConfig,

    /// Metric series storage
    metrics: Arc<RwLock<HashMap<String, MetricSeries>>>,

    /// Metric points receiver
    metric_receiver: mpsc::UnboundedReceiver<MetricPoint>,

    /// Agent start time
    start_time: SystemTime,

    /// Running flag
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(
        config: MetricsConfig,
        metric_receiver: mpsc::UnboundedReceiver<MetricPoint>,
    ) -> Self {
        Self {
            config,
            metrics: Arc::new(RwLock::new(HashMap::new())),
            metric_receiver,
            start_time: SystemTime::now(),
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Create a new metrics collector with config only (for testing)
    pub fn new_with_config(config: MetricsConfig) -> Self {
        let (_tx, metric_receiver) = mpsc::unbounded_channel();
        Self::new(config, metric_receiver)
    }

    /// Start metrics collection
    pub async fn start(&mut self) -> CoreResult<()> {
        tracing::info!("Starting metrics collector");

        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let collection_interval = Duration::from_secs(self.config.collection_interval_seconds);
        let mut last_collection = SystemTime::now();

        while self.running.load(std::sync::atomic::Ordering::SeqCst) {
            // Process incoming metric points
            self.process_metric_points().await?;

            // Collect system metrics periodically
            if last_collection.elapsed().unwrap_or(Duration::ZERO) >= collection_interval {
                self.collect_system_metrics().await?;
                last_collection = SystemTime::now();
            }

            // Export metrics if configured
            if self.config.prometheus_enabled {
                self.export_prometheus_metrics().await?;
            }

            if self.config.statsd_enabled {
                self.export_statsd_metrics().await?;
            }

            // Clean up old metrics
            self.cleanup_old_metrics().await?;

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Ok(())
    }

    /// Stop metrics collection
    pub async fn stop(&mut self) -> CoreResult<()> {
        tracing::info!("Stopping metrics collector");
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Process incoming metric points
    async fn process_metric_points(&mut self) -> CoreResult<()> {
        while let Ok(point) = self.metric_receiver.try_recv() {
            self.add_metric_point(point).await?;
        }
        Ok(())
    }

    /// Add a metric point
    pub async fn add_metric_point(&self, point: MetricPoint) -> CoreResult<()> {
        let series_key = format!("{}:{:?}", point.name, point.metric_type);

        let mut metrics = self.metrics.write().unwrap();
        let series = metrics.entry(series_key.clone()).or_insert_with(|| {
            MetricSeries {
                name: point.name.clone(),
                metric_type: point.metric_type.clone(),
                points: VecDeque::new(),
            }
        });

        series.points.push_back(point);

        Ok(())
    }

    /// Collect system metrics
    async fn collect_system_metrics(&self) -> CoreResult<()> {
        tracing::debug!("Collecting system metrics");

        // Performance metrics
        let cpu_usage = self.get_cpu_usage().await?;
        let memory_usage = self.get_memory_usage().await?;
        let disk_usage = self.get_disk_usage().await?;
        let load_average = self.get_load_average().await?;
        let network_stats = self.get_network_stats().await?;

        // Create metric points
        let points = vec![
            MetricPoint::new(
                "system_cpu_usage_percent".to_string(),
                MetricType::Gauge,
                cpu_usage,
            ),
            MetricPoint::new(
                "system_memory_usage_percent".to_string(),
                MetricType::Gauge,
                memory_usage,
            ),
            MetricPoint::new(
                "system_disk_usage_percent".to_string(),
                MetricType::Gauge,
                disk_usage,
            ),
            MetricPoint::new(
                "system_load_average_1m".to_string(),
                MetricType::Gauge,
                load_average,
            ),
            MetricPoint::new(
                "system_network_bytes_sent".to_string(),
                MetricType::Counter,
                network_stats.0,
            ),
            MetricPoint::new(
                "system_network_bytes_received".to_string(),
                MetricType::Counter,
                network_stats.1,
            ),
        ];

        // Add to metrics storage
        for point in points {
            self.add_metric_point(point).await?;
        }

        Ok(())
    }

    /// Get CPU usage percentage
    async fn get_cpu_usage(&self) -> CoreResult<f64> {
        let mut system = System::new();
        system.refresh_cpu();

        // Calculate average CPU usage across all cores
        let cpu_usage: f64 = system.cpus().iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() as f64
            / system.cpus().len() as f64;

        Ok(cpu_usage)
    }

    /// Get memory usage percentage
    async fn get_memory_usage(&self) -> CoreResult<f64> {
        let mut system = System::new();
        system.refresh_memory();

        let total_memory = system.total_memory();
        let used_memory = system.used_memory();

        if total_memory > 0 {
            Ok((used_memory as f64 / total_memory as f64) * 100.0)
        } else {
            Ok(0.0)
        }
    }

    /// Get disk usage percentage
    async fn get_disk_usage(&self) -> CoreResult<f64> {
        let _system = System::new();

        // For sysinfo 0.30, use Disks API
        use sysinfo::Disks;
        let disks = Disks::new_with_refreshed_list();

        // Calculate total disk usage across all disks
        let mut total_available = 0u64;
        let mut total_used = 0u64;

        for disk in disks.iter() {
            total_available += disk.total_space();
            total_used += disk.total_space() - disk.available_space();
        }

        if total_available > 0 {
            Ok((total_used as f64 / total_available as f64) * 100.0)
        } else {
            Ok(0.0)
        }
    }

    /// Get load average
    async fn get_load_average(&self) -> CoreResult<f64> {
        // Load average is not directly available in sysinfo
        // For now, return a placeholder value
        Ok(1.0) // Placeholder - would need platform-specific implementation
    }

    /// Get network statistics (bytes sent, bytes received)
    async fn get_network_stats(&self) -> CoreResult<(f64, f64)> {
        // For sysinfo 0.30, use Networks API
        use sysinfo::Networks;
        let networks = Networks::new_with_refreshed_list();

        let mut total_received = 0u64;
        let mut total_transmitted = 0u64;

        for (_, network) in networks.iter() {
            total_received += network.received();
            total_transmitted += network.transmitted();
        }

        Ok((total_transmitted as f64, total_received as f64))
    }

    /// Export metrics to Prometheus format
    async fn export_prometheus_metrics(&self) -> CoreResult<()> {
        if !self.config.prometheus_enabled {
            return Ok(());
        }

        tracing::debug!("Exporting Prometheus metrics");

        let metrics = self.metrics.read().unwrap();
        let mut prometheus_output = String::new();

        for (_, series) in metrics.iter() {
            if let Some(latest) = series.points.back() {
                prometheus_output.push_str(&format!(
                    "# TYPE {} {}\n",
                    series.name.replace('-', "_"),
                    match series.metric_type {
                        MetricType::Counter => "counter",
                        MetricType::Gauge => "gauge",
                        MetricType::Histogram => "histogram",
                        MetricType::Summary => "summary",
                    }
                ));

                let mut labels = String::new();
                if !latest.labels.is_empty() {
                    let label_pairs: Vec<String> = latest
                        .labels
                        .iter()
                        .map(|(k, v)| format!("{}=\"{}\"", k, v))
                        .collect();
                    labels = format!("{{{}}}", label_pairs.join(","));
                }

                prometheus_output.push_str(&format!(
                    "{}{} {}\n",
                    series.name.replace('-', "_"),
                    labels,
                    latest.value
                ));
            }
        }

        // In a real implementation, this would be served via HTTP endpoint
        tracing::debug!(
            "Prometheus metrics: {} lines",
            prometheus_output.lines().count()
        );

        Ok(())
    }

    /// Export metrics to StatsD
    async fn export_statsd_metrics(&self) -> CoreResult<()> {
        if !self.config.statsd_enabled {
            return Ok(());
        }

        tracing::debug!("Exporting StatsD metrics");

        let metrics = self.metrics.read().unwrap();

        for (_, series) in metrics.iter() {
            if let Some(latest) = series.points.back() {
                let metric_type_suffix = match series.metric_type {
                    MetricType::Counter => "c",
                    MetricType::Gauge => "g",
                    MetricType::Histogram => "h",
                    MetricType::Summary => "ms",
                };

                let statsd_metric =
                    format!("{}:{}|{}", series.name, latest.value, metric_type_suffix);

                // In a real implementation, this would be sent via UDP to StatsD server
                tracing::debug!("StatsD metric: {}", statsd_metric);
            }
        }

        Ok(())
    }

    /// Clean up old metrics
    async fn cleanup_old_metrics(&self) -> CoreResult<()> {
        let retention_cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - self.config.retention_seconds;

        let mut metrics = self.metrics.write().unwrap();

        for (_, series) in metrics.iter_mut() {
            series
                .points
                .retain(|point| point.timestamp >= retention_cutoff);
        }

        // Remove empty series
        metrics.retain(|_, series| !series.points.is_empty());

        Ok(())
    }

    /// Get metric series by name
    pub fn get_metric_series(&self, name: &str) -> Option<MetricSeries> {
        let metrics = self.metrics.read().unwrap();
        for (_, series) in metrics.iter() {
            if series.name == name {
                return Some(series.clone());
            }
        }
        None
    }

    /// Record a custom metric
    pub async fn record_metric(
        &self,
        name: String,
        metric_type: MetricType,
        value: f64,
        labels: HashMap<String, String>,
    ) -> CoreResult<()> {
        let mut point = MetricPoint::new(name, metric_type, value);
        point.labels.extend(labels);
        self.add_metric_point(point).await
    }

    /// Get all metric names
    pub fn get_metric_names(&self) -> Vec<String> {
        let metrics = self.metrics.read().unwrap();
        metrics.values().map(|series| series.name.clone()).collect()
    }

    /// Check if metrics collector is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get uptime in seconds
    pub fn get_uptime(&self) -> u64 {
        self.start_time
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

/// HTTP handler for /metrics endpoint
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Generate Prometheus format metrics
    let metrics = state.metrics.read().unwrap();
    let mut prometheus_output = String::new();

    for (_, series) in metrics.iter() {
        if let Some(latest) = series.points.back() {
            prometheus_output.push_str(&format!(
                "# TYPE {} {}\n",
                series.name.replace('-', "_"),
                match series.metric_type {
                    MetricType::Counter => "counter",
                    MetricType::Gauge => "gauge",
                    MetricType::Histogram => "histogram",
                    MetricType::Summary => "summary",
                }
            ));

            prometheus_output.push_str(&format!(
                "{}{} {}\n",
                series.name.replace('-', "_"),
                if latest.labels.is_empty() {
                    String::new()
                } else {
                    format!(
                        "{{{}}}",
                        latest
                            .labels
                            .iter()
                            .map(|(k, v)| format!("{}=\"{}\"", k, v))
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                },
                latest.value
            ));
        }
    }

    (StatusCode::OK, prometheus_output)
}

/// HTTP handler for /health endpoint
async fn health_handler(State(_state): State<AppState>) -> impl IntoResponse {
    // Simple health check
    let health_status = "healthy";
    (
        StatusCode::OK,
        format!("{{\"status\":\"{}\"}}", health_status),
    )
}
