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
