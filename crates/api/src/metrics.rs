use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub value: MetricValue,
    pub tags: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(Vec<f64>),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemMetrics {
    pub performance: PerformanceMetrics,
    pub system: SystemResourceMetrics,
    pub requests: RequestMetrics,
}

impl SystemMetrics {
    pub fn record(&mut self, metric: Metric) {
        if metric.name == "requests_total" {
            if let MetricValue::Counter(val) = metric.value {
                self.requests.total_requests += val;
            }
        }
        // Simplified recording logic
    }

    pub fn update_system_metrics(&mut self, metrics: SystemResourceMetrics) {
        self.system = metrics;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceMetrics {
    pub cpu_usage_percent: f32,
    pub memory_usage_bytes: u64,
    pub total_memory_bytes: u64,
    pub disk_usage_bytes: u64,
    pub total_disk_bytes: u64,
    pub network_io_bytes: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemResourceMetrics {
    pub active_connections: u32,
    pub uptime_seconds: u64,
    pub load_average_1m: f32,
    pub load_average_5m: f32,
    pub load_average_15m: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequestMetrics {
    pub total_requests: u64,
    pub failed_requests: u64,
    pub avg_latency_ms: f64,
}
