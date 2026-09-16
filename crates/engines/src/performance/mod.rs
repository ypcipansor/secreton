//! # Secreton Performance Optimization
//!
//! Unified performance optimization, monitoring, and benchmarking system for Secreton.
//! Provides security-aware performance optimization, secret access optimization, and
//! comprehensive performance monitoring capabilities.
//!
//! ## Features
//!
//! - **Security Performance Optimizer**: Balances security requirements with performance needs
//! - **Secret Performance Optimizer**: Optimizes secret access patterns, caching, and queries
//! - **Performance Monitoring**: Comprehensive metrics collection and analysis
//! - **Benchmarking**: Automated performance benchmarking and regression detection
//! - **Adaptive Optimization**: Runtime performance adaptation based on usage patterns
//!
//! ## Security vs Performance Balance
//!
//! The system provides different optimization levels:
//!
//! - **MaximumSecurity**: Highest security, minimum performance (production-critical)
//! - **HighSecurity**: Good security with performance (standard production)
//! - **Balanced**: Balanced security and performance (development/staging)
//! - **MaximumPerformance**: Maximum performance, reduced security (testing only)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// Re-export optimization levels
pub use optimization_levels::*;

// Re-export security performance optimizer
pub use security_optimizer::*;

// Re-export secret performance optimizer
pub use secret_optimizer::*;

mod optimization_levels;
mod secret_optimizer;
mod security_optimizer;

/// Main performance optimization coordinator
#[derive(Debug)]
pub struct PerformanceCoordinator {
    security_optimizer: Arc<RwLock<SecurityPerformanceOptimizer>>,
    secret_optimizer: Arc<RwLock<SecretPerformanceOptimizer>>,
    metrics_aggregator: Arc<MetricsAggregator>,
}

impl PerformanceCoordinator {
    /// Create a new performance coordinator
    pub fn new(security_config: PerformanceConfig, secret_config: SecretPerformanceConfig) -> Self {
        Self {
            security_optimizer: Arc::new(RwLock::new(SecurityPerformanceOptimizer::new(
                security_config,
            ))),
            secret_optimizer: Arc::new(RwLock::new(SecretPerformanceOptimizer::new(secret_config))),
            metrics_aggregator: Arc::new(MetricsAggregator::new()),
        }
    }

    /// Record operation metrics for security optimizer
    pub async fn record_security_operation(
        &self,
        operation_name: &str,
        duration: Duration,
        success: bool,
    ) {
        let mut optimizer = self.security_optimizer.write().await;
        optimizer.record_operation(operation_name, duration, success);

        // Also aggregate in metrics aggregator
        self.metrics_aggregator
            .record_metric(
                "security_operation",
                operation_name,
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            )
            .await;
    }

    /// Record secret access metrics for secret optimizer
    pub async fn record_secret_access(
        &self,
        secret_path: &str,
        access_type: AccessType,
        duration: Duration,
        success: bool,
    ) {
        let optimizer = self.secret_optimizer.write().await;
        optimizer
            .record_access(secret_path, access_type, duration, success)
            .await;

        // Also aggregate in metrics aggregator
        self.metrics_aggregator
            .record_metric(
                "secret_access",
                secret_path,
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            )
            .await;
    }

    /// Get comprehensive performance recommendations
    pub async fn get_performance_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Get security performance recommendations
        {
            let optimizer = self.security_optimizer.read().await;
            recommendations.extend(optimizer.get_optimization_recommendations());
        }

        // Get secret performance recommendations
        {
            let optimizer = self.secret_optimizer.read().await;
            recommendations.extend(
                optimizer
                    .get_scaling_recommendations()
                    .await
                    .unwrap_or_default(),
            );
        }

        recommendations
    }

    /// Get aggregated performance metrics
    pub async fn get_aggregated_metrics(&self) -> AggregatedMetrics {
        let security_metrics = {
            let optimizer = self.security_optimizer.read().await;
            optimizer.get_metrics().clone()
        };

        let secret_metrics = {
            let optimizer = self.secret_optimizer.read().await;
            optimizer.analyze_performance().await.unwrap_or_default()
        };

        let aggregated = self.metrics_aggregator.get_aggregated_metrics().await;

        AggregatedMetrics {
            security_metrics,
            secret_metrics,
            aggregated,
        }
    }

    /// Suggest adaptive optimization changes
    pub async fn suggest_adaptive_optimization(&self) -> Option<OptimizationLevel> {
        let optimizer = self.security_optimizer.read().await;
        optimizer.suggest_adaptive_optimization()
    }
}

/// Aggregated performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    pub security_metrics: HashMap<String, OperationMetrics>,
    pub secret_metrics: SecretPerformanceMetrics,
    pub aggregated: HashMap<String, MetricValue>,
}

/// Metric value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(Vec<u64>),
}

/// Metrics aggregator for collecting and aggregating performance data
#[derive(Debug)]
struct MetricsAggregator {
    metrics: RwLock<HashMap<String, Vec<u64>>>,
}

impl MetricsAggregator {
    fn new() -> Self {
        Self {
            metrics: RwLock::new(HashMap::new()),
        }
    }

    async fn record_metric(&self, category: &str, key: &str, value: u64) {
        let metric_key = format!("{}:{}", category, key);
        let mut metrics = self.metrics.write().await;
        metrics
            .entry(metric_key.clone())
            .or_insert_with(Vec::new)
            .push(value);

        // Keep only last 1000 values to prevent unbounded growth
        if let Some(values) = metrics.get_mut(&metric_key)
            && values.len() > 1000
        {
            values.remove(0);
        }
    }

    async fn get_aggregated_metrics(&self) -> HashMap<String, MetricValue> {
        let metrics = self.metrics.read().await;
        let mut aggregated = HashMap::new();

        for (key, values) in metrics.iter() {
            if values.is_empty() {
                continue;
            }

            // `min`/`max` are `None` only for an empty slice, which the guard above
            // already skipped — taken together rather than unwrapped twice.
            let (Some(&min), Some(&max)) = (values.iter().min(), values.iter().max()) else {
                continue;
            };
            let sum: u64 = values.iter().sum();
            let count = u64::try_from(values.len()).unwrap_or(u64::MAX).max(1);
            let avg = sum / count;

            aggregated.insert(format!("{}_count", key), MetricValue::Counter(count));
            aggregated.insert(format!("{}_avg", key), MetricValue::Gauge(avg as f64));
            aggregated.insert(format!("{}_min", key), MetricValue::Gauge(min as f64));
            aggregated.insert(format!("{}_max", key), MetricValue::Gauge(max as f64));
        }

        aggregated
    }
}

/// Access type for secret operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessType {
    Read,
    Write,
    List,
    Delete,
    Rotate,
    Restore,
}
