//! Performance vs Security optimization profiles
//!
//! Provides different optimization levels that balance security requirements
//! with performance needs for various deployment scenarios.

use axum::Router;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::ApiState;

/// Create performance monitoring routes
pub fn performance_routes() -> Router<()> {
    use axum::{Router, extract::Extension, response::Json, routing::get};

    async fn get_performance_metrics(
        Extension(state): Extension<ApiState>,
    ) -> Json<HashMap<String, OperationMetrics>> {
        let optimizer = state.performance_optimizer.read().unwrap();
        Json(optimizer.get_metrics().clone())
    }

    async fn get_optimization_recommendations(
        Extension(state): Extension<ApiState>,
    ) -> Json<Vec<String>> {
        let optimizer = state
            .performance_optimizer
            .write()
            .expect("Failed to acquire write lock");
        Json(optimizer.get_optimization_recommendations())
    }

    Router::new()
        .route("/performance/metrics", get(get_performance_metrics))
        .route(
            "/performance/recommendations",
            get(get_optimization_recommendations),
        )
}

/// Security vs Performance optimization levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OptimizationLevel {
    /// Maximum security, minimum performance (Production-Critical)
    MaximumSecurity,
    /// High security with good performance (Production-Standard)
    HighSecurity,
    /// Balanced security and performance (Development/Staging)
    Balanced,
    /// Maximum performance, reduced security (Testing Only)
    MaximumPerformance,
}

impl Default for OptimizationLevel {
    fn default() -> Self {
        OptimizationLevel::HighSecurity
    }
}

impl OptimizationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            OptimizationLevel::MaximumSecurity => "max-security",
            OptimizationLevel::HighSecurity => "high-security",
            OptimizationLevel::Balanced => "balanced",
            OptimizationLevel::MaximumPerformance => "max-performance",
        }
    }

    /// Get security score (0.0 = no security, 1.0 = maximum security)
    pub fn security_score(&self) -> f64 {
        match self {
            OptimizationLevel::MaximumSecurity => 1.0,
            OptimizationLevel::HighSecurity => 0.9,
            OptimizationLevel::Balanced => 0.7,
            OptimizationLevel::MaximumPerformance => 0.3,
        }
    }

    /// Get performance score (0.0 = slowest, 1.0 = fastest)
    pub fn performance_score(&self) -> f64 {
        match self {
            OptimizationLevel::MaximumSecurity => 0.3,
            OptimizationLevel::HighSecurity => 0.6,
            OptimizationLevel::Balanced => 0.8,
            OptimizationLevel::MaximumPerformance => 1.0,
        }
    }

    /// Get recommended use case
    pub fn recommended_use(&self) -> &'static str {
        match self {
            OptimizationLevel::MaximumSecurity => {
                "Production systems with highest security requirements (banking, healthcare)"
            }
            OptimizationLevel::HighSecurity => {
                "Standard production deployments (enterprise applications)"
            }
            OptimizationLevel::Balanced => "Development and staging environments",
            OptimizationLevel::MaximumPerformance => "Testing and development (NOT for production)",
        }
    }
}

/// Performance monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub optimization_level: OptimizationLevel,
    pub enable_profiling: bool,
    pub enable_benchmarks: bool,
    pub max_concurrent_operations: usize,
    pub operation_timeout_ms: u64,
    pub memory_limit_mb: Option<usize>,
    pub cpu_limit_percent: Option<f64>,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            optimization_level: OptimizationLevel::HighSecurity,
            enable_profiling: false,
            enable_benchmarks: false,
            max_concurrent_operations: 1000,
            operation_timeout_ms: 30000, // 30 seconds
            memory_limit_mb: None,
            cpu_limit_percent: None,
        }
    }
}

/// Performance vs Security optimizer
#[derive(Debug)]
pub struct SecurityPerformanceOptimizer {
    config: PerformanceConfig,
    metrics: HashMap<String, OperationMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationMetrics {
    pub operation_name: String,
    pub total_operations: u64,
    pub total_time_ms: u64,
    pub min_time_ms: u64,
    pub max_time_ms: u64,
    pub avg_time_ms: u64,
    pub p95_time_ms: u64,
    pub p99_time_ms: u64,
    pub error_count: u64,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl SecurityPerformanceOptimizer {
    pub fn new(config: PerformanceConfig) -> Self {
        info!(
            "Initializing Security-Performance Optimizer: {:?} ({})",
            config.optimization_level,
            config.optimization_level.recommended_use()
        );

        Self {
            config,
            metrics: HashMap::new(),
        }
    }

    /// Record operation metrics
    pub fn record_operation(&mut self, operation_name: &str, duration: Duration, success: bool) {
        let duration_ms = duration.as_millis() as u64;
        let now = chrono::Utc::now();

        let metrics = self
            .metrics
            .entry(operation_name.to_string())
            .or_insert_with(|| OperationMetrics {
                operation_name: operation_name.to_string(),
                total_operations: 0,
                total_time_ms: 0,
                min_time_ms: u64::MAX,
                max_time_ms: 0,
                avg_time_ms: 0,
                p95_time_ms: 0,
                p99_time_ms: 0,
                error_count: 0,
                last_updated: now,
            });

        metrics.total_operations += 1;
        metrics.total_time_ms += duration_ms;
        metrics.min_time_ms = metrics.min_time_ms.min(duration_ms);
        metrics.max_time_ms = metrics.max_time_ms.max(duration_ms);
        metrics.avg_time_ms = metrics.total_time_ms / metrics.total_operations;

        if !success {
            metrics.error_count += 1;
        }

        metrics.last_updated = now;

        // Update percentiles (simplified calculation)
        if duration_ms > metrics.p95_time_ms {
            metrics.p95_time_ms = duration_ms;
        }
        if duration_ms > metrics.p99_time_ms {
            metrics.p99_time_ms = duration_ms;
        }

        // Log slow operations based on optimization level
        match self.config.optimization_level {
            OptimizationLevel::MaximumSecurity => {
                if duration_ms > 1000 {
                    // 1 second
                    warn!(
                        "Slow operation detected: {} took {}ms",
                        operation_name, duration_ms
                    );
                }
            }
            OptimizationLevel::HighSecurity => {
                if duration_ms > 5000 {
                    // 5 seconds
                    warn!(
                        "Slow operation detected: {} took {}ms",
                        operation_name, duration_ms
                    );
                }
            }
            _ => {} // Less strict for other levels
        }
    }

    /// Get operation metrics
    pub fn get_metrics(&self) -> &HashMap<String, OperationMetrics> {
        &self.metrics
    }

    /// Check if operation is within performance bounds
    pub fn check_performance_bounds(&self, _operation_name: &str, duration: Duration) -> bool {
        let duration_ms = duration.as_millis() as u64;

        match self.config.optimization_level {
            OptimizationLevel::MaximumSecurity => duration_ms < 2000, // 2 seconds
            OptimizationLevel::HighSecurity => duration_ms < 10000,   // 10 seconds
            OptimizationLevel::Balanced => duration_ms < 30000,       // 30 seconds
            OptimizationLevel::MaximumPerformance => true,            // No limits
        }
    }

    /// Get optimization recommendations
    pub fn get_optimization_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Check for slow operations
        for (operation, metrics) in &self.metrics {
            if metrics.avg_time_ms > 1000 {
                // Operations taking > 1 second on average
                recommendations.push(format!(
                    "Optimize {}: average {}ms (consider caching or algorithm improvements)",
                    operation, metrics.avg_time_ms
                ));
            }

            // Check error rates
            if metrics.total_operations > 0 {
                let error_rate = metrics.error_count as f64 / metrics.total_operations as f64;
                if error_rate > 0.01 {
                    // > 1% error rate
                    recommendations.push(format!(
                        "High error rate in {}: {:.2}% (investigate reliability issues)",
                        operation,
                        error_rate * 100.0
                    ));
                }
            }
        }

        // Check memory usage patterns
        match self.config.optimization_level {
            OptimizationLevel::MaximumSecurity => {
                recommendations.push("Memory zeroization enabled - consider connection pooling for frequently accessed resources".to_string());
            }
            OptimizationLevel::MaximumPerformance => {
                recommendations.push(
                    "Memory zeroization disabled for performance - ensure sensitive data cleanup"
                        .to_string(),
                );
            }
            _ => {}
        }

        recommendations
    }

    /// Adaptive optimization based on runtime metrics
    pub fn suggest_adaptive_optimization(&mut self) -> Option<OptimizationLevel> {
        let crypto_operations = self
            .metrics
            .values()
            .filter(|m| {
                m.operation_name.contains("crypto")
                    || m.operation_name.contains("encrypt")
                    || m.operation_name.contains("decrypt")
            })
            .collect::<Vec<_>>();

        if crypto_operations.is_empty() {
            return None;
        }

        let avg_crypto_time: u64 = crypto_operations.iter().map(|m| m.avg_time_ms).sum::<u64>()
            / crypto_operations.len() as u64;

        // If crypto operations are consistently slow, suggest optimization
        if avg_crypto_time > 1000 {
            // > 1 second average
            match self.config.optimization_level {
                OptimizationLevel::MaximumSecurity => {
                    // Already at maximum security, suggest hardware acceleration
                    info!(
                        "Crypto operations slow ({}ms avg) at maximum security - consider hardware acceleration",
                        avg_crypto_time
                    );
                    None
                }
                OptimizationLevel::HighSecurity => {
                    // Could optimize further
                    Some(OptimizationLevel::Balanced)
                }
                OptimizationLevel::Balanced => Some(OptimizationLevel::MaximumPerformance),
                OptimizationLevel::MaximumPerformance => {
                    // Already at maximum performance
                    None
                }
            }
        } else {
            None
        }
    }
}

/// Performance benchmarking utilities
pub struct PerformanceBenchmark;

impl PerformanceBenchmark {
    /// Benchmark encryption performance
    pub async fn benchmark_encryption(
        data_sizes: &[usize],
        iterations: usize,
    ) -> HashMap<usize, Duration> {
        use secreton_crypto::*;

        let mut results = HashMap::new();
        let mut rng = rand::thread_rng();

        for &size in data_sizes {
            let mut data = vec![0u8; size];
            rand::RngCore::fill_bytes(&mut rng, &mut data);

            let key = generate_key(AlgorithmId::Aes256Gcm).unwrap();

            let start = Instant::now();

            for _ in 0..iterations {
                let engine = CryptoEngine::new();
                let _encrypted = engine.encrypt(AlgorithmId::Aes256Gcm, &data, &key).unwrap();
            }

            let duration = start.elapsed() / iterations as u32;
            results.insert(size, duration);
        }

        results
    }

    /// Benchmark decryption performance
    pub async fn benchmark_decryption(
        data_sizes: &[usize],
        iterations: usize,
    ) -> HashMap<usize, Duration> {
        use secreton_crypto::*;

        let mut results = HashMap::new();
        let mut rng = rand::thread_rng();

        for &size in data_sizes {
            let mut data = vec![0u8; size];
            rand::RngCore::fill_bytes(&mut rng, &mut data);

            let key = generate_key(AlgorithmId::Aes256Gcm).unwrap();
            let engine = CryptoEngine::new();

            // Pre-encrypt data
            let encrypted = engine.encrypt(AlgorithmId::Aes256Gcm, &data, &key).unwrap();

            let start = Instant::now();

            for _ in 0..iterations {
                let _decrypted = engine.decrypt(&encrypted, &key).unwrap();
            }

            let duration = start.elapsed() / iterations as u32;
            results.insert(size, duration);
        }

        results
    }
}

/// Security-focused performance testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimization_level_scoring() {
        assert_eq!(OptimizationLevel::MaximumSecurity.security_score(), 1.0);
        assert_eq!(
            OptimizationLevel::MaximumPerformance.performance_score(),
            1.0
        );
        assert!(
            OptimizationLevel::HighSecurity.security_score()
                > OptimizationLevel::Balanced.security_score()
        );
        assert!(
            OptimizationLevel::Balanced.performance_score()
                > OptimizationLevel::HighSecurity.performance_score()
        );
    }

    #[test]
    fn test_performance_config_defaults() {
        let config = PerformanceConfig::default();
        assert_eq!(config.optimization_level, OptimizationLevel::HighSecurity);
        assert_eq!(config.max_concurrent_operations, 1000);
        assert_eq!(config.operation_timeout_ms, 30000);
    }

    #[tokio::test]
    async fn test_metrics_recording() {
        let mut optimizer = SecurityPerformanceOptimizer::new(PerformanceConfig::default());

        optimizer.record_operation("test_op", Duration::from_millis(100), true);
        optimizer.record_operation("test_op", Duration::from_millis(200), true);

        let metrics = optimizer.get_metrics();
        assert!(metrics.contains_key("test_op"));

        let op_metrics = &metrics["test_op"];
        assert_eq!(op_metrics.total_operations, 2);
        assert_eq!(op_metrics.avg_time_ms, 150); // (100 + 200) / 2
    }
}
