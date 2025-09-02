//! Optimized trait definitions to replace type erasure anti-patterns
//! This module provides concrete, type-safe alternatives to Box<dyn Any>

use crate::error::SecretonResult;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

/// Key Usage Tracker for monitoring key access patterns
#[derive(Debug, Default, Clone)]
pub struct KeyUsageTracker {
    pub usage_counts: std::collections::HashMap<String, u64>,
    pub last_access: std::collections::HashMap<String, std::time::SystemTime>,
    pub access_patterns: std::collections::HashMap<String, Vec<AccessEvent>>,
}

/// Access event for tracking key usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    pub timestamp: std::time::SystemTime,
    pub operation: String,
    pub success: bool,
}

/// Rotation Scheduler Trait - replacing Box<dyn Any>
pub trait RotationScheduler: Send + Sync {
    fn schedule_rotation(
        &self,
        key_id: &str,
        interval: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>>;
    fn cancel_rotation(
        &self,
        key_id: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>>;
    fn get_next_rotations(
        &self,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<Vec<ScheduledRotation>>> + Send + '_>>;
    fn process_due_rotations(
        &self,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<Vec<RotationResult>>> + Send + '_>>;
}

/// Key Governance Trait - replacing Box<dyn Any>
pub trait KeyGovernance: Send + Sync {
    fn check_operation_allowed(
        &self,
        key_id: &str,
        operation: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<bool>> + Send + '_>>;
    fn enforce_lifecycle_policies(
        &self,
        key_id: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>>;
    fn audit_compliance(
        &self,
        key_id: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<ComplianceReport>> + Send + '_>>;
    fn get_required_approvals(
        &self,
        key_id: &str,
        operation: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<Vec<String>>> + Send + '_>>;
}

/// Audit Logger Trait - replacing Box<dyn Any>
pub trait KeyAuditLogger: Send + Sync {
    fn log_key_generation(
        &self,
        key_id: &str,
        metadata: &KeyMetadata,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>>;
    fn log_key_import(
        &self,
        key_id: &str,
        source: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>>;
    fn log_key_operation(
        &self,
        key_id: &str,
        operation: &str,
        result: &OperationResult,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>>;
    fn log_key_rotation(
        &self,
        result: &RotationResult,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>>;
    fn log_policy_violation(
        &self,
        key_id: &str,
        violation: &PolicyViolation,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>>;
}

/// Cache Manager Trait - for performance optimization
pub trait CacheManager: Send + Sync {
    fn get<T: Clone + Send + Sync + 'static>(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Option<T>> + Send + '_>>;
    fn set<T: Clone + Send + Sync + 'static>(
        &self,
        key: &str,
        value: T,
        ttl: Option<std::time::Duration>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
    fn invalidate(&self, key: &str) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
    fn clear(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
    fn get_stats(&self) -> Pin<Box<dyn Future<Output = CacheStats> + Send + '_>>;
}

/// Performance Monitor Trait - for metrics collection
pub trait PerformanceMonitor: Send + Sync {
    fn record_operation(
        &self,
        operation: &str,
        duration: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>>;
    fn get_metrics(
        &self,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<PerformanceMetrics>> + Send + '_>>;
    fn get_health_status(
        &self,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<HealthStatus>> + Send + '_>>;
}

// Supporting types for the traits

/// Scheduled rotation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledRotation {
    pub key_id: String,
    pub scheduled_time: chrono::DateTime<chrono::Utc>,
    pub rotation_reason: String,
    pub priority: u8,
}

/// Compliance report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub total_operations: u64,
    pub compliant_operations: u64,
    pub violations: Vec<String>,
}

/// Key metadata for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub key_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub algorithm: String,
    pub size_bits: u32,
}

/// Operation result for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    pub success: bool,
    pub operation_id: String,
    pub duration_ms: u64,
    pub error_message: Option<String>,
}

/// Rotation result for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationResult {
    pub key_id: String,
    pub old_version: u32,
    pub new_version: u32,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Policy violation for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub violation_id: String,
    pub policy_name: String,
    pub severity: String,
    pub description: String,
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub memory_usage_bytes: u64,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceMetrics {
    pub total_operations: u64,
    pub average_latency_ms: f64,
    pub throughput_ops_per_sec: f64,
    pub error_rate: f64,
    pub system: SystemMetrics,
    pub application: ApplicationMetrics,
    pub network: NetworkMetrics,
}

/// Health status enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemMetrics {
    pub cpu_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_io_read_bytes: u64,
    pub disk_io_write_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApplicationMetrics {
    pub requests_per_second: f64,
    pub average_latency_ms: f64,
    pub active_connections: u32,
    pub cache_hit_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

/// Default key governance implementation
pub struct DefaultKeyGovernance;

impl KeyGovernance for DefaultKeyGovernance {
    fn check_operation_allowed(
        &self,
        _key_id: &str,
        _operation: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<bool>> + Send + '_>> {
        Box::pin(async { Ok(true) }) // Default: allow all operations
    }

    fn enforce_lifecycle_policies(
        &self,
        _key_id: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>> {
        Box::pin(async { Ok(()) }) // Default: no enforcement
    }

    fn audit_compliance(
        &self,
        _key_id: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<ComplianceReport>> + Send + '_>> {
        Box::pin(async { Ok(ComplianceReport::default()) }) // Default: compliant
    }

    fn get_required_approvals(
        &self,
        _key_id: &str,
        _operation: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<Vec<String>>> + Send + '_>> {
        Box::pin(async { Ok(Vec::new()) }) // Default: no approvals required
    }
}

/// Default audit logger implementation
pub struct DefaultKeyAuditLogger;

impl KeyAuditLogger for DefaultKeyAuditLogger {
    fn log_key_generation(
        &self,
        _key_id: &str,
        _metadata: &KeyMetadata,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>> {
        Box::pin(async { Ok(()) }) // Default: no-op
    }

    fn log_key_import(
        &self,
        _key_id: &str,
        _source: &str,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>> {
        Box::pin(async { Ok(()) }) // Default: no-op
    }

    fn log_key_operation(
        &self,
        _key_id: &str,
        _operation: &str,
        _result: &OperationResult,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>> {
        Box::pin(async { Ok(()) }) // Default: no-op
    }

    fn log_key_rotation(
        &self,
        _result: &RotationResult,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>> {
        Box::pin(async { Ok(()) }) // Default: no-op
    }

    fn log_policy_violation(
        &self,
        _key_id: &str,
        _violation: &PolicyViolation,
    ) -> Pin<Box<dyn Future<Output = SecretonResult<()>> + Send + '_>> {
        Box::pin(async { Ok(()) }) // Default: no-op
    }
}
