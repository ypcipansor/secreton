// Quotas System - Resource limiting per path, namespace, and role
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum QuotaError {
    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("Quota not found: {0}")]
    NotFound(String),
    #[error("Invalid quota configuration: {0}")]
    InvalidConfig(String),
    #[error("Quota already exists: {0}")]
    AlreadyExists(String),
}

pub type Result<T> = std::result::Result<T, QuotaError>;

/// Type of quota limit
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuotaType {
    /// Rate limit - requests per time window
    RateLimit,
    /// Lease count limit - maximum concurrent leases
    LeaseCount,
    /// Path count limit - maximum paths that can be written
    PathCount,
}

/// Quota configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaConfig {
    pub name: String,
    pub quota_type: QuotaType,
    pub path: String, // Path pattern, supports wildcards
    pub namespace: Option<String>,
    pub role: Option<String>,
    pub limit: u64,
    pub window_seconds: Option<u64>, // For rate limits
    pub description: String,
    pub created_at: DateTime<Utc>,
}

/// Usage tracking for a quota
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaUsage {
    pub quota_name: String,
    pub current_count: u64,
    pub limit: u64,
    pub window_start: Option<DateTime<Utc>>, // For rate limits
    pub violations: u64,                     // Number of times quota was exceeded
    pub last_violation: Option<DateTime<Utc>>,
    pub last_reset: DateTime<Utc>,
}

/// Individual request/lease tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaEntry {
    pub id: String,
    pub quota_name: String,
    pub path: String,
    pub namespace: Option<String>,
    pub role: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub entry_type: QuotaEntryType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuotaEntryType {
    Request,
    Lease,
    Path,
}

/// Quota enforcement result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaCheckResult {
    pub allowed: bool,
    pub quota_name: String,
    pub current_usage: u64,
    pub limit: u64,
    pub remaining: u64,
    pub reset_at: Option<DateTime<Utc>>,
}

impl QuotaConfig {
    pub fn new(name: String, quota_type: QuotaType, path: String, limit: u64) -> Self {
        Self {
            name,
            quota_type,
            path,
            namespace: None,
            role: None,
            limit,
            window_seconds: None,
            description: String::new(),
            created_at: Utc::now(),
        }
    }

    pub fn with_namespace(mut self, namespace: String) -> Self {
        self.namespace = Some(namespace);
        self
    }

    pub fn with_role(mut self, role: String) -> Self {
        self.role = Some(role);
        self
    }

    pub fn with_window(mut self, window_seconds: u64) -> Self {
        self.window_seconds = Some(window_seconds);
        self
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    /// Check if path matches this quota's path pattern
    pub fn matches_path(&self, path: &str) -> bool {
        if self.path == "*" {
            return true;
        }

        if self.path.ends_with("/*") {
            let prefix = &self.path[..self.path.len() - 2];
            return path.starts_with(prefix);
        }

        path == self.path
    }

    /// Check if namespace matches
    pub fn matches_namespace(&self, namespace: Option<&str>) -> bool {
        match (&self.namespace, namespace) {
            (None, _) => true, // No namespace restriction
            (Some(quota_ns), Some(req_ns)) => quota_ns == req_ns,
            (Some(_), None) => false,
        }
    }

    /// Check if role matches
    pub fn matches_role(&self, role: Option<&str>) -> bool {
        match (&self.role, role) {
            (None, _) => true, // No role restriction
            (Some(quota_role), Some(req_role)) => quota_role == req_role,
            (Some(_), None) => false,
        }
    }
}

impl QuotaUsage {
    pub fn new(quota_name: String, limit: u64) -> Self {
        Self {
            quota_name,
            current_count: 0,
            limit,
            window_start: None,
            violations: 0,
            last_violation: None,
            last_reset: Utc::now(),
        }
    }

    pub fn is_exceeded(&self) -> bool {
        self.current_count >= self.limit
    }

    pub fn remaining(&self) -> u64 {
        if self.current_count >= self.limit {
            0
        } else {
            self.limit - self.current_count
        }
    }

    pub fn increment(&mut self) {
        self.current_count += 1;
    }

    pub fn decrement(&mut self) {
        if self.current_count > 0 {
            self.current_count -= 1;
        }
    }

    pub fn reset(&mut self) {
        self.current_count = 0;
        self.window_start = Some(Utc::now());
        self.last_reset = Utc::now();
    }

    pub fn record_violation(&mut self) {
        self.violations += 1;
        self.last_violation = Some(Utc::now());
    }
}

/// Quotas service managing resource limits
pub struct QuotasService {
    quotas: Arc<RwLock<HashMap<String, QuotaConfig>>>,
    usage: Arc<RwLock<HashMap<String, QuotaUsage>>>,
    entries: Arc<RwLock<Vec<QuotaEntry>>>,
}

impl QuotasService {
    pub fn new() -> Self {
        Self {
            quotas: Arc::new(RwLock::new(HashMap::new())),
            usage: Arc::new(RwLock::new(HashMap::new())),
            entries: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a new quota
    pub async fn create_quota(&self, config: QuotaConfig) -> Result<()> {
        // Validate configuration
        if config.limit == 0 {
            return Err(QuotaError::InvalidConfig(
                "Limit must be greater than 0".to_string(),
            ));
        }

        if config.quota_type == QuotaType::RateLimit && config.window_seconds.is_none() {
            return Err(QuotaError::InvalidConfig(
                "Rate limit requires window_seconds".to_string(),
            ));
        }

        let mut quotas = self.quotas.write().await;

        if quotas.contains_key(&config.name) {
            return Err(QuotaError::AlreadyExists(config.name.clone()));
        }

        let quota_name = config.name.clone();
        quotas.insert(config.name.clone(), config.clone());

        // Initialize usage tracking
        drop(quotas);
        let mut usage = self.usage.write().await;
        usage.insert(
            quota_name.clone(),
            QuotaUsage::new(quota_name, config.limit),
        );

        Ok(())
    }

    /// Check if a request is allowed under quota limits
    pub async fn check_quota(
        &self,
        path: &str,
        namespace: Option<&str>,
        role: Option<&str>,
        entry_type: QuotaEntryType,
    ) -> Result<QuotaCheckResult> {
        // Find applicable quotas
        let applicable: Vec<QuotaConfig> = {
            let quotas = self.quotas.read().await;
            quotas
                .values()
                .filter(|q| {
                    q.matches_path(path)
                        && q.matches_namespace(namespace)
                        && q.matches_role(role)
                        && match entry_type {
                            QuotaEntryType::Request => q.quota_type == QuotaType::RateLimit,
                            QuotaEntryType::Lease => q.quota_type == QuotaType::LeaseCount,
                            QuotaEntryType::Path => q.quota_type == QuotaType::PathCount,
                        }
                })
                .cloned()
                .collect()
        };

        if applicable.is_empty() {
            // No quota applies, allow
            return Ok(QuotaCheckResult {
                allowed: true,
                quota_name: "none".to_string(),
                current_usage: 0,
                limit: u64::MAX,
                remaining: u64::MAX,
                reset_at: None,
            });
        }

        // Keep first quota name for success result
        let first_quota_name = applicable[0].name.clone();
        let first_quota_limit = applicable[0].limit;

        let mut usage = self.usage.write().await;

        // Check each applicable quota
        for quota in applicable {
            let quota_usage = usage
                .get_mut(&quota.name)
                .ok_or_else(|| QuotaError::NotFound(quota.name.clone()))?;

            // For rate limits, check if window has expired
            if quota.quota_type == QuotaType::RateLimit {
                if let Some(window_start) = quota_usage.window_start {
                    let window_duration =
                        chrono::Duration::seconds(quota.window_seconds.unwrap() as i64);
                    if Utc::now() - window_start > window_duration {
                        // Window expired, reset
                        quota_usage.reset();
                    }
                } else {
                    // First request in window
                    quota_usage.window_start = Some(Utc::now());
                }
            }

            if quota_usage.is_exceeded() {
                quota_usage.record_violation();

                let reset_at = if quota.quota_type == QuotaType::RateLimit {
                    quota_usage.window_start.map(|start| {
                        start + chrono::Duration::seconds(quota.window_seconds.unwrap() as i64)
                    })
                } else {
                    None
                };

                return Ok(QuotaCheckResult {
                    allowed: false,
                    quota_name: quota.name.clone(),
                    current_usage: quota_usage.current_count,
                    limit: quota_usage.limit,
                    remaining: 0,
                    reset_at,
                });
            }
        }

        // All quotas passed
        Ok(QuotaCheckResult {
            allowed: true,
            quota_name: first_quota_name.clone(),
            current_usage: usage[&first_quota_name].current_count,
            limit: first_quota_limit,
            remaining: usage[&first_quota_name].remaining(),
            reset_at: None,
        })
    }

    /// Record usage after a successful operation
    pub async fn record_usage(
        &self,
        path: &str,
        namespace: Option<String>,
        role: Option<String>,
        entry_type: QuotaEntryType,
    ) -> Result<()> {
        let quotas = self.quotas.read().await;

        let applicable: Vec<_> = quotas
            .values()
            .filter(|q| {
                q.matches_path(path)
                    && q.matches_namespace(namespace.as_deref())
                    && q.matches_role(role.as_deref())
                    && match entry_type {
                        QuotaEntryType::Request => q.quota_type == QuotaType::RateLimit,
                        QuotaEntryType::Lease => q.quota_type == QuotaType::LeaseCount,
                        QuotaEntryType::Path => q.quota_type == QuotaType::PathCount,
                    }
            })
            .map(|q| q.name.clone())
            .collect();

        drop(quotas);

        let mut usage = self.usage.write().await;
        for quota_name in applicable {
            if let Some(quota_usage) = usage.get_mut(&quota_name) {
                quota_usage.increment();
            }
        }

        // Record entry
        let mut entries = self.entries.write().await;
        entries.push(QuotaEntry {
            id: uuid::Uuid::new_v4().to_string(),
            quota_name: "tracked".to_string(),
            path: path.to_string(),
            namespace,
            role,
            timestamp: Utc::now(),
            entry_type,
        });

        Ok(())
    }

    /// Release usage (e.g., when lease is revoked)
    pub async fn release_usage(
        &self,
        path: &str,
        namespace: Option<&str>,
        role: Option<&str>,
        entry_type: QuotaEntryType,
    ) -> Result<()> {
        let quotas = self.quotas.read().await;

        let applicable: Vec<_> = quotas
            .values()
            .filter(|q| {
                q.matches_path(path)
                    && q.matches_namespace(namespace)
                    && q.matches_role(role)
                    && match entry_type {
                        QuotaEntryType::Request => q.quota_type == QuotaType::RateLimit,
                        QuotaEntryType::Lease => q.quota_type == QuotaType::LeaseCount,
                        QuotaEntryType::Path => q.quota_type == QuotaType::PathCount,
                    }
            })
            .map(|q| q.name.clone())
            .collect();

        drop(quotas);

        let mut usage = self.usage.write().await;
        for quota_name in applicable {
            if let Some(quota_usage) = usage.get_mut(&quota_name) {
                quota_usage.decrement();
            }
        }

        Ok(())
    }

    /// Get quota by name
    pub async fn get_quota(&self, name: &str) -> Result<QuotaConfig> {
        let quotas = self.quotas.read().await;
        quotas
            .get(name)
            .cloned()
            .ok_or_else(|| QuotaError::NotFound(name.to_string()))
    }

    /// Get quota usage statistics
    pub async fn get_usage(&self, name: &str) -> Result<QuotaUsage> {
        let usage = self.usage.read().await;
        usage
            .get(name)
            .cloned()
            .ok_or_else(|| QuotaError::NotFound(name.to_string()))
    }

    /// List all quotas
    pub async fn list_quotas(&self) -> Vec<QuotaConfig> {
        let quotas = self.quotas.read().await;
        quotas.values().cloned().collect()
    }

    /// List all usage statistics
    pub async fn list_usage(&self) -> Vec<QuotaUsage> {
        let usage = self.usage.read().await;
        usage.values().cloned().collect()
    }

    /// Delete a quota
    pub async fn delete_quota(&self, name: &str) -> Result<()> {
        let mut quotas = self.quotas.write().await;
        quotas
            .remove(name)
            .ok_or_else(|| QuotaError::NotFound(name.to_string()))?;

        let mut usage = self.usage.write().await;
        usage.remove(name);

        Ok(())
    }

    /// Reset quota usage
    pub async fn reset_quota(&self, name: &str) -> Result<()> {
        let mut usage = self.usage.write().await;
        let quota_usage = usage
            .get_mut(name)
            .ok_or_else(|| QuotaError::NotFound(name.to_string()))?;

        quota_usage.reset();
        Ok(())
    }

    /// Get entries within a time range
    pub async fn get_entries(
        &self,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Vec<QuotaEntry> {
        let entries = self.entries.read().await;

        entries
            .iter()
            .filter(|e| {
                let after_start = start.map_or(true, |s| e.timestamp >= s);
                let before_end = end.map_or(true, |e_time| e.timestamp <= e_time);
                after_start && before_end
            })
            .take(limit)
            .cloned()
            .collect()
    }
}

impl Default for QuotasService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_rate_limit_quota() {
        let service = QuotasService::new();

        let config = QuotaConfig::new(
            "api-rate-limit".to_string(),
            QuotaType::RateLimit,
            "api/*".to_string(),
            100,
        )
        .with_window(60)
        .with_description("API rate limit: 100 req/min".to_string());

        service.create_quota(config).await.unwrap();

        let quota = service.get_quota("api-rate-limit").await.unwrap();
        assert_eq!(quota.limit, 100);
        assert_eq!(quota.window_seconds, Some(60));
        assert!(quota.matches_path("api/v1/secret"));
    }

    #[tokio::test]
    async fn test_quota_enforcement() {
        let service = QuotasService::new();

        let config = QuotaConfig::new(
            "lease-limit".to_string(),
            QuotaType::LeaseCount,
            "secret/*".to_string(),
            2,
        );

        service.create_quota(config).await.unwrap();

        // First request - should succeed
        let result = service
            .check_quota("secret/data", None, None, QuotaEntryType::Lease)
            .await
            .unwrap();
        assert!(result.allowed);
        service
            .record_usage("secret/data", None, None, QuotaEntryType::Lease)
            .await
            .unwrap();

        // Second request - should succeed
        let result = service
            .check_quota("secret/data", None, None, QuotaEntryType::Lease)
            .await
            .unwrap();
        assert!(result.allowed);
        service
            .record_usage("secret/data", None, None, QuotaEntryType::Lease)
            .await
            .unwrap();

        // Third request - should fail (quota exceeded)
        let result = service
            .check_quota("secret/data", None, None, QuotaEntryType::Lease)
            .await
            .unwrap();
        assert!(!result.allowed);
        assert_eq!(result.current_usage, 2);
        assert_eq!(result.remaining, 0);
    }

    #[tokio::test]
    async fn test_quota_release() {
        let service = QuotasService::new();

        let config = QuotaConfig::new(
            "lease-limit".to_string(),
            QuotaType::LeaseCount,
            "secret/*".to_string(),
            2,
        );

        service.create_quota(config).await.unwrap();

        // Use quota twice
        service
            .record_usage("secret/data", None, None, QuotaEntryType::Lease)
            .await
            .unwrap();
        service
            .record_usage("secret/data", None, None, QuotaEntryType::Lease)
            .await
            .unwrap();

        let usage = service.get_usage("lease-limit").await.unwrap();
        assert_eq!(usage.current_count, 2);

        // Release one
        service
            .release_usage("secret/data", None, None, QuotaEntryType::Lease)
            .await
            .unwrap();

        let usage = service.get_usage("lease-limit").await.unwrap();
        assert_eq!(usage.current_count, 1);
    }

    #[tokio::test]
    async fn test_namespace_scoped_quota() {
        let service = QuotasService::new();

        let config = QuotaConfig::new(
            "org1-limit".to_string(),
            QuotaType::PathCount,
            "*".to_string(),
            5,
        )
        .with_namespace("org1".to_string());

        service.create_quota(config).await.unwrap();

        // Request from org1 - should be checked
        let result = service
            .check_quota("secret/data", Some("org1"), None, QuotaEntryType::Path)
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.quota_name, "org1-limit");

        // Request from org2 - should not be checked against org1 quota
        let result = service
            .check_quota("secret/data", Some("org2"), None, QuotaEntryType::Path)
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.quota_name, "none"); // No applicable quota
    }

    #[tokio::test]
    async fn test_quota_violations_tracking() {
        let service = QuotasService::new();

        let config = QuotaConfig::new(
            "test-limit".to_string(),
            QuotaType::LeaseCount,
            "*".to_string(),
            1,
        );

        service.create_quota(config).await.unwrap();

        // First usage
        service
            .record_usage("test/path", None, None, QuotaEntryType::Lease)
            .await
            .unwrap();

        // Attempt to exceed quota
        let result = service
            .check_quota("test/path", None, None, QuotaEntryType::Lease)
            .await
            .unwrap();
        assert!(!result.allowed);

        // Check violations were recorded
        let usage = service.get_usage("test-limit").await.unwrap();
        assert_eq!(usage.violations, 1);
        assert!(usage.last_violation.is_some());
    }
}
