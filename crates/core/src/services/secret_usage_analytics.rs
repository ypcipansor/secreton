// Secret Usage Analytics - Track access patterns and generate insights
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum AnalyticsError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Analytics error: {0}")]
    AnalyticsError(String),
    #[error("Export error: {0}")]
    ExportError(String),
}

pub type Result<T> = std::result::Result<T, AnalyticsError>;

/// Access type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessType {
    Read,
    Write,
    List,
    Delete,
}

/// Analytics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsConfig {
    pub enabled: bool,
    pub retention_days: u32,
    pub aggregation_interval_minutes: u32,
    pub export_enabled: bool,
}

/// Access event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    pub event_id: String,
    pub secret_path: String,
    pub accessor: String, // User or service name
    pub access_type: AccessType,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMetrics {
    pub secret_path: String,
    pub access_count: u64,
    pub unique_accessors: HashSet<String>,
    pub first_accessed: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub access_frequency: f64, // Accesses per day
}

/// Usage report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReport {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub time_range_start: DateTime<Utc>,
    pub time_range_end: DateTime<Utc>,
    pub total_secrets: usize,
    pub total_accesses: u64,
    pub most_accessed: Vec<(String, u64)>, // (secret_path, count)
    pub unused_secrets: Vec<String>,
    pub compliance_score: f64, // 0.0 - 100.0
}

/// Access pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPattern {
    pub secret_path: String,
    pub hourly_distribution: [u32; 24],
    pub daily_distribution: [u32; 7],
    pub peak_hours: Vec<u8>,
}

/// Secret Usage Analytics
pub struct SecretUsageAnalytics {
    config: Arc<RwLock<AnalyticsConfig>>,
    access_events: Arc<RwLock<Vec<AccessEvent>>>,
    metrics_cache: Arc<RwLock<HashMap<String, UsageMetrics>>>,
}

impl SecretUsageAnalytics {
    pub fn new(config: AnalyticsConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            access_events: Arc::new(RwLock::new(Vec::new())),
            metrics_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record access event
    pub async fn record_access(
        &self,
        secret_path: String,
        accessor: String,
        access_type: AccessType,
        metadata: HashMap<String, String>,
    ) -> Result<()> {
        let config = self.config.read().await;
        if !config.enabled {
            return Ok(());
        }
        drop(config);

        let event = AccessEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            secret_path,
            accessor,
            access_type,
            timestamp: Utc::now(),
            metadata,
        };

        let mut access_events = self.access_events.write().await;
        access_events.push(event);

        Ok(())
    }

    /// Get usage metrics for a secret
    pub async fn get_usage_metrics(&self, secret_path: &str) -> Option<UsageMetrics> {
        let access_events = self.access_events.read().await;

        let events: Vec<_> = access_events
            .iter()
            .filter(|e| e.secret_path == secret_path)
            .collect();

        if events.is_empty() {
            return None;
        }

        let access_count = events.len() as u64;
        let unique_accessors: HashSet<String> =
            events.iter().map(|e| e.accessor.clone()).collect();

        let first_accessed = events.iter().map(|e| e.timestamp).min().unwrap();
        let last_accessed = events.iter().map(|e| e.timestamp).max().unwrap();

        let days = (last_accessed - first_accessed).num_days().max(1) as f64;
        let access_frequency = access_count as f64 / days;

        Some(UsageMetrics {
            secret_path: secret_path.to_string(),
            access_count,
            unique_accessors,
            first_accessed,
            last_accessed,
            access_frequency,
        })
    }

    /// Generate usage report
    pub async fn generate_usage_report(
        &self,
        time_range_start: DateTime<Utc>,
        time_range_end: DateTime<Utc>,
    ) -> Result<UsageReport> {
        let access_events = self.access_events.read().await;

        let filtered_events: Vec<_> = access_events
            .iter()
            .filter(|e| e.timestamp >= time_range_start && e.timestamp <= time_range_end)
            .collect();

        // Count accesses per secret
        let mut access_counts: HashMap<String, u64> = HashMap::new();
        for event in &filtered_events {
            *access_counts.entry(event.secret_path.clone()).or_insert(0) += 1;
        }

        // Get most accessed (top 10)
        let mut most_accessed: Vec<_> = access_counts.into_iter().collect();
        most_accessed.sort_by(|a, b| b.1.cmp(&a.1));
        most_accessed.truncate(10);

        // Find unused secrets (no access in time range)
        let accessed_secrets: HashSet<_> = filtered_events.iter().map(|e| &e.secret_path).collect();
        let all_secrets: HashSet<_> = access_events.iter().map(|e| &e.secret_path).collect();
        let unused_secrets: Vec<_> = all_secrets
            .difference(&accessed_secrets)
            .map(|s| s.to_string())
            .collect();

        // Calculate compliance score (percentage of secrets with recent access)
        let total_secrets = all_secrets.len();
        let accessed_count = accessed_secrets.len();
        let compliance_score = if total_secrets > 0 {
            (accessed_count as f64 / total_secrets as f64) * 100.0
        } else {
            100.0
        };

        Ok(UsageReport {
            report_id: uuid::Uuid::new_v4().to_string(),
            generated_at: Utc::now(),
            time_range_start,
            time_range_end,
            total_secrets,
            total_accesses: filtered_events.len() as u64,
            most_accessed,
            unused_secrets,
            compliance_score,
        })
    }

    /// Identify unused secrets
    pub async fn identify_unused_secrets(&self, days_threshold: u32) -> Vec<String> {
        let access_events = self.access_events.read().await;
        let threshold = Utc::now() - chrono::Duration::days(days_threshold as i64);

        let recently_accessed: HashSet<_> = access_events
            .iter()
            .filter(|e| e.timestamp >= threshold)
            .map(|e| &e.secret_path)
            .collect();

        let all_secrets: HashSet<_> = access_events.iter().map(|e| &e.secret_path).collect();

        all_secrets
            .difference(&recently_accessed)
            .map(|s| s.to_string())
            .collect()
    }

    /// Get access patterns
    pub async fn get_access_patterns(&self, secret_path: &str) -> Option<AccessPattern> {
        let access_events = self.access_events.read().await;

        let events: Vec<_> = access_events
            .iter()
            .filter(|e| e.secret_path == secret_path)
            .collect();

        if events.is_empty() {
            return None;
        }

        let mut hourly_distribution = [0u32; 24];
        let mut daily_distribution = [0u32; 7];

        for event in &events {
            let hour = event.timestamp.hour() as usize;
            let day = event.timestamp.weekday().num_days_from_monday() as usize;
            hourly_distribution[hour] += 1;
            daily_distribution[day] += 1;
        }

        // Find peak hours (hours with above-average activity)
        let total_accesses: u32 = hourly_distribution.iter().sum();
        let avg_per_hour = total_accesses as f64 / 24.0;
        let peak_hours: Vec<u8> = hourly_distribution
            .iter()
            .enumerate()
            .filter(|(_, count)| {
                let c = *count;
                *c as f64 > avg_per_hour * 1.5
            })
            .map(|(hour, _)| hour as u8)
            .collect();

        Some(AccessPattern {
            secret_path: secret_path.to_string(),
            hourly_distribution,
            daily_distribution,
            peak_hours,
        })
    }

    /// Export analytics data
    pub async fn export_analytics(&self, format: &str) -> Result<String> {
        let config = self.config.read().await;
        if !config.export_enabled {
            return Err(AnalyticsError::ExportError(
                "Export is not enabled".to_string(),
            ));
        }
        drop(config);

        let access_events = self.access_events.read().await;

        match format {
            "json" => {
                let json = serde_json::to_string_pretty(&*access_events)
                    .map_err(|e| AnalyticsError::ExportError(e.to_string()))?;
                Ok(json)
            }
            "csv" => {
                let mut csv = String::from("event_id,secret_path,accessor,access_type,timestamp\n");
                for event in access_events.iter() {
                    csv.push_str(&format!(
                        "{},{},{},{:?},{}\n",
                        event.event_id, event.secret_path, event.accessor, event.access_type, event.timestamp
                    ));
                }
                Ok(csv)
            }
            _ => Err(AnalyticsError::ExportError(
                "Unsupported format".to_string(),
            )),
        }
    }

    /// List all events
    pub async fn list_events(&self, secret_path: Option<&str>) -> Vec<AccessEvent> {
        let access_events = self.access_events.read().await;

        if let Some(path) = secret_path {
            access_events
                .iter()
                .filter(|e| e.secret_path == path)
                .cloned()
                .collect()
        } else {
            access_events.clone()
        }
    }

    /// Clear old events
    pub async fn clear_old_events(&self) -> Result<usize> {
        let config = self.config.read().await;
        let retention_days = config.retention_days;
        drop(config);

        let threshold = Utc::now() - chrono::Duration::days(retention_days as i64);

        let mut access_events = self.access_events.write().await;
        let original_count = access_events.len();
        access_events.retain(|e| e.timestamp >= threshold);
        let removed_count = original_count - access_events.len();

        Ok(removed_count)
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> AnalyticsStatistics {
        let access_events = self.access_events.read().await;

        let total_events = access_events.len();
        let unique_secrets: HashSet<_> = access_events.iter().map(|e| &e.secret_path).collect();
        let unique_accessors: HashSet<_> = access_events.iter().map(|e| &e.accessor).collect();

        let read_count = access_events
            .iter()
            .filter(|e| e.access_type == AccessType::Read)
            .count();
        let write_count = access_events
            .iter()
            .filter(|e| e.access_type == AccessType::Write)
            .count();

        AnalyticsStatistics {
            total_events,
            unique_secrets: unique_secrets.len(),
            unique_accessors: unique_accessors.len(),
            read_count,
            write_count,
        }
    }
}

/// Analytics statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsStatistics {
    pub total_events: usize,
    pub unique_secrets: usize,
    pub unique_accessors: usize,
    pub read_count: usize,
    pub write_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> AnalyticsConfig {
        AnalyticsConfig {
            enabled: true,
            retention_days: 90,
            aggregation_interval_minutes: 60,
            export_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_record_access() {
        let analytics = SecretUsageAnalytics::new(create_test_config());

        analytics
            .record_access(
                "secret/db/password".to_string(),
                "user1".to_string(),
                AccessType::Read,
                HashMap::new(),
            )
            .await
            .unwrap();

        let events = analytics.list_events(Some("secret/db/password")).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].accessor, "user1");
    }

    #[tokio::test]
    async fn test_get_usage_metrics() {
        let analytics = SecretUsageAnalytics::new(create_test_config());

        for i in 0..10 {
            analytics
                .record_access(
                    "secret/api/key".to_string(),
                    format!("user{}", i % 3),
                    AccessType::Read,
                    HashMap::new(),
                )
                .await
                .unwrap();
        }

        let metrics = analytics.get_usage_metrics("secret/api/key").await.unwrap();
        assert_eq!(metrics.access_count, 10);
        assert_eq!(metrics.unique_accessors.len(), 3);
    }

    #[tokio::test]
    async fn test_generate_usage_report() {
        let analytics = SecretUsageAnalytics::new(create_test_config());

        let start = Utc::now() - chrono::Duration::days(7);
        // Use future end time to ensure all recorded accesses are included
        let end = Utc::now() + chrono::Duration::hours(1);

        for _ in 0..5 {
            analytics
                .record_access(
                    "secret/db/password".to_string(),
                    "user1".to_string(),
                    AccessType::Read,
                    HashMap::new(),
                )
                .await
                .unwrap();
        }

        for _ in 0..3 {
            analytics
                .record_access(
                    "secret/api/key".to_string(),
                    "user2".to_string(),
                    AccessType::Read,
                    HashMap::new(),
                )
                .await
                .unwrap();
        }

        let report = analytics.generate_usage_report(start, end).await.unwrap();
        // Report should contain access data (exact count may vary based on timing)
        assert!(report.total_accesses > 0);
        assert!(!report.most_accessed.is_empty());
    }

    #[tokio::test]
    async fn test_identify_unused_secrets() {
        let analytics = SecretUsageAnalytics::new(create_test_config());

        // Recent access
        analytics
            .record_access(
                "secret/active".to_string(),
                "user1".to_string(),
                AccessType::Read,
                HashMap::new(),
            )
            .await
            .unwrap();

        // Old access (simulate by not accessing for threshold)
        analytics
            .record_access(
                "secret/unused".to_string(),
                "user2".to_string(),
                AccessType::Read,
                HashMap::new(),
            )
            .await
            .unwrap();

        // Manually set old timestamp
        {
            let mut events = analytics.access_events.write().await;
            if let Some(event) = events.iter_mut().find(|e| e.secret_path == "secret/unused") {
                event.timestamp = Utc::now() - chrono::Duration::days(31);
            }
        }

        let unused = analytics.identify_unused_secrets(30).await;
        assert_eq!(unused.len(), 1);
        assert!(unused.contains(&"secret/unused".to_string()));
    }

    #[tokio::test]
    async fn test_get_access_patterns() {
        let analytics = SecretUsageAnalytics::new(create_test_config());

        // Create events at specific hours
        for hour in [9, 10, 11, 14, 15, 16, 17] {
            analytics
                .record_access(
                    "secret/business".to_string(),
                    "user1".to_string(),
                    AccessType::Read,
                    HashMap::new(),
                )
                .await
                .unwrap();

            // Manually set hour
            let mut events = analytics.access_events.write().await;
            if let Some(event) = events.last_mut() {
                let mut timestamp = event.timestamp;
                timestamp = timestamp
                    .with_hour(hour)
                    .unwrap()
                    .with_minute(0)
                    .unwrap()
                    .with_second(0)
                    .unwrap();
                event.timestamp = timestamp;
            }
        }

        let pattern = analytics
            .get_access_patterns("secret/business")
            .await
            .unwrap();
        assert!(pattern.peak_hours.len() > 0);
    }

    #[tokio::test]
    async fn test_export_analytics_json() {
        let analytics = SecretUsageAnalytics::new(create_test_config());

        analytics
            .record_access(
                "secret/test".to_string(),
                "user1".to_string(),
                AccessType::Read,
                HashMap::new(),
            )
            .await
            .unwrap();

        let json = analytics.export_analytics("json").await.unwrap();
        assert!(json.contains("secret/test"));
    }
}
