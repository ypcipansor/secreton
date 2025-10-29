// Secrets Rotation Scheduler - Automated rotation policies and scheduling
use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum RotationError {
    #[error("Policy error: {0}")]
    PolicyError(String),
    #[error("Rotation error: {0}")]
    RotationError(String),
    #[error("Schedule error: {0}")]
    ScheduleError(String),
}

pub type Result<T> = std::result::Result<T, RotationError>;

/// Rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    pub enabled: bool,
    pub default_rotation_interval_days: i64,
    pub max_rotation_age_days: i64,
    pub notification_enabled: bool,
}

/// Rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    pub policy_id: String,
    pub name: String,
    pub secret_path_pattern: String, // e.g., "secret/data/db/*"
    pub rotation_interval_days: i64,
    pub auto_rotate: bool,
    pub notification_enabled: bool,
    pub rotation_window: RotationWindow,
    pub created_at: DateTime<Utc>,
}

/// Rotation window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationWindow {
    pub start_hour: u8, // 0-23
    pub end_hour: u8,   // 0-23
}

/// Job status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Scheduled,
    Running,
    Completed,
    Failed,
}

/// Rotation job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationJob {
    pub job_id: String,
    pub policy_id: String,
    pub secret_path: String,
    pub next_rotation_at: DateTime<Utc>,
    pub last_rotated_at: Option<DateTime<Utc>>,
    pub status: JobStatus,
    pub rotation_count: u64,
}

/// Rotation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationResult {
    pub job_id: String,
    pub secret_path: String,
    pub rotated_at: DateTime<Utc>,
    pub old_version: u32,
    pub new_version: u32,
    pub duration_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Secrets Rotation Scheduler
pub struct RotationScheduler {
    config: Arc<RwLock<RotationConfig>>,
    policies: Arc<RwLock<HashMap<String, RotationPolicy>>>,
    jobs: Arc<RwLock<HashMap<String, RotationJob>>>,
    history: Arc<RwLock<Vec<RotationResult>>>,
}

impl RotationScheduler {
    pub fn new(config: RotationConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            policies: Arc::new(RwLock::new(HashMap::new())),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create rotation policy
    pub async fn create_policy(&self, policy: RotationPolicy) -> Result<()> {
        if policy.rotation_interval_days <= 0 {
            return Err(RotationError::PolicyError(
                "Rotation interval must be positive".to_string(),
            ));
        }

        if policy.rotation_window.start_hour >= 24 || policy.rotation_window.end_hour >= 24 {
            return Err(RotationError::PolicyError(
                "Invalid rotation window hours".to_string(),
            ));
        }

        let mut policies = self.policies.write().await;
        policies.insert(policy.policy_id.clone(), policy);

        Ok(())
    }

    /// Schedule rotation
    pub async fn schedule_rotation(&self, policy_id: &str, secret_path: String) -> Result<String> {
        let policies = self.policies.read().await;
        let policy = policies
            .get(policy_id)
            .ok_or_else(|| RotationError::PolicyError("Policy not found".to_string()))?;

        let job_id = uuid::Uuid::new_v4().to_string();

        let next_rotation = Utc::now() + Duration::days(policy.rotation_interval_days);

        let job = RotationJob {
            job_id: job_id.clone(),
            policy_id: policy_id.to_string(),
            secret_path: secret_path.clone(),
            next_rotation_at: next_rotation,
            last_rotated_at: None,
            status: JobStatus::Scheduled,
            rotation_count: 0,
        };

        let mut jobs = self.jobs.write().await;
        jobs.insert(job_id.clone(), job);

        Ok(job_id)
    }

    /// Execute rotation
    pub async fn execute_rotation(&self, job_id: &str) -> Result<RotationResult> {
        let start_time = std::time::Instant::now();

        // Get policy_id first
        let (policy_id, secret_path) = {
            let jobs = self.jobs.read().await;
            let job = jobs
                .get(job_id)
                .ok_or_else(|| RotationError::RotationError("Job not found".to_string()))?;
            (job.policy_id.clone(), job.secret_path.clone())
        };

        // Check if within rotation window
        let rotation_interval_days = {
            let policies = self.policies.read().await;
            let policy = policies
                .get(&policy_id)
                .ok_or_else(|| RotationError::PolicyError("Policy not found".to_string()))?;

            let current_hour = Utc::now().hour() as u8;
            if !self.is_within_window(current_hour, &policy.rotation_window) {
                return Err(RotationError::ScheduleError(
                    "Current time is outside rotation window".to_string(),
                ));
            }

            policy.rotation_interval_days
        };

        // Now update job
        let (old_version, new_version) = {
            let mut jobs = self.jobs.write().await;
            let job = jobs.get_mut(job_id).unwrap();

            job.status = JobStatus::Running;

            // Mock secret rotation
            let old_version = job.rotation_count as u32;
            let new_version = old_version + 1;

            // Simulate rotation
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            job.status = JobStatus::Completed;
            job.last_rotated_at = Some(Utc::now());
            job.rotation_count += 1;

            // Schedule next rotation
            job.next_rotation_at = Utc::now() + Duration::days(rotation_interval_days);

            (old_version, new_version)
        };

        let duration_ms = start_time.elapsed().as_millis() as u64;

        let result = RotationResult {
            job_id: job_id.to_string(),
            secret_path,
            rotated_at: Utc::now(),
            old_version,
            new_version,
            duration_ms,
            success: true,
            error_message: None,
        };

        let mut history = self.history.write().await;
        history.push(result.clone());

        Ok(result)
    }

    /// Check due rotations
    pub async fn check_due_rotations(&self) -> Vec<String> {
        let jobs = self.jobs.read().await;
        let now = Utc::now();

        jobs.iter()
            .filter(|(_, job)| job.status == JobStatus::Scheduled && job.next_rotation_at <= now)
            .map(|(job_id, _)| job_id.clone())
            .collect()
    }

    /// Get rotation history
    pub async fn get_rotation_history(&self, secret_path: &str) -> Vec<RotationResult> {
        let history = self.history.read().await;
        history
            .iter()
            .filter(|r| r.secret_path == secret_path)
            .cloned()
            .collect()
    }

    /// List policies
    pub async fn list_policies(&self) -> Vec<RotationPolicy> {
        let policies = self.policies.read().await;
        policies.values().cloned().collect()
    }

    /// Get policy
    pub async fn get_policy(&self, policy_id: &str) -> Option<RotationPolicy> {
        let policies = self.policies.read().await;
        policies.get(policy_id).cloned()
    }

    /// Update policy
    pub async fn update_policy(&self, policy: RotationPolicy) -> Result<()> {
        let mut policies = self.policies.write().await;

        if !policies.contains_key(&policy.policy_id) {
            return Err(RotationError::PolicyError("Policy not found".to_string()));
        }

        policies.insert(policy.policy_id.clone(), policy);

        Ok(())
    }

    /// Disable policy
    pub async fn disable_policy(&self, policy_id: &str) -> Result<()> {
        let mut policies = self.policies.write().await;
        let policy = policies
            .get_mut(policy_id)
            .ok_or_else(|| RotationError::PolicyError("Policy not found".to_string()))?;

        policy.auto_rotate = false;

        Ok(())
    }

    /// List jobs
    pub async fn list_jobs(&self) -> Vec<RotationJob> {
        let jobs = self.jobs.read().await;
        jobs.values().cloned().collect()
    }

    /// Get job
    pub async fn get_job(&self, job_id: &str) -> Option<RotationJob> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id).cloned()
    }

    /// Check if within rotation window
    fn is_within_window(&self, current_hour: u8, window: &RotationWindow) -> bool {
        if window.start_hour <= window.end_hour {
            current_hour >= window.start_hour && current_hour < window.end_hour
        } else {
            // Crosses midnight
            current_hour >= window.start_hour || current_hour < window.end_hour
        }
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> RotationStats {
        let jobs = self.jobs.read().await;
        let history = self.history.read().await;

        let total_jobs = jobs.len();
        let completed_rotations = history.iter().filter(|r| r.success).count();
        let failed_rotations = history.iter().filter(|r| !r.success).count();
        let pending_jobs = jobs
            .values()
            .filter(|j| j.status == JobStatus::Scheduled)
            .count();

        RotationStats {
            total_jobs,
            completed_rotations,
            failed_rotations,
            pending_jobs,
        }
    }
}

/// Rotation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStats {
    pub total_jobs: usize,
    pub completed_rotations: usize,
    pub failed_rotations: usize,
    pub pending_jobs: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> RotationConfig {
        RotationConfig {
            enabled: true,
            default_rotation_interval_days: 90,
            max_rotation_age_days: 365,
            notification_enabled: true,
        }
    }

    fn create_test_policy() -> RotationPolicy {
        RotationPolicy {
            policy_id: "db-rotation".to_string(),
            name: "Database Rotation".to_string(),
            secret_path_pattern: "secret/data/db/*".to_string(),
            rotation_interval_days: 30,
            auto_rotate: true,
            notification_enabled: true,
            rotation_window: RotationWindow {
                start_hour: 2,
                end_hour: 6,
            },
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_create_policy() {
        let scheduler = RotationScheduler::new(create_test_config());
        let policy = create_test_policy();

        scheduler.create_policy(policy).await.unwrap();

        let policies = scheduler.list_policies().await;
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].name, "Database Rotation");
    }

    #[tokio::test]
    async fn test_schedule_rotation() {
        let scheduler = RotationScheduler::new(create_test_config());
        let policy = create_test_policy();

        scheduler.create_policy(policy).await.unwrap();

        let job_id = scheduler
            .schedule_rotation("db-rotation", "secret/data/db/password".to_string())
            .await
            .unwrap();

        let job = scheduler.get_job(&job_id).await.unwrap();
        assert_eq!(job.secret_path, "secret/data/db/password");
        assert_eq!(job.status, JobStatus::Scheduled);
    }

    #[tokio::test]
    async fn test_execute_rotation() {
        let scheduler = RotationScheduler::new(create_test_config());
        let mut policy = create_test_policy();

        // Set rotation window to current hour
        let current_hour = Utc::now().hour() as u8;
        policy.rotation_window = RotationWindow {
            start_hour: current_hour.saturating_sub(1),
            end_hour: (current_hour + 2) % 24,
        };

        scheduler.create_policy(policy).await.unwrap();

        let job_id = scheduler
            .schedule_rotation("db-rotation", "secret/data/db/password".to_string())
            .await
            .unwrap();

        let result = scheduler.execute_rotation(&job_id).await.unwrap();

        assert!(result.success);
        assert_eq!(result.old_version, 0);
        assert_eq!(result.new_version, 1);

        let job = scheduler.get_job(&job_id).await.unwrap();
        assert_eq!(job.rotation_count, 1);
        assert_eq!(job.status, JobStatus::Completed);
    }

    #[tokio::test]
    async fn test_check_due_rotations() {
        let scheduler = RotationScheduler::new(create_test_config());
        let mut policy = create_test_policy();
        policy.rotation_interval_days = 1; // Valid positive interval

        scheduler.create_policy(policy).await.unwrap();

        let job_id = scheduler
            .schedule_rotation("db-rotation", "secret/data/db/password".to_string())
            .await
            .unwrap();

        // Manually set next_rotation_at to past
        let mut jobs = scheduler.jobs.write().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            job.next_rotation_at = Utc::now() - Duration::hours(1);
        }
        drop(jobs);

        let due_jobs = scheduler.check_due_rotations().await;
        assert_eq!(due_jobs.len(), 1);
        assert_eq!(due_jobs[0], job_id);
    }

    #[tokio::test]
    async fn test_rotation_history() {
        let scheduler = RotationScheduler::new(create_test_config());
        let mut policy = create_test_policy();

        let current_hour = Utc::now().hour() as u8;
        policy.rotation_window = RotationWindow {
            start_hour: current_hour.saturating_sub(1),
            end_hour: (current_hour + 2) % 24,
        };

        scheduler.create_policy(policy).await.unwrap();

        let secret_path = "secret/data/db/password".to_string();
        let job_id = scheduler
            .schedule_rotation("db-rotation", secret_path.clone())
            .await
            .unwrap();

        scheduler.execute_rotation(&job_id).await.unwrap();

        let history = scheduler.get_rotation_history(&secret_path).await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].secret_path, secret_path);
    }
}
