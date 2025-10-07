// CI/CD Pipeline Integration - Secret injection for Jenkins/GitLab/GitHub Actions
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("Pipeline error: {0}")]
    PipelineError(String),
    #[error("Secret error: {0}")]
    SecretError(String),
    #[error("Injection error: {0}")]
    InjectionError(String),
}

pub type Result<T> = std::result::Result<T, PipelineError>;

/// Pipeline platform
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PipelinePlatform {
    Jenkins,
    GitLabCI,
    GitHubActions,
    CircleCI,
}

/// Auth method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthMethod {
    AppRole,
    JWT,
    Token,
}

/// Pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub platform: PipelinePlatform,
    pub vault_url: String,
    pub auth_method: AuthMethod,
    pub namespace: Option<String>,
}

/// Pipeline stage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PipelineStage {
    Build,
    Test,
    Deploy,
    Release,
}

/// Job status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Running,
    Success,
    Failed,
    Cancelled,
}

/// Pipeline job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineJob {
    pub job_id: String,
    pub pipeline_name: String,
    pub stage: PipelineStage,
    pub secrets_requested: Vec<String>, // secret paths
    pub status: JobStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Secret injection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInjection {
    pub injection_id: String,
    pub job_id: String,
    pub secret_path: String,
    pub env_var_name: String,
    pub injected_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

/// Pipeline audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineAudit {
    pub audit_id: String,
    pub job_id: String,
    pub pipeline_name: String,
    pub platform: PipelinePlatform,
    pub secrets_accessed: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// CI/CD Pipeline Integration
pub struct CICDPipeline {
    config: Arc<RwLock<PipelineConfig>>,
    jobs: Arc<RwLock<HashMap<String, PipelineJob>>>,
    injections: Arc<RwLock<HashMap<String, SecretInjection>>>,
    audit_log: Arc<RwLock<Vec<PipelineAudit>>>,
}

impl CICDPipeline {
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            injections: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register pipeline
    pub async fn register_pipeline(&self, pipeline_name: String) -> Result<()> {
        // Mock pipeline registration
        tracing::info!("Registered pipeline: {}", pipeline_name);
        Ok(())
    }

    /// Request secrets for job
    pub async fn request_secrets(
        &self,
        job: PipelineJob,
        ttl_seconds: i64,
    ) -> Result<HashMap<String, String>> {
        if job.secrets_requested.is_empty() {
            return Err(PipelineError::SecretError(
                "No secrets requested".to_string(),
            ));
        }

        let job_id = job.job_id.clone();
        let secrets_requested = job.secrets_requested.clone();

        // Store job
        let mut jobs = self.jobs.write().await;
        jobs.insert(job_id.clone(), job);
        drop(jobs);

        // Mock secret retrieval
        let mut secrets = HashMap::new();
        for secret_path in &secrets_requested {
            let secret_value = format!("secret_value_for_{}", secret_path);
            secrets.insert(secret_path.clone(), secret_value);
        }

        // Create injections
        for secret_path in &secrets_requested {
            let injection = SecretInjection {
                injection_id: uuid::Uuid::new_v4().to_string(),
                job_id: job_id.clone(),
                secret_path: secret_path.clone(),
                env_var_name: self.path_to_env_var(secret_path),
                injected_at: Utc::now(),
                expires_at: Utc::now() + Duration::seconds(ttl_seconds),
                revoked: false,
            };

            let mut injections = self.injections.write().await;
            injections.insert(injection.injection_id.clone(), injection);
        }

        Ok(secrets)
    }

    /// Inject secrets into environment
    pub async fn inject_into_env(
        &self,
        job_id: &str,
    ) -> Result<HashMap<String, String>> {
        let injections = self.injections.read().await;

        let mut env_vars = HashMap::new();
        for injection in injections.values() {
            if injection.job_id == job_id && !injection.revoked {
                // Mock secret value
                let secret_value = format!("value_for_{}", injection.secret_path);
                env_vars.insert(injection.env_var_name.clone(), secret_value);
            }
        }

        Ok(env_vars)
    }

    /// Revoke secrets on completion
    pub async fn revoke_on_completion(&self, job_id: &str) -> Result<usize> {
        let mut jobs = self.jobs.write().await;
        let job = jobs
            .get_mut(job_id)
            .ok_or_else(|| PipelineError::PipelineError("Job not found".to_string()))?;

        job.status = JobStatus::Success;
        job.completed_at = Some(Utc::now());

        drop(jobs);

        // Revoke all injections for this job
        let mut injections = self.injections.write().await;
        let mut revoked_count = 0;

        for injection in injections.values_mut() {
            if injection.job_id == job_id && !injection.revoked {
                injection.revoked = true;
                revoked_count += 1;
            }
        }

        Ok(revoked_count)
    }

    /// Audit pipeline access
    pub async fn audit_pipeline_access(&self, job_id: &str) -> Result<()> {
        let jobs = self.jobs.read().await;
        let job = jobs
            .get(job_id)
            .ok_or_else(|| PipelineError::PipelineError("Job not found".to_string()))?;

        let config = self.config.read().await;

        let audit = PipelineAudit {
            audit_id: uuid::Uuid::new_v4().to_string(),
            job_id: job_id.to_string(),
            pipeline_name: job.pipeline_name.clone(),
            platform: config.platform.clone(),
            secrets_accessed: job.secrets_requested.clone(),
            timestamp: Utc::now(),
        };

        drop(jobs);
        drop(config);

        let mut audit_log = self.audit_log.write().await;
        audit_log.push(audit);

        Ok(())
    }

    /// List active injections
    pub async fn list_active_injections(&self) -> Vec<SecretInjection> {
        let injections = self.injections.read().await;
        injections
            .values()
            .filter(|i| !i.revoked && Utc::now() < i.expires_at)
            .cloned()
            .collect()
    }

    /// Get job
    pub async fn get_job(&self, job_id: &str) -> Option<PipelineJob> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id).cloned()
    }

    /// List jobs
    pub async fn list_jobs(&self) -> Vec<PipelineJob> {
        let jobs = self.jobs.read().await;
        jobs.values().cloned().collect()
    }

    /// Get audit log
    pub async fn get_audit_log(&self) -> Vec<PipelineAudit> {
        let audit_log = self.audit_log.read().await;
        audit_log.clone()
    }

    /// Convert secret path to environment variable name
    fn path_to_env_var(&self, path: &str) -> String {
        path.replace('/', "_")
            .replace("-", "_")
            .to_uppercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> PipelineConfig {
        PipelineConfig {
            platform: PipelinePlatform::GitHubActions,
            vault_url: "https://vault.example.com".to_string(),
            auth_method: AuthMethod::JWT,
            namespace: Some("ci-cd".to_string()),
        }
    }

    fn create_test_job() -> PipelineJob {
        PipelineJob {
            job_id: uuid::Uuid::new_v4().to_string(),
            pipeline_name: "deploy-production".to_string(),
            stage: PipelineStage::Deploy,
            secrets_requested: vec![
                "secret/data/db/password".to_string(),
                "secret/data/api/key".to_string(),
            ],
            status: JobStatus::Running,
            started_at: Utc::now(),
            completed_at: None,
        }
    }

    #[tokio::test]
    async fn test_register_pipeline() {
        let cicd = CICDPipeline::new(create_test_config());

        cicd.register_pipeline("deploy-production".to_string())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_request_secrets() {
        let cicd = CICDPipeline::new(create_test_config());
        let job = create_test_job();

        let secrets = cicd.request_secrets(job.clone(), 3600).await.unwrap();

        assert_eq!(secrets.len(), 2);
        assert!(secrets.contains_key("secret/data/db/password"));
        assert!(secrets.contains_key("secret/data/api/key"));
    }

    #[tokio::test]
    async fn test_inject_into_env() {
        let cicd = CICDPipeline::new(create_test_config());
        let job = create_test_job();
        let job_id = job.job_id.clone();

        cicd.request_secrets(job, 3600).await.unwrap();

        let env_vars = cicd.inject_into_env(&job_id).await.unwrap();

        assert_eq!(env_vars.len(), 2);
        assert!(env_vars.contains_key("SECRET_DATA_DB_PASSWORD"));
        assert!(env_vars.contains_key("SECRET_DATA_API_KEY"));
    }

    #[tokio::test]
    async fn test_revoke_on_completion() {
        let cicd = CICDPipeline::new(create_test_config());
        let job = create_test_job();
        let job_id = job.job_id.clone();

        cicd.request_secrets(job, 3600).await.unwrap();

        let active = cicd.list_active_injections().await;
        assert_eq!(active.len(), 2);

        let revoked_count = cicd.revoke_on_completion(&job_id).await.unwrap();
        assert_eq!(revoked_count, 2);

        let active = cicd.list_active_injections().await;
        assert_eq!(active.len(), 0);
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let cicd = CICDPipeline::new(create_test_config());
        let job = create_test_job();
        let job_id = job.job_id.clone();

        cicd.request_secrets(job, 3600).await.unwrap();
        cicd.audit_pipeline_access(&job_id).await.unwrap();

        let audit_log = cicd.get_audit_log().await;
        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log[0].job_id, job_id);
        assert_eq!(audit_log[0].platform, PipelinePlatform::GitHubActions);
    }
}
