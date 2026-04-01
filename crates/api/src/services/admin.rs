//! Admin service for system management operations.

#![allow(clippy::collapsible_if)]

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use uuid;
// sha2::Digest is imported locally where needed (e.g., create_backup)

use crate::services::auth::{AuthenticationService, USER_STORAGE_PREFIX};
use crate::services::crypto::CryptoService;

pub const ROLE_STORAGE_PREFIX: &str = "sys/auth/roles/";
use secreton_performance::SecretPerformanceOptimizer;
use secreton_storage::{QueryParams, StorageBackend};

/// Admin service errors
#[derive(Error, Debug)]
pub enum AdminError {
    #[error("Operation not permitted: {0}")]
    NotPermitted(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Resource already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("System maintenance in progress")]
    MaintenanceInProgress,

    #[error("Auth service error: {0}")]
    Auth(#[from] crate::services::auth::AuthError),

    #[error("Storage error: {0}")]
    Storage(#[from] secreton_storage::StorageError),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// System statistics
#[derive(Debug, Serialize)]
pub struct SystemStats {
    pub uptime_seconds: u64,
    pub total_users: u64,
    pub active_sessions: u64,
    pub total_secrets: u64,
    pub total_keys: u64,
    pub storage_usage_bytes: u64,
    pub cache_hit_rate: f64,
    pub requests_per_minute: f64,
}

/// Backup information
#[derive(Debug, Serialize)]
pub struct BackupInfo {
    pub id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub size_bytes: u64,
    pub compressed: bool,
    pub encrypted: bool,
    pub checksum: String,
    pub metadata: HashMap<String, String>,
}

/// Maintenance operation result
#[derive(Debug, Serialize)]
pub struct MaintenanceResult {
    pub operation: String,
    pub success: bool,
    pub duration_ms: u64,
    pub details: HashMap<String, serde_json::Value>,
}

/// User information
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_enabled() -> bool {
    true
}

/// User creation request
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

/// User update request
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub enabled: Option<bool>,
    pub roles: Option<Vec<String>>,
}

/// Role information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RoleInfo {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub users: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

/// Role creation request
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub metadata: Option<HashMap<String, String>>,
}

/// Role update request — all fields are optional to support partial updates
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateRoleRequest {
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, String>>,
}

/// Admin service for system management with request metrics tracking
pub struct AdminService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    auth: Arc<AuthenticationService>,
    performance: Arc<SecretPerformanceOptimizer>,
    audit: Arc<crate::services::audit::AuditLogger>,
    crypto: Option<Arc<CryptoService>>,
}

impl AdminService {
    /// Create new admin service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        auth: Arc<AuthenticationService>,
        performance: Arc<SecretPerformanceOptimizer>,
        audit: Arc<crate::services::audit::AuditLogger>,
    ) -> Result<Self> {
        Ok(Self {
            storage,
            auth,
            performance,
            audit,
            crypto: None,
        })
    }

    /// Set crypto service
    pub fn with_crypto(mut self, crypto: Arc<CryptoService>) -> Self {
        self.crypto = Some(crypto);
        self
    }

    /// Get system statistics
    pub async fn get_system_stats(&self) -> Result<SystemStats, AdminError> {
        // Get uptime
        let uptime_seconds = self.get_system_uptime().await;

        // Get user count from auth service
        let total_users = self.auth.get_user_count().await.map_err(AdminError::Auth)?;

        // Get active sessions
        let active_sessions = self
            .auth
            .get_active_session_count()
            .await
            .map_err(AdminError::Auth)?;

        // Get secret/key counts from storage
        let (total_secrets, total_keys) = self.get_storage_counts().await?;

        // Get storage usage
        let storage_usage_bytes = self.get_storage_usage().await?;

        // Calculate cache hit rate (try to get from metrics, fallback to default)
        let cache_hit_rate = self.get_cache_hit_rate().await;

        // Calculate requests per minute based on recent activity
        let requests_per_minute = self.get_requests_per_minute().await;

        Ok(SystemStats {
            uptime_seconds,
            total_users,
            active_sessions,
            total_secrets,
            total_keys,
            storage_usage_bytes,
            cache_hit_rate,
            requests_per_minute,
        })
    }

    /// Get system uptime in seconds
    async fn get_system_uptime(&self) -> u64 {
        // Try to read from /proc/uptime
        if let Ok(content) = tokio::fs::read_to_string("/proc/uptime").await {
            if let Some(uptime_str) = content.split_whitespace().next() {
                if let Ok(uptime) = uptime_str.parse::<f64>() {
                    return uptime as u64;
                }
            }
        }

        // Fallback: use process start time
        std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Get storage counts (secrets and keys)
    async fn get_storage_counts(&self) -> Result<(u64, u64), AdminError> {
        let stats = self
            .storage
            .get_stats()
            .await
            .map_err(AdminError::Storage)?;

        // For now, consider all entries as secrets, and keys as a subset
        // In a real implementation, you might distinguish based on paths or tags
        let total_secrets = stats.total_entries;
        let total_keys = (total_secrets / 10).max(1); // Rough estimate

        Ok((total_secrets, total_keys))
    }

    /// Get storage usage in bytes
    async fn get_storage_usage(&self) -> Result<u64, AdminError> {
        let stats = self
            .storage
            .get_stats()
            .await
            .map_err(AdminError::Storage)?;
        Ok(stats.total_size_bytes)
    }

    /// Get cache hit rate (0.0 to 1.0)
    async fn get_cache_hit_rate(&self) -> f64 {
        match self.performance.analyze_performance().await {
            Ok(metrics) => metrics.cache_hit_rate,
            Err(_) => 0.0,
        }
    }

    /// Get requests per minute (actual implementation based on audit logs)
    async fn get_requests_per_minute(&self) -> f64 {
        // Get audit logs from the last 5 minutes
        let end_time = chrono::Utc::now();
        let start_time = end_time - chrono::Duration::minutes(5);

        let filters = crate::services::audit::AuditFilters {
            start_date: Some(start_time),
            end_date: Some(end_time),
            ..Default::default()
        };

        match self.audit.get_entries(filters).await {
            Ok(audit_logs) => {
                let total_requests = audit_logs.len() as f64;
                let minutes_elapsed = 5.0; // 5 minutes window

                // Calculate requests per minute
                let rpm = total_requests / minutes_elapsed;

                // If no recent activity, fall back to a minimum rate
                if rpm > 0.0 {
                    rpm
                } else {
                    1.0 // Minimum rate to indicate system is active
                }
            }
            Err(_) => {
                // If we can't access audit logs, fall back to a reasonable default
                10.0
            }
        }
    }

    /// Create system backup
    pub async fn create_backup(&self) -> Result<BackupInfo, AdminError> {
        let backup_id = uuid::Uuid::new_v4().to_string();
        let backup_path = format!("backups/{}", backup_id);

        // Get all secreton entries to backup
        let query_params = secreton_storage::QueryParams {
            path_prefix: None,

            limit: None,
            offset: Some(0),
            ..Default::default()
        };

        let entries: Vec<_> = self
            .storage
            .list(&query_params)
            .await
            .map_err(AdminError::Storage)?
            .into_iter()
            .filter(|e| !e.path.starts_with("backups/"))
            .collect();

        // Serialize all entries
        let backup_data =
            serde_json::to_string(&entries).map_err(|e| AdminError::Internal(e.into()))?;

        // Calculate checksum
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(backup_data.as_bytes());
        let checksum = format!("sha256:{:x}", hasher.finalize());

        // Store backup metadata
        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
        metadata.insert("type".to_string(), "full".to_string());
        metadata.insert("entry_count".to_string(), entries.len().to_string());
        let (encrypted_data, encryption_metadata, is_encrypted) = if let Some(crypto) = &self.crypto {
            let enc = crypto.encrypt_data(backup_data.as_bytes()).await.map_err(|e| {
                AdminError::Internal(anyhow::anyhow!("Encryption failed: {}", e))
            })?;
            (
                enc,
                secreton_storage::EncryptionMetadata {
                    algorithm: "encrypted".to_string(),
                    key_id: "active".to_string(),
                    iv: Vec::new(),
                    auth_tag: None,
                    aad: None,
                    kdf_params: None,
                },
                true,
            )
        } else {
            (
                backup_data.as_bytes().to_vec(),
                secreton_storage::EncryptionMetadata {
                    algorithm: "none".to_string(),
                    key_id: "backup".to_string(),
                    iv: Vec::new(),
                    auth_tag: None,
                    aad: None,
                    kdf_params: None,
                },
                false,
            )
        };

        let mut final_metadata = metadata.clone();
        if !is_encrypted {
            final_metadata.insert("data".to_string(), backup_data.clone());
        }

        let mut backup_entry = secreton_storage::SecretEntry::new(
            backup_path,
            encrypted_data.clone(),
            encryption_metadata,
            secreton_storage::SecurityLevel::TopSecret,
            uuid::Uuid::new_v4(),
        );
        backup_entry.id = uuid::Uuid::new_v4();
        backup_entry.metadata = final_metadata;
        backup_entry.tags = vec!["backup".to_string(), "system".to_string()];

        let size_bytes = if is_encrypted {
            encrypted_data.len() as u64
        } else {
            backup_data.len() as u64
        };

        self.storage
            .store(&backup_entry)
            .await
            .map_err(AdminError::Storage)?;

        let backup_info = BackupInfo {
            id: backup_id,
            created_at: chrono::Utc::now(),
            size_bytes,
            compressed: false,
            encrypted: is_encrypted,
            checksum,
            metadata: {
                let mut m = HashMap::new();
                m.insert(
                    "version".to_string(),
                    env!("CARGO_PKG_VERSION").to_string(),
                );
                m.insert("type".to_string(), "full".to_string());
                m.insert("entry_count".to_string(), entries.len().to_string());
                m
            },
        };

        Ok(backup_info)
    }

    /// List available backups
    pub async fn list_backups(&self) -> Result<Vec<BackupInfo>, AdminError> {
        let query_params = secreton_storage::QueryParams {
            path_prefix: None,

            limit: None,
            offset: Some(0),
            ..Default::default()
        };

        let entries: Vec<_> = self
            .storage
            .list(&query_params)
            .await
            .map_err(AdminError::Storage)?
            .into_iter()
            .filter(|e| e.path.starts_with("backups/"))
            .collect();

        let backups = entries
            .into_iter()
            .filter_map(|entry| {
                let backup_id = entry.path.split('/').next_back()?.to_string();
                let encrypted = entry.encryption_metadata.algorithm != "none" || !entry.metadata.contains_key("data");
                let size_bytes = if let Some(data) = entry.metadata.get("data") {
                    data.len() as u64
                } else {
                    entry.encrypted_data.len() as u64
                };

                Some(BackupInfo {
                    id: backup_id,
                    created_at: entry.created_at,
                    size_bytes,
                    compressed: false,
                    encrypted,
                    checksum: entry.metadata.get("checksum").cloned().unwrap_or_default(),
                    metadata: {
                        let mut m = entry.metadata;
                        m.remove("data");
                        m
                    },
                })
            })
            .collect();

        Ok(backups)
    }

    /// Restore from backup
    pub async fn restore_backup(&self, backup_id: &str) -> Result<MaintenanceResult, AdminError> {
        let start_time = std::time::Instant::now();

        let backup_path = format!("backups/{}", backup_id);
        let backup_entry = self
            .storage
            .get_by_path(&backup_path)
            .await
            .map_err(AdminError::Storage)?
            .ok_or_else(|| AdminError::NotFound(format!("Backup {} not found", backup_id)))?;

        // Get backup data
        let backup_data_bytes = if let Some(data) = backup_entry.metadata.get("data") {
            data.as_bytes().to_vec()
        } else if !backup_entry.encrypted_data.is_empty() {
            if let Some(crypto) = &self.crypto {
                crypto.decrypt(&backup_entry.encrypted_data).await.map_err(|e| {
                    AdminError::Internal(anyhow::anyhow!("Failed to decrypt backup data: {}", e))
                })?
            } else {
                return Err(AdminError::Internal(anyhow::anyhow!(
                    "Crypto service unavailable, cannot decrypt backup"
                )));
            }
        } else {
            return Err(AdminError::Internal(anyhow::anyhow!("Backup data not found")));
        };

        // Verify checksum
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&backup_data_bytes);
        let computed_checksum = format!("sha256:{:x}", hasher.finalize());

        if let Some(stored_checksum) = backup_entry.metadata.get("checksum") {
            if stored_checksum != &computed_checksum {
                return Err(AdminError::Internal(anyhow::anyhow!(
                    "Backup data integrity check failed: checksum mismatch"
                )));
            }
        }

        // Parse entries
        let entries: Vec<secreton_storage::SecretEntry> =
            serde_json::from_slice(&backup_data_bytes).map_err(|e| AdminError::Internal(e.into()))?;

        // Restore each entry (excluding backup entries themselves)
        for entry in &entries {
            if !entry.path.starts_with("backups/") {
                self.storage
                    .store(entry)
                    .await
                    .map_err(AdminError::Storage)?;
            }
        }

        let duration = start_time.elapsed();
        Ok(MaintenanceResult {
            operation: "restore_backup".to_string(),
            success: true,
            duration_ms: duration.as_millis() as u64,
            details: {
                let mut details = HashMap::new();
                details.insert(
                    "backup_id".to_string(),
                    serde_json::Value::String(backup_id.to_string()),
                );
                details.insert(
                    "entries_restored".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(entries.len() as u64)),
                );
                details
            },
        })
    }

    /// Run garbage collection
    pub async fn run_garbage_collection(&self) -> Result<MaintenanceResult, AdminError> {
        let start_time = std::time::Instant::now();

        // Clean expired sessions
        let expired_sessions = self
            .auth
            .cleanup_expired_sessions()
            .await
            .map_err(AdminError::Auth)?;

        // Clean expired secrets (this would need to be implemented in storage)
        let expired_secrets = self.cleanup_expired_secrets().await?;

        // Compact storage if supported
        let storage_cleaned = self.storage_cleanup().await?;

        let duration = start_time.elapsed();

        let mut details = HashMap::new();
        details.insert(
            "expired_sessions".to_string(),
            serde_json::Value::Number(expired_sessions.into()),
        );
        details.insert(
            "expired_secrets".to_string(),
            serde_json::Value::Number(expired_secrets.into()),
        );
        details.insert(
            "storage_cleaned_bytes".to_string(),
            serde_json::Value::Number(storage_cleaned.into()),
        );

        Ok(MaintenanceResult {
            operation: "garbage_collection".to_string(),
            success: true,
            duration_ms: duration.as_millis() as u64,
            details,
        })
    }

    /// Compact database

    /// Get a specific backup
    pub async fn get_backup(&self, backup_id: &str) -> Result<BackupInfo, AdminError> {
        let backup_path = format!("backups/{}", backup_id);

        let entry_opt: Option<secreton_storage::SecretEntry> = self
            .storage
            .get_by_path(&backup_path)
            .await
            .map_err(AdminError::Storage)?;

        let entry = entry_opt
            .ok_or_else(|| AdminError::NotFound(format!("Backup {} not found", backup_id)))?;

        let size_bytes = if let Some(data) = entry.metadata.get("data") {
            data.len() as u64
        } else {
            entry.encrypted_data.len() as u64
        };

        Ok(BackupInfo {
            id: backup_id.to_string(),
            created_at: entry.created_at,
            size_bytes,
            compressed: false,
            encrypted: entry.encryption_metadata.algorithm != "none" || !entry.metadata.contains_key("data"),
            checksum: entry.metadata.get("checksum").cloned().unwrap_or_default(),
            metadata: {
                let mut m = entry.metadata;
                m.remove("data");
                m
            },
        })
    }

    /// Delete a backup
    pub async fn delete_backup(&self, backup_id: &str) -> Result<bool, AdminError> {
        let backup_path = format!("backups/{}", backup_id);

        let entry_opt: Option<secreton_storage::SecretEntry> = self
            .storage
            .get_by_path(&backup_path)
            .await
            .map_err(AdminError::Storage)?;

        if let Some(entry) = entry_opt {
            self.storage
                .delete_by_id(entry.id)
                .await
                .map_err(AdminError::Storage)?;
            Ok(true)
        } else {
            Err(AdminError::NotFound(format!(
                "Backup {} not found",
                backup_id
            )))
        }
    }

    pub async fn compact_database(&self) -> Result<MaintenanceResult, AdminError> {
        let start_time = std::time::Instant::now();

        // Perform database compaction based on storage backend
        let compaction_result = self.perform_database_compaction().await?;

        let duration = start_time.elapsed();

        Ok(MaintenanceResult {
            operation: "compact_database".to_string(),
            success: compaction_result.success,
            duration_ms: duration.as_millis() as u64,
            details: compaction_result.details,
        })
    }

    /// Get audit logs with filtering
    pub async fn get_audit_logs(
        &self,
        start_time: Option<chrono::DateTime<chrono::Utc>>,
        end_time: Option<chrono::DateTime<chrono::Utc>>,
        user_id: Option<&str>,
        action: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<AuditLogEntry>, AdminError> {
        let filters = crate::services::audit::AuditFilters {
            user: user_id.map(|s| s.to_string()),
            action: action.map(|s| s.to_string()),
            start_date: start_time,
            end_date: end_time,
            ..Default::default()
        };

        let entries = self
            .audit
            .get_entries(filters)
            .await
            .map_err(|e| AdminError::Internal(e.into()))?;

        let mut logs: Vec<AuditLogEntry> = entries
            .into_iter()
            .map(|e| AuditLogEntry {
                id: e.id.to_string(),
                timestamp: e.timestamp,
                user_id: e.user_id.to_string(),
                action: e.action,
                resource: e.resource_type,
                resource_id: e.resource_id,
                ip_address: e.ip_address.unwrap_or_default(),
                user_agent: e.user_agent.unwrap_or_default(),
                success: e.success,
                details: Some(serde_json::to_value(e.details).unwrap_or_default()),
            })
            .collect();

        if let Some(l) = limit {
            logs.truncate(l as usize);
        }

        Ok(logs)
    }

    /// Export audit logs in specified format
    pub async fn export_audit_logs(
        &self,
        format: &str,
        start_time: Option<chrono::DateTime<chrono::Utc>>,
        end_time: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<String, AdminError> {
        // Get all audit logs for the time range
        let audit_logs = self
            .get_audit_logs(start_time, end_time, None, None, None)
            .await?;

        match format.to_lowercase().as_str() {
            "json" => serde_json::to_string_pretty(&audit_logs)
                .map_err(|e| AdminError::Internal(e.into())),
            "csv" => {
                let mut csv_content = String::from(
                    "timestamp,user_id,action,resource,resource_id,ip_address,user_agent,success\n",
                );
                for log in audit_logs {
                    csv_content.push_str(&format!(
                        "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                        log.timestamp,
                        log.user_id,
                        log.action,
                        log.resource,
                        log.resource_id.unwrap_or_default(),
                        log.ip_address,
                        log.user_agent,
                        log.success
                    ));
                }
                Ok(csv_content)
            }
            "xml" => {
                let mut xml_content =
                    String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<audit_logs>\n");
                for log in audit_logs {
                    xml_content.push_str(&format!(
                        "  <entry>\n    <timestamp>{}</timestamp>\n    <user_id>{}</user_id>\n    <action>{}</action>\n    <resource>{}</resource>\n    <success>{}</success>\n  </entry>\n",
                        log.timestamp,
                        log.user_id,
                        log.action,
                        log.resource,
                        log.success
                    ));
                }
                xml_content.push_str("</audit_logs>");
                Ok(xml_content)
            }
            _ => Err(AdminError::InvalidConfig(format!(
                "Unsupported export format: {}",
                format
            ))),
        }
    }

    /// Run security scan
    pub async fn run_security_scan(&self) -> Result<SecurityScanResult, AdminError> {
        let scan_id = uuid::Uuid::new_v4().to_string();
        let started_at = chrono::Utc::now();

        let mut findings = Vec::new();

        // Run checks concurrently
        let (pw_res, cert_res, config_res, activity_res) = tokio::join!(
            self.check_password_security(),
            self.check_certificate_expiry(),
            self.check_security_configuration(),
            self.check_suspicious_activity()
        );

        findings.extend(pw_res?);
        findings.extend(cert_res?);
        findings.extend(config_res?);
        findings.extend(activity_res?);

        let completed_at = chrono::Utc::now();

        Ok(SecurityScanResult {
            scan_id,
            status: "completed".to_string(),
            started_at,
            completed_at: Some(completed_at),
            findings,
        })
    }

    /// Update a policy definition
    pub async fn update_policy(&self, _name: &str, _content: &str) -> Result<(), AdminError> {
        // Placeholder - requires reference to PolicyService or storage update
        // In a real implementation this would validate and store the policy JSON/HCL
        Ok(())
    }

    /// Check password security
    async fn check_password_security(&self) -> Result<Vec<SecurityFinding>, AdminError> {
        let mut findings = Vec::new();

        // Get password policy from configuration
        let password_policy = self.get_password_policy().await?;

        // Query for all users
        let users = self
            .list_users()
            .await
            .map_err(|e| AdminError::Internal(anyhow::anyhow!("Failed to list users: {}", e)))?;

        // Check each user account
        for user in &users {
            // Check if user has been inactive for too long
            if let Some(last_login) = user.last_login {
                let days_since_login = (chrono::Utc::now() - last_login).num_days();
                if days_since_login > 90 {
                    // 90 days inactivity threshold
                    findings.push(SecurityFinding {
                        severity: "medium".to_string(),
                        category: "authentication".to_string(),
                        title: format!("Inactive user account: {}", user.username),
                        description: format!(
                            "User {} has not logged in for {} days",
                            user.username, days_since_login
                        ),
                        recommendation: "Review inactive accounts and disable if no longer needed"
                            .to_string(),
                        affected_resources: vec![format!("user:{}", user.username)],
                    });
                }
            }

            // Check if user has never logged in (account created but never used)
            let days_since_creation = (chrono::Utc::now() - user.created_at).num_days();
            if user.last_login.is_none() && days_since_creation > 30 {
                findings.push(SecurityFinding {
                    severity: "low".to_string(),
                    category: "authentication".to_string(),
                    title: format!("Unused user account: {}", user.username),
                    description: format!(
                        "User {} was created {} days ago but has never logged in",
                        user.username, days_since_creation
                    ),
                    recommendation: "Review unused accounts and remove if not needed".to_string(),
                    affected_resources: vec![format!("user:{}", user.username)],
                });
            }
        }

        // Check for weak password policies
        if password_policy.min_length < 8 {
            findings.push(SecurityFinding {
                severity: "high".to_string(),
                category: "configuration".to_string(),
                title: "Weak password minimum length".to_string(),
                description: format!(
                    "Password policy requires minimum length of {} characters",
                    password_policy.min_length
                ),
                recommendation: "Increase minimum password length to at least 8 characters"
                    .to_string(),
                affected_resources: vec!["password_policy".to_string()],
            });
        }

        if !password_policy.require_uppercase {
            findings.push(SecurityFinding {
                severity: "medium".to_string(),
                category: "configuration".to_string(),
                title: "Password policy doesn't require uppercase".to_string(),
                description: "Password policy should require at least one uppercase character"
                    .to_string(),
                recommendation: "Enable uppercase character requirement in password policy"
                    .to_string(),
                affected_resources: vec!["password_policy".to_string()],
            });
        }

        if !password_policy.require_numbers {
            findings.push(SecurityFinding {
                severity: "medium".to_string(),
                category: "configuration".to_string(),
                title: "Password policy doesn't require numbers".to_string(),
                description: "Password policy should require at least one numeric character"
                    .to_string(),
                recommendation: "Enable numeric character requirement in password policy"
                    .to_string(),
                affected_resources: vec!["password_policy".to_string()],
            });
        }

        if !password_policy.require_special {
            findings.push(SecurityFinding {
                severity: "low".to_string(),
                category: "configuration".to_string(),
                title: "Password policy doesn't require special characters".to_string(),
                description: "Password policy should require at least one special character"
                    .to_string(),
                recommendation: "Enable special character requirement in password policy"
                    .to_string(),
                affected_resources: vec!["password_policy".to_string()],
            });
        }

        // Check for users with default/weak passwords (in a real system, this would check against known weak passwords)
        // Since passwords are hashed, we can only check for patterns in metadata
        let weak_password_indicators = vec!["password", "123456", "admin", "user", "default"];
        for user in &users {
            if let Some(password_hint) = user.metadata.get("password_hint") {
                for indicator in &weak_password_indicators {
                    if password_hint.to_lowercase().contains(indicator) {
                        findings.push(SecurityFinding {
                            severity: "high".to_string(),
                            category: "authentication".to_string(),
                            title: format!("Potentially weak password for user: {}", user.username),
                            description: format!(
                                "User {} has a password hint containing '{}'",
                                user.username, indicator
                            ),
                            recommendation: "Require user to change password immediately"
                                .to_string(),
                            affected_resources: vec![format!("user:{}", user.username)],
                        });
                        break;
                    }
                }
            }
        }

        // If no specific findings, add a general policy review reminder
        if findings.is_empty() {
            findings.push(SecurityFinding {
                severity: "info".to_string(),
                category: "authentication".to_string(),
                title: "Password security review completed".to_string(),
                description: "No immediate password security issues found".to_string(),
                recommendation: "Continue regular password policy reviews and user account audits"
                    .to_string(),
                affected_resources: vec!["password_security".to_string()],
            });
        }

        Ok(findings)
    }

    /// Get password policy from configuration
    async fn get_password_policy(
        &self,
    ) -> Result<secreton_common::password::PasswordPolicy, AdminError> {
        // Try to get password policy from system config
        let config_path = "system/config";
        if let Ok(Some(config_entry)) = self.storage.get_by_path(config_path).await {
            if let Some(config_data) = config_entry.metadata.get("config_data") {
                if let Ok(config) = serde_json::from_str::<serde_json::Value>(config_data) {
                    // Extract password policy settings
                    let min_length = config
                        .get("password_policy_min_length")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(8) as usize;

                    let require_uppercase = config
                        .get("password_policy_require_uppercase")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);

                    let require_numbers = config
                        .get("password_policy_require_numbers")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);

                    let require_special = config
                        .get("password_policy_require_special")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    return Ok(secreton_common::password::PasswordPolicy {
                        min_length,
                        max_length: None, // Not used in this context
                        require_uppercase,
                        require_lowercase: true, // Assume always required
                        require_numbers,
                        require_special,
                        allowed_special_chars: None, // Not used in this context
                    });
                }
            }
        }

        // Return default policy if not configured
        Ok(secreton_common::password::PasswordPolicy {
            min_length: 8,
            max_length: None,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: false,
            allowed_special_chars: None,
        })
    }

    /// Check certificate expiry
    async fn check_certificate_expiry(&self) -> Result<Vec<SecurityFinding>, AdminError> {
        let mut findings = Vec::new();

        // Check for certificates/keys expiring soon
        // Scan certificate storage for entries with expiry dates
        let query_params = QueryParams {
            path_prefix: None,
            ..Default::default()
        };

        match self.storage.list(&query_params).await {
            Ok(entries) => {
                let now = chrono::Utc::now();
                let _warning_threshold = chrono::Duration::days(30);
                let _critical_threshold = chrono::Duration::days(7);

                for entry in &entries {
                    // Check if entry has expiry metadata
                    if let Some(expiry_str) = entry.metadata.get("expires_at") {
                        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expiry_str) {
                            let expiry_utc = expiry.with_timezone(&chrono::Utc);
                            let days_until_expiry = (expiry_utc - now).num_days();
                            let hours_until_expiry = (expiry_utc - now).num_hours();

                            if days_until_expiry <= 0 {
                                findings.push(SecurityFinding {
                                    severity: "critical".to_string(),
                                    category: "certificates".to_string(),
                                    title: format!("Certificate expired: {}", entry.path),
                                    description: format!("Certificate {} has expired {} days ago", entry.path, days_until_expiry.abs()),
                                    recommendation: "Renew the certificate immediately and update all dependent services".to_string(),
                                    affected_resources: vec![entry.path.clone()],
                                });
                            } else if days_until_expiry <= 7 {
                                findings.push(SecurityFinding {
                                    severity: "critical".to_string(),
                                    category: "certificates".to_string(),
                                    title: format!("Certificate expiring critically soon: {}", entry.path),
                                    description: format!("Certificate {} expires in {} days ({} hours)", entry.path, days_until_expiry, hours_until_expiry),
                                    recommendation: "Renew the certificate immediately to prevent service disruption".to_string(),
                                    affected_resources: vec![entry.path.clone()],
                                });
                            } else if days_until_expiry <= 30 {
                                findings.push(SecurityFinding {
                                    severity: "high".to_string(),
                                    category: "certificates".to_string(),
                                    title: format!("Certificate expiring soon: {}", entry.path),
                                    description: format!(
                                        "Certificate {} expires in {} days",
                                        entry.path, days_until_expiry
                                    ),
                                    recommendation: "Renew the certificate before it expires"
                                        .to_string(),
                                    affected_resources: vec![entry.path.clone()],
                                });
                            }
                        }
                    }
                }

                // Check for certificates without expiry information
                let certs_without_expiry: Vec<_> = entries
                    .into_iter()
                    .filter(|entry| !entry.metadata.contains_key("expires_at"))
                    .collect();

                if !certs_without_expiry.is_empty() {
                    findings.push(SecurityFinding {
                        severity: "medium".to_string(),
                        category: "certificates".to_string(),
                        title: format!("Certificates without expiry information: {}", certs_without_expiry.len()),
                        description: format!("Found {} certificates that don't have expiry information set", certs_without_expiry.len()),
                        recommendation: "Review certificates and ensure expiry dates are properly configured for monitoring".to_string(),
                        affected_resources: certs_without_expiry.into_iter().map(|e| e.path).collect(),
                    });
                }
            }
            Err(_) => {
                // If we can't access certificate storage, note it as a finding
                findings.push(SecurityFinding {
                    severity: "medium".to_string(),
                    category: "certificates".to_string(),
                    title: "Certificate monitoring not available".to_string(),
                    description: "Unable to scan certificate storage for expiry dates".to_string(),
                    recommendation:
                        "Ensure certificate storage is accessible and properly configured"
                            .to_string(),
                    affected_resources: vec!["certificate_storage".to_string()],
                });
            }
        }

        // Also check for PKI certificates if available
        // This would integrate with the PKI service to check CA and issued certificates
        let pki_query_params = QueryParams {
            path_prefix: None,
            ..Default::default()
        };

        match self.storage.list(&pki_query_params).await {
            Ok(pki_entries) => {
                let now = chrono::Utc::now();
                for entry in pki_entries {
                    // Check PKI-specific expiry fields
                    if let Some(expiry_str) = entry.metadata.get("certificate_expires_at") {
                        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expiry_str) {
                            let expiry_utc = expiry.with_timezone(&chrono::Utc);
                            let days_until_expiry = (expiry_utc - now).num_days();

                            if days_until_expiry <= 30 && days_until_expiry > 0 {
                                findings.push(SecurityFinding {
                                    severity: "high".to_string(),
                                    category: "pki_certificates".to_string(),
                                    title: format!("PKI Certificate expiring soon: {}", entry.path),
                                    description: format!(
                                        "PKI Certificate {} expires in {} days",
                                        entry.path, days_until_expiry
                                    ),
                                    recommendation: "Renew the PKI certificate before it expires"
                                        .to_string(),
                                    affected_resources: vec![entry.path],
                                });
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // PKI storage not accessible, but this is not critical
                tracing::debug!("PKI certificate storage not accessible for expiry checking");
            }
        }

        Ok(findings)
    }

    /// Check security configuration
    async fn check_security_configuration(&self) -> Result<Vec<SecurityFinding>, AdminError> {
        let mut findings = Vec::new();

        // Get system configuration
        let config_path = "system/config";
        let config = self.storage.get_by_path(config_path).await;

        // Parse configuration data
        let config_data = if let Ok(Some(config_entry)) = &config {
            if let Some(config_json) = config_entry.metadata.get("config_data") {
                serde_json::from_str::<serde_json::Value>(config_json).ok()
            } else {
                None
            }
        } else {
            None
        };

        // Check if audit logging is enabled
        if let Some(config) = &config_data {
            if let Some(audit_enabled) = config.get("enable_audit_logging") {
                if audit_enabled == false {
                    findings.push(SecurityFinding {
                        severity: "high".to_string(),
                        category: "configuration".to_string(),
                        title: "Audit logging disabled".to_string(),
                        description: "Audit logging is disabled, which reduces security monitoring capabilities".to_string(),
                        recommendation: "Enable audit logging to track security-relevant events".to_string(),
                        affected_resources: vec!["audit_system".to_string()],
                    });
                }
            } else {
                findings.push(SecurityFinding {
                    severity: "medium".to_string(),
                    category: "configuration".to_string(),
                    title: "Audit logging configuration missing".to_string(),
                    description: "Audit logging configuration is not set".to_string(),
                    recommendation: "Configure audit logging to track security-relevant events"
                        .to_string(),
                    affected_resources: vec!["audit_system".to_string()],
                });
            }
        }

        // Check MFA requirement
        if let Some(config) = &config_data {
            if let Some(enable_mfa) = config.get("enable_mfa") {
                if enable_mfa == false {
                    findings.push(SecurityFinding {
                        severity: "medium".to_string(),
                        category: "authentication".to_string(),
                        title: "Multi-factor authentication disabled".to_string(),
                        description: "MFA is disabled, reducing authentication security"
                            .to_string(),
                        recommendation: "Enable multi-factor authentication for all users"
                            .to_string(),
                        affected_resources: vec!["authentication".to_string()],
                    });
                }
            } else {
                findings.push(SecurityFinding {
                    severity: "medium".to_string(),
                    category: "authentication".to_string(),
                    title: "MFA configuration missing".to_string(),
                    description: "Multi-factor authentication configuration is not set".to_string(),
                    recommendation: "Configure and enable multi-factor authentication".to_string(),
                    affected_resources: vec!["authentication".to_string()],
                });
            }
        }

        // Check session timeout configuration
        if let Some(config) = &config_data {
            if let Some(session_timeout) = config.get("session_timeout") {
                if let Some(timeout_minutes) = session_timeout.as_u64() {
                    if timeout_minutes > 480 {
                        // 8 hours
                        findings.push(SecurityFinding {
                            severity: "low".to_string(),
                            category: "configuration".to_string(),
                            title: "Long session timeout".to_string(),
                            description: format!(
                                "Session timeout is set to {} minutes, which may reduce security",
                                timeout_minutes
                            ),
                            recommendation:
                                "Consider reducing session timeout to 480 minutes (8 hours) or less"
                                    .to_string(),
                            affected_resources: vec!["session_management".to_string()],
                        });
                    } else if timeout_minutes < 15 {
                        // 15 minutes minimum
                        findings.push(SecurityFinding {
                            severity: "medium".to_string(),
                            category: "configuration".to_string(),
                            title: "Very short session timeout".to_string(),
                            description: format!(
                                "Session timeout is set to {} minutes, which may impact usability",
                                timeout_minutes
                            ),
                            recommendation:
                                "Consider increasing session timeout to at least 15 minutes"
                                    .to_string(),
                            affected_resources: vec!["session_management".to_string()],
                        });
                    }
                }
            }
        }

        // Check JWT expiration
        if let Some(config) = &config_data {
            if let Some(jwt_expiration) = config.get("jwt_expiration") {
                if let Some(expiration_hours) = jwt_expiration.as_u64() {
                    if expiration_hours > 24 {
                        // 24 hours
                        findings.push(SecurityFinding {
                            severity: "low".to_string(),
                            category: "configuration".to_string(),
                            title: "Long JWT expiration".to_string(),
                            description: format!(
                                "JWT tokens expire after {} hours, which may reduce security",
                                expiration_hours
                            ),
                            recommendation: "Consider reducing JWT expiration to 24 hours or less"
                                .to_string(),
                            affected_resources: vec!["authentication".to_string()],
                        });
                    }
                }
            }
        }

        // Check rate limiting
        if let Some(config) = &config_data {
            if let Some(rate_limit) = config.get("rate_limit_requests_per_minute") {
                if let Some(limit) = rate_limit.as_u64() {
                    if limit > 1000 {
                        // Very high limit
                        findings.push(SecurityFinding {
                            severity: "low".to_string(),
                            category: "configuration".to_string(),
                            title: "High rate limit threshold".to_string(),
                            description: format!("Rate limit is set to {} requests per minute, which may allow abuse", limit),
                            recommendation: "Consider reducing rate limit to prevent abuse".to_string(),
                            affected_resources: vec!["rate_limiting".to_string()],
                        });
                    } else if limit < 10 {
                        // Very low limit
                        findings.push(SecurityFinding {
                            severity: "medium".to_string(),
                            category: "configuration".to_string(),
                            title: "Very low rate limit".to_string(),
                            description: format!("Rate limit is set to {} requests per minute, which may impact legitimate usage", limit),
                            recommendation: "Consider increasing rate limit to allow legitimate usage".to_string(),
                            affected_resources: vec!["rate_limiting".to_string()],
                        });
                    }
                }
            } else {
                findings.push(SecurityFinding {
                    severity: "medium".to_string(),
                    category: "configuration".to_string(),
                    title: "Rate limiting not configured".to_string(),
                    description: "Rate limiting configuration is missing".to_string(),
                    recommendation: "Configure rate limiting to prevent abuse".to_string(),
                    affected_resources: vec!["rate_limiting".to_string()],
                });
            }
        }

        // Check failed login attempt limits
        if let Some(config) = &config_data {
            if let Some(max_failed_attempts) = config.get("max_failed_attempts") {
                if let Some(max_attempts) = max_failed_attempts.as_u64() {
                    if max_attempts > 10 {
                        findings.push(SecurityFinding {
                            severity: "low".to_string(),
                            category: "configuration".to_string(),
                            title: "High failed login attempt limit".to_string(),
                            description: format!("Maximum failed login attempts is set to {}, which may allow brute force attacks", max_attempts),
                            recommendation: "Consider reducing maximum failed attempts to 5-10".to_string(),
                            affected_resources: vec!["authentication".to_string()],
                        });
                    } else if max_attempts < 3 {
                        findings.push(SecurityFinding {
                            severity: "low".to_string(),
                            category: "configuration".to_string(),
                            title: "Low failed login attempt limit".to_string(),
                            description: format!("Maximum failed login attempts is set to {}, which may cause usability issues", max_attempts),
                            recommendation: "Consider increasing maximum failed attempts to at least 3".to_string(),
                            affected_resources: vec!["authentication".to_string()],
                        });
                    }
                }
            }
        }

        // Check backup retention
        if let Some(config) = &config_data {
            if let Some(backup_retention) = config.get("backup_retention_days") {
                if let Some(days) = backup_retention.as_u64() {
                    if days > 365 {
                        // Over a year
                        findings.push(SecurityFinding {
                            severity: "low".to_string(),
                            category: "configuration".to_string(),
                            title: "Long backup retention period".to_string(),
                            description: format!("Backup retention is set to {} days, which may consume excessive storage", days),
                            recommendation: "Consider reducing backup retention period".to_string(),
                            affected_resources: vec!["backup_system".to_string()],
                        });
                    } else if days < 7 {
                        // Less than a week
                        findings.push(SecurityFinding {
                            severity: "medium".to_string(),
                            category: "configuration".to_string(),
                            title: "Short backup retention period".to_string(),
                            description: format!("Backup retention is set to {} days, which may not provide adequate recovery options", days),
                            recommendation: "Consider increasing backup retention period to at least 7 days".to_string(),
                            affected_resources: vec!["backup_system".to_string()],
                        });
                    }
                }
            }
        }

        // Check log retention
        if let Some(config) = &config_data {
            if let Some(log_retention) = config.get("log_retention_days") {
                if let Some(days) = log_retention.as_u64() {
                    if days > 365 {
                        // Over a year
                        findings.push(SecurityFinding {
                            severity: "low".to_string(),
                            category: "configuration".to_string(),
                            title: "Long log retention period".to_string(),
                            description: format!("Log retention is set to {} days, which may consume excessive storage", days),
                            recommendation: "Consider reducing log retention period based on compliance requirements".to_string(),
                            affected_resources: vec!["logging_system".to_string()],
                        });
                    } else if days < 30 {
                        // Less than a month
                        findings.push(SecurityFinding {
                            severity: "medium".to_string(),
                            category: "configuration".to_string(),
                            title: "Short log retention period".to_string(),
                            description: format!("Log retention is set to {} days, which may not meet compliance requirements", days),
                            recommendation: "Consider increasing log retention period to meet compliance requirements".to_string(),
                            affected_resources: vec!["logging_system".to_string()],
                        });
                    }
                }
            }
        }

        // If no configuration found, add general recommendation
        if config_data.is_none() {
            findings.push(SecurityFinding {
                severity: "high".to_string(),
                category: "configuration".to_string(),
                title: "Security configuration missing".to_string(),
                description: "System security configuration is not properly set up".to_string(),
                recommendation: "Create and configure system security settings including audit logging, MFA, and session management".to_string(),
                affected_resources: vec!["system_configuration".to_string()],
            });
        }

        Ok(findings)
    }

    /// Check for suspicious activity
    async fn check_suspicious_activity(&self) -> Result<Vec<SecurityFinding>, AdminError> {
        let mut findings = Vec::new();

        // Check audit logs for suspicious patterns
        // Get recent audit logs (last 24 hours)
        let end_time = chrono::Utc::now();
        let start_time = end_time - chrono::Duration::hours(24);

        let audit_logs = self
            .get_audit_logs(Some(start_time), Some(end_time), None, None, Some(1000))
            .await?;

        // Check for failed login attempts
        let failed_logins = audit_logs
            .iter()
            .filter(|log| log.action == "login" && !log.success)
            .count();

        if failed_logins > 10 {
            findings.push(SecurityFinding {
                severity: "medium".to_string(),
                category: "authentication".to_string(),
                title: "High number of failed login attempts".to_string(),
                description: format!("Detected {} failed login attempts in the last 24 hours", failed_logins),
                recommendation: "Review authentication logs and consider implementing additional security measures".to_string(),
                affected_resources: vec!["authentication".to_string()],
            });
        }

        // Check for unusual access patterns
        let suspicious_actions = audit_logs
            .iter()
            .filter(|log| log.action == "delete" || log.action == "modify")
            .count();

        if suspicious_actions > 50 {
            findings.push(SecurityFinding {
                severity: "low".to_string(),
                category: "access_control".to_string(),
                title: "High volume of destructive operations".to_string(),
                description: format!(
                    "Detected {} potentially destructive operations in the last 24 hours",
                    suspicious_actions
                ),
                recommendation:
                    "Monitor for unusual access patterns and ensure proper authorization"
                        .to_string(),
                affected_resources: vec!["secreton_operations".to_string()],
            });
        }

        Ok(findings)
    }

    /// Update system configuration
    pub async fn update_config(
        &self,
        config_updates: HashMap<String, serde_json::Value>,
    ) -> Result<MaintenanceResult, AdminError> {
        let start_time = std::time::Instant::now();

        // Validate configuration updates
        let mut invalid_keys = Vec::new();
        for key in config_updates.keys() {
            // Only allow specific configuration keys for security
            if !matches!(
                key.as_str(),
                "jwt_expiration"
                    | "session_timeout"
                    | "max_failed_attempts"
                    | "password_policy_min_length"
                    | "password_policy_require_uppercase"
                    | "password_policy_require_numbers"
                    | "password_policy_require_special"
                    | "rate_limit_requests_per_minute"
                    | "enable_mfa"
                    | "enable_audit_logging"
                    | "backup_retention_days"
                    | "log_retention_days"
            ) {
                invalid_keys.push(key.clone());
            }
        }

        if !invalid_keys.is_empty() {
            return Err(AdminError::InvalidConfig(format!(
                "Invalid configuration keys: {}",
                invalid_keys.join(", ")
            )));
        }

        // Store configuration in system config path
        let config_path = "system/config";
        let current_config = self
            .storage
            .get_by_path(config_path)
            .await
            .map_err(AdminError::Storage)?;

        let mut config_data: HashMap<String, serde_json::Value> = current_config
            .and_then(|entry| {
                entry
                    .metadata
                    .get("config_data")
                    .and_then(|data| serde_json::from_str(data).ok())
            })
            .unwrap_or_default();

        // Apply updates
        let mut updated_count = 0;
        for (key, value) in config_updates {
            config_data.insert(key, value);
            updated_count += 1;
        }

        // Persist updated configuration
        let config_json =
            serde_json::to_string(&config_data).map_err(|e| AdminError::Internal(e.into()))?;

        let mut metadata = HashMap::new();
        metadata.insert("config_data".to_string(), config_json);
        metadata.insert("updated_at".to_string(), chrono::Utc::now().to_rfc3339());

        let config_entry = secreton_storage::SecretEntry {
            id: uuid::Uuid::new_v4(),
            path: config_path.to_string(),
            encrypted_data: Vec::new(),
            encryption_metadata: secreton_storage::EncryptionMetadata {
                algorithm: "none".to_string(),
                key_id: "config".to_string(),
                iv: Vec::new(),
                auth_tag: None,
                aad: None,
                kdf_params: None,
            },
            security_level: secreton_storage::SecurityLevel::Secret,
            metadata,
            tags: vec!["system".to_string(), "config".to_string()],
            version: 1,
            owner_id: uuid::Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };

        self.storage
            .store(&config_entry)
            .await
            .map_err(AdminError::Storage)?;

        let duration = start_time.elapsed();
        Ok(MaintenanceResult {
            operation: "update_config".to_string(),
            success: true,
            duration_ms: duration.as_millis() as u64,
            details: {
                let mut details = HashMap::new();
                details.insert(
                    "updated_keys".to_string(),
                    serde_json::Value::Array(
                        config_data
                            .keys()
                            .map(|k| serde_json::Value::String(k.clone()))
                            .collect(),
                    ),
                );
                details.insert(
                    "update_count".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(updated_count as u64)),
                );
                details
            },
        })
    }

    /// Get a single role by name
    pub async fn get_role(&self, name: &str) -> Result<RoleInfo, AdminError> {
        Self::validate_role_name(name)?;
        let path = format!("{}{}", ROLE_STORAGE_PREFIX, name);
        let entry = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(AdminError::Storage)?
            .ok_or_else(|| AdminError::NotFound(format!("Role {} not found", name)))?;
        self.secreton_entry_to_role_info(&entry).await
    }

    /// List all roles
    pub async fn list_roles(&self) -> Result<Vec<RoleInfo>, AdminError> {
        let query_params = QueryParams {
            path_prefix: Some(ROLE_STORAGE_PREFIX.to_string()),
            limit: Some(1000),
            offset: Some(0),
            ..Default::default()
        };

        let entries: Vec<_> = self
            .storage
            .list(&query_params)
            .await
            .map_err(AdminError::Storage)?
            .into_iter()
            .collect();

        let mut roles = Vec::new();
        for entry in entries {
            match self.secreton_entry_to_role_info(&entry).await {
                Ok(role) => roles.push(role),
                Err(e) => {
                    tracing::warn!("Failed to deserialize role at {}: {}", entry.path, e);
                }
            }
        }

        Ok(roles)
    }

    /// Validate that a role name is safe for use in storage paths and URL path segments.
    /// Only ASCII alphanumeric characters, hyphens, underscores, dots, and `@` are allowed.
    /// Double-dots (`..`) are explicitly rejected to prevent path traversal.
    fn validate_role_name(name: &str) -> Result<(), AdminError> {
        if name.is_empty() || name.trim().is_empty() {
            return Err(AdminError::InvalidConfig(
                "Role name cannot be empty".to_string(),
            ));
        }
        if name.len() > 256 {
            return Err(AdminError::InvalidConfig(
                "Role name is too long (max 256 characters)".to_string(),
            ));
        }
        if name.contains("..") {
            return Err(AdminError::InvalidConfig(
                "Role name cannot contain '..' (path traversal)".to_string(),
            ));
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@') {
            return Err(AdminError::InvalidConfig(
                "Role name contains invalid characters (only ASCII alphanumeric, '-', '_', '.', '@' are allowed)".to_string(),
            ));
        }
        Ok(())
    }

    /// Create a new role
    pub async fn create_role(&self, request: CreateRoleRequest) -> Result<RoleInfo, AdminError> {
        Self::validate_role_name(&request.name)?;
        let path = format!("{}{}", ROLE_STORAGE_PREFIX, request.name);
        if self
            .storage
            .exists(&path)
            .await
            .map_err(AdminError::Storage)?
        {
            return Err(AdminError::AlreadyExists(format!("Role '{}'", request.name)));
        }

        let now = chrono::Utc::now();
        let role = RoleInfo {
            name: request.name,
            description: request.description,
            permissions: request.permissions,
            users: Vec::new(),
            created_at: now,
            updated_at: now,
            metadata: request.metadata.unwrap_or_default(),
        };

        let entry = self.role_info_to_secreton_entry(&role).await?;
        self.storage
            .store(&entry)
            .await
            .map_err(AdminError::Storage)?;

        Ok(role)
    }

    /// Helper method to convert RoleInfo to SecretEntry for storage
    async fn role_info_to_secreton_entry(
        &self,
        role: &RoleInfo,
    ) -> Result<secreton_storage::SecretEntry, AdminError> {
        use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel};

        let role_data = serde_json::to_vec(role).map_err(|e| {
            AdminError::Internal(anyhow::anyhow!("Failed to serialize role: {}", e))
        })?;

        let (encrypted_data, encryption_metadata) = if let Some(crypto) = &self.crypto {
            let enc = crypto
                .encrypt_data(&role_data)
                .await
                .map_err(|e| AdminError::Internal(anyhow::anyhow!("Encryption failed: {}", e)))?;
            (
                enc,
                EncryptionMetadata {
                    algorithm: "encrypted".to_string(),
                    key_id: "active".to_string(),
                    iv: vec![],
                    auth_tag: None,
                    aad: None,
                    kdf_params: None,
                },
            )
        } else {
            (
                role_data,
                EncryptionMetadata {
                    algorithm: "none".to_string(),
                    key_id: "none".to_string(),
                    iv: vec![],
                    auth_tag: None,
                    aad: None,
                    kdf_params: None,
                },
            )
        };

        Ok(SecretEntry::new(
            format!("{}{}", ROLE_STORAGE_PREFIX, role.name),
            encrypted_data,
            encryption_metadata,
            SecurityLevel::Secret,
            uuid::Uuid::nil(), // System owned
        ))
    }

    /// Helper method to convert SecretEntry to RoleInfo
    async fn secreton_entry_to_role_info(
        &self,
        entry: &secreton_storage::SecretEntry,
    ) -> Result<RoleInfo, AdminError> {
        let data = if let Some(crypto) = &self.crypto {
            match crypto.decrypt(&entry.encrypted_data).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("Decryption failed for role at {}, falling back to plaintext: {}", entry.path, e);
                    entry.encrypted_data.clone()
                }
            }
        } else {
            entry.encrypted_data.clone()
        };

        let role: RoleInfo = serde_json::from_slice(&data).map_err(|e| {
            AdminError::Internal(anyhow::anyhow!("Failed to deserialize role: {}", e))
        })?;
        Ok(role)
    }

    /// Update an existing role
    pub async fn update_role(
        &self,
        name: &str,
        request: UpdateRoleRequest,
    ) -> Result<RoleInfo, AdminError> {
        Self::validate_role_name(name)?;
        let path = format!("{}{}", ROLE_STORAGE_PREFIX, name);

        let now = chrono::Utc::now();
        let entry = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(AdminError::Storage)?
            .ok_or_else(|| AdminError::NotFound(format!("Role {} not found", name)))?;

        let mut role = self.secreton_entry_to_role_info(&entry).await?;

        if let Some(description) = request.description {
            role.description = Some(description);
        }
        if let Some(permissions) = request.permissions {
            role.permissions = permissions;
        }
        role.updated_at = now;
        if let Some(metadata) = request.metadata {
            role.metadata = metadata;
        }

        let mut new_entry = self.role_info_to_secreton_entry(&role).await?;
        new_entry.id = entry.id; // Preserve original entry ID for UPDATE WHERE id = $1
        new_entry.path = entry.path.clone(); // Preserve original storage path
        new_entry.created_at = entry.created_at; // Preserve original creation timestamp
        new_entry.owner_id = entry.owner_id; // Preserve original ownership
        new_entry.version = entry.version; // Preserve version for optimistic concurrency
        new_entry.tags = entry.tags.clone(); // Preserve entry-level tags
        new_entry.metadata = entry.metadata.clone(); // Preserve entry-level metadata
        self.storage
            .update(&new_entry)
            .await
            .map_err(AdminError::Storage)?;

        Ok(role)
    }

    /// Delete a role
    pub async fn delete_role(&self, name: &str) -> Result<(), AdminError> {
        Self::validate_role_name(name)?;
        let path = format!("{}{}", ROLE_STORAGE_PREFIX, name);
        let deleted = self
            .storage
            .delete_by_path(&path)
            .await
            .map_err(AdminError::Storage)?;

        if !deleted {
            return Err(AdminError::NotFound(format!("Role {} not found", name)));
        }

        Ok(())
    }

    /// List all users
    pub async fn list_users(&self) -> Result<Vec<UserInfo>, AdminError> {
        use secreton_storage::QueryParams;

        let query_params = QueryParams {
            path_prefix: Some(USER_STORAGE_PREFIX.to_string()),
            limit: Some(1000),
            offset: Some(0),
            ..Default::default()
        };

        let entries: Vec<_> = self
            .storage
            .list(&query_params)
            .await
            .map_err(AdminError::Storage)?
            .into_iter()
            .collect();

        let mut users = Vec::new();
        for entry in entries {
            if let Ok(user) = self.secreton_entry_to_user_info(&entry).await {
                users.push(user);
            }
        }

        Ok(users)
    }

    /// Validate that a username is safe for use in storage paths and URL path segments.
    /// Only ASCII alphanumeric characters, hyphens, underscores, dots, and `@` are allowed.
    /// Double-dots (`..`) are explicitly rejected to prevent path traversal.
    fn validate_username(username: &str) -> Result<(), AdminError> {
        if username.is_empty() || username.trim().is_empty() {
            return Err(AdminError::InvalidConfig(
                "Username cannot be empty".to_string(),
            ));
        }
        if username.len() > 256 {
            return Err(AdminError::InvalidConfig(
                "Username is too long (max 256 characters)".to_string(),
            ));
        }
        if username.contains("..") {
            return Err(AdminError::InvalidConfig(
                "Username cannot contain '..' (path traversal)".to_string(),
            ));
        }
        if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@') {
            return Err(AdminError::InvalidConfig(
                "Username contains invalid characters (only ASCII alphanumeric, '-', '_', '.', '@' are allowed)".to_string(),
            ));
        }
        Ok(())
    }

    /// Get user by username
    pub async fn get_user(&self, username: &str) -> Result<UserInfo, AdminError> {
        Self::validate_username(username)?;
        let path = format!("{}{}", USER_STORAGE_PREFIX, username);
        let entry = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(AdminError::Storage)?
            .ok_or_else(|| AdminError::NotFound(format!("User {} not found", username)))?;

        self.secreton_entry_to_user_info(&entry).await
    }

    /// Create a new user
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<UserInfo, AdminError> {
        Self::validate_username(&request.username)?;

        // Use auth service to create user (handles password hashing and storage)
        let user = self
            .auth
            .create_user(
                &request.username,
                &request.email,
                &request.password,
                request.roles,
                request.permissions,
            )
            .await
            .map_err(AdminError::Auth)?;

        // Persist caller-supplied metadata and full_name/enabled via raw-JSON
        // update, since auth.create_user does not forward these fields.
        let has_extra_fields = !request.metadata.is_empty()
            || request.full_name.is_some()
            || request.enabled.is_some();

        if has_extra_fields {
            let path = format!("{}{}", USER_STORAGE_PREFIX, user.username);
            let original_entry = self
                .storage
                .get_by_path(&path)
                .await
                .map_err(AdminError::Storage)?
                .ok_or_else(|| {
                    AdminError::Internal(anyhow::anyhow!(
                        "User {} was created but not found in storage for patching extra fields",
                        user.username
                    ))
                })?;

            let raw_data = self.decrypt_entry_data(&original_entry).await?;
            let mut doc: serde_json::Value =
                serde_json::from_slice(&raw_data).map_err(|e| {
                    AdminError::Internal(anyhow::anyhow!(
                        "Failed to deserialize newly created user: {}",
                        e
                    ))
                })?;

            if !request.metadata.is_empty() {
                doc["metadata"] = serde_json::to_value(&request.metadata).map_err(|e| {
                    AdminError::Internal(anyhow::anyhow!(
                        "Failed to serialize metadata: {}",
                        e
                    ))
                })?;
            }
            if let Some(full_name) = &request.full_name {
                doc["full_name"] = serde_json::Value::String(full_name.clone());
            }
            if let Some(enabled) = request.enabled {
                doc["enabled"] = serde_json::Value::Bool(enabled);
            }

            let updated_bytes = serde_json::to_vec(&doc).map_err(|e| {
                AdminError::Internal(anyhow::anyhow!(
                    "Failed to serialize patched user: {}",
                    e
                ))
            })?;
            let mut entry = self
                .build_encrypted_entry(&updated_bytes, &original_entry.path)
                .await?;
            entry.id = original_entry.id;
            entry.path = original_entry.path.clone();
            entry.created_at = original_entry.created_at;
            entry.owner_id = original_entry.owner_id;
            entry.version = original_entry.version;
            entry.tags = original_entry.tags.clone();
            entry.metadata = original_entry.metadata.clone();
            self.storage
                .update(&entry)
                .await
                .map_err(AdminError::Storage)?;
        }

        // Map User to UserInfo
        Ok(UserInfo {
            id: user.id,
            username: user.username,
            email: user.email.unwrap_or_default(),
            full_name: request.full_name.or(user.full_name),
            enabled: request.enabled.unwrap_or(user.enabled),
            roles: user.roles,
            permissions: user.permissions,
            last_login: user.last_login,
            created_at: user.created_at,
            updated_at: user.updated_at,
            metadata: if request.metadata.is_empty() {
                user.metadata
            } else {
                request.metadata
            },
        })
    }

    /// Update an existing user
    ///
    /// IMPORTANT: Users are stored as the full `secreton_auth::User` struct which
    /// contains security-critical fields (`password_hash`, `is_superuser`,
    /// `mfa_enabled`, `failed_login_attempts`, `locked_until`, etc.) that are NOT
    /// present in `UserInfo`. To avoid destroying those fields we operate on the
    /// raw JSON (`serde_json::Value`) and only mutate the requested keys before
    /// writing the complete document back.
    pub async fn update_user(
        &self,
        username: &str,
        request: UpdateUserRequest,
    ) -> Result<UserInfo, AdminError> {
        Self::validate_username(username)?;
        let path = format!("{}{}", USER_STORAGE_PREFIX, username);
        let original_entry = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(AdminError::Storage)?
            .ok_or_else(|| AdminError::NotFound(format!("User {} not found", username)))?;

        // Decrypt to raw bytes
        let raw_data = self.decrypt_entry_data(&original_entry).await?;

        // Parse as generic JSON so we never drop unknown fields
        let mut doc: serde_json::Value = serde_json::from_slice(&raw_data).map_err(|e| {
            AdminError::Internal(anyhow::anyhow!("Failed to deserialize user: {}", e))
        })?;

        // Apply only the requested mutations
        if let Some(email) = request.email {
            doc["email"] = serde_json::Value::String(email);
        }
        if let Some(full_name) = request.full_name {
            doc["full_name"] = serde_json::Value::String(full_name);
        }
        if let Some(enabled) = request.enabled {
            // Prevent disabling the default admin user
            if username == "admin" && !enabled {
                return Err(AdminError::NotPermitted(
                    "Cannot disable the default admin user".to_string(),
                ));
            }
            doc["enabled"] = serde_json::Value::Bool(enabled);
        }
        if let Some(ref roles) = request.roles {
            // Prevent removing admin privileges from the default admin user
            if username == "admin"
                && !roles.contains(&"admin".to_string())
                && !roles.contains(&"root".to_string())
            {
                return Err(AdminError::NotPermitted(
                    "Cannot remove admin privileges from the default admin user".to_string(),
                ));
            }
            doc["roles"] = serde_json::to_value(roles).map_err(|e| {
                AdminError::Internal(anyhow::anyhow!("Failed to serialize roles: {}", e))
            })?;
        }
        doc["updated_at"] = serde_json::Value::String(chrono::Utc::now().to_rfc3339());

        // Re-encrypt the full document and write back
        let updated_bytes = serde_json::to_vec(&doc).map_err(|e| {
            AdminError::Internal(anyhow::anyhow!("Failed to serialize user: {}", e))
        })?;
        let mut entry = self.build_encrypted_entry(&updated_bytes, &original_entry.path).await?;
        entry.id = original_entry.id;
        entry.path = original_entry.path.clone();
        entry.created_at = original_entry.created_at;
        entry.owner_id = original_entry.owner_id;
        entry.version = original_entry.version;
        entry.tags = original_entry.tags.clone();
        entry.metadata = original_entry.metadata.clone();
        self.storage
            .update(&entry)
            .await
            .map_err(AdminError::Storage)?;

        // Return the UserInfo view to the caller
        self.secreton_entry_to_user_info_from_value(&doc)
    }

    /// Get user roles
    pub async fn get_user_roles(&self, username: &str) -> Result<Vec<String>, AdminError> {
        let user = self.get_user(username).await?;
        Ok(user.roles)
    }

    /// Assign roles to user
    ///
    /// Uses raw JSON manipulation to avoid dropping security-critical fields
    /// from the stored `User` struct (see `update_user` for details).
    pub async fn assign_user_roles(
        &self,
        username: &str,
        roles: Vec<String>,
    ) -> Result<(), AdminError> {
        Self::validate_username(username)?;

        // Prevent removing the "admin" role from the default admin user
        if username == "admin"
            && !roles.contains(&"admin".to_string())
            && !roles.contains(&"root".to_string())
        {
            return Err(AdminError::NotPermitted(
                "Cannot remove admin privileges from the default admin user".to_string(),
            ));
        }

        let path = format!("{}{}", USER_STORAGE_PREFIX, username);
        let original_entry = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(AdminError::Storage)?
            .ok_or_else(|| AdminError::NotFound(format!("User {} not found", username)))?;

        // Decrypt to raw bytes
        let raw_data = self.decrypt_entry_data(&original_entry).await?;

        // Parse as generic JSON so we never drop unknown fields
        let mut doc: serde_json::Value = serde_json::from_slice(&raw_data).map_err(|e| {
            AdminError::Internal(anyhow::anyhow!("Failed to deserialize user: {}", e))
        })?;

        doc["roles"] = serde_json::to_value(&roles).map_err(|e| {
            AdminError::Internal(anyhow::anyhow!("Failed to serialize roles: {}", e))
        })?;
        doc["updated_at"] = serde_json::Value::String(chrono::Utc::now().to_rfc3339());

        // Re-encrypt the full document and write back
        let updated_bytes = serde_json::to_vec(&doc).map_err(|e| {
            AdminError::Internal(anyhow::anyhow!("Failed to serialize user: {}", e))
        })?;
        let mut entry = self.build_encrypted_entry(&updated_bytes, &original_entry.path).await?;
        entry.id = original_entry.id;
        entry.path = original_entry.path.clone();
        entry.created_at = original_entry.created_at;
        entry.owner_id = original_entry.owner_id;
        entry.version = original_entry.version;
        entry.tags = original_entry.tags.clone();
        entry.metadata = original_entry.metadata.clone();
        self.storage
            .update(&entry)
            .await
            .map_err(AdminError::Storage)?;

        Ok(())
    }

    /// Get user permissions
    pub async fn get_user_permissions(&self, username: &str) -> Result<Vec<String>, AdminError> {
        let user = self.get_user(username).await?;
        Ok(user.permissions)
    }

    /// Delete a user by username
    pub async fn delete_user(&self, username: &str) -> Result<(), AdminError> {
        Self::validate_username(username)?;
        // Prevent deletion of the default admin user
        if username == "admin" {
            return Err(AdminError::NotPermitted(
                "Cannot delete admin user".to_string(),
            ));
        }

        let path = format!("{}{}", USER_STORAGE_PREFIX, username);

        // Read the user record before deletion so we can extract the UUID for
        // cascade-deleting owned secrets. The stored document is the full
        // `secreton_auth::User` struct which contains an `id` field (UUID string).
        let owner_uuid = if let Ok(Some(entry)) = self.storage.get_by_path(&path).await {
            if let Ok(raw_data) = self.decrypt_entry_data(&entry).await {
                if let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&raw_data) {
                    doc.get("id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| uuid::Uuid::parse_str(s).ok())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let deleted = self
            .storage
            .delete_by_path(&path)
            .await
            .map_err(AdminError::Storage)?;

        if !deleted {
            return Err(AdminError::NotFound(format!("User {} not found", username)));
        }

        // Cascade delete: Remove all secrets owned by this user
        if let Some(owner_uuid) = owner_uuid {
            let query_params = secreton_storage::QueryParams::new().with_owner(owner_uuid);

            if let Ok(secrets) = self.storage.list(&query_params).await {
                for secret in secrets {
                    // Log failure but continue deletion
                    if let Err(e) = self.storage.delete_by_path(&secret.path).await {
                        tracing::error!("Failed to cascade delete secret {}: {}", secret.path, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Decrypt the `encrypted_data` of a storage entry, falling back to
    /// plaintext when no crypto service is configured or decryption fails.
    async fn decrypt_entry_data(
        &self,
        entry: &secreton_storage::SecretEntry,
    ) -> Result<Vec<u8>, AdminError> {
        if let Some(crypto) = &self.crypto {
            match crypto.decrypt(&entry.encrypted_data).await {
                Ok(d) => Ok(d),
                Err(e) => {
                    tracing::warn!(
                        "Decryption failed for entry at {}, falling back to plaintext: {}",
                        entry.path,
                        e
                    );
                    Ok(entry.encrypted_data.clone())
                }
            }
        } else {
            Ok(entry.encrypted_data.clone())
        }
    }

    /// Build a `SecretEntry` from raw bytes, encrypting if a crypto service is
    /// available. The caller is responsible for overriding `id`, `path`, and
    /// `created_at` from the original entry when performing an UPDATE.
    async fn build_encrypted_entry(
        &self,
        data: &[u8],
        path: &str,
    ) -> Result<secreton_storage::SecretEntry, AdminError> {
        use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel};

        let (encrypted_data, encryption_metadata) = if let Some(crypto) = &self.crypto {
            let enc = crypto
                .encrypt_data(data)
                .await
                .map_err(|e| AdminError::Internal(anyhow::anyhow!("Encryption failed: {}", e)))?;
            (
                enc,
                EncryptionMetadata {
                    algorithm: "encrypted".to_string(),
                    key_id: "active".to_string(),
                    iv: vec![],
                    auth_tag: None,
                    aad: None,
                    kdf_params: None,
                },
            )
        } else {
            (
                data.to_vec(),
                EncryptionMetadata {
                    algorithm: "none".to_string(),
                    key_id: "none".to_string(),
                    iv: vec![],
                    auth_tag: None,
                    aad: None,
                    kdf_params: None,
                },
            )
        };

        Ok(SecretEntry::new(
            path.to_string(),
            encrypted_data,
            encryption_metadata,
            SecurityLevel::Secret,
            uuid::Uuid::nil(),
        ))
    }

    /// Extract a `UserInfo` view from an already-parsed `serde_json::Value`.
    /// This is used after raw-JSON updates so we can return a `UserInfo` to
    /// the caller without a second storage round-trip.
    ///
    /// NOTE: The stored `User` struct has `email: Option<String>`, but `UserInfo`
    /// expects `email: String`. We normalise `null` → `""` before deserialising
    /// so that users created without an email don't cause a type-mismatch error.
    fn secreton_entry_to_user_info_from_value(
        &self,
        doc: &serde_json::Value,
    ) -> Result<UserInfo, AdminError> {
        let mut doc = doc.clone();
        // Normalise null email to empty string to match UserInfo's non-optional field.
        if let Some(obj) = doc.as_object_mut() {
            if matches!(obj.get("email"), None | Some(serde_json::Value::Null)) {
                obj.insert(
                    "email".to_string(),
                    serde_json::Value::String(String::new()),
                );
            }
        }
        // Deserialize only the UserInfo subset; unknown fields are ignored by serde.
        let user: UserInfo = serde_json::from_value(doc).map_err(|e| {
            AdminError::Internal(anyhow::anyhow!("Failed to extract UserInfo: {}", e))
        })?;
        Ok(user)
    }

    /// Helper method to convert SecretEntry to UserInfo
    ///
    /// NOTE: The stored `User` struct has `email: Option<String>`, but `UserInfo`
    /// expects `email: String`. We normalise `null` → `""` before deserialising
    /// so that users with a null email don't cause a type-mismatch error.
    async fn secreton_entry_to_user_info(
        &self,
        entry: &secreton_storage::SecretEntry,
    ) -> Result<UserInfo, AdminError> {
        let data = if let Some(crypto) = &self.crypto {
            match crypto.decrypt(&entry.encrypted_data).await {
                Ok(d) => d,
                Err(e) => {
                    // Try plaintext fallback if decryption fails (legacy data)
                    tracing::warn!("Decryption failed for user at {}, falling back to plaintext: {}", entry.path, e);
                    entry.encrypted_data.clone()
                }
            }
        } else {
            entry.encrypted_data.clone()
        };

        // Parse as Value first so we can normalise null email.
        let mut doc: serde_json::Value = serde_json::from_slice(&data).map_err(|e| {
            AdminError::Internal(anyhow::anyhow!("Failed to deserialize user: {}", e))
        })?;
        if let Some(obj) = doc.as_object_mut() {
            if matches!(obj.get("email"), None | Some(serde_json::Value::Null)) {
                obj.insert(
                    "email".to_string(),
                    serde_json::Value::String(String::new()),
                );
            }
        }
        let user: UserInfo = serde_json::from_value(doc).map_err(|e| {
            AdminError::Internal(anyhow::anyhow!("Failed to deserialize user: {}", e))
        })?;
        Ok(user)
    }

    /// Perform storage cleanup
    async fn storage_cleanup(&self) -> Result<u64, AdminError> {
        // Get current storage stats
        let before_stats = self
            .storage
            .get_stats()
            .await
            .map_err(AdminError::Storage)?;

        // Perform cleanup operations
        self.storage
            .delete_expired(None)
            .await
            .map_err(AdminError::Storage)?;

        // Get stats after cleanup
        let after_stats = self
            .storage
            .get_stats()
            .await
            .map_err(AdminError::Storage)?;

        // Calculate cleanup bytes
        let cleanup_bytes = before_stats
            .total_size_bytes
            .saturating_sub(after_stats.total_size_bytes);

        Ok(cleanup_bytes)
    }

    /// Clean up expired secrets
    async fn cleanup_expired_secrets(&self) -> Result<u64, AdminError> {
        use secreton_storage::QueryParams;

        let mut expired_count = 0;
        let now = chrono::Utc::now();

        // Query for all secrets with expiry metadata
        let query_params = QueryParams {
            path_prefix: None,
            ..Default::default()
        };

        let entries: Vec<_> = self
            .storage
            .list(&query_params)
            .await
            .map_err(AdminError::Storage)?
            .into_iter()
            .collect();

        for entry in entries {
            // Check if the secret has an expires_at field
            if let Some(expires_at_str) = entry.metadata.get("expires_at")
                && let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at_str)
            {
                let expires_at_utc = expires_at.with_timezone(&chrono::Utc);
                if expires_at_utc <= now
                    && self
                        .storage
                        .delete_by_path(&entry.path)
                        .await
                        .map_err(AdminError::Storage)?
                {
                    expired_count += 1;
                    // Log the cleanup
                    tracing::info!("Cleaned up expired secret: {}", entry.path);
                }
            }
        }

        Ok(expired_count)
    }

    /// Perform database compaction
    async fn perform_database_compaction(&self) -> Result<CompactionResult, AdminError> {
        // Get stats before compaction
        let stats_before = self
            .storage
            .get_stats()
            .await
            .map_err(AdminError::Storage)?;

        // Perform compaction based on storage backend type
        // For now, this is a placeholder - real implementation would depend on backend
        let compaction_successful = true;

        // Get stats after compaction (simulated)
        let stats_after = self
            .storage
            .get_stats()
            .await
            .map_err(AdminError::Storage)?;

        let mut details = HashMap::new();
        details.insert(
            "original_size_bytes".to_string(),
            serde_json::Value::Number(stats_before.total_size_bytes.into()),
        );
        details.insert(
            "compacted_size_bytes".to_string(),
            serde_json::Value::Number(stats_after.total_size_bytes.into()),
        );
        details.insert(
            "space_saved_bytes".to_string(),
            serde_json::Value::Number(
                (stats_before
                    .total_size_bytes
                    .saturating_sub(stats_after.total_size_bytes))
                .into(),
            ),
        );
        details.insert(
            "entries_processed".to_string(),
            serde_json::Value::Number(stats_before.total_entries.into()),
        );

        Ok(CompactionResult {
            success: compaction_successful,
            details,
        })
    }
}

/// Audit log entry
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user_id: String,
    pub action: String,
    pub resource: String,
    pub resource_id: Option<String>,
    pub ip_address: String,
    pub user_agent: String,
    pub success: bool,
    pub details: Option<serde_json::Value>,
}

/// Security finding from scan
#[derive(Debug, Serialize)]
pub struct SecurityFinding {
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub affected_resources: Vec<String>,
}

/// Security scan result
#[derive(Debug, Serialize)]
pub struct SecurityScanResult {
    pub scan_id: String,
    pub status: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub findings: Vec<SecurityFinding>,
}

/// Database compaction result
#[derive(Debug, Serialize)]
pub struct CompactionResult {
    pub success: bool,
    pub details: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::services::audit::AuditLogger;
    use secreton_crypto::SecurityParams;
    use secreton_storage::MockStorageBackend;

    #[tokio::test]
    async fn test_admin_service_creation() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(
            crate::services::crypto::CryptoService::new(storage.clone())
                .await
                .unwrap(),
        );
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();
        let auth = Arc::new(
            AuthenticationService::new(storage.clone(), crypto, &config)
                .await
                .unwrap(),
        );
        let performance = Arc::new(SecretPerformanceOptimizer::default());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 90, 1000, false)
                .await
                .unwrap(),
        );

        let admin_service = AdminService::new(storage, auth, performance, audit).await;
        assert!(admin_service.is_ok());
    }

    #[tokio::test]
    async fn test_get_system_stats() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(
            crate::services::crypto::CryptoService::new(storage.clone())
                .await
                .unwrap(),
        );
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();
        let auth = Arc::new(
            AuthenticationService::new(storage.clone(), crypto, &config)
                .await
                .unwrap(),
        );
        let performance = Arc::new(SecretPerformanceOptimizer::default());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 90, 1000, false)
                .await
                .unwrap(),
        );
        let service = AdminService::new(storage, auth, performance, audit).await.unwrap();

        let stats = service
            .get_system_stats()
            .await
            .expect("stats should be retrieved");
        assert!(stats.uptime_seconds >= 0);
        assert!(stats.total_users >= 0);
        assert!(stats.cache_hit_rate >= 0.0 && stats.cache_hit_rate <= 1.0);
        assert!(stats.requests_per_minute >= 0.0);
    }

    #[tokio::test]
    async fn test_create_backup_returns_metadata() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(
            crate::services::crypto::CryptoService::new(storage.clone())
                .await
                .unwrap(),
        );

        // Pre-populate mock storage to avoid initialization errors during unseal
        let active_key_id = "test_active_key_123";
        let active_key_data = vec![1; 32]; // dummy encrypted key data

        let mut active_key_ref_entry = secreton_storage::SecretEntry::new(
            "sys/keys/active_key_ref".to_string(),
            active_key_id.as_bytes().to_vec(),
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::TopSecret,
            uuid::Uuid::nil(),
        );
        let mut active_key_entry = secreton_storage::SecretEntry::new(
            format!("sys/keys/{}", active_key_id),
            active_key_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::TopSecret,
            uuid::Uuid::nil(),
        );
        let _ = storage.store(&active_key_ref_entry).await;
        let _ = storage.store(&active_key_entry).await;

        crypto.set_root_key(vec![0; 32]).await.unwrap();

        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();
        let auth = Arc::new(
            AuthenticationService::new(storage.clone(), crypto.clone(), &config)
                .await
                .unwrap(),
        );
        let performance = Arc::new(SecretPerformanceOptimizer::default());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 90, 1000, false)
                .await
                .unwrap(),
        );
        let service = AdminService::new(storage, auth, performance, audit)
            .await
            .unwrap()
            .with_crypto(crypto);

        let backup = service.create_backup().await.expect("backup");
        assert!(backup.encrypted);
        assert!(backup.metadata.contains_key("version"));
    }

    #[tokio::test]
    async fn test_run_garbage_collection_returns_details() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(
            crate::services::crypto::CryptoService::new(storage.clone())
                .await
                .unwrap(),
        );
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();
        let auth = Arc::new(
            AuthenticationService::new(storage.clone(), crypto, &config)
                .await
                .unwrap(),
        );
        let performance = Arc::new(SecretPerformanceOptimizer::default());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 90, 1000, false)
                .await
                .unwrap(),
        );
        let service = AdminService::new(storage, auth, performance, audit).await.unwrap();

        let result = service.run_garbage_collection().await.expect("gc");
        assert_eq!(result.operation, "garbage_collection");
        assert!(result.details.contains_key("expired_sessions"));
        assert!(result.details.contains_key("expired_secrets"));
        assert!(result.details.contains_key("storage_cleaned_bytes"));
    }

    #[tokio::test]
    async fn test_storage_cleanup_removes_expired_items() {
        use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel};

        let storage = Arc::new(MockStorageBackend::new());

        // Add an expired entry
        let expired_entry = SecretEntry::new(
            "expired/path".to_string(),
            vec![1, 2, 3, 4, 5], // 5 bytes
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            uuid::Uuid::new_v4(),
        )
        .with_expiration(chrono::Utc::now() - chrono::Duration::hours(1));

        storage.store(&expired_entry).await.unwrap();

        // Add a valid entry
        let valid_entry = SecretEntry::new(
            "valid/path".to_string(),
            vec![1, 2, 3], // 3 bytes
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            uuid::Uuid::new_v4(),
        )
        .with_expiration(chrono::Utc::now() + chrono::Duration::hours(1));

        storage.store(&valid_entry).await.unwrap();

        let crypto = Arc::new(
            crate::services::crypto::CryptoService::new(storage.clone())
                .await
                .unwrap(),
        );
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();
        let auth = Arc::new(
            AuthenticationService::new(storage.clone(), crypto, &config)
                .await
                .unwrap(),
        );
        let performance = Arc::new(SecretPerformanceOptimizer::default());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 90, 1000, false)
                .await
                .unwrap(),
        );
        let service = AdminService::new(storage.clone(), auth, performance, audit)
            .await
            .unwrap();

        // Run cleanup
        let cleaned_bytes = service.storage_cleanup().await.unwrap();

        // Verify result
        assert_eq!(cleaned_bytes, 5); // Should have removed 5 bytes

        // Verify the correct entry was removed
        assert!(storage.get_by_path("expired/path").await.unwrap().is_none());
        assert!(storage.get_by_path("valid/path").await.unwrap().is_some());
    }
}
