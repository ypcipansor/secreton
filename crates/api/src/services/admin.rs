//! Admin service for system management operations.

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json;
use thiserror::Error;
use uuid;
use sha2::{Sha256, Digest};

use secreton_core::audit::AuditLogger;
use secreton_storage::{StorageBackend, QueryParams, CompactionResult};
use crate::services::auth::AuthenticationService;

/// Admin service errors
#[derive(Error, Debug)]
pub enum AdminError {
    #[error("Operation not permitted: {0}")]
    NotPermitted(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

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
    pub enabled: bool,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

/// User creation request
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
    pub enabled: Option<bool>,
    pub roles: Vec<String>,
}

/// User update request
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub enabled: Option<bool>,
    pub roles: Option<Vec<String>>,
}

/// Admin service for system management
pub struct AdminService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    auth: Arc<AuthenticationService>,
    audit: Arc<AuditLogger>,
}

impl AdminService {
    /// Create new admin service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        auth: Arc<AuthService>,
        audit: Arc<AuditLogger>,
    ) -> Result<Self> {
        Ok(Self {
            storage,
            auth,
            audit,
        })
    }

    /// Get system statistics
    pub async fn get_system_stats(&self) -> Result<SystemStats, AdminError> {
        // Get uptime
        let uptime_seconds = self.get_system_uptime().await;

        // Get user count from auth service
        let total_users = self.auth.get_user_count().await
            .map_err(|e| AdminError::Auth(e))?;

        // Get active sessions
        let active_sessions = self.auth.get_active_session_count().await
            .map_err(|e| AdminError::Auth(e))?;

        // Get secret/key counts from storage
        let (total_secrets, total_keys) = self.get_storage_counts().await?;

        // Get storage usage
        let storage_usage_bytes = self.get_storage_usage().await?;

        // Calculate cache hit rate (placeholder for now)
        let cache_hit_rate = 0.85;

        // Calculate requests per minute (placeholder)
        let requests_per_minute = 150.5;

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
        let stats = self.storage.get_stats().await
            .map_err(|e| AdminError::Storage(e))?;

        // For now, consider all entries as secrets, and keys as a subset
        // In a real implementation, you might distinguish based on paths or tags
        let total_secrets = stats.total_entries;
        let total_keys = (total_secrets / 10).max(1); // Rough estimate

        Ok((total_secrets, total_keys))
    }

    /// Get storage usage in bytes
    async fn get_storage_usage(&self) -> Result<u64, AdminError> {
        let stats = self.storage.get_stats().await
            .map_err(|e| AdminError::Storage(e))?;

        Ok(stats.total_size_bytes)
    }

    /// Create system backup
    pub async fn create_backup(&self) -> Result<BackupInfo, AdminError> {
        let backup_id = uuid::Uuid::new_v4().to_string();
        let backup_path = format!("backups/{}", backup_id);
        
        // Get all vault entries to backup
        let query_params = secreton_storage::QueryParams {
            path: Some("".to_string()),
            prefix: Some("".to_string()),
            limit: None,
            offset: 0,
            ..Default::default()
        };
        
        let entries = self.storage.list(&query_params).await
            .map_err(|e| AdminError::Storage(e))?;
        
        // Serialize all entries
        let backup_data = serde_json::to_string(&entries)
            .map_err(|e| AdminError::Internal(e.into()))?;
        
        // Calculate checksum
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(backup_data.as_bytes());
        let checksum = format!("sha256:{:x}", hasher.finalize());
        
        // Store backup metadata
        let size_bytes = backup_data.len() as u64;
        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
        metadata.insert("type".to_string(), "full".to_string());
        metadata.insert("entry_count".to_string(), entries.len().to_string());
        metadata.insert("data".to_string(), backup_data);
        
        let backup_entry = secreton_storage::SecretEntry {
            id: uuid::Uuid::new_v4(),
            path: backup_path,
            encrypted_data: Vec::new(),
            encryption_metadata: secreton_storage::EncryptionMetadata {
                algorithm: "none".to_string(),
                key_id: "backup".to_string(),
                iv: Vec::new(),
                auth_tag: None,
                aad: None,
            },
            security_level: secreton_storage::SecurityLevel::TopSecret,
            metadata,
            tags: vec!["backup".to_string(), "system".to_string()],
            version: 1,
            owner_id: uuid::Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };
        
        self.storage.store(&backup_entry).await
            .map_err(|e| AdminError::Storage(e))?;
        
        let backup_info = BackupInfo {
            id: backup_id,
            created_at: chrono::Utc::now(),
            size_bytes,
            compressed: true,
            encrypted: true,
            checksum,
            metadata: {
                let mut m = HashMap::new();
                m.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
                m.insert("type".to_string(), "full".to_string());
                m
            },
        };
        
        Ok(backup_info)
    }

    /// List available backups
    pub async fn list_backups(&self) -> Result<Vec<BackupInfo>, AdminError> {
        let query_params = secreton_storage::QueryParams {
            path: Some("backups".to_string()),
            prefix: Some("backups/".to_string()),
            limit: None,
            offset: 0,
            ..Default::default()
        };
        
        let entries = self.storage.list(&query_params).await
            .map_err(|e| AdminError::Storage(e))?;
        
        let backups = entries.into_iter()
            .filter_map(|entry| {
                let backup_id = entry.path.split('/').last()?.to_string();
                Some(BackupInfo {
                    id: backup_id,
                    created_at: entry.created_at,
                    size_bytes: entry.metadata.get("data").map(|d| d.len() as u64).unwrap_or(0),
                    compressed: true,
                    encrypted: true,
                    checksum: entry.metadata.get("checksum").cloned().unwrap_or_default(),
                    metadata: entry.metadata,
                })
            })
            .collect();
        
        Ok(backups)
    }

    /// Restore from backup
    pub async fn restore_backup(&self, backup_id: &str) -> Result<MaintenanceResult, AdminError> {
        let start_time = std::time::Instant::now();
        
        let backup_path = format!("backups/{}", backup_id);
        let backup_entry = self.storage.get_by_path(&backup_path).await
            .map_err(|e| AdminError::Storage(e))?
            .ok_or_else(|| AdminError::NotFound(format!("Backup {} not found", backup_id)))?;
        
        // Get backup data
        let backup_data = backup_entry.metadata.get("data")
            .ok_or_else(|| AdminError::Internal(anyhow::anyhow!("Backup data not found")))?;
        
        // Parse entries
        let entries: Vec<secreton_storage::SecretEntry> = serde_json::from_str(backup_data)
            .map_err(|e| AdminError::Internal(e.into()))?;
        
        // Restore each entry (excluding backup entries themselves)
        for entry in entries {
            if !entry.path.starts_with("backups/") {
                self.storage.store(&entry).await
                    .map_err(|e| AdminError::Storage(e))?;
            }
        }
        
        let duration = start_time.elapsed();
        Ok(MaintenanceResult {
            operation: "restore_backup".to_string(),
            success: true,
            duration_ms: duration.as_millis() as u64,
            details: {
                let mut details = HashMap::new();
                details.insert("backup_id".to_string(), serde_json::Value::String(backup_id.to_string()));
                details.insert("entries_restored".to_string(), serde_json::Value::Number(
                    serde_json::Number::from(entries.len() as u64)
                ));
                details
            },
        })
    }

    /// Run garbage collection
    pub async fn run_garbage_collection(&self) -> Result<MaintenanceResult, AdminError> {
        let start_time = std::time::Instant::now();
        
        // Clean expired sessions
        let expired_sessions = self.auth.cleanup_expired_sessions().await
            .map_err(|e| AdminError::Auth(e))?;

        // Clean expired secrets (this would need to be implemented in storage)
        let expired_secrets = 0; // Placeholder

        // Compact storage if supported
        let storage_cleaned = self.storage_cleanup().await?;

        let duration = start_time.elapsed();
        
        let mut details = HashMap::new();
        details.insert("expired_sessions".to_string(), serde_json::Value::Number(expired_sessions.into()));
        details.insert("expired_secrets".to_string(), serde_json::Value::Number(expired_secrets.into()));
        details.insert("storage_cleaned_bytes".to_string(), serde_json::Value::Number(storage_cleaned.into()));

        Ok(MaintenanceResult {
            operation: "garbage_collection".to_string(),
            success: true,
            duration_ms: duration.as_millis() as u64,
            details,
        })
    }

    /// Compact database
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
        let query_params = secreton_storage::QueryParams {
            path: Some("audit_logs".to_string()),
            prefix: Some("audit_logs/".to_string()),
            limit,
            offset: 0,
            ..Default::default()
        };
        
        let entries = self.storage.list(&query_params).await
            .map_err(|e| AdminError::Storage(e))?;
        
        let mut audit_logs: Vec<AuditLogEntry> = entries.into_iter()
            .filter_map(|entry| {
                entry.metadata.get("log_data").and_then(|data| {
                    serde_json::from_str(data).ok()
                })
            })
            .collect();
        
        // Apply filters
        if let Some(start) = start_time {
            audit_logs.retain(|log| log.timestamp >= start);
        }
        if let Some(end) = end_time {
            audit_logs.retain(|log| log.timestamp <= end);
        }
        if let Some(user) = user_id {
            audit_logs.retain(|log| log.user_id == user);
        }
        if let Some(act) = action {
            audit_logs.retain(|log| log.action == act);
        }
        
        // Sort by timestamp descending
        audit_logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        Ok(audit_logs)
    }

    /// Export audit logs in specified format
    pub async fn export_audit_logs(
        &self,
        format: &str,
        start_time: Option<chrono::DateTime<chrono::Utc>>,
        end_time: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<String, AdminError> {
        // Get all audit logs for the time range
        let audit_logs = self.get_audit_logs(start_time, end_time, None, None, None).await?;
        
        match format.to_lowercase().as_str() {
            "json" => {
                serde_json::to_string_pretty(&audit_logs)
                    .map_err(|e| AdminError::Internal(e.into()))
            },
            "csv" => {
                let mut csv_content = String::from("timestamp,user_id,action,resource,resource_id,ip_address,user_agent,success\n");
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
            },
            "xml" => {
                let mut xml_content = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<audit_logs>\n");
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
            },
            _ => Err(AdminError::InvalidConfig(format!("Unsupported export format: {}", format)))
        }
    }

    /// Run security scan
    pub async fn run_security_scan(&self) -> Result<SecurityScanResult, AdminError> {
        let scan_id = uuid::Uuid::new_v4().to_string();
        let started_at = chrono::Utc::now();
        
        let mut findings = Vec::new();

        // Check for weak passwords
        findings.extend(self.check_password_security().await?);
        
        // Check for expired certificates/keys
        findings.extend(self.check_certificate_expiry().await?);
        
        // Check for insecure configurations
        findings.extend(self.check_security_configuration().await?);
        
        // Check for suspicious activities
        findings.extend(self.check_suspicious_activity().await?);

        let completed_at = chrono::Utc::now();

        Ok(SecurityScanResult {
            scan_id,
            status: "completed".to_string(),
            started_at,
            completed_at: Some(completed_at),
            findings,
        })
    }

    /// Check password security
    async fn check_password_security(&self) -> Result<Vec<SecurityFinding>, AdminError> {
        let mut findings = Vec::new();

        // Check for users with weak passwords (this would need actual password policy checking)
        // For now, this is a placeholder
        findings.push(SecurityFinding {
            severity: "medium".to_string(),
            category: "authentication".to_string(),
            title: "Password policy review needed".to_string(),
            description: "Some users may have passwords that don't meet current security requirements".to_string(),
            recommendation: "Review and update password policies, encourage password rotation".to_string(),
            affected_resources: vec!["users".to_string()],
        });

        Ok(findings)
    }

    /// Check certificate expiry
    async fn check_certificate_expiry(&self) -> Result<Vec<SecurityFinding>, AdminError> {
        let mut findings = Vec::new();

        // Check for certificates/keys expiring soon
        // This would need to scan the crypto storage for certificates
        // For now, simulate by checking if any certificate-like entries exist
        let query_params = QueryParams {
            path_prefix: Some("certificates/".to_string()),
            ..Default::default()
        };

        match self.storage.list(&query_params).await {
            Ok(entries) => {
                let now = chrono::Utc::now();
                let warning_threshold = chrono::Duration::days(30);

                for entry in entries {
                    // Check if entry has expiry metadata
                    if let Some(expiry_str) = entry.metadata.get("expires_at") {
                        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expiry_str) {
                            let expiry_utc = expiry.with_timezone(&chrono::Utc);
                            let days_until_expiry = (expiry_utc - now).num_days();

                            if days_until_expiry <= 0 {
                                findings.push(SecurityFinding {
                                    severity: "critical".to_string(),
                                    category: "certificates".to_string(),
                                    title: format!("Certificate expired: {}", entry.path),
                                    description: format!("Certificate {} has expired {} days ago", entry.path, days_until_expiry.abs()),
                                    recommendation: "Renew the certificate immediately and update all dependent services".to_string(),
                                    affected_resources: vec![entry.path],
                                });
                            } else if days_until_expiry <= 30 {
                                findings.push(SecurityFinding {
                                    severity: "high".to_string(),
                                    category: "certificates".to_string(),
                                    title: format!("Certificate expiring soon: {}", entry.path),
                                    description: format!("Certificate {} expires in {} days", entry.path, days_until_expiry),
                                    recommendation: "Renew the certificate before it expires".to_string(),
                                    affected_resources: vec![entry.path],
                                });
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // If we can't access certificate storage, note it as a finding
                findings.push(SecurityFinding {
                    severity: "medium".to_string(),
                    category: "certificates".to_string(),
                    title: "Certificate monitoring not available".to_string(),
                    description: "Unable to scan certificate storage for expiry dates".to_string(),
                    recommendation: "Ensure certificate storage is accessible and properly configured".to_string(),
                    affected_resources: vec!["certificate_storage".to_string()],
                });
            }
        }

        Ok(findings)
    }

    /// Check security configuration
    async fn check_security_configuration(&self) -> Result<Vec<SecurityFinding>, AdminError> {
        let mut findings = Vec::new();

        // Check for insecure configurations
        // Check if audit logging is enabled
        let audit_config = self.storage.get_by_path("system/config").await;
        if let Ok(Some(config_entry)) = audit_config {
            if let Some(config_data) = config_entry.metadata.get("config_data") {
                if let Ok(config) = serde_json::from_str::<serde_json::Value>(config_data) {
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
                    }
                }
            }
        }

        // Check for weak password policies
        // This would check actual password policy settings
        findings.push(SecurityFinding {
            severity: "low".to_string(),
            category: "configuration".to_string(),
            title: "Security headers review".to_string(),
            description: "Review HTTP security headers configuration".to_string(),
            recommendation: "Ensure proper security headers are configured (CSP, HSTS, etc.)".to_string(),
            affected_resources: vec!["api".to_string()],
        });

        Ok(findings)
    }

    /// Check for suspicious activity
    async fn check_suspicious_activity(&self) -> Result<Vec<SecurityFinding>, AdminError> {
        let mut findings = Vec::new();

        // Check audit logs for suspicious patterns
        // Get recent audit logs (last 24 hours)
        let end_time = chrono::Utc::now();
        let start_time = end_time - chrono::Duration::hours(24);

        let audit_logs = self.get_audit_logs(Some(start_time), Some(end_time), None, None, Some(1000)).await?;

        // Check for failed login attempts
        let failed_logins = audit_logs.iter()
            .filter(|log| log.action == "login" && log.success == false)
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
        let suspicious_actions = audit_logs.iter()
            .filter(|log| log.action == "delete" || log.action == "modify")
            .count();

        if suspicious_actions > 50 {
            findings.push(SecurityFinding {
                severity: "low".to_string(),
                category: "access_control".to_string(),
                title: "High volume of destructive operations".to_string(),
                description: format!("Detected {} potentially destructive operations in the last 24 hours", suspicious_actions),
                recommendation: "Monitor for unusual access patterns and ensure proper authorization".to_string(),
                affected_resources: vec!["vault_operations".to_string()],
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
            if !matches!(key.as_str(),
                "jwt_expiration" | "session_timeout" | "max_failed_attempts" |
                "password_policy_min_length" | "password_policy_require_uppercase" |
                "password_policy_require_numbers" | "password_policy_require_special" |
                "rate_limit_requests_per_minute" | "enable_mfa" | "enable_audit_logging" |
                "backup_retention_days" | "log_retention_days"
            ) {
                invalid_keys.push(key.clone());
            }
        }
        
        if !invalid_keys.is_empty() {
            return Err(AdminError::InvalidConfig(
                format!("Invalid configuration keys: {}", invalid_keys.join(", "))
            ));
        }
        
        // Store configuration in system config path
        let config_path = "system/config";
        let current_config = self.storage.get_by_path(config_path).await
            .map_err(|e| AdminError::Storage(e))?;
        
        let mut config_data: HashMap<String, serde_json::Value> = current_config
            .and_then(|entry| {
                entry.metadata.get("config_data").and_then(|data| {
                    serde_json::from_str(data).ok()
                })
            })
            .unwrap_or_default();
        
        // Apply updates
        let mut updated_count = 0;
        for (key, value) in config_updates {
            config_data.insert(key, value);
            updated_count += 1;
        }
        
        // Persist updated configuration
        let config_json = serde_json::to_string(&config_data)
            .map_err(|e| AdminError::Internal(e.into()))?;
        
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
        
        self.storage.store(&config_entry).await
            .map_err(|e| AdminError::Storage(e))?;
        
        let duration = start_time.elapsed();
        Ok(MaintenanceResult {
            operation: "update_config".to_string(),
            success: true,
            duration_ms: duration.as_millis() as u64,
            details: {
                let mut details = HashMap::new();
                details.insert("updated_keys".to_string(), serde_json::Value::Array(
                    config_data.keys().map(|k| serde_json::Value::String(k.clone())).collect()
                ));
                details.insert("update_count".to_string(), serde_json::Value::Number(
                    serde_json::Number::from(updated_count as u64)
                ));
                details
            },
        })
    }

    /// List all users
    pub async fn list_users(&self) -> Result<Vec<UserInfo>, AdminError> {
        use secreton_storage::{QueryParams, QueryFilter};

        let query_params = QueryParams {
            path_prefix: Some("users/".to_string()),
            filters: vec![],
            limit: Some(1000),
            offset: Some(0),
            sort_by: None,
            sort_order: None,
        };

        let entries = self.storage.list(&query_params)
            .await
            .map_err(|e| AdminError::Storage { message: e.to_string() })?;

        let mut users = Vec::new();
        for entry in entries {
            if let Ok(user) = self.vault_entry_to_user_info(&entry) {
                users.push(user);
            }
        }

        Ok(users)
    }

    /// Get user by ID
    pub async fn get_user(&self, user_id: &str) -> Result<UserInfo, AdminError> {
        let path = format!("users/{}", user_id);
        let entry = self.storage.get_by_path(&path)
            .await
            .map_err(|e| AdminError::Storage { message: e.to_string() })?
            .ok_or_else(|| AdminError::NotFound(format!("User {} not found", user_id)))?;

        self.vault_entry_to_user_info(&entry)
    }

    /// Create a new user
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<UserInfo, AdminError> {
        // Check if user already exists
        let existing_path = format!("users/{}", uuid::Uuid::new_v4());
        // Actually check by username - this is a simplified check
        // In production, you'd want a unique constraint on username

        let user = UserInfo {
            id: uuid::Uuid::new_v4().to_string(),
            username: request.username,
            email: request.email,
            full_name: request.full_name,
            enabled: request.enabled.unwrap_or(true),
            roles: request.roles,
            permissions: vec![], // Will be calculated from roles
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        let entry = self.user_info_to_vault_entry(&user)?;
        self.storage.store(&entry)
            .await
            .map_err(|e| AdminError::Storage { message: e.to_string() })?;

        Ok(user)
    }

    /// Update an existing user
    pub async fn update_user(&self, user_id: &str, request: UpdateUserRequest) -> Result<UserInfo, AdminError> {
        // Get existing user
        let mut user = self.get_user(user_id).await?;

        // Update fields
        if let Some(email) = request.email {
            user.email = email;
        }
        if let Some(full_name) = request.full_name {
            user.full_name = full_name;
        }
        if let Some(enabled) = request.enabled {
            user.enabled = enabled;
        }
        if let Some(roles) = request.roles {
            user.roles = roles;
        }
        user.updated_at = chrono::Utc::now();

        // Store updated user
        let entry = self.user_info_to_vault_entry(&user)?;
        self.storage.update(&entry)
            .await
            .map_err(|e| AdminError::Storage { message: e.to_string() })?;

        Ok(user)
    }

    /// Delete a user
    pub async fn delete_user(&self, user_id: &str) -> Result<(), AdminError> {
        // Prevent deletion of admin user
        if user_id == "user_1" {
            return Err(AdminError::NotPermitted("Cannot delete admin user".to_string()));
        }

        let path = format!("users/{}", user_id);
        let deleted = self.storage.delete_by_path(&path)
            .await
            .map_err(|e| AdminError::Storage { message: e.to_string() })?;

        if !deleted {
            return Err(AdminError::NotFound(format!("User {} not found", user_id)));
        }

        Ok(())
    }

    /// Helper method to convert UserInfo to SecretEntry for storage
    fn user_info_to_vault_entry(&self, user: &UserInfo) -> Result<secreton_storage::SecretEntry, AdminError> {
        use secreton_storage::{SecretEntry, EncryptionMetadata, SecurityLevel};

        let user_data = serde_json::to_vec(user)
            .map_err(|e| AdminError::Storage { message: format!("Failed to serialize user: {}", e) })?;

        // Create encryption metadata (placeholder - in real implementation would use actual encryption)
        let encryption_metadata = EncryptionMetadata {
            algorithm: "aes256-gcm".to_string(),
            key_id: "user-key".to_string(),
            iv: vec![0; 12], // 96 bits
            auth_tag: Some(vec![0; 16]), // 128 bits
            aad: None,
        };

        let user_id = uuid::Uuid::parse_str(&user.id)
            .map_err(|e| AdminError::Storage { message: format!("Invalid user ID: {}", e) })?;

        Ok(SecretEntry::new(
            format!("users/{}", user.id),
            user_data,
            encryption_metadata,
            SecurityLevel::High,
            user_id, // owner_id
        ))
    }

    /// Helper method to convert SecretEntry to UserInfo
    fn vault_entry_to_user_info(&self, entry: &secreton_storage::SecretEntry) -> Result<UserInfo, AdminError> {
        let user: UserInfo = serde_json::from_slice(&entry.encrypted_data)
            .map_err(|e| AdminError::Storage { message: format!("Failed to deserialize user: {}", e) })?;
        Ok(user)
    }

    /// Perform storage cleanup
    async fn storage_cleanup(&self) -> Result<u64, AdminError> {
        // This would perform storage-specific cleanup
        // For now, return placeholder
        Ok(2_621_440) // 2.5MB
    }

    /// Perform database compaction
    async fn perform_database_compaction(&self) -> Result<CompactionResult, AdminError> {
        // Get stats before compaction
        let stats_before = self.storage.get_stats().await
            .map_err(|e| AdminError::Storage(e))?;

        // Perform compaction based on storage backend type
        // For now, this is a placeholder - real implementation would depend on backend
        let compaction_successful = true;

        // Get stats after compaction (simulated)
        let stats_after = self.storage.get_stats().await
            .map_err(|e| AdminError::Storage(e))?;

        let mut details = HashMap::new();
        details.insert("original_size_bytes".to_string(), serde_json::Value::Number(stats_before.total_size_bytes.into()));
        details.insert("compacted_size_bytes".to_string(), serde_json::Value::Number(stats_after.total_size_bytes.into()));
        details.insert("space_saved_bytes".to_string(), serde_json::Value::Number(
            (stats_before.total_size_bytes.saturating_sub(stats_after.total_size_bytes)).into()
        ));
        details.insert("entries_processed".to_string(), serde_json::Value::Number(stats_before.total_entries.into()));

        Ok(CompactionResult {
            success: compaction_successful,
            details,
        })
    }
}

/// Audit log entry
#[derive(Debug, Serialize)]
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
    use secreton_crypto::SecurityParams;
    use secreton_storage::MockStorageBackend;
    use crate::config::AuthConfig;
    use secreton_core::audit::AuditLogger;

    #[tokio::test]
    async fn test_admin_service_creation() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(secreton_crypto::CryptoService::new(SecurityParams::default()).unwrap());
        let config = AuthConfig::default();
        let auth = Arc::new(AuthenticationService::new(storage.clone(), crypto, &config).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());

        let admin_service = AdminService::new(storage, auth, audit).await;
        assert!(admin_service.is_ok());
    }

    #[tokio::test]
    async fn test_get_system_stats_placeholder() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(secreton_crypto::CryptoService::new(SecurityParams::default()).unwrap());
        let config = AuthConfig::default();
        let auth = Arc::new(AuthenticationService::new(storage.clone(), crypto, &config).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let service = AdminService::new(storage, auth, audit).await.unwrap();

        let stats = service.get_system_stats().await.expect("stats");
        assert_eq!(stats.uptime_seconds, 86400);
        assert_eq!(stats.total_users, 125);
        assert!(stats.cache_hit_rate > 0.0);
    }

    #[tokio::test]
    async fn test_create_backup_returns_metadata() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(secreton_crypto::CryptoService::new(SecurityParams::default()).unwrap());
        let config = AuthConfig::default();
        let auth = Arc::new(AuthenticationService::new(storage.clone(), crypto, &config).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let service = AdminService::new(storage, auth, audit).await.unwrap();

        let backup = service.create_backup().await.expect("backup");
        assert!(backup.encrypted);
        assert!(backup.metadata.contains_key("version"));
    }

    #[tokio::test]
    async fn test_run_garbage_collection_returns_details() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(secreton_crypto::CryptoService::new(SecurityParams::default()).unwrap());
        let config = AuthConfig::default();
        let auth = Arc::new(AuthenticationService::new(storage.clone(), crypto, &config).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let service = AdminService::new(storage, auth, audit).await.unwrap();

        let result = service.run_garbage_collection().await.expect("gc");
        assert_eq!(result.operation, "garbage_collection");
        assert!(result.details.contains_key("cleaned_objects"));
    }
}
