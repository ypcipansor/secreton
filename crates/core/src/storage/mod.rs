//! Storage system for Secreton
//!
//! This module provides a comprehensive storage system with multiple backends
//! and a unified interface for data persistence.

use crate::CoreError;
use crate::models::plugin::PluginCatalogEntry;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use secreton_auth::MfaMethod;
use secreton_auth::policies::{Policy, PolicyEffect, PolicyRule, PolicyType};
use secreton_auth::{token::Token, token::TokenStatus, token::TokenType};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::any::Any;
use std::collections::HashMap;
use uuid::Uuid;

pub mod legacy_storage;
pub mod mfa;
pub mod secret;
pub mod secure;
pub mod traits;
pub mod types;

// Re-export types and traits
pub use mfa::{MfaRecoveryCodes, MfaSecret, MfaStorage};
pub use secret::*;
pub use secure::storage::{SecureStorage, SharedSecureStorage};
pub use traits::*;
pub use types::*;

// Type alias for backward compatibility
pub use legacy_storage::Storage;
pub type MemoryStorage = Storage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub user: Option<String>,
    pub action: Option<String>,
    pub path: Option<String>,
    pub status: Option<String>,
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    fn as_any(&self) -> &dyn Any;

    // MFA related methods
    async fn store_mfa_secret(
        &self,
        user_id: &str,
        secret: &str,
        method: MfaMethod,
    ) -> Result<(), CoreError>;
    async fn get_mfa_secret(&self, user_id: &str, method: MfaMethod) -> Result<String, CoreError>;
    async fn delete_mfa_secret(&self, user_id: &str, method: MfaMethod) -> Result<(), CoreError>;
    async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool, CoreError>;
    async fn get_user_mfa_methods(&self, user_id: &str) -> Result<Vec<MfaMethod>, CoreError>;
    async fn get_mfa_status(
        &self,
        user_id: &str,
    ) -> Result<std::collections::HashMap<MfaMethod, bool>, CoreError>;
    async fn enable_mfa(&self, user_id: &str, method: MfaMethod) -> Result<(), CoreError>;
    async fn disable_mfa(&self, user_id: &str) -> Result<(), CoreError>;
    async fn store_mfa_recovery_codes(
        &self,
        user_id: &str,
        codes: &[String],
    ) -> Result<(), CoreError>;
    async fn get_mfa_recovery_codes(&self, user_id: &str) -> Result<Vec<String>, CoreError>;
    async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32, CoreError>;
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>, CoreError>;
    async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, Value)>, CoreError>;
    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<(), CoreError>;
    async fn create_user(&self, username: &str, password: &str) -> Result<(), CoreError>;
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool, CoreError>;
    async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<(), CoreError>;
    async fn add_policy_to_role(
        &self,
        role: &str,
        path: &str,
        action: &str,
        effect: &str,
    ) -> Result<(), CoreError>;
    async fn check_policy(
        &self,
        username: &str,
        path: &str,
        action: &str,
    ) -> Result<bool, CoreError>;
    async fn insert_token(
        &self,
        user: &str,
        token: &str,
        expires_at: Option<&str>,
    ) -> Result<(), CoreError>;
    async fn is_token_valid(&self, token: &str) -> Result<bool, CoreError>;
    async fn revoke_token(&self, token: &str) -> Result<(), CoreError>;
    async fn log_audit(
        &self,
        user: &str,
        action: &str,
        path: &str,
        status: &str,
    ) -> Result<(), CoreError>;
    async fn get_policies_for_user(
        &self,
        user_id: &str,
        entity_alias: Option<&str>,
    ) -> Result<Vec<Policy>, CoreError>;
    async fn insert_sentinel_policy_version(
        &self,
        p: &crate::models::sentinel::SentinelPolicy,
    ) -> Result<(), CoreError>;
    async fn list_sentinel_policy_versions(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<crate::models::sentinel::SentinelPolicy>, CoreError>;
    async fn delete_sentinel_policy_version(
        &self,
        namespace: &str,
        name: &str,
        version: u32,
    ) -> Result<(), CoreError>;
    async fn delete_secret(&self, path: &str, namespace: &str) -> Result<(), CoreError>;
    async fn list_users(&self) -> Result<Vec<secreton_auth::UserInfo>, CoreError>;
    async fn get_user_details(
        &self,
        username: &str,
    ) -> Result<Option<secreton_auth::UserInfo>, CoreError>;
}

pub enum StorageType {
    Sqlite(legacy_storage::Storage),
    // Postgres(PostgresStorage),
}

pub struct PostgresStorage {
    pool: Pool,
}

impl PostgresStorage {
    pub async fn new(pool: Pool) -> Result<Self, CoreError> {
        Self::create_tables(&pool)
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(Self { pool })
    }

    pub async fn from_url(database_url: &str) -> Result<Self, CoreError> {
        use deadpool_postgres::{Config, ManagerConfig, RecyclingMethod, Runtime};
        use tokio_postgres::{Config as PgConfig, NoTls};

        let _pg_config = database_url
            .parse::<PgConfig>()
            .map_err(|e| anyhow::anyhow!("Failed to parse database URL: {}", e))?;
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let config = Config {
            manager: Some(mgr_config),
            ..Default::default()
        };

        let pool = config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|e| anyhow::anyhow!("Failed to create pool: {:?}", e))?;
        Self::new(pool).await
    }
    async fn create_tables(pool: &Pool) -> Result<(), CoreError> {
        let client = pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        // Create MFA tables
        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS mfa_secrets (
                id SERIAL PRIMARY KEY,
                user_id TEXT NOT NULL,
                method TEXT NOT NULL,
                secret TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(user_id, method)
            )
            "#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS user_mfa_settings (
                user_id TEXT PRIMARY KEY,
                is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                method TEXT,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
            "#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        // Create main tables
        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS secrets (
                id SERIAL PRIMARY KEY,
                path TEXT NOT NULL,
                version INTEGER NOT NULL,
                data TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(path, version)
            )
            "#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
            "#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS secreton_state (
                id SERIAL PRIMARY KEY,
                sealed BOOLEAN NOT NULL DEFAULT TRUE,
                master_key TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
            "#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                user TEXT,
                action TEXT,
                path TEXT,
                status TEXT,
                timestamp TIMESTAMPTZ DEFAULT NOW()
            )
            "#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        Ok(())
    }

    pub async fn migrate_tokens(&self) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS tokens (
                id TEXT PRIMARY KEY,
                token TEXT NOT NULL UNIQUE,
                token_type TEXT NOT NULL,
                policies TEXT[], -- Array of policy names
                entity_id TEXT,
                display_name TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP,
                renewed_at TIMESTAMP,
                renew_count INTEGER DEFAULT 0,
                max_renewals INTEGER,
                ttl INTEGER NOT NULL,
                max_ttl INTEGER NOT NULL,
                parent_id TEXT,
                num_uses INTEGER DEFAULT 0,
                metadata JSONB,
                revoked BOOLEAN DEFAULT FALSE,
                revoked_at TIMESTAMP
            )
        "#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    pub async fn insert_token(&self, t: &Token) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let policies_json = serde_json::to_value(&t.policies)?;
        let metadata_json = serde_json::to_value(&t.metadata)?;
        client
            .execute(
                r#"
            INSERT INTO tokens (id, token, token_type, policies, entity_id, display_name, created_at, expires_at, renewed_at, renew_count, max_renewals, ttl, max_ttl, parent_id, num_uses, metadata, revoked, revoked_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
        "#,
                &[
                    &t.id.to_string(),
                    &t.accessor,
                    &serde_json::to_string(&t.token_type)?,
                    &policies_json,
                    &t.entity_id.map(|id| id.to_string()),
                    &"token-display-name".to_string(), // Placeholder
                    &t.creation_time,
                    &t.expiry_time,
                    &t.last_renewal_time,
                    &0i32, // renew_count placeholder
                    &None::<i32>, // max_renewals placeholder
                    &3600i32, // ttl placeholder (1 hour)
                    &86400i32, // max_ttl placeholder (24 hours)
                    &None::<String>, // parent_id placeholder
                    &t.num_uses.map(|n| n as i32),
                    &metadata_json,
                    &(t.status == TokenStatus::Revoked),
                    &None::<DateTime<Utc>>, // revoked_at placeholder
                ],
            )
            .await.map_err(|e| CoreError::Database { message: e.to_string() })?;
        Ok(())
    }

    pub async fn update_token_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                r#"
            UPDATE tokens SET expires_at = $1 WHERE token = $2
        "#,
                &[&expires_at, &token],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    pub async fn delete_token(&self, token: &str) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute("DELETE FROM tokens WHERE token = $1", &[&token])
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    pub async fn lockout_user_tokens(&self, user: &str) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                "UPDATE tokens SET locked = TRUE WHERE username = $1",
                &[&user],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    pub async fn get_token(&self, token: &str) -> Result<Option<Token>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client.query(
            "SELECT id, token, token_type, policies, entity_id, display_name, created_at, expires_at, renewed_at, renew_count, max_renewals, ttl, max_ttl, parent_id, num_uses, metadata, revoked, revoked_at FROM tokens WHERE token = $1",
            &[&token]
        ).await.map_err(|e| CoreError::Database { message: e.to_string() })?;

        if let Some(row) = rows.first() {
            let id: String = row.get(0);
            let token_val: String = row.get(1);
            let token_type_str: String = row.get(2);
            let policies_json: serde_json::Value = row.get(3);
            let _entity_id: Option<String> = row.get(4);
            let _display_name: String = row.get(5);
            let created_at: DateTime<Utc> = row.get(6);
            let expires_at: Option<DateTime<Utc>> = row.get(7);
            let renewed_at: Option<DateTime<Utc>> = row.get(8);
            let _renew_count: i32 = row.get(9);
            let _max_renewals: Option<i32> = row.get(10);
            let _ttl: i32 = row.get(11);
            let _max_ttl: i32 = row.get(12);
            let _parent_id: Option<String> = row.get(13);
            let num_uses: i32 = row.get(14);
            let metadata_json: serde_json::Value = row.get(15);
            let revoked: bool = row.get(16);
            let _revoked_at: Option<DateTime<Utc>> = row.get(17);

            let token_type: TokenType = serde_json::from_str(&token_type_str)?;
            let policies: Vec<String> = serde_json::from_value(policies_json)?;
            let metadata: HashMap<String, String> = serde_json::from_value(metadata_json)?;

            Ok(Some(Token {
                id: Uuid::parse_str(&id).map_err(|_| CoreError::Database {
                    message: "Invalid UUID".to_string(),
                })?,
                accessor: token_val.clone(),
                entity_id: None, // Not stored in this schema
                token_type,
                policies,
                metadata,
                creation_time: created_at,
                expiry_time: expires_at,
                last_renewal_time: renewed_at,
                status: if revoked {
                    TokenStatus::Revoked
                } else {
                    TokenStatus::Active
                },
                renewable: true,        // Default assumption
                explicit_max_ttl: None, // Not stored
                num_uses: Some(num_uses as u32),
                remaining_uses: None, // Not tracked in this schema
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn cleanup_expired_tokens(&self) -> Result<u64, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let res = client
            .execute(
                "DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at < NOW()",
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(res)
    }

    pub async fn migrate_plugin_catalog(&self) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS plugin_catalog (
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                checksum TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                pinned BOOLEAN,
                metadata JSONB,
                PRIMARY KEY (name, version)
            )
        "#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    pub async fn insert_plugin(&self, p: &PluginCatalogEntry) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                r#"
            INSERT INTO plugin_catalog (name, version, checksum, artifact_path, pinned, metadata)
            VALUES ($1, $2, $3, $4, $5, $6)
        "#,
                &[
                    &p.name,
                    &p.version,
                    &p.checksum,
                    &p.artifact_path,
                    &p.pinned,
                    &p.metadata,
                ],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    pub async fn pin_plugin(
        &self,
        name: &str,
        version: &str,
        pinned: bool,
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                "UPDATE plugin_catalog SET pinned = $1 WHERE name = $2 AND version = $3",
                &[&pinned, &name, &version],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    pub async fn list_plugin_catalog(&self) -> Result<Vec<PluginCatalogEntry>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client.query(
            "SELECT name, version, checksum, artifact_path, pinned, metadata FROM plugin_catalog",
            &[],
        ).await.map_err(|e| CoreError::Database { message: e.to_string() })?;

        Ok(rows
            .iter()
            .map(|row| PluginCatalogEntry {
                name: row.get("name"),
                version: row.get("version"),
                checksum: row.get("checksum"),
                artifact_path: row.get("artifact_path"),
                pinned: row.get("pinned"),
                metadata: row.get("metadata"),
            })
            .collect())
    }

    pub async fn store_secret_versioned(
        &self,
        path: &str,
        data: &serde_json::Value,
    ) -> Result<u32, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client
            .query("SELECT MAX(version) FROM secrets WHERE path = $1", &[&path])
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        let version = if let Some(row) = rows.first() {
            let max_version: Option<i64> = row.get(0);
            max_version.unwrap_or(0) + 1
        } else {
            1
        };
        client
            .execute(
                "INSERT INTO secrets (path, version, data) VALUES ($1, $2, $3)",
                &[&path, &(version as i32), &data],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(version as u32)
    }

    pub async fn get_secret_versions(
        &self,
        path: &str,
    ) -> Result<Vec<(u32, serde_json::Value)>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client
            .query(
                "SELECT version, data FROM secrets WHERE path = $1 ORDER BY version DESC",
                &[&path],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        let mut result = Vec::new();
        for row in rows {
            let version: i64 = row.get(0);
            let data: serde_json::Value = row.get(1);
            result.push((version as u32, data));
        }
        Ok(result)
    }

    pub async fn backup_data(&self) -> Result<serde_json::Value, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client
            .query("SELECT path, version, data FROM secrets", &[])
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        let secrets_json: Vec<_> = rows.iter().map(|row| serde_json::json!({"path": row.get::<_, String>("path"), "version": row.get::<_, i64>("version"), "data": row.get::<_, serde_json::Value>("data")})).collect();
        Ok(serde_json::json!({"secrets": secrets_json}))
    }

    pub async fn restore_data(&self, backup: &serde_json::Value) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        if let Some(secrets) = backup.get("secrets").and_then(|v| v.as_array()) {
            for s in secrets {
                let path = s.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let version = s.get("version").and_then(|v| v.as_i64()).unwrap_or(1);
                let default_data = serde_json::json!({});
                let data = s.get("data").unwrap_or(&default_data);
                client.execute("INSERT INTO secrets (path, version, data) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", &[&path, &version, &data]).await.map_err(|e| CoreError::Database { message: e.to_string() })?;
            }
        }
        Ok(())
    }

    pub async fn migrate_sentinel_policy_versions(&self) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS sentinel_policies (
                id SERIAL PRIMARY KEY,
                namespace TEXT NOT NULL,
                name TEXT NOT NULL,
                version INTEGER NOT NULL,
                policy_type TEXT NOT NULL,
                source_code TEXT NOT NULL,
                egp BOOLEAN,
                rgp BOOLEAN,
                created_at TIMESTAMP NOT NULL
            )
        "#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    pub async fn insert_sentinel_policy_version(
        &self,
        p: &crate::models::sentinel::SentinelPolicy,
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client.execute(r#"
            INSERT INTO sentinel_policies (namespace, name, version, policy_type, source_code, egp, rgp, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#, &[&p.namespace, &p.name, &(p.version as i32), &p.policy_type, &p.source_code, &p.egp, &p.rgp, &p.created_at]).await.map_err(|e| CoreError::Database { message: e.to_string() })?;
        Ok(())
    }

    pub async fn list_sentinel_policy_versions(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<crate::models::sentinel::SentinelPolicy>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client.query(
            "SELECT id, namespace, name, version, policy_type, source_code, egp, rgp, created_at FROM sentinel_policies WHERE namespace = $1 AND name = $2 ORDER BY version DESC",
            &[&namespace, &name],
        ).await.map_err(|e| CoreError::Database { message: e.to_string() })?;

        Ok(rows
            .iter()
            .map(|row| crate::models::sentinel::SentinelPolicy {
                id: row.get("id"),
                namespace: row.get("namespace"),
                name: row.get("name"),
                version: row.get::<_, i32>("version") as u32,
                policy_type: row.get("policy_type"),
                source_code: row.get("source_code"),
                egp: row.get("egp"),
                rgp: row.get("rgp"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    pub async fn delete_sentinel_policy_version(
        &self,
        namespace: &str,
        name: &str,
        version: u32,
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                "DELETE FROM sentinel_policies WHERE namespace = $1 AND name = $2 AND version = $3",
                &[&namespace, &name, &(version as i32)],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }
    pub async fn delete_secret(&self, path: &str, namespace: &str) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                "DELETE FROM secrets WHERE path = $1 AND namespace = $2",
                &[&path, &namespace],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for PostgresStorage {
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn store_mfa_secret(
        &self,
        user_id: &str,
        secret: &str,
        method: MfaMethod,
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let method_str = match method {
            MfaMethod::Totp => "totp",
            MfaMethod::Sms => "sms",
            MfaMethod::Push => "push",
            MfaMethod::Hardware => "hardware",
            MfaMethod::WebAuthn => "webauthn",
            MfaMethod::Email => "email",
            MfaMethod::Recovery => "recovery",
        };

        client
            .execute(
                r#"
            INSERT INTO mfa_secrets (user_id, method, secret)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, method) 
            DO UPDATE SET secret = $3, updated_at = NOW()
            "#,
                &[&user_id, &method_str, &secret],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    async fn get_mfa_secret(&self, user_id: &str, method: MfaMethod) -> Result<String, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let method_str = match method {
            MfaMethod::Totp => "totp",
            MfaMethod::Sms => "sms",
            MfaMethod::Push => "push",
            MfaMethod::Hardware => "hardware",
            MfaMethod::WebAuthn => "webauthn",
            MfaMethod::Email => "email",
            MfaMethod::Recovery => "recovery",
        };

        let rows = client
            .query(
                "SELECT secret FROM mfa_secrets WHERE user_id = $1 AND method = $2",
                &[&user_id, &method_str],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        rows.first()
            .map(|r| r.get::<_, String>("secret"))
            .ok_or_else(|| CoreError::Database {
                message: "MFA secret not found".to_string(),
            })
    }

    async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client
            .query(
                "SELECT is_enabled FROM user_mfa_settings WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        Ok(rows
            .first()
            .map(|r| r.get::<_, bool>("is_enabled"))
            .unwrap_or(false))
    }

    async fn enable_mfa(&self, user_id: &str, method: MfaMethod) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let method_str = match method {
            MfaMethod::Totp => "totp",
            MfaMethod::Sms => "sms",
            MfaMethod::Push => "push",
            MfaMethod::Hardware => "hardware",
            MfaMethod::WebAuthn => "webauthn",
            MfaMethod::Email => "email",
            MfaMethod::Recovery => "recovery",
        };

        client
            .execute(
                r#"
            INSERT INTO user_mfa_settings (user_id, is_enabled, method)
            VALUES ($1, TRUE, $2)
            ON CONFLICT (user_id) 
            DO UPDATE SET is_enabled = TRUE, method = $2, updated_at = NOW()
            "#,
                &[&user_id, &method_str],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        Ok(())
    }

    async fn disable_mfa(&self, user_id: &str) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                r#"
            UPDATE user_mfa_settings 
            SET is_enabled = FALSE, updated_at = NOW()
            WHERE user_id = $1
            "#,
                &[&user_id],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        Ok(())
    }

    async fn delete_mfa_secret(&self, user_id: &str, method: MfaMethod) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let method_str = match method {
            MfaMethod::Totp => "totp",
            MfaMethod::Sms => "sms",
            MfaMethod::Push => "push",
            MfaMethod::Hardware => "hardware",
            MfaMethod::WebAuthn => "webauthn",
            MfaMethod::Email => "email",
            MfaMethod::Recovery => "recovery",
        };

        client
            .execute(
                r#"
            DELETE FROM mfa_secrets 
            WHERE user_id = $1 AND method = $2
            "#,
                &[&user_id, &method_str],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        Ok(())
    }

    async fn get_user_mfa_methods(&self, user_id: &str) -> Result<Vec<MfaMethod>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client
            .query(
                "SELECT method FROM user_mfa_settings WHERE user_id = $1 AND is_enabled = TRUE",
                &[&user_id],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        let methods = rows
            .into_iter()
            .filter_map(|r| r.get::<_, String>("method").parse().ok())
            .collect();

        Ok(methods)
    }

    async fn get_mfa_status(
        &self,
        user_id: &str,
    ) -> Result<std::collections::HashMap<MfaMethod, bool>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client
            .query(
                "SELECT method, is_enabled FROM user_mfa_settings WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        let mut status = std::collections::HashMap::new();
        for row in rows {
            let method_str: String = row.get("method");
            let is_enabled: bool = row.get("is_enabled");
            if let Ok(method) = method_str.parse() {
                status.insert(method, is_enabled);
            }
        }

        // Check all possible methods and set to false if not present
        for method in [
            MfaMethod::Totp,
            MfaMethod::WebAuthn,
            MfaMethod::Email,
            MfaMethod::Recovery,
        ] {
            status.entry(method).or_insert(false);
        }

        Ok(status)
    }

    async fn store_mfa_recovery_codes(
        &self,
        user_id: &str,
        codes: &[String],
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        // Delete existing codes
        client
            .execute(
                r#"
            DELETE FROM mfa_recovery_codes 
            WHERE user_id = $1
            "#,
                &[&user_id],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        // Insert new codes
        for code in codes {
            client
                .execute(
                    r#"
                INSERT INTO mfa_recovery_codes (user_id, code, is_used)
                VALUES ($1, $2, FALSE)
                "#,
                    &[&user_id, code],
                )
                .await
                .map_err(|e| CoreError::Database {
                    message: e.to_string(),
                })?;
        }

        Ok(())
    }

    async fn get_mfa_recovery_codes(&self, user_id: &str) -> Result<Vec<String>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client
            .query(
                "SELECT code FROM mfa_recovery_codes WHERE user_id = $1 AND is_used = FALSE",
                &[&user_id],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        let codes = rows
            .into_iter()
            .map(|r| r.get::<_, String>("code"))
            .collect();
        Ok(codes)
    }

    async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        // Get the latest version
        let row = client
            .query_opt(
                "SELECT COALESCE(MAX(version), 0) as max_version FROM secrets WHERE path = $1",
                &[&path],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        let version: i32 = row.map_or(0, |r| r.get("max_version"));
        let new_version = version + 1;

        let data_str = serde_json::to_string(data)?;
        client
            .execute(
                "INSERT INTO secrets (path, version, data) VALUES ($1, $2, $3)",
                &[&path, &new_version, &data_str],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        Ok(new_version as u32)
    }
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        let row = client
            .query_opt(
                "SELECT data, version FROM secrets WHERE path = $1 ORDER BY version DESC LIMIT 1",
                &[&path],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        if let Some(row) = row {
            let data: String = row.get("data");
            let version: i32 = row.get("version");
            let value: Value = serde_json::from_str(&data)?;
            Ok(Some((value, version as u32)))
        } else {
            Ok(None)
        }
    }
    async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, Value)>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        let rows = client
            .query(
                "SELECT version, data FROM secrets WHERE path = $1 ORDER BY version DESC",
                &[&path],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        let mut result = Vec::new();
        for row in rows {
            let version: i32 = row.get("version");
            let data: String = row.get("data");
            let value: Value = serde_json::from_str(&data)?;
            result.push((version as u32, value));
        }
        Ok(result)
    }
    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        let rows_affected = client
            .execute(
                "DELETE FROM secrets WHERE path = $1 AND version = $2",
                &[&path, &(version as i32)],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        if rows_affected == 0 {
            return Err(CoreError::NotFound {
                resource: format!("secret version {} for path {}", version, path),
            });
        }

        Ok(())
    }
    async fn create_user(&self, username: &str, password: &str) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let hash = legacy_storage::Storage::hash_password(password)?;
        client
            .execute(
                "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
                &[&username, &hash],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client
            .query(
                "SELECT password_hash FROM users WHERE username = $1",
                &[&username],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        if let Some(row) = rows.first() {
            let hash: String = row.get("password_hash");
            Ok(legacy_storage::Storage::verify_password(&hash, password)?)
        } else {
            Ok(false)
        }
    }
    async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        // Ensure tables exist
        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS roles (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL
            )"#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS user_roles (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                UNIQUE(user_id, role_id)
            )"#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        // Insert role if not exists
        client
            .execute(
                "INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
                &[&role],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        // Get user_id and role_id
        let user_row = client
            .query_one("SELECT id FROM users WHERE username = $1", &[&username])
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        let user_id: i32 = user_row.get("id");

        let role_row = client
            .query_one("SELECT id FROM roles WHERE name = $1", &[&role])
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        let role_id: i32 = role_row.get("id");

        // Insert into user_roles
        client.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING", &[&user_id, &role_id])
            .await.map_err(|e| CoreError::Database { message: e.to_string() })?;
        Ok(())
    }
    async fn add_policy_to_role(
        &self,
        role: &str,
        path: &str,
        action: &str,
        effect: &str,
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        // Ensure policies table exists
        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS policies (
                id UUID PRIMARY KEY,
                name TEXT NOT NULL,
                policy_type TEXT NOT NULL,
                effect TEXT NOT NULL,
                rules JSONB NOT NULL,
                metadata JSONB,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE
            )"#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        client
            .execute(
                "INSERT INTO policies (role, path, action, effect) VALUES ($1, $2, $3, $4)",
                &[&role, &path, &action, &effect],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }
    async fn check_policy(
        &self,
        username: &str,
        path: &str,
        action: &str,
    ) -> Result<bool, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let row = client
            .query_one(
                r#"
            SELECT COUNT(*) as count FROM user_roles ur
            JOIN users u ON ur.user_id = u.id
            JOIN roles r ON ur.role_id = r.id
            JOIN policies p ON p.role = r.name
            WHERE u.username = $1 AND p.path = $2 AND p.action = $3 AND p.effect = 'allow'
            "#,
                &[&username, &path, &action],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        let count: i64 = row.get("count");
        Ok(count > 0)
    }
    async fn insert_token(
        &self,
        user: &str,
        token: &str,
        expires_at: Option<&str>,
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS tokens (
                id SERIAL PRIMARY KEY,
                user TEXT NOT NULL,
                token TEXT NOT NULL,
                expires_at TIMESTAMPTZ
            )"#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        client
            .execute(
                "INSERT INTO tokens (user, token, expires_at) VALUES ($1, $2, $3)",
                &[&user, &token, &expires_at],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }
    async fn is_token_valid(&self, token: &str) -> Result<bool, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let row = client
            .query_opt("SELECT expires_at FROM tokens WHERE token = $1", &[&token])
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        if let Some(row) = row {
            let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("expires_at").ok();
            if let Some(exp) = expires_at {
                Ok(exp > chrono::Utc::now())
            } else {
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }
    async fn revoke_token(&self, token: &str) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute("DELETE FROM tokens WHERE token = $1", &[&token])
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }
    async fn log_audit(
        &self,
        user: &str,
        action: &str,
        path: &str,
        status: &str,
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                "INSERT INTO audit_logs (user, action, path, status) VALUES ($1, $2, $3, $4)",
                &[&user, &action, &path, &status],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }
    async fn get_policies_for_user(
        &self,
        _user_id: &str,
        _entity_alias: Option<&str>,
    ) -> Result<Vec<Policy>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let mut policies = Vec::new();

        // Get policies based on user_id (via role)
        let rows = client
            .query(
                r#"
            SELECT id, name, policy_type, effect, rules, metadata, created_at, updated_at, enabled
            FROM policies
            WHERE enabled = true
            "#,
                &[],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        for row in rows {
            let id: uuid::Uuid = row.get("id");
            let name: String = row.get("name");
            let policy_type_str: String = row.get("policy_type");
            let effect_str: String = row.get("effect");
            let rules_json: serde_json::Value = row.get("rules");
            let metadata_json: Option<serde_json::Value> = row.get("metadata");
            let created_at: DateTime<Utc> = row.get("created_at");
            let updated_at: DateTime<Utc> = row.get("updated_at");
            let enabled: bool = row.get("enabled");

            let policy_type: PolicyType =
                serde_json::from_str(&format!("\"{}\"", policy_type_str))?;
            let effect: PolicyEffect = serde_json::from_str(&format!("\"{}\"", effect_str))?;
            let rules: Vec<PolicyRule> = serde_json::from_value(rules_json)?;
            let metadata: HashMap<String, String> = metadata_json
                .map(serde_json::from_value)
                .transpose()?
                .unwrap_or_default();

            policies.push(Policy {
                id,
                name,
                policy_type,
                effect,
                rules,
                metadata,
                created_at,
                updated_at,
                enabled,
            });
        }

        // Note: entity_alias filtering removed as it's not part of the new Policy struct
        Ok(policies)
    }
    async fn insert_sentinel_policy_version(
        &self,
        p: &crate::models::sentinel::SentinelPolicy,
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client.execute(r#"
            INSERT INTO sentinel_policies (namespace, name, version, policy_type, source_code, egp, rgp, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#, &[&p.namespace, &p.name, &(p.version as i32), &p.policy_type, &p.source_code, &p.egp, &p.rgp, &p.created_at])
        .await.map_err(|e| CoreError::Database { message: e.to_string() })?;
        Ok(())
    }
    async fn list_sentinel_policy_versions(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<crate::models::sentinel::SentinelPolicy>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        let rows = client.query(
            "SELECT id, namespace, name, version, policy_type, source_code, egp, rgp, created_at FROM sentinel_policies WHERE namespace = $1 AND name = $2 ORDER BY version DESC",
            &[&namespace, &name]
        )
        .await.map_err(|e| CoreError::Database { message: e.to_string() })?;

        Ok(rows
            .into_iter()
            .map(|row| crate::models::sentinel::SentinelPolicy {
                id: row.get("id"),
                namespace: row.get("namespace"),
                name: row.get("name"),
                version: row.get::<_, i32>("version") as u32,
                policy_type: row.get("policy_type"),
                source_code: row.get("source_code"),
                egp: row.get("egp"),
                rgp: row.get("rgp"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    async fn delete_sentinel_policy_version(
        &self,
        namespace: &str,
        name: &str,
        version: u32,
    ) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                "DELETE FROM sentinel_policies WHERE namespace = $1 AND name = $2 AND version = $3",
                &[&namespace, &name, &(version as i32)],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    async fn delete_secret(&self, path: &str, namespace: &str) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;
        client
            .execute(
                "DELETE FROM secrets WHERE path = $1 AND namespace = $2",
                &[&path, &namespace],
            )
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<secreton_auth::UserInfo>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        let query = r#"
            SELECT u.id, u.username, u.created_at, array_agg(r.name) as roles
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            GROUP BY u.id, u.username, u.created_at
        "#;

        let rows = client
            .query(query, &[])
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        let mut users = Vec::new();
        for row in rows {
            let id: i32 = row.get("id");
            let username: String = row.get("username");
            let roles: Option<Vec<String>> = row.get("roles");

            let user = secreton_auth::UserInfo {
                id: Some(id.to_string()),
                username,
                email: None,
                display_name: None,
                roles: roles.unwrap_or_default(),
                permissions: vec![],
                metadata: std::collections::HashMap::new(),
                last_login: None,
            };
            users.push(user);
        }
        Ok(users)
    }

    async fn get_user_details(
        &self,
        username: &str,
    ) -> Result<Option<secreton_auth::UserInfo>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::Database {
            message: e.to_string(),
        })?;

        let query = r#"
            SELECT u.id, u.username, u.created_at, array_agg(r.name) as roles
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE u.username = $1
            GROUP BY u.id, u.username, u.created_at
        "#;

        let rows = client
            .query(query, &[&username])
            .await
            .map_err(|e| CoreError::Database {
                message: e.to_string(),
            })?;

        if let Some(row) = rows.first() {
            let id: i32 = row.get("id");
            let username: String = row.get("username");
            let roles: Option<Vec<String>> = row.get("roles");

            Ok(Some(secreton_auth::UserInfo {
                id: Some(id.to_string()),
                username,
                email: None,
                display_name: None,
                roles: roles.unwrap_or_default(),
                permissions: vec![],
                metadata: std::collections::HashMap::new(),
                last_login: None,
            }))
        } else {
            Ok(None)
        }
    }
}

// Re-export for backward compatibility
