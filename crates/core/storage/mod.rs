use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::any::Any;
use std::collections::HashMap;
use tracing::info;

use argon2::password_hash::{rand_core::OsRng, PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};

use crate::error::CoreError;
use crate::models::lease::Lease;
use crate::models::pki::{PkiCa, PkiCert};
use crate::models::plugin::PluginCatalogEntry;
use crate::models::policy::Policy;
use crate::models::sentinel::SentinelPolicy;
use crate::models::user::Token;
use crate::services::audit::AuditDevice;

// Re-export storage types
pub mod mfa;
pub mod secure;

pub use mfa::{MfaRecoveryCodes, MfaSecret, MfaStorage};
pub use secure::{SecureStorage, SharedSecureStorage};

// Core storage types needed by engines
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

// Storage engine trait for simple key-value operations
#[async_trait]
pub trait StorageEngine: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, CoreError>;
    async fn put(&self, entry: StorageEntry) -> Result<(), CoreError>;
    async fn delete(&self, key: &str) -> Result<(), CoreError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, CoreError>;
}

// Type alias for backward compatibility
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
        method: crate::auth::mfa::MfaMethod,
    ) -> Result<()>;
    async fn get_mfa_secret(
        &self,
        user_id: &str,
        method: crate::auth::mfa::MfaMethod,
    ) -> Result<String>;
    async fn delete_mfa_secret(
        &self,
        user_id: &str,
        method: crate::auth::mfa::MfaMethod,
    ) -> Result<()>;
    async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool>;
    async fn get_user_mfa_methods(&self, user_id: &str)
        -> Result<Vec<crate::auth::mfa::MfaMethod>>;
    async fn get_mfa_status(
        &self,
        user_id: &str,
    ) -> Result<std::collections::HashMap<crate::auth::mfa::MfaMethod, bool>>;
    async fn enable_mfa(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<()>;
    async fn disable_mfa(&self, user_id: &str) -> Result<()>;
    async fn store_mfa_recovery_codes(&self, user_id: &str, codes: &[String]) -> Result<()>;
    async fn get_mfa_recovery_codes(&self, user_id: &str) -> Result<Vec<String>>;
    async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32>;
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>>;
    async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, Value)>>;
    async fn create_user(&self, username: &str, password: &str) -> Result<()>;
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool>;
    async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<()>;
    async fn add_policy_to_role(
        &self,
        role: &str,
        path: &str,
        action: &str,
        effect: &str,
    ) -> Result<()>;
    async fn check_policy(&self, username: &str, path: &str, action: &str) -> Result<bool>;
    async fn insert_token(&self, user: &str, token: &str, expires_at: Option<&str>) -> Result<()>;
    async fn is_token_valid(&self, token: &str) -> Result<bool>;
    async fn revoke_token(&self, token: &str) -> Result<()>;
    async fn log_audit(&self, user: &str, action: &str, path: &str, status: &str) -> Result<()>;
    async fn get_policies_for_user(
        &self,
        user_id: &str,
        entity_alias: Option<&str>,
    ) -> Result<Vec<Policy>>;
    async fn insert_sentinel_policy_version(
        &self,
        p: &crate::models::sentinel::SentinelPolicy,
    ) -> Result<()>;
    async fn list_sentinel_policy_versions(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<crate::models::sentinel::SentinelPolicy>>;
    async fn delete_sentinel_policy_version(
        &self,
        namespace: &str,
        name: &str,
        version: u32,
    ) -> Result<()>;
    async fn delete_secret(&self, path: &str, namespace: &str) -> Result<()>;
}

pub enum StorageType {
    Sqlite(Storage),
    // Postgres(PostgresStorage),
}

pub struct PostgresStorage {
    pool: Pool,
}

impl PostgresStorage {
    pub async fn new(pool: Pool) -> Result<Self> {
        Self::create_tables(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn from_url(database_url: &str) -> Result<Self> {
        use deadpool_postgres::{Config, ManagerConfig, RecyclingMethod, Runtime};
        use tokio_postgres::{Config as PgConfig, NoTls};

        let _pg_config = database_url.parse::<PgConfig>()?;
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let config = Config {
            manager: Some(mgr_config),
            ..Default::default()
        };

        let pool = config.create_pool(Some(Runtime::Tokio1), NoTls)?;
        Self::new(pool).await
    }
    async fn create_tables(pool: &Pool) -> Result<()> {
        let client = pool.get().await?;

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
            .await?;

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
            .await?;

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
            .await?;

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
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS vault_state (
                id SERIAL PRIMARY KEY,
                sealed BOOLEAN NOT NULL DEFAULT TRUE,
                master_key TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
            "#,
                &[],
            )
            .await?;

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
            .await?;

        Ok(())
    }

    pub async fn migrate_tokens(&self) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at TIMESTAMP,
                orphan BOOLEAN,
                batch BOOLEAN,
                locked BOOLEAN,
                created_at TIMESTAMP NOT NULL
            )
        "#,
                &[],
            )
            .await?;
        Ok(())
    }

    pub async fn insert_token(&self, t: &Token) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"
            INSERT INTO tokens (token, username, expires_at, orphan, batch, locked, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
                &[
                    &t.token,
                    &t.user,
                    &t.expires_at,
                    &t.orphan,
                    &t.batch,
                    &t.locked,
                    &t.created_at,
                ],
            )
            .await?;
        Ok(())
    }

    pub async fn update_token_expiry(&self, token: &str, expires_at: DateTime<Utc>) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"
            UPDATE tokens SET expires_at = $1 WHERE token = $2
        "#,
                &[&expires_at, &token],
            )
            .await?;
        Ok(())
    }

    pub async fn delete_token(&self, token: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute("DELETE FROM tokens WHERE token = $1", &[&token])
            .await?;
        Ok(())
    }

    pub async fn lockout_user_tokens(&self, user: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE tokens SET locked = TRUE WHERE username = $1",
                &[&user],
            )
            .await?;
        Ok(())
    }

    pub async fn get_token(&self, token: &str) -> Result<Option<Token>> {
        let client = self.pool.get().await?;
        let rows = client.query(
            "SELECT token, username, expires_at, orphan, batch, locked, created_at FROM tokens WHERE token = $1",
            &[&token]
        ).await?;

        if let Some(row) = rows.first() {
            let token_val: String = row.get(0);
            let user: String = row.get(1);
            let expires_at: Option<DateTime<Utc>> = row.get(2);
            let orphan: bool = row.get(3);
            let batch: bool = row.get(4);
            let locked: bool = row.get(5);
            let created_at: DateTime<Utc> = row.get(6);

            Ok(Some(Token {
                token: token_val,
                user,
                expires_at,
                orphan,
                batch,
                locked,
                created_at,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn cleanup_expired_tokens(&self) -> Result<u64> {
        let client = self.pool.get().await?;
        let res = client
            .execute(
                "DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at < NOW()",
                &[],
            )
            .await?;
        Ok(res)
    }

    pub async fn migrate_plugin_catalog(&self) -> Result<()> {
        let client = self.pool.get().await?;
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
            .await?;
        Ok(())
    }

    pub async fn insert_plugin(&self, p: &PluginCatalogEntry) -> Result<()> {
        let client = self.pool.get().await?;
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
            .await?;
        Ok(())
    }

    pub async fn pin_plugin(&self, name: &str, version: &str, pinned: bool) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE plugin_catalog SET pinned = $1 WHERE name = $2 AND version = $3",
                &[&pinned, &name, &version],
            )
            .await?;
        Ok(())
    }

    pub async fn list_plugin_catalog(&self) -> Result<Vec<PluginCatalogEntry>> {
        let client = self.pool.get().await?;
        let rows = client.query(
            "SELECT name, version, checksum, artifact_path, pinned, metadata FROM plugin_catalog",
            &[],
        ).await?;

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
    ) -> Result<u32> {
        let client = self.pool.get().await?;
        let rows = client
            .query("SELECT MAX(version) FROM secrets WHERE path = $1", &[&path])
            .await?;
        let version = if let Some(row) = rows.first() {
            let max_version: Option<i64> = row.get(0);
            max_version.unwrap_or(0) + 1
        } else {
            1
        };
        client
            .execute(
                "INSERT INTO secrets (path, version, data) VALUES ($1, $2, $3)",
                &[&path, &(version as i64), &data],
            )
            .await?;
        Ok(version as u32)
    }

    pub async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, serde_json::Value)>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT version, data FROM secrets WHERE path = $1 ORDER BY version DESC",
                &[&path],
            )
            .await?;
        let mut result = Vec::new();
        for row in rows {
            let version: i64 = row.get(0);
            let data: serde_json::Value = row.get(1);
            result.push((version as u32, data));
        }
        Ok(result)
    }

    pub async fn backup_data(&self) -> Result<serde_json::Value> {
        let client = self.pool.get().await?;
        let rows = client
            .query("SELECT path, version, data FROM secrets", &[])
            .await?;

        let secrets_json: Vec<_> = rows.iter().map(|row| serde_json::json!({"path": row.get::<_, String>("path"), "version": row.get::<_, i64>("version"), "data": row.get::<_, serde_json::Value>("data")})).collect();
        Ok(serde_json::json!({"secrets": secrets_json}))
    }

    pub async fn restore_data(&self, backup: &serde_json::Value) -> Result<()> {
        let client = self.pool.get().await?;
        if let Some(secrets) = backup.get("secrets").and_then(|v| v.as_array()) {
            for s in secrets {
                let path = s.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let version = s.get("version").and_then(|v| v.as_i64()).unwrap_or(1);
                let default_data = serde_json::json!({});
                let data = s.get("data").unwrap_or(&default_data);
                client.execute("INSERT INTO secrets (path, version, data) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", &[&path, &version, &data]).await?;
            }
        }
        Ok(())
    }

    pub async fn migrate_sentinel_policy_versions(&self) -> Result<()> {
        let client = self.pool.get().await?;
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
            .await?;
        Ok(())
    }

    pub async fn insert_sentinel_policy_version(
        &self,
        p: &crate::models::sentinel::SentinelPolicy,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client.execute(r#"
            INSERT INTO sentinel_policies (namespace, name, version, policy_type, source_code, egp, rgp, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#, &[&p.namespace, &p.name, &p.version, &p.policy_type, &p.source_code, &p.egp, &p.rgp, &p.created_at]).await?;
        Ok(())
    }

    pub async fn list_sentinel_policy_versions(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<crate::models::sentinel::SentinelPolicy>> {
        let client = self.pool.get().await?;
        let rows = client.query(
            "SELECT id, namespace, name, version, policy_type, source_code, egp, rgp, created_at FROM sentinel_policies WHERE namespace = $1 AND name = $2 ORDER BY version DESC",
            &[&namespace, &name],
        ).await?;

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
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "DELETE FROM sentinel_policies WHERE namespace = $1 AND name = $2 AND version = $3",
                &[&namespace, &name, &version],
            )
            .await?;
        Ok(())
    }
    pub async fn delete_secret(&self, path: &str, namespace: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "DELETE FROM secrets WHERE path = $1 AND namespace = $2",
                &[&path, &namespace],
            )
            .await?;
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
        method: crate::auth::mfa::MfaMethod,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
            crate::auth::mfa::MfaMethod::Recovery => "recovery",
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
            .await?;
        Ok(())
    }

    async fn get_mfa_secret(
        &self,
        user_id: &str,
        method: crate::auth::mfa::MfaMethod,
    ) -> Result<String> {
        let client = self.pool.get().await?;
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
            crate::auth::mfa::MfaMethod::Recovery => "recovery",
        };

        let rows = client
            .query(
                "SELECT secret FROM mfa_secrets WHERE user_id = $1 AND method = $2",
                &[&user_id, &method_str],
            )
            .await?;

        rows.get(0)
            .map(|r| r.get::<_, String>("secret"))
            .ok_or_else(|| anyhow::anyhow!("MFA secret not found"))
    }

    async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT is_enabled FROM user_mfa_settings WHERE user_id = $1",
                &[&user_id],
            )
            .await?;

        Ok(rows
            .get(0)
            .map(|r| r.get::<_, bool>("is_enabled"))
            .unwrap_or(false))
    }

    async fn enable_mfa(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<()> {
        let client = self.pool.get().await?;
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
            crate::auth::mfa::MfaMethod::Recovery => "recovery",
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
            .await?;

        Ok(())
    }

    async fn disable_mfa(&self, user_id: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"
            UPDATE user_mfa_settings 
            SET is_enabled = FALSE, updated_at = NOW()
            WHERE user_id = $1
            "#,
                &[&user_id],
            )
            .await?;

        Ok(())
    }

    async fn delete_mfa_secret(
        &self,
        user_id: &str,
        method: crate::auth::mfa::MfaMethod,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
            crate::auth::mfa::MfaMethod::Recovery => "recovery",
        };

        client
            .execute(
                r#"
            DELETE FROM mfa_secrets 
            WHERE user_id = $1 AND method = $2
            "#,
                &[&user_id, &method_str],
            )
            .await?;

        Ok(())
    }

    async fn get_user_mfa_methods(
        &self,
        user_id: &str,
    ) -> Result<Vec<crate::auth::mfa::MfaMethod>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT method FROM user_mfa_settings WHERE user_id = $1 AND is_enabled = TRUE",
                &[&user_id],
            )
            .await?;

        let methods = rows
            .into_iter()
            .filter_map(|r| r.get::<_, String>("method").parse().ok())
            .collect();

        Ok(methods)
    }

    async fn get_mfa_status(
        &self,
        user_id: &str,
    ) -> Result<std::collections::HashMap<crate::auth::mfa::MfaMethod, bool>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT method, is_enabled FROM user_mfa_settings WHERE user_id = $1",
                &[&user_id],
            )
            .await?;

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
            crate::auth::mfa::MfaMethod::Totp,
            crate::auth::mfa::MfaMethod::WebAuthn,
            crate::auth::mfa::MfaMethod::Email,
            crate::auth::mfa::MfaMethod::Recovery,
        ] {
            status.entry(method).or_insert(false);
        }

        Ok(status)
    }

    async fn store_mfa_recovery_codes(&self, user_id: &str, codes: &[String]) -> Result<()> {
        let client = self.pool.get().await?;

        // Delete existing codes
        client
            .execute(
                r#"
            DELETE FROM mfa_recovery_codes 
            WHERE user_id = $1
            "#,
                &[&user_id],
            )
            .await?;

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
                .await?;
        }

        Ok(())
    }

    async fn get_mfa_recovery_codes(&self, user_id: &str) -> Result<Vec<String>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT code FROM mfa_recovery_codes WHERE user_id = $1 AND is_used = FALSE",
                &[&user_id],
            )
            .await?;

        let codes = rows
            .into_iter()
            .map(|r| r.get::<_, String>("code"))
            .collect();
        Ok(codes)
    }

    async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32> {
        let client = self.pool.get().await?;

        // Get the latest version
        let row = client
            .query_opt(
                "SELECT COALESCE(MAX(version), 0) as max_version FROM secrets WHERE path = $1",
                &[&path],
            )
            .await?;

        let version: i32 = row.map_or(0, |r| r.get("max_version"));
        let new_version = version + 1;

        let data_str = serde_json::to_string(data)?;
        client
            .execute(
                "INSERT INTO secrets (path, version, data) VALUES ($1, $2, $3)",
                &[&path, &new_version, &data_str],
            )
            .await?;

        Ok(new_version as u32)
    }
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>> {
        let client = self.pool.get().await?;

        let row = client
            .query_opt(
                "SELECT data, version FROM secrets WHERE path = $1 ORDER BY version DESC LIMIT 1",
                &[&path],
            )
            .await?;

        if let Some(row) = row {
            let data: String = row.get("data");
            let version: i32 = row.get("version");
            let value: Value = serde_json::from_str(&data)?;
            Ok(Some((value, version as u32)))
        } else {
            Ok(None)
        }
    }
    async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, Value)>> {
        let client = self.pool.get().await?;

        let rows = client
            .query(
                "SELECT version, data FROM secrets WHERE path = $1 ORDER BY version DESC",
                &[&path],
            )
            .await?;

        let mut result = Vec::new();
        for row in rows {
            let version: i32 = row.get("version");
            let data: String = row.get("data");
            let value: Value = serde_json::from_str(&data)?;
            result.push((version as u32, value));
        }
        Ok(result)
    }
    async fn create_user(&self, username: &str, password: &str) -> Result<()> {
        let client = self.pool.get().await?;
        let hash = Storage::hash_password(password)?;
        client
            .execute(
                "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
                &[&username, &hash],
            )
            .await?;
        Ok(())
    }
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT password_hash FROM users WHERE username = $1",
                &[&username],
            )
            .await?;

        if let Some(row) = rows.get(0) {
            let hash: String = row.get("password_hash");
            Ok(Storage::verify_password(&hash, password)?)
        } else {
            Ok(false)
        }
    }
    async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<()> {
        let client = self.pool.get().await?;

        // Ensure tables exist
        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS roles (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL
            )"#,
                &[],
            )
            .await?;

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
            .await?;

        // Insert role if not exists
        client
            .execute(
                "INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
                &[&role],
            )
            .await?;

        // Get user_id and role_id
        let user_row = client
            .query_one("SELECT id FROM users WHERE username = $1", &[&username])
            .await?;
        let user_id: i32 = user_row.get("id");

        let role_row = client
            .query_one("SELECT id FROM roles WHERE name = $1", &[&role])
            .await?;
        let role_id: i32 = role_row.get("id");

        // Insert into user_roles
        client.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING", &[&user_id, &role_id])
            .await?;
        Ok(())
    }
    async fn add_policy_to_role(
        &self,
        role: &str,
        path: &str,
        action: &str,
        effect: &str,
    ) -> Result<()> {
        let client = self.pool.get().await?;

        // Ensure policies table exists
        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS policies (
                id SERIAL PRIMARY KEY,
                role TEXT NOT NULL,
                path TEXT NOT NULL,
                action TEXT NOT NULL,
                effect TEXT NOT NULL,
                entity_alias TEXT
            )"#,
                &[],
            )
            .await?;

        client
            .execute(
                "INSERT INTO policies (role, path, action, effect) VALUES ($1, $2, $3, $4)",
                &[&role, &path, &action, &effect],
            )
            .await?;
        Ok(())
    }
    async fn check_policy(&self, username: &str, path: &str, action: &str) -> Result<bool> {
        let client = self.pool.get().await?;
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
            .await?;
        let count: i64 = row.get("count");
        Ok(count > 0)
    }
    async fn insert_token(&self, user: &str, token: &str, expires_at: Option<&str>) -> Result<()> {
        let client = self.pool.get().await?;

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
            .await?;

        client
            .execute(
                "INSERT INTO tokens (user, token, expires_at) VALUES ($1, $2, $3)",
                &[&user, &token, &expires_at],
            )
            .await?;
        Ok(())
    }
    async fn is_token_valid(&self, token: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt("SELECT expires_at FROM tokens WHERE token = $1", &[&token])
            .await?;

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
    async fn revoke_token(&self, token: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute("DELETE FROM tokens WHERE token = $1", &[&token])
            .await?;
        Ok(())
    }
    async fn log_audit(&self, user: &str, action: &str, path: &str, status: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO audit_logs (user, action, path, status) VALUES ($1, $2, $3, $4)",
                &[&user, &action, &path, &status],
            )
            .await?;
        Ok(())
    }
    async fn get_policies_for_user(
        &self,
        user_id: &str,
        entity_alias: Option<&str>,
    ) -> Result<Vec<Policy>> {
        let client = self.pool.get().await?;
        let mut policies = Vec::new();

        // Get policies based on user_id (via role)
        let rows = client
            .query(
                r#"
            SELECT p.id, r.name as role, p.path, p.action, p.effect, p.entity_alias
            FROM user_roles ur
            JOIN users u ON ur.user_id = u.id
            JOIN roles r ON ur.role_id = r.id
            JOIN policies p ON p.role = r.name
            WHERE u.username = $1
            "#,
                &[&user_id],
            )
            .await?;
        for row in rows {
            policies.push(Policy {
                id: row.get("id"),
                role: row.get("role"),
                path: row.get("path"),
                action: row.get("action"),
                effect: row.get("effect"),
                entity_alias: row.get("entity_alias"),
                namespace: row
                    .get::<_, Option<String>>("namespace")
                    .unwrap_or_else(|| "default".to_string()),
            });
        }

        // If entity_alias exists, get matching policies
        if let Some(alias) = entity_alias {
            let rows = client
                .query(
                    r#"
                SELECT id, role, path, action, effect, entity_alias
                FROM policies
                WHERE entity_alias = $1
                "#,
                    &[&alias],
                )
                .await?;

            for row in rows {
                policies.push(Policy {
                    id: row.get("id"),
                    role: row.get("role"),
                    path: row.get("path"),
                    action: row.get("action"),
                    effect: row.get("effect"),
                    entity_alias: row.get("entity_alias"),
                    namespace: row
                        .get::<_, Option<String>>("namespace")
                        .unwrap_or_else(|| "default".to_string()),
                });
            }
        }
        Ok(policies)
    }
    async fn insert_sentinel_policy_version(
        &self,
        p: &crate::models::sentinel::SentinelPolicy,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client.execute(r#"
            INSERT INTO sentinel_policies (namespace, name, version, policy_type, source_code, egp, rgp, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#, &[&p.namespace, &p.name, &p.version, &p.policy_type, &p.source_code, &p.egp, &p.rgp, &p.created_at])
        .await?;
        Ok(())
    }
    async fn list_sentinel_policy_versions(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Vec<crate::models::sentinel::SentinelPolicy>> {
        let client = self.pool.get().await?;
        let rows = client.query(
            "SELECT id, namespace, name, version, policy_type, source_code, egp, rgp, created_at FROM sentinel_policies WHERE namespace = $1 AND name = $2 ORDER BY version DESC",
            &[&namespace, &name]
        )
        .await?;

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
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "DELETE FROM sentinel_policies WHERE namespace = $1 AND name = $2 AND version = $3",
                &[&namespace, &name, &version],
            )
            .await?;
        Ok(())
    }

    async fn delete_secret(&self, path: &str, namespace: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "DELETE FROM secrets WHERE path = $1 AND namespace = $2",
                &[&path, &namespace],
            )
            .await?;
        Ok(())
    }
}

impl StorageType {
    pub async fn from_config(
        backend: &str,
        url: &str,
    ) -> Result<std::sync::Arc<dyn StorageBackend>> {
        match backend {
            "sqlite" => Ok(std::sync::Arc::new(Storage::new(url).await?)),
            "postgres" => Ok(std::sync::Arc::new(PostgresStorage::from_url(url).await?)),
            _ => Err(anyhow::anyhow!("Unknown backend")),
        }
    }
}
#[async_trait]
impl StorageBackend for Storage {
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn store_mfa_secret(
        &self,
        user_id: &str,
        secret: &str,
        method: crate::auth::mfa::MfaMethod,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
            crate::auth::mfa::MfaMethod::Recovery => "recovery",
        };

        client.execute(
            "INSERT INTO mfa_secrets (user_id, method, secret, updated_at) VALUES ($1, $2, $3, CURRENT_TIMESTAMP) ON CONFLICT (user_id, method) DO UPDATE SET secret = $3, updated_at = CURRENT_TIMESTAMP",
            &[&user_id, &method_str, &secret],
        ).await?;

        Ok(())
    }

    async fn get_mfa_secret(
        &self,
        user_id: &str,
        method: crate::auth::mfa::MfaMethod,
    ) -> Result<String> {
        let client = self.pool.get().await?;
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
            crate::auth::mfa::MfaMethod::Recovery => "recovery",
        };

        let rows = client
            .query(
                "SELECT secret FROM mfa_secrets WHERE user_id = $1 AND method = $2",
                &[&user_id, &method_str],
            )
            .await?;

        rows.get(0)
            .map(|r| r.get::<_, String>("secret"))
            .ok_or_else(|| anyhow::anyhow!("MFA secret not found"))
    }

    async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT is_enabled FROM user_mfa_settings WHERE user_id = $1",
                &[&user_id],
            )
            .await?;

        Ok(rows
            .get(0)
            .map(|r| r.get::<_, bool>("is_enabled"))
            .unwrap_or(false))
    }

    async fn enable_mfa(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<()> {
        let client = self.pool.get().await?;
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
            crate::auth::mfa::MfaMethod::Recovery => "recovery",
        };

        client.execute(
            "INSERT INTO user_mfa_settings (user_id, is_enabled, method, updated_at) VALUES ($1, true, $2, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET is_enabled = true, method = $2, updated_at = CURRENT_TIMESTAMP",
            &[&user_id, &method_str],
        ).await?;

        Ok(())
    }

    async fn disable_mfa(&self, user_id: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client.execute(
            "UPDATE user_mfa_settings SET is_enabled = false, updated_at = CURRENT_TIMESTAMP WHERE user_id = $1",
            &[&user_id],
        ).await?;

        Ok(())
    }
    async fn delete_mfa_secret(
        &self,
        user_id: &str,
        method: crate::auth::mfa::MfaMethod,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
            crate::auth::mfa::MfaMethod::Recovery => "recovery",
        };
        client
            .execute(
                "DELETE FROM mfa_secrets WHERE user_id = $1 AND method = $2",
                &[&user_id, &method_str],
            )
            .await?;
        Ok(())
    }
    async fn get_user_mfa_methods(
        &self,
        user_id: &str,
    ) -> Result<Vec<crate::auth::mfa::MfaMethod>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT method FROM user_mfa_settings WHERE user_id = $1 AND is_enabled = true",
                &[&user_id],
            )
            .await?;

        let mut methods = Vec::new();
        for row in &rows {
            let m: String = row.get("method");
            let parsed = match m.as_str() {
                "totp" => Some(crate::auth::mfa::MfaMethod::Totp),
                "webauthn" => Some(crate::auth::mfa::MfaMethod::WebAuthn),
                "email" => Some(crate::auth::mfa::MfaMethod::Email),
                _ => None,
            };
            if let Some(p) = parsed {
                methods.push(p);
            }
        }
        Ok(methods)
    }
    async fn get_mfa_status(
        &self,
        user_id: &str,
    ) -> Result<std::collections::HashMap<crate::auth::mfa::MfaMethod, bool>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT method, is_enabled FROM user_mfa_settings WHERE user_id = $1",
                &[&user_id],
            )
            .await?;

        let mut status = std::collections::HashMap::new();
        for row in &rows {
            let m: String = row.get("method");
            let enabled: bool = row.get("is_enabled");
            let method = match m.as_str() {
                "totp" => Some(crate::auth::mfa::MfaMethod::Totp),
                "webauthn" => Some(crate::auth::mfa::MfaMethod::WebAuthn),
                "email" => Some(crate::auth::mfa::MfaMethod::Email),
                _ => None,
            };
            if let Some(mm) = method {
                status.insert(mm, enabled);
            }
        }

        // Ensure all methods are represented
        for method in [
            crate::auth::mfa::MfaMethod::Totp,
            crate::auth::mfa::MfaMethod::WebAuthn,
            crate::auth::mfa::MfaMethod::Email,
        ] {
            status.entry(method).or_insert(false);
        }
        Ok(status)
    }

    async fn store_mfa_recovery_codes(&self, user_id: &str, codes: &[String]) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "DELETE FROM mfa_recovery_codes WHERE user_id = $1",
                &[&user_id],
            )
            .await?;

        for c in codes {
            client.execute("INSERT INTO mfa_recovery_codes (user_id, code, is_used) VALUES ($1, $2, false)", &[&user_id, c]).await?;
        }
        Ok(())
    }
    async fn get_mfa_recovery_codes(&self, user_id: &str) -> Result<Vec<String>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT code FROM mfa_recovery_codes WHERE user_id = $1 AND is_used = false",
                &[&user_id],
            )
            .await?;

        Ok(rows.iter().map(|r| r.get::<_, String>("code")).collect())
    }
    async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32> {
        self.store_secret_versioned(path, data).await
    }
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>> {
        self.get_latest_secret(path).await
    }
    async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, Value)>> {
        self.get_secret_versions(path).await
    }
    async fn create_user(&self, username: &str, password: &str) -> Result<()> {
        self.create_user(username, password, "default").await
    }
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool> {
        self.authenticate_user(username, password).await
    }
    async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<()> {
        self.assign_role_to_user(username, role).await
    }
    async fn add_policy_to_role(
        &self,
        role: &str,
        path: &str,
        action: &str,
        effect: &str,
    ) -> Result<()> {
        self.add_policy_to_role(role, path, action, effect).await
    }
    async fn check_policy(&self, username: &str, path: &str, action: &str) -> Result<bool> {
        self.check_policy(username, path, action).await
    }
    async fn insert_token(&self, user: &str, token: &str, expires_at: Option<&str>) -> Result<()> {
        self.insert_token(user, token, expires_at).await
    }
    async fn is_token_valid(&self, token: &str) -> Result<bool> {
        self.is_token_valid(token).await
    }
    async fn revoke_token(&self, token: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE tokens SET revoked = true WHERE token = $1",
                &[&token],
            )
            .await?;
        Ok(())
    }
    async fn log_audit(&self, user: &str, action: &str, path: &str, status: &str) -> Result<()> {
        self.log_audit(user, action, path, status).await
    }
    async fn get_policies_for_user(
        &self,
        user_id: &str,
        entity_alias: Option<&str>,
    ) -> Result<Vec<Policy>> {
        let client = self.pool.get().await?;
        let mut policies = Vec::new();
        // Ambil policies berdasarkan user_id (via role)
        let rows = client
            .query(
                r#"
            SELECT p.id, r.name as role, p.path, p.action, p.effect, p.entity_alias
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            JOIN policies p ON p.role = r.name
            WHERE ur.user_id = (SELECT id FROM users WHERE username = $1)
            "#,
                &[&user_id],
            )
            .await?;
        for row in rows {
            policies.push(Policy {
                id: row.get("id"),
                role: row.get("role"),
                path: row.get("path"),
                action: row.get("action"),
                effect: row.get("effect"),
                entity_alias: row.get("entity_alias"),
                namespace: row
                    .get::<_, Option<String>>("namespace")
                    .unwrap_or_else(|| "default".to_string()),
            });
        }
        // Jika entity_alias ada, ambil policies yang entity_alias-nya cocok
        if let Some(alias) = entity_alias {
            let rows = client
                .query(
                    r#"
                SELECT id, role, path, action, effect, entity_alias
                FROM policies
                WHERE entity_alias = $1
                "#,
                    &[&alias],
                )
                .await?;

            for row in &rows {
                policies.push(Policy {
                    id: row.get("id"),
                    role: row.get("role"),
                    path: row.get("path"),
                    action: row.get("action"),
                    effect: row.get("effect"),
                    entity_alias: row.get("entity_alias"),
                    namespace: row
                        .get::<_, Option<String>>("namespace")
                        .unwrap_or_else(|| "default".to_string()),
                });
            }
        }
        Ok(policies)
    }
    async fn insert_sentinel_policy_version(
        &self,
        _p: &crate::models::sentinel::SentinelPolicy,
    ) -> Result<()> {
        // TODO: Implement SQLite version of sentinel policy storage
        Ok(())
    }
    async fn list_sentinel_policy_versions(
        &self,
        _namespace: &str,
        _name: &str,
    ) -> Result<Vec<crate::models::sentinel::SentinelPolicy>> {
        // TODO: Implement SQLite version of sentinel policy listing
        Ok(vec![])
    }
    async fn delete_sentinel_policy_version(
        &self,
        _namespace: &str,
        _name: &str,
        _version: u32,
    ) -> Result<()> {
        // TODO: Implement SQLite version of sentinel policy deletion
        Ok(())
    }
    async fn delete_secret(&self, path: &str, namespace: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "DELETE FROM secrets WHERE path = $1 AND namespace = $2",
                &[&path, &namespace],
            )
            .await?;
        Ok(())
    }
}

pub struct Storage {
    pool: Pool,
}

impl Storage {
    pub async fn new(database_url: &str) -> Result<Self> {
        use deadpool_postgres::{Config, ManagerConfig, RecyclingMethod, Runtime};
        use tokio_postgres::{Config as PgConfig, NoTls};

        let _pg_config = database_url.parse::<PgConfig>()?;
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let config = Config {
            manager: Some(mgr_config),
            ..Default::default()
        };

        let pool = config.create_pool(Some(Runtime::Tokio1), NoTls)?;

        // Create tables if they don't exist
        Self::create_tables(&pool).await?;

        Ok(Self { pool })
    }

    async fn create_tables(pool: &Pool) -> Result<()> {
        let client = pool.get().await?;

        // Create MFA tables first
        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS mfa_secrets (
                id SERIAL PRIMARY KEY,
                user_id TEXT NOT NULL,
                method TEXT NOT NULL,
                secret TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, method)
            )
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS user_mfa_settings (
                user_id TEXT PRIMARY KEY,
                is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                method TEXT,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            "#,
                &[],
            )
            .await?;

        // Create main tables
        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS secrets (
                id SERIAL PRIMARY KEY,
                path TEXT NOT NULL,
                version INTEGER NOT NULL,
                data TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(path, version)
            )
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS vault_state (
                id INTEGER PRIMARY KEY,
                sealed BOOLEAN NOT NULL DEFAULT TRUE,
                master_key TEXT,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                user_name TEXT,
                action TEXT,
                path TEXT,
                status TEXT,
                timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS roles (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL
            )
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER,
                role_id INTEGER,
                PRIMARY KEY (user_id, role_id)
            )
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS policies (
                id SERIAL PRIMARY KEY,
                role_id INTEGER,
                path TEXT NOT NULL,
                action TEXT NOT NULL,
                effect TEXT NOT NULL
            )
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS tokens (
                id SERIAL PRIMARY KEY,
                user_name TEXT NOT NULL,
                token TEXT NOT NULL,
                issued_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMPTZ,
                revoked BOOLEAN DEFAULT FALSE
            )
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS leases (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                issued_at TIMESTAMPTZ NOT NULL,
                expired_at TIMESTAMPTZ NOT NULL,
                status TEXT NOT NULL
            )"#,
                &[],
            )
            .await?;

        // Insert default user admin:admin (hashed)
        let admin_hash = Self::hash_password("admin")?;
        client
            .execute(
                r#"
            INSERT INTO users (username, password_hash) VALUES ($1, $2) 
            ON CONFLICT (username) DO NOTHING
            "#,
                &[&"admin", &admin_hash],
            )
            .await?;

        Ok(())
    }

    pub fn hash_password(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!(e))?
            .to_string();
        Ok(hash)
    }

    pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!(e))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    pub async fn create_user(&self, username: &str, password: &str, namespace: &str) -> Result<()> {
        let client = self.pool.get().await?;
        let hash = Self::hash_password(password)?;
        client.execute(
            r#"INSERT INTO users (username, password_hash, created_at, namespace) VALUES ($1, $2, $3, $4)"#,
            &[&username, &hash, &chrono::Utc::now(), &namespace]
        ).await?;
        Ok(())
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"SELECT password_hash FROM users WHERE username = $1"#,
                &[&username],
            )
            .await?;

        match row {
            Some(row) => {
                let stored_hash: String = row.get("password_hash");
                Ok(Self::verify_password(&stored_hash, password)?)
            }
            None => Ok(false),
        }
    }

    pub async fn store_secret(&self, path: &str, data: &Value) -> Result<()> {
        let client = self.pool.get().await?;
        let data_json = serde_json::to_string(data)?;

        client
            .execute(
                r#"
            INSERT INTO secrets (path, data, updated_at)
            VALUES ($1, $2, CURRENT_TIMESTAMP)
            ON CONFLICT (path) DO UPDATE SET 
                data = EXCLUDED.data,
                updated_at = EXCLUDED.updated_at
            "#,
                &[&path, &data_json],
            )
            .await?;

        info!("Stored secret at path: {}", path);
        Ok(())
    }

    pub async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32> {
        let client = self.pool.get().await?;

        // Get the latest version
        let latest_version: Option<i32> = client
            .query_opt("SELECT MAX(version) FROM secrets WHERE path = $1", &[&path])
            .await?
            .map(|row| row.get(0));

        let new_version = latest_version.unwrap_or(0) + 1;
        let data_json = serde_json::to_string(data)?;

        client
            .execute(
                r#"
            INSERT INTO secrets (path, version, data, updated_at)
            VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
            "#,
                &[&path, &new_version, &data_json],
            )
            .await?;

        Ok(new_version as u32)
    }

    pub async fn get_secret(&self, path: &str) -> Result<Option<Value>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
            SELECT data FROM secrets WHERE path = $1
            "#,
                &[&path],
            )
            .await?;

        match row {
            Some(row) => {
                let data_json: String = row.get("data");
                let data: Value = serde_json::from_str(&data_json)?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    pub async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
            SELECT data, version FROM secrets WHERE path = $1 ORDER BY version DESC LIMIT 1
            "#,
                &[&path],
            )
            .await?;

        match row {
            Some(row) => {
                let data_json: String = row.get("data");
                let version: i32 = row.get("version");
                let data: Value = serde_json::from_str(&data_json)?;
                Ok(Some((data, version as u32)))
            }
            None => Ok(None),
        }
    }

    pub async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, Value)>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                r#"
            SELECT version, data FROM secrets WHERE path = $1 ORDER BY version DESC
            "#,
                &[&path],
            )
            .await?;

        let mut versions = Vec::new();
        for row in rows {
            let version: i32 = row.get("version");
            let data_json: String = row.get("data");
            let data: Value = serde_json::from_str(&data_json)?;
            versions.push((version as u32, data));
        }
        Ok(versions)
    }

    pub async fn delete_secret(&self, path: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        let result = client
            .execute(
                r#"
            DELETE FROM secrets WHERE path = $1
            "#,
                &[&path],
            )
            .await?;

        Ok(result > 0)
    }

    pub async fn list_secrets(&self, prefix: &str) -> Result<Vec<String>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                r#"
            SELECT path FROM secrets WHERE path LIKE $1
            "#,
                &[&format!("{}%", prefix)],
            )
            .await?;

        let paths: Vec<String> = rows
            .iter()
            .map(|row| row.get::<_, String>("path"))
            .collect();

        Ok(paths)
    }

    pub async fn set_vault_state(&self, sealed: bool, master_key: Option<&str>) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"
            INSERT INTO vault_state (id, sealed, master_key)
            VALUES (1, $1, $2)
            ON CONFLICT (id) DO UPDATE SET 
                sealed = EXCLUDED.sealed,
                master_key = EXCLUDED.master_key
            "#,
                &[&sealed, &master_key],
            )
            .await?;

        Ok(())
    }

    pub async fn get_vault_state(&self) -> Result<(bool, Option<String>)> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
            SELECT sealed, master_key FROM vault_state WHERE id = 1
            "#,
                &[],
            )
            .await?;

        match row {
            Some(row) => {
                let sealed: bool = row.get("sealed");
                let master_key: Option<String> = row.get("master_key");
                Ok((sealed, master_key))
            }
            None => Ok((true, None)), // Default to sealed
        }
    }

    pub async fn log_audit(
        &self,
        user: &str,
        action: &str,
        path: &str,
        status: &str,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client.execute(
            r#"INSERT INTO audit_logs (user_name, action, path, status) VALUES ($1, $2, $3, $4)"#,
            &[&user, &action, &path, &status],
        ).await?;
        Ok(())
    }

    pub async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<()> {
        let client = self.pool.get().await?;
        let user_id: i64 = client
            .query_one("SELECT id FROM users WHERE username = $1", &[&username])
            .await?
            .get("id");

        let role_id: i64 = client
            .query_one("SELECT id FROM roles WHERE name = $1", &[&role])
            .await?
            .get("id");

        client
            .execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                &[&user_id, &role_id],
            )
            .await?;
        Ok(())
    }

    pub async fn add_policy_to_role(
        &self,
        role: &str,
        path: &str,
        action: &str,
        effect: &str,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        let role_id: i64 = client
            .query_one("SELECT id FROM roles WHERE name = $1", &[&role])
            .await?
            .get("id");

        client
            .execute(
                "INSERT INTO policies (role_id, path, action, effect) VALUES ($1, $2, $3, $4)",
                &[&role_id, &path, &action, &effect],
            )
            .await?;
        Ok(())
    }

    pub async fn check_policy(&self, username: &str, path: &str, action: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        let user_id_row = client
            .query_opt("SELECT id FROM users WHERE username = $1", &[&username])
            .await?;

        if let Some(row) = user_id_row {
            let user_id: i64 = row.get("id");
            let rows = client
                .query(
                    r#"
                SELECT p.effect FROM user_roles ur
                JOIN policies p ON ur.role_id = p.role_id
                WHERE ur.user_id = $1 AND $2 LIKE p.path AND p.action = $3
                "#,
                    &[&user_id, &path, &action],
                )
                .await?;

            for row in rows {
                let effect: String = row.get("effect");
                if effect == "deny" {
                    return Ok(false);
                } else if effect == "allow" {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub async fn insert_token(
        &self,
        user: &str,
        token: &str,
        expires_at: Option<&str>,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO tokens (user, token, expires_at) VALUES ($1, $2, $3)",
                &[&user, &token, &expires_at],
            )
            .await?;
        Ok(())
    }

    pub async fn is_token_valid(&self, token: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "SELECT revoked, expires_at FROM tokens WHERE token = $1 ORDER BY id DESC LIMIT 1",
                &[&token],
            )
            .await?;

        if let Some(row) = rows.first() {
            let revoked: bool = row.get("revoked");
            let expires_at: Option<String> = row.get("expires_at");
            if revoked {
                return Ok(false);
            }
            if let Some(exp) = expires_at.as_deref() {
                if let Ok(exp_time) = chrono::DateTime::parse_from_rfc3339(&exp) {
                    if chrono::Utc::now() > exp_time.with_timezone(&chrono::Utc) {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn revoke_token(
        &self,
        token: &str,
        _audit_devices: &Vec<Box<dyn AuditDevice>>,
        user: &str,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute("UPDATE tokens SET revoked = 1 WHERE token = $1", &[&token])
            .await?;
        self.log_audit(user, "revoke_token", token, "success")
            .await?;
        Ok(())
    }

    pub async fn create_lease_db(&self, lease: &Lease) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS leases (
                id TEXT PRIMARY KEY,
                user TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                issued_at TIMESTAMPTZ NOT NULL,
                expired_at TIMESTAMPTZ NOT NULL,
                status TEXT NOT NULL
            )"#,
                &[],
            )
            .await?;

        client.execute(
            "INSERT INTO leases (id, user, resource, resource_type, issued_at, expired_at, status) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[&lease.id, &lease.user, &lease.resource, &lease.resource_type, &lease.issued_at, &lease.expired_at, &lease.status]
        ).await?;
        Ok(())
    }
    pub async fn get_lease_db(&self, id: &str) -> Result<Option<Lease>> {
        let client = self.pool.get().await?;
        let rows = client.query(
            "SELECT id, user, resource, resource_type, issued_at, expired_at, status FROM leases WHERE id = $1",
            &[&id],
        ).await?;

        if let Some(row) = rows.get(0) {
            Ok(Some(Lease {
                id: row.get("id"),
                user: row.get("user"),
                resource: row.get("resource"),
                resource_type: row.get("resource_type"),
                issued_at: row.get("issued_at"),
                expired_at: row.get("expired_at"),
                status: row.get("status"),
                namespace: row.get("namespace"),
            }))
        } else {
            Ok(None)
        }
    }
    pub async fn update_lease_db(&self, lease: &Lease) -> Result<()> {
        let client = self.pool.get().await?;
        client.execute(
            "UPDATE leases SET user = $2, resource = $3, resource_type = $4, issued_at = $5, expired_at = $6, status = $7 WHERE id = $1",
            &[&lease.id, &lease.user, &lease.resource, &lease.resource_type, &lease.issued_at, &lease.expired_at, &lease.status]
        )
        .await?;
        Ok(())
    }
    pub async fn revoke_lease_db(&self, id: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute("UPDATE leases SET status = 'revoked' WHERE id = $1", &[&id])
            .await?;
        Ok(())
    }
    pub async fn get_expired_leases(&self) -> Result<Vec<Lease>> {
        let client = self.pool.get().await?;
        let now = chrono::Utc::now();
        let rows = client.query(
            "SELECT id, user, resource, resource_type, issued_at, expired_at, status FROM leases WHERE expired_at < $1 AND status = 'active'",
            &[&now],
        ).await?;
        let mut leases = Vec::new();
        for row in rows {
            leases.push(Lease {
                id: row.get("id"),
                user: row.get("user"),
                resource: row.get("resource"),
                resource_type: row.get("resource_type"),
                issued_at: row.get("issued_at"),
                expired_at: row.get("expired_at"),
                status: row.get("status"),
                namespace: row.get("namespace"),
            });
        }
        Ok(leases)
    }

    pub async fn get_audit_logs(
        &self,
        user: Option<String>,
        action: Option<String>,
        status: Option<String>,
        limit: u32,
    ) -> Result<Vec<AuditLog>> {
        let client = self.pool.get().await?;
        let mut query =
            String::from("SELECT user, action, path, status, timestamp FROM audit_logs WHERE 1=1");
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
        let mut idx = 1;

        if let Some(ref u) = user {
            query.push_str(&format!(" AND user = ${}", idx));
            params.push(u);
            idx += 1;
        }
        if let Some(ref a) = action {
            query.push_str(&format!(" AND action = ${}", idx));
            params.push(a);
            idx += 1;
        }
        if let Some(ref s) = status {
            query.push_str(&format!(" AND status = ${}", idx));
            params.push(s);
        }
        query.push_str(&format!(" ORDER BY timestamp DESC LIMIT {}", limit));

        let rows = client.query(&query, &params).await?;
        let mut logs = Vec::new();
        for row in rows {
            logs.push(AuditLog {
                user: row.try_get("user").ok(),
                action: row.try_get("action").ok(),
                path: row.try_get("path").ok(),
                status: row.try_get("status").ok(),
                timestamp: row.try_get("timestamp").ok(),
            });
        }
        Ok(logs)
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub async fn create_namespace(&self, name: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS namespaces (
                name TEXT PRIMARY KEY
            )"#,
                &[],
            )
            .await?;
        client
            .execute(
                "INSERT INTO namespaces (name) VALUES ($1) ON CONFLICT DO NOTHING",
                &[&name],
            )
            .await?;
        Ok(())
    }
    pub async fn list_namespaces(&self) -> Result<Vec<String>> {
        let client = self.pool.get().await?;
        client
            .execute(
                "CREATE TABLE IF NOT EXISTS namespaces (name TEXT PRIMARY KEY)",
                &[],
            )
            .await?;
        let rows = client.query("SELECT name FROM namespaces", &[]).await?;
        Ok(rows.iter().map(|row| row.get("name")).collect())
    }
    pub async fn delete_namespace(&self, name: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute("DELETE FROM namespaces WHERE name = $1", &[&name])
            .await?;
        Ok(())
    }

    pub async fn create_ca(&self, ca: &PkiCa) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS pki_ca (
                id SERIAL PRIMARY KEY,
                namespace TEXT NOT NULL,
                common_name TEXT NOT NULL,
                pem TEXT NOT NULL,
                private_key TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            )"#,
                &[],
            )
            .await?;
        client.execute("INSERT INTO pki_ca (namespace, common_name, pem, private_key, created_at) VALUES ($1, $2, $3, $4, $5)",
            &[&ca.namespace, &ca.common_name, &ca.pem, &ca.private_key, &ca.created_at])
            .await?;
        Ok(())
    }
    pub async fn get_ca(&self, namespace: &str, common_name: &str) -> Result<Option<PkiCa>> {
        let client = self.pool.get().await?;
        let rows = client.query("SELECT id, namespace, common_name, pem, private_key, created_at FROM pki_ca WHERE namespace = $1 AND common_name = $2 ORDER BY created_at DESC LIMIT 1", &[&namespace, &common_name]).await?;

        if let Some(row) = rows.get(0) {
            Ok(Some(PkiCa {
                id: row.get("id"),
                namespace: row.get("namespace"),
                common_name: row.get("common_name"),
                pem: row.get("pem"),
                private_key: row.get("private_key"),
                created_at: row.get("created_at"),
            }))
        } else {
            Ok(None)
        }
    }
    pub async fn create_cert(&self, cert: &PkiCert) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS pki_cert (
                id SERIAL PRIMARY KEY,
                namespace TEXT NOT NULL,
                common_name TEXT NOT NULL,
                pem TEXT NOT NULL,
                private_key TEXT NOT NULL,
                ca_id INTEGER NOT NULL,
                serial TEXT NOT NULL,
                issued_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked BOOLEAN NOT NULL
            )"#,
                &[],
            )
            .await?;
        client.execute("INSERT INTO pki_cert (namespace, common_name, pem, private_key, ca_id, serial, issued_at, expires_at, revoked) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[&cert.namespace, &cert.common_name, &cert.pem, &cert.private_key, &cert.ca_id, &cert.serial, &cert.issued_at, &cert.expires_at, &cert.revoked])
            .await?;
        Ok(())
    }
    pub async fn get_cert(&self, namespace: &str, serial: &str) -> Result<Option<PkiCert>> {
        let client = self.pool.get().await?;
        let rows = client.query("SELECT id, namespace, common_name, pem, private_key, ca_id, serial, issued_at, expires_at, revoked FROM pki_cert WHERE namespace = $1 AND serial = $2", &[&namespace, &serial]).await?;

        if let Some(row) = rows.get(0) {
            Ok(Some(PkiCert {
                id: row.get("id"),
                namespace: row.get("namespace"),
                common_name: row.get("common_name"),
                pem: row.get("pem"),
                private_key: row.get("private_key"),
                ca_id: row.get("ca_id"),
                serial: row.get("serial"),
                issued_at: row.get("issued_at"),
                expires_at: row.get("expires_at"),
                revoked: row.get("revoked"),
                // Default values for new fields
                serial_number: row.get::<_, String>("serial").clone(),
                certificate: row.get::<_, String>("pem").clone(),
                issuing_ca: "".to_string(),
                ca_chain: vec![],
                private_key_type: "RSA".to_string(),
                alt_names: vec![],
                ip_sans: vec![],
                uri_sans: vec![],
                other_sans: vec![],
                ou: vec![],
                organization: vec![],
                country: vec![],
                locality: vec![],
                province: vec![],
                street_address: vec![],
                postal_code: vec![],
                not_before: row.get("issued_at"),
                not_after: row.get("expires_at"),
                revocation_time: None,
                revocation_time_rfc3339: None,
            }))
        } else {
            Ok(None)
        }
    }
    pub async fn revoke_cert(&self, namespace: &str, serial: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE pki_cert SET revoked = TRUE WHERE namespace = $1 AND serial = $2",
                &[&namespace, &serial],
            )
            .await?;
        Ok(())
    }

    pub async fn create_sentinel_policy(&self, policy: &SentinelPolicy) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                r#"CREATE TABLE IF NOT EXISTS sentinel_policy (
                id SERIAL PRIMARY KEY,
                namespace TEXT NOT NULL,
                name TEXT NOT NULL,
                policy_type TEXT NOT NULL,
                source_code TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            )"#,
                &[],
            )
            .await?;
        client.execute("INSERT INTO sentinel_policy (namespace, name, policy_type, source_code, created_at) VALUES ($1, $2, $3, $4, $5)",
            &[&policy.namespace, &policy.name, &policy.policy_type, &policy.source_code, &policy.created_at])
            .await?;
        Ok(())
    }
    pub async fn list_sentinel_policies(&self, namespace: &str) -> Result<Vec<SentinelPolicy>> {
        let client = self.pool.get().await?;
        let rows = client.query("SELECT id, namespace, name, policy_type, source_code, created_at FROM sentinel_policy WHERE namespace = $1", &[&namespace]).await?;

        Ok(rows
            .iter()
            .map(|row| SentinelPolicy {
                id: row.get("id"),
                namespace: row.get("namespace"),
                name: row.get("name"),
                policy_type: row.get("policy_type"),
                source_code: row.get("source_code"),
                created_at: row.get("created_at"),
                egp: false, // Default EGP disabled
                rgp: false, // Default RGP disabled
                version: 1, // Default version
            })
            .collect())
    }
    pub async fn delete_sentinel_policy(&self, namespace: &str, name: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "DELETE FROM sentinel_policy WHERE namespace = $1 AND name = $2",
                &[&namespace, &name],
            )
            .await?;
        Ok(())
    }
}

// Implement StorageEngine trait for Storage to provide simple key-value interface
#[async_trait]
impl StorageEngine for Storage {
    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, CoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CoreError::Internal(anyhow::anyhow!(e.to_string())))?;
        let rows = client
            .query(
                "SELECT value, metadata FROM kv_store WHERE key = $1",
                &[&key],
            )
            .await
            .map_err(|e| CoreError::Internal(anyhow::anyhow!(e.to_string())))?;

        if let Some(row) = rows.get(0) {
            let value: Vec<u8> = row.get("value");
            let metadata_json: String = row.get("metadata");
            let metadata: HashMap<String, String> =
                serde_json::from_str(&metadata_json).unwrap_or_default();

            Ok(Some(StorageEntry {
                key: key.to_string(),
                value,
                metadata,
            }))
        } else {
            Ok(None)
        }
    }

    async fn put(&self, entry: StorageEntry) -> Result<(), CoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CoreError::Internal(anyhow::anyhow!(e.to_string())))?;
        let metadata_json =
            serde_json::to_string(&entry.metadata).map_err(|e| CoreError::Serialization(e))?;

        client
            .execute(
                "INSERT INTO kv_store (key, value, metadata, created_at, updated_at) 
             VALUES ($1, $2, $3, NOW(), NOW()) ON CONFLICT (key) DO UPDATE SET 
             value = EXCLUDED.value, metadata = EXCLUDED.metadata, updated_at = NOW()",
                &[&entry.key, &entry.value, &metadata_json],
            )
            .await
            .map_err(|e| CoreError::Internal(anyhow::anyhow!(e.to_string())))?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CoreError::Internal(anyhow::anyhow!(e.to_string())))?;
        client
            .execute("DELETE FROM kv_store WHERE key = $1", &[&key])
            .await
            .map_err(|e| CoreError::Internal(anyhow::anyhow!(e.to_string())))?;

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, CoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CoreError::Internal(anyhow::anyhow!(e.to_string())))?;
        let pattern = format!("{}%", prefix);
        let rows = client
            .query("SELECT key FROM kv_store WHERE key LIKE $1", &[&pattern])
            .await
            .map_err(|e| CoreError::Internal(anyhow::anyhow!(e.to_string())))?;

        let keys: Vec<String> = rows
            .into_iter()
            .map(|row| row.get::<_, String>("key"))
            .collect();

        Ok(keys)
    }
}
