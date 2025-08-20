use std::any::Any;
use std::sync::Arc;
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use sqlx::{PgPool, Row, SqlitePool};
use tokio::sync::RwLock;
use tracing::{info, error};

use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, SaltString};

use crate::models::lease::Lease;
use crate::models::policy::Policy;
use crate::models::pki::{PkiCa, PkiCert};
use crate::models::sentinel::SentinelPolicy;
use crate::models::user::Token;
use crate::models::plugin::PluginCatalogEntry;
use crate::audit::AuditDevice;
use crate::state::AppState;

// Re-export storage types
pub mod mfa;
pub mod secure;

pub use mfa::{MfaSecret, MfaRecoveryCodes, MfaStorage};
pub use secure::{SecureStorage, SharedSecureStorage};

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
    async fn store_mfa_secret(&self, user_id: &str, secret: &str, method: crate::auth::mfa::MfaMethod) -> Result<()>;
    async fn get_mfa_secret(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<String>;
    async fn delete_mfa_secret(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<()>;
    async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool>;
    async fn get_user_mfa_methods(&self, user_id: &str) -> Result<Vec<crate::auth::mfa::MfaMethod>>;
    async fn get_mfa_status(&self, user_id: &str) -> Result<std::collections::HashMap<crate::auth::mfa::MfaMethod, bool>>;
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
    async fn add_policy_to_role(&self, role: &str, path: &str, action: &str, effect: &str) -> Result<()>;
    async fn check_policy(&self, username: &str, path: &str, action: &str) -> Result<bool>;
    async fn insert_token(&self, user: &str, token: &str, expires_at: Option<&str>) -> Result<()>;
    async fn is_token_valid(&self, token: &str) -> Result<bool>;
    async fn revoke_token(&self, token: &str) -> Result<()>;
    async fn log_audit(&self, user: &str, action: &str, path: &str, status: &str) -> Result<()>;
    async fn get_policies_for_user(&self, user_id: &str, entity_alias: Option<&str>) -> Result<Vec<Policy>>;
    async fn insert_sentinel_policy_version(&self, p: &crate::models::sentinel::SentinelPolicy) -> Result<()>;
    async fn list_sentinel_policy_versions(&self, namespace: &str, name: &str) -> Result<Vec<crate::models::sentinel::SentinelPolicy>>;
    async fn delete_sentinel_policy_version(&self, namespace: &str, name: &str, version: u32) -> Result<()>;
    async fn delete_secret(&self, path: &str, namespace: &str) -> Result<()>;
}

pub enum StorageType {
    Sqlite(Storage),
    // Postgres(PostgresStorage),
}

pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url).await?;
        Self::create_tables(&pool).await?;
        Ok(Self { pool })
    }
    async fn create_tables(pool: &PgPool) -> Result<()> {
        // Create MFA tables
        sqlx::query(
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
            "#
        ).execute(pool).await?;
        
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_mfa_settings (
                user_id TEXT PRIMARY KEY,
                is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                method TEXT,
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
            "#
        ).execute(pool).await?;
        
        // Create main tables
        sqlx::query(
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
            "#
        ).execute(pool).await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
            "#
        ).execute(pool).await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vault_state (
                id SERIAL PRIMARY KEY,
                sealed BOOLEAN NOT NULL DEFAULT TRUE,
                master_key TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
            "#
        ).execute(pool).await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                user TEXT,
                action TEXT,
                path TEXT,
                status TEXT,
                timestamp TIMESTAMPTZ DEFAULT NOW()
            )
            "#
        ).execute(pool).await?;
        Ok(())
    }

    pub async fn migrate_tokens(&self) -> Result<()> {
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at TIMESTAMP,
                orphan BOOLEAN,
                batch BOOLEAN,
                locked BOOLEAN,
                created_at TIMESTAMP NOT NULL
            )
        "#)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_token(&self, t: &Token) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO tokens (token, username, expires_at, orphan, batch, locked, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#)
        .bind(&t.token)
        .bind(&t.user)
        .bind(t.expires_at)
        .bind(t.orphan)
        .bind(t.batch)
        .bind(t.locked)
        .bind(t.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_token_expiry(&self, token: &str, expires_at: DateTime<Utc>) -> Result<()> {
        sqlx::query(r#"
            UPDATE tokens SET expires_at = $1 WHERE token = $2
        "#)
        .bind(expires_at)
        .bind(token)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_token(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn lockout_user_tokens(&self, user: &str) -> Result<()> {
        sqlx::query("UPDATE tokens SET locked = TRUE WHERE username = $1")
            .bind(user)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_token(&self, token: &str) -> Result<Option<Token>> {
        let rec = sqlx::query_as::<_, (String, String, Option<DateTime<Utc>>, bool, bool, bool, DateTime<Utc>)>(
            "SELECT token, username, expires_at, orphan, batch, locked, created_at FROM tokens WHERE token = $1"
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec.map(|(token, user, expires_at, orphan, batch, locked, created_at)| Token {
            token, user, expires_at, orphan, batch, locked, created_at
        }))
    }

    pub async fn cleanup_expired_tokens(&self) -> Result<u64> {
        let res = sqlx::query("DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at < NOW()")
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn migrate_plugin_catalog(&self) -> Result<()> {
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS plugin_catalog (
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                checksum TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                pinned BOOLEAN,
                metadata JSONB,
                PRIMARY KEY (name, version)
            )
        "#)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_plugin(&self, p: &PluginCatalogEntry) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO plugin_catalog (name, version, checksum, artifact_path, pinned, metadata)
            VALUES ($1, $2, $3, $4, $5, $6)
        "#)
        .bind(&p.name)
        .bind(&p.version)
        .bind(&p.checksum)
        .bind(&p.artifact_path)
        .bind(p.pinned)
        .bind(serde_json::to_value(&p.metadata).ok())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn pin_plugin(&self, name: &str, version: &str, pinned: bool) -> Result<()> {
        sqlx::query("UPDATE plugin_catalog SET pinned = $1 WHERE name = $2 AND version = $3")
            .bind(pinned)
            .bind(name)
            .bind(version)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_plugin_catalog(&self) -> Result<Vec<PluginCatalogEntry>> {
        let rows = sqlx::query_as::<_, (String, String, String, String, bool, Option<serde_json::Value>)>(
            "SELECT name, version, checksum, artifact_path, pinned, metadata FROM plugin_catalog"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(name, version, checksum, artifact_path, pinned, metadata)| PluginCatalogEntry {
            name, version, checksum, artifact_path, pinned, metadata
        }).collect())
    }

    pub async fn store_secret_versioned(&self, path: &str, data: &serde_json::Value) -> Result<u32> {
        let version = sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(version) FROM secrets WHERE path = $1")
            .bind(path)
            .fetch_one(&self.pool)
            .await?
            .unwrap_or(0) + 1;
        sqlx::query("INSERT INTO secrets (path, version, data) VALUES ($1, $2, $3)")
            .bind(path)
            .bind(version)
            .bind(data)
            .execute(&self.pool)
            .await?;
        Ok(version as u32)
    }

    pub async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, serde_json::Value)>> {
        let rows = sqlx::query_as::<_, (i64, serde_json::Value)>(
            "SELECT version, data FROM secrets WHERE path = $1 ORDER BY version DESC"
        )
        .bind(path)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(v, d)| (v as u32, d)).collect())
    }

    pub async fn backup_data(&self) -> Result<serde_json::Value> {
        let secrets = sqlx::query_as::<_, (String, i64, serde_json::Value)>(
            "SELECT path, version, data FROM secrets"
        )
        .fetch_all(&self.pool)
        .await?;
        let secrets_json: Vec<_> = secrets.into_iter().map(|(path, version, data)| serde_json::json!({"path": path, "version": version, "data": data})).collect();
        Ok(serde_json::json!({"secrets": secrets_json}))
    }

    pub async fn restore_data(&self, backup: &serde_json::Value) -> Result<()> {
        if let Some(secrets) = backup.get("secrets").and_then(|v| v.as_array()) {
            for s in secrets {
                let path = s.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let version = s.get("version").and_then(|v| v.as_i64()).unwrap_or(1);
                let data = s.get("data").unwrap_or(&serde_json::json!({}));
                sqlx::query("INSERT INTO secrets (path, version, data) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                    .bind(path)
                    .bind(version)
                    .bind(data)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn migrate_sentinel_policy_versions(&self) -> Result<()> {
        sqlx::query(r#"
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
        "#)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_sentinel_policy_version(&self, p: &crate::models::sentinel::SentinelPolicy) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO sentinel_policies (namespace, name, version, policy_type, source_code, egp, rgp, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#)
        .bind(&p.namespace)
        .bind(&p.name)
        .bind(p.version as i32)
        .bind(&p.policy_type)
        .bind(&p.source_code)
        .bind(p.egp)
        .bind(p.rgp)
        .bind(p.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_sentinel_policy_versions(&self, namespace: &str, name: &str) -> Result<Vec<crate::models::sentinel::SentinelPolicy>> {
        let rows = sqlx::query_as::<_, (i64, String, String, i32, String, String, bool, bool, chrono::DateTime<chrono::Utc>)>(
            "SELECT id, namespace, name, version, policy_type, source_code, egp, rgp, created_at FROM sentinel_policies WHERE namespace = $1 AND name = $2 ORDER BY version DESC"
        )
        .bind(namespace)
        .bind(name)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, namespace, name, version, policy_type, source_code, egp, rgp, created_at)| crate::models::sentinel::SentinelPolicy {
            id, namespace, name, version: version as u32, policy_type, source_code, egp, rgp, created_at
        }).collect())
    }

    pub async fn delete_sentinel_policy_version(&self, namespace: &str, name: &str, version: u32) -> Result<()> {
        sqlx::query("DELETE FROM sentinel_policies WHERE namespace = $1 AND name = $2 AND version = $3")
            .bind(namespace)
            .bind(name)
            .bind(version as i32)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn delete_secret(&self, path: &str, namespace: &str) -> Result<()> {
        sqlx::query("DELETE FROM secrets WHERE path = $1 AND namespace = $2")
            .bind(path)
            .bind(namespace)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for PostgresStorage {
    fn as_any(&self) -> &dyn Any {
        self
    }
    
    async fn store_mfa_secret(&self, user_id: &str, secret: &str, method: crate::auth::mfa::MfaMethod) -> Result<()> {
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
        };
        
        sqlx::query(
            r#"
            INSERT INTO mfa_secrets (user_id, method, secret)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, method) 
            DO UPDATE SET secret = $3, updated_at = NOW()
            "#,
        )
        .bind(user_id)
        .bind(method_str)
        .bind(secret)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    async fn get_mfa_secret(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<String> {
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
        };
        
        let row = sqlx::query(
            "SELECT secret FROM mfa_secrets WHERE user_id = ? AND method = ?"
        )
        .bind(user_id)
        .bind(method_str)
        .fetch_optional(&self.pool)
        .await?;
        
        row
            .map(|r| r.get::<String, _>("secret"))
            .ok_or_else(|| anyhow::anyhow!("MFA secret not found"))
    }
    
    async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT is_enabled FROM user_mfa_settings WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| r.get::<bool, _>("is_enabled")).unwrap_or(false))
    }
    
    async fn enable_mfa(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<()> {
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
            crate::auth::mfa::MfaMethod::Recovery => "recovery",
        };
        
        sqlx::query(
            r#"
            INSERT INTO user_mfa_settings (user_id, is_enabled, method)
            VALUES ($1, TRUE, $2)
            ON CONFLICT (user_id) 
            DO UPDATE SET is_enabled = TRUE, method = $2, updated_at = NOW()
            "#,
        )
        .bind(user_id)
        .bind(method_str)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    async fn disable_mfa(&self, user_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE user_mfa_settings 
            SET is_enabled = FALSE, updated_at = NOW()
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    async fn delete_mfa_secret(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<()> {
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
            crate::auth::mfa::MfaMethod::Recovery => "recovery",
        };
        
        sqlx::query(
            r#"
            DELETE FROM mfa_secrets 
            WHERE user_id = $1 AND method = $2
            "#,
        )
        .bind(user_id)
        .bind(method_str)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    async fn get_user_mfa_methods(&self, user_id: &str) -> Result<Vec<crate::auth::mfa::MfaMethod>> {
        let rows = sqlx::query(
            "SELECT method FROM user_mfa_settings WHERE user_id = ? AND is_enabled = 1"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        
        let methods = rows
            .into_iter()
            .filter_map(|r| r.get::<String,_>("method").parse().ok())
            .collect();
            
        Ok(methods)
    }
    
    async fn get_mfa_status(&self, user_id: &str) -> Result<std::collections::HashMap<crate::auth::mfa::MfaMethod, bool>> {
        let rows = sqlx::query(
            "SELECT method, is_enabled FROM user_mfa_settings WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
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
        for method in crate::auth::mfa::MfaMethod::all() {
            status.entry(method).or_insert(false);
        }
        
        Ok(status)
    }
    
    async fn store_mfa_recovery_codes(&self, user_id: &str, codes: &[String]) -> Result<()> {
        // Delete existing codes
        sqlx::query(
            r#"
            DELETE FROM mfa_recovery_codes 
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        
        // Insert new codes in a transaction
        let mut tx = self.pool.begin().await?;
        
        for code in codes {
            sqlx::query(
                r#"
                INSERT INTO mfa_recovery_codes (user_id, code, is_used)
                VALUES ($1, $2, FALSE)
                "#,
            )
            .bind(user_id)
            .bind(code)
            .execute(&mut *tx)
            .await?;
        }
        
        tx.commit().await?;
        
        Ok(())
    }
    
    async fn get_mfa_recovery_codes(&self, user_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT code FROM mfa_recovery_codes WHERE user_id = ? AND is_used = 0"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        
        let codes = rows.into_iter().map(|r| r.get::<String,_>("code")).collect();
        Ok(codes)
    }
    
    async fn disable_mfa(&self, user_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE user_mfa_settings 
            SET is_enabled = FALSE, updated_at = NOW()
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32> {
        // Ambil versi terakhir
        let row = sqlx::query("SELECT COALESCE(MAX(version), 0) as max_version FROM secrets WHERE path = $1")
            .bind(path)
            .fetch_one(&self.pool)
            .await?;
        let version: i32 = row.get("max_version");
        let new_version = version + 1;
        sqlx::query("INSERT INTO secrets (path, version, data) VALUES ($1, $2, $3)")
            .bind(path)
            .bind(new_version)
            .bind(data.to_string())
            .execute(&self.pool)
            .await?;
        Ok(new_version as u32)
    }
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>> {
        let row = sqlx::query("SELECT data, version FROM secrets WHERE path = $1 ORDER BY version DESC LIMIT 1")
            .bind(path)
            .fetch_optional(&self.pool)
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
        let rows = sqlx::query("SELECT version, data FROM secrets WHERE path = $1 ORDER BY version DESC")
            .bind(path)
            .fetch_all(&self.pool)
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
        let hash = Storage::hash_password(password)?;
        sqlx::query("INSERT INTO users (username, password_hash) VALUES ($1, $2)")
            .bind(username)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool> {
        let row = sqlx::query("SELECT password_hash FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
            let hash: String = row.get("password_hash");
            Ok(Storage::verify_password(&hash, password)?)
        } else {
            Ok(false)
        }
    }
    async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<()> {
        // Pastikan tabel roles dan user_roles ada
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS roles (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL
            )"#
        ).execute(&self.pool).await?;
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS user_roles (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                UNIQUE(user_id, role_id)
            )"#
        ).execute(&self.pool).await?;
        // Insert role jika belum ada
        sqlx::query("INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING")
            .bind(role)
            .execute(&self.pool)
            .await?;
        // Ambil user_id dan role_id
        let user_id: i32 = sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(username)
            .fetch_one(&self.pool)
            .await?;
        let role_id: i32 = sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
            .bind(role)
            .fetch_one(&self.pool)
            .await?;
        // Insert ke user_roles
        sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING")
            .bind(user_id)
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn add_policy_to_role(&self, role: &str, path: &str, action: &str, effect: &str) -> Result<()> {
        // Pastikan tabel policies ada
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS policies (
                id SERIAL PRIMARY KEY,
                role TEXT NOT NULL,
                path TEXT NOT NULL,
                action TEXT NOT NULL,
                effect TEXT NOT NULL,
                entity_alias TEXT
            )"#
        ).execute(&self.pool).await?;
        sqlx::query("INSERT INTO policies (role, path, action, effect) VALUES ($1, $2, $3, $4)")
            .bind(role)
            .bind(path)
            .bind(action)
            .bind(effect)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn check_policy(&self, username: &str, path: &str, action: &str) -> Result<bool> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) FROM user_roles ur
            JOIN users u ON ur.user_id = u.id
            JOIN roles r ON ur.role_id = r.id
            JOIN policies p ON p.role = r.name
            WHERE u.username = $1 AND p.path = $2 AND p.action = $3 AND p.effect = 'allow'
            "#
        )
        .bind(username)
        .bind(path)
        .bind(action)
        .fetch_one(&self.pool)
        .await?;
        let count: i64 = row.get(0);
        Ok(count > 0)
    }
    async fn insert_token(&self, user: &str, token: &str, expires_at: Option<&str>) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS tokens (
                id SERIAL PRIMARY KEY,
                user TEXT NOT NULL,
                token TEXT NOT NULL,
                expires_at TIMESTAMPTZ
            )"#
        ).execute(&self.pool).await?;
        sqlx::query("INSERT INTO tokens (user, token, expires_at) VALUES ($1, $2, $3)")
            .bind(user)
            .bind(token)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn is_token_valid(&self, token: &str) -> Result<bool> {
        let row = sqlx::query("SELECT expires_at FROM tokens WHERE token = $1")
            .bind(token)
            .fetch_optional(&self.pool)
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
        sqlx::query("DELETE FROM tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn log_audit(&self, user: &str, action: &str, path: &str, status: &str) -> Result<()> {
        sqlx::query("INSERT INTO audit_logs (user, action, path, status) VALUES ($1, $2, $3, $4)")
            .bind(user)
            .bind(action)
            .bind(path)
            .bind(status)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn get_policies_for_user(&self, user_id: &str, entity_alias: Option<&str>) -> Result<Vec<Policy>> {
        let mut policies = Vec::new();
        // Ambil policies berdasarkan user_id (via role)
        let rows = sqlx::query(
            r#"
            SELECT p.id, r.name as role, p.path, p.action, p.effect, p.entity_alias
            FROM user_roles ur
            JOIN users u ON ur.user_id = u.id
            JOIN roles r ON ur.role_id = r.id
            JOIN policies p ON p.role = r.name
            WHERE u.username = $1
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        for row in rows {
            policies.push(Policy {
                id: row.get("id"),
                role: row.get("role"),
                path: row.get("path"),
                action: row.get("action"),
                effect: row.get("effect"),
                entity_alias: row.get("entity_alias"),
            });
        }
        // Jika entity_alias ada, ambil policies yang entity_alias-nya cocok
        if let Some(alias) = entity_alias {
            let rows = sqlx::query(
                r#"
                SELECT id, role, path, action, effect, entity_alias
                FROM policies
                WHERE entity_alias = $1
                "#
            )
            .bind(alias)
            .fetch_all(&self.pool)
            .await?;
            for row in rows {
                policies.push(Policy {
                    id: row.get("id"),
                    role: row.get("role"),
                    path: row.get("path"),
                    action: row.get("action"),
                    effect: row.get("effect"),
                    entity_alias: row.get("entity_alias"),
                });
            }
        }
        Ok(policies)
    }
    async fn insert_sentinel_policy_version(&self, p: &crate::models::sentinel::SentinelPolicy) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO sentinel_policies (namespace, name, version, policy_type, source_code, egp, rgp, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#)
        .bind(&p.namespace)
        .bind(&p.name)
        .bind(p.version as i32)
        .bind(&p.policy_type)
        .bind(&p.source_code)
        .bind(p.egp)
        .bind(p.rgp)
        .bind(p.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    async fn list_sentinel_policy_versions(&self, namespace: &str, name: &str) -> Result<Vec<crate::models::sentinel::SentinelPolicy>> {
        let rows = sqlx::query_as::<_, (i64, String, String, i32, String, String, bool, bool, chrono::DateTime<chrono::Utc>)>(
            "SELECT id, namespace, name, version, policy_type, source_code, egp, rgp, created_at FROM sentinel_policies WHERE namespace = $1 AND name = $2 ORDER BY version DESC"
        )
        .bind(namespace)
        .bind(name)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id, namespace, name, version, policy_type, source_code, egp, rgp, created_at)| crate::models::sentinel::SentinelPolicy {
            id, namespace, name, version: version as u32, policy_type, source_code, egp, rgp, created_at
        }).collect())
    }
    async fn delete_sentinel_policy_version(&self, namespace: &str, name: &str, version: u32) -> Result<()> {
        sqlx::query("DELETE FROM sentinel_policies WHERE namespace = $1 AND name = $2 AND version = $3")
            .bind(namespace)
            .bind(name)
            .bind(version as i32)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl StorageType {
    pub async fn from_config(backend: &str, url: &str) -> Result<std::sync::Arc<dyn StorageBackend>> {
        match backend {
            "sqlite" => Ok(std::sync::Arc::new(Storage::new(url).await?)),
            "postgres" => Ok(std::sync::Arc::new(PostgresStorage::new(url).await?)),
            _ => Err(anyhow::anyhow!("Unknown backend")),
        }
    }
}
#[async_trait]
impl StorageBackend for Storage {
    fn as_any(&self) -> &dyn Any { self }
    
    async fn store_mfa_secret(&self, user_id: &str, secret: &str, method: crate::auth::mfa::MfaMethod) -> Result<()> {
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
        };
        
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO mfa_secrets (user_id, method, secret, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            "#,
        )
        .bind(user_id)
        .bind(method_str)
        .bind(secret)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    async fn get_mfa_secret(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<String> {
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
        };
        
        let row = sqlx::query(
            "SELECT secret FROM mfa_secrets WHERE user_id = ? AND method = ?"
        )
        .bind(user_id)
        .bind(method_str)
        .fetch_optional(&self.pool)
        .await?;
        
        row
            .map(|r| r.get::<String,_>("secret"))
            .ok_or_else(|| anyhow::anyhow!("MFA secret not found"))
    }
    
    async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT is_enabled FROM user_mfa_settings WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| r.get::<bool,_>("is_enabled")).unwrap_or(false))
    }
    
    async fn enable_mfa(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<()> {
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
        };
        
        sqlx::query(
            r#"
            INSERT INTO user_mfa_settings (user_id, is_enabled, method, updated_at)
            VALUES (?, 1, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) 
            DO UPDATE SET is_enabled = 1, method = ?, updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(user_id)
        .bind(method_str)
        .bind(method_str)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    async fn disable_mfa(&self, user_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE user_mfa_settings 
            SET is_enabled = 0, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    async fn delete_mfa_secret(&self, user_id: &str, method: crate::auth::mfa::MfaMethod) -> Result<()> {
        let method_str = match method {
            crate::auth::mfa::MfaMethod::Totp => "totp",
            crate::auth::mfa::MfaMethod::WebAuthn => "webauthn",
            crate::auth::mfa::MfaMethod::Email => "email",
        };
        sqlx::query("DELETE FROM mfa_secrets WHERE user_id = ? AND method = ?")
            .bind(user_id)
            .bind(method_str)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn get_user_mfa_methods(&self, user_id: &str) -> Result<Vec<crate::auth::mfa::MfaMethod>> {
        let rows = sqlx::query("SELECT method FROM user_mfa_settings WHERE user_id = ? AND is_enabled = 1")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        let mut methods = Vec::new();
        for row in rows {
            let m: String = row.get("method");
            let parsed = match m.as_str() {
                "totp" => Some(crate::auth::mfa::MfaMethod::Totp),
                "webauthn" => Some(crate::auth::mfa::MfaMethod::WebAuthn),
                "email" => Some(crate::auth::mfa::MfaMethod::Email),
                _ => None,
            };
            if let Some(p) = parsed { methods.push(p); }
        }
        Ok(methods)
    }
    async fn get_mfa_status(&self, user_id: &str) -> Result<std::collections::HashMap<crate::auth::mfa::MfaMethod, bool>> {
        let rows = sqlx::query("SELECT method, is_enabled FROM user_mfa_settings WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        let mut status = std::collections::HashMap::new();
        for row in rows {
            let m: String = row.get("method");
            let enabled: bool = row.get("is_enabled");
            let method = match m.as_str() {
                "totp" => Some(crate::auth::mfa::MfaMethod::Totp),
                "webauthn" => Some(crate::auth::mfa::MfaMethod::WebAuthn),
                "email" => Some(crate::auth::mfa::MfaMethod::Email),
                _ => None,
            };
            if let Some(mm) = method { status.insert(mm, enabled); }
        }
        for method in [crate::auth::mfa::MfaMethod::Totp, crate::auth::mfa::MfaMethod::WebAuthn, crate::auth::mfa::MfaMethod::Email] { status.entry(method).or_insert(false); }
        Ok(status)
    }
    async fn store_mfa_recovery_codes(&self, user_id: &str, codes: &[String]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for c in codes {
            sqlx::query("INSERT INTO mfa_recovery_codes (user_id, code, is_used) VALUES (?, ?, 0)")
                .bind(user_id)
                .bind(c)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    async fn get_mfa_recovery_codes(&self, user_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT code FROM mfa_recovery_codes WHERE user_id = ? AND is_used = 0")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get::<String,_>("code")).collect())
    }
    async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32> { self.store_secret_versioned(path, data).await }
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>> { self.get_latest_secret(path).await }
    async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, Value)>> { self.get_secret_versions(path).await }
    async fn create_user(&self, username: &str, password: &str) -> Result<()> { self.create_user(username, password).await }
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool> { self.authenticate_user(username, password).await }
    async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<()> { self.assign_role_to_user(username, role).await }
    async fn add_policy_to_role(&self, role: &str, path: &str, action: &str, effect: &str) -> Result<()> { self.add_policy_to_role(role, path, action, effect).await }
    async fn check_policy(&self, username: &str, path: &str, action: &str) -> Result<bool> { self.check_policy(username, path, action).await }
    async fn insert_token(&self, user: &str, token: &str, expires_at: Option<&str>) -> Result<()> { self.insert_token(user, token, expires_at).await }
    async fn is_token_valid(&self, token: &str) -> Result<bool> { self.is_token_valid(token).await }
    async fn revoke_token(&self, token: &str) -> Result<()> { self.revoke_token(token).await }
    async fn log_audit(&self, user: &str, action: &str, path: &str, status: &str) -> Result<()> { self.log_audit(user, action, path, status).await }
    async fn get_policies_for_user(&self, user_id: &str, entity_alias: Option<&str>) -> Result<Vec<Policy>> {
        let mut policies = Vec::new();
        // Ambil policies berdasarkan user_id (via role)
        let rows = sqlx::query(
            r#"
            SELECT p.id, r.name as role, p.path, p.action, p.effect, p.entity_alias
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            JOIN policies p ON p.role = r.name
            WHERE ur.user_id = (SELECT id FROM users WHERE username = ?)
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        for row in rows {
            policies.push(Policy {
                id: row.get("id"),
                role: row.get("role"),
                path: row.get("path"),
                action: row.get("action"),
                effect: row.get("effect"),
                entity_alias: row.get("entity_alias"),
            });
        }
        // Jika entity_alias ada, ambil policies yang entity_alias-nya cocok
        if let Some(alias) = entity_alias {
            let rows = sqlx::query(
                r#"
                SELECT id, role, path, action, effect, entity_alias
                FROM policies
                WHERE entity_alias = ?
                "#
            )
            .bind(alias)
            .fetch_all(&self.pool)
            .await?;
            for row in rows {
                policies.push(Policy {
                    id: row.get("id"),
                    role: row.get("role"),
                    path: row.get("path"),
                    action: row.get("action"),
                    effect: row.get("effect"),
                    entity_alias: row.get("entity_alias"),
                });
            }
        }
        Ok(policies)
    }
    async fn insert_sentinel_policy_version(&self, p: &crate::models::sentinel::SentinelPolicy) -> Result<()> {
        self.pg.insert_sentinel_policy_version(p).await
    }
    async fn list_sentinel_policy_versions(&self, namespace: &str, name: &str) -> Result<Vec<crate::models::sentinel::SentinelPolicy>> {
        self.pg.list_sentinel_policy_versions(namespace, name).await
    }
    async fn delete_sentinel_policy_version(&self, namespace: &str, name: &str, version: u32) -> Result<()> {
        self.pg.delete_sentinel_policy_version(namespace, name, version).await
    }
    async fn delete_secret(&self, path: &str, namespace: &str) -> Result<()> {
        self.pg.delete_secret(path, namespace).await
    }
}

pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;
        
        // Create tables if they don't exist
        Self::create_tables(&pool).await?;
        
        Ok(Self { pool })
    }

    async fn create_tables(pool: &SqlitePool) -> Result<()> {
        // Create MFA tables first
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS mfa_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                method TEXT NOT NULL,
                secret TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, method)
            )
            "#
        ).execute(pool).await?;
        
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_mfa_settings (
                user_id TEXT PRIMARY KEY,
                is_enabled BOOLEAN NOT NULL DEFAULT 0,
                method TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#
        ).execute(pool).await?;
        
        // Create main tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                version INTEGER NOT NULL,
                data TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(path, version)
            )
            "#
        ).execute(pool).await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#
        ).execute(pool).await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vault_state (
                id INTEGER PRIMARY KEY,
                sealed BOOLEAN NOT NULL DEFAULT 1,
                master_key TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#
        ).execute(pool).await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                action TEXT,
                path TEXT,
                status TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#
        ).execute(pool).await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
            "#
        ).execute(pool).await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER,
                role_id INTEGER,
                PRIMARY KEY (user_id, role_id)
            )
            "#
        ).execute(pool).await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role_id INTEGER,
                path TEXT NOT NULL,
                action TEXT NOT NULL,
                effect TEXT NOT NULL
            )
            "#
        ).execute(pool).await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                token TEXT NOT NULL,
                issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                revoked BOOLEAN DEFAULT 0
            )
            "#
        ).execute(pool).await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS leases (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                issued_at TIMESTAMPTZ NOT NULL,
                expired_at TIMESTAMPTZ NOT NULL,
                status TEXT NOT NULL
            )"#
        ).execute(pool).await?;

        // Insert default user admin:admin (hashed)
        let admin_hash = Self::hash_password("admin")?;
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO users (username, password_hash) VALUES ('admin', ?)
            "#
        )
        .bind(admin_hash)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub fn hash_password(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!(e))?
            .to_string();
        Ok(hash)
    }

    pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!(e))?;
        Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    pub async fn create_user(&self, username: &str, password: &str, namespace: &str) -> Result<()> {
        let hash = Self::hash_password(password)?;
        sqlx::query(
            r#"INSERT INTO users (username, password_hash, created_at, namespace) VALUES (?, ?, ?, ?)"#
        )
        .bind(username)
        .bind(hash)
        .bind(chrono::Utc::now())
        .bind(namespace)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool> {
        let row = sqlx::query(
            r#"SELECT password_hash FROM users WHERE username = ?"#
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let stored_hash: String = row.get("password_hash");
                Ok(Self::verify_password(&stored_hash, password)? )
            }
            None => Ok(false),
        }
    }

    pub async fn store_secret(&self, path: &str, data: &Value) -> Result<()> {
        let data_json = serde_json::to_string(data)?;
        
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO secrets (path, data, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            "#
        )
        .bind(path)
        .bind(data_json)
        .execute(&self.pool)
        .await?;

        info!("Stored secret at path: {}", path);
        Ok(())
    }

    pub async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32> {
        // Ambil versi terakhir
        let latest_version: Option<i32> = sqlx::query_scalar(
            "SELECT MAX(version) FROM secrets WHERE path = ?"
        )
        .bind(path)
        .fetch_one(&self.pool)
        .await?;
        let new_version = latest_version.unwrap_or(0) + 1;
        let data_json = serde_json::to_string(data)?;
        sqlx::query(
            r#"
            INSERT INTO secrets (path, version, data, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            "#
        )
        .bind(path)
        .bind(new_version)
        .bind(data_json)
        .execute(&self.pool)
        .await?;
        Ok(new_version as u32)
    }

    pub async fn get_secret(&self, path: &str) -> Result<Option<Value>> {
        let row = sqlx::query(
            r#"
            SELECT data FROM secrets WHERE path = ?
            "#
        )
        .bind(path)
        .fetch_optional(&self.pool)
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
        let row = sqlx::query(
            r#"
            SELECT data, version FROM secrets WHERE path = ? ORDER BY version DESC LIMIT 1
            "#
        )
        .bind(path)
        .fetch_optional(&self.pool)
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
        let rows = sqlx::query(
            r#"
            SELECT version, data FROM secrets WHERE path = ? ORDER BY version DESC
            "#
        )
        .bind(path)
        .fetch_all(&self.pool)
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
        let result = sqlx::query(
            r#"
            DELETE FROM secrets WHERE path = ?
            "#
        )
        .bind(path)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn list_secrets(&self, prefix: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT path FROM secrets WHERE path LIKE ?
            "#
        )
        .bind(format!("{}%", prefix))
        .fetch_all(&self.pool)
        .await?;

        let paths: Vec<String> = rows.iter()
            .map(|row| row.get::<String, _>("path"))
            .collect();

        Ok(paths)
    }

    pub async fn set_vault_state(&self, sealed: bool, master_key: Option<&str>) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO vault_state (id, sealed, master_key)
            VALUES (1, ?, ?)
            "#
        )
        .bind(sealed)
        .bind(master_key)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_vault_state(&self) -> Result<(bool, Option<String>)> {
        let row = sqlx::query(
            r#"
            SELECT sealed, master_key FROM vault_state WHERE id = 1
            "#
        )
        .fetch_optional(&self.pool)
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

    pub async fn log_audit(&self, user: &str, action: &str, path: &str, status: &str) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO audit_logs (user, action, path, status) VALUES (?, ?, ?, ?)"#
        )
        .bind(user)
        .bind(action)
        .bind(path)
        .bind(status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<()> {
        let user_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
            .bind(username)
            .fetch_one(&self.pool)
            .await?;
        let role_id: i64 = sqlx::query_scalar("SELECT id FROM roles WHERE name = ?")
            .bind(role)
            .fetch_one(&self.pool)
            .await?;
        sqlx::query("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)")
            .bind(user_id)
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn add_policy_to_role(&self, role: &str, path: &str, action: &str, effect: &str) -> Result<()> {
        let role_id: i64 = sqlx::query_scalar("SELECT id FROM roles WHERE name = ?")
            .bind(role)
            .fetch_one(&self.pool)
            .await?;
        sqlx::query("INSERT INTO policies (role_id, path, action, effect) VALUES (?, ?, ?, ?)")
            .bind(role_id)
            .bind(path)
            .bind(action)
            .bind(effect)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn check_policy(&self, username: &str, path: &str, action: &str) -> Result<bool> {
        let user_id: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(user_id) = user_id {
            let rows = sqlx::query(
                r#"
                SELECT p.effect FROM user_roles ur
                JOIN policies p ON ur.role_id = p.role_id
                WHERE ur.user_id = ? AND ? LIKE p.path AND p.action = ?
                "#
            )
            .bind(user_id)
            .bind(path)
            .bind(action)
            .fetch_all(&self.pool)
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

    pub async fn insert_token(&self, user: &str, token: &str, expires_at: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT INTO tokens (user, token, expires_at) VALUES (?, ?, ?)"
        )
        .bind(user)
        .bind(token)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_token_valid(&self, token: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT revoked, expires_at FROM tokens WHERE token = ? ORDER BY id DESC LIMIT 1"
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = row {
            let revoked: bool = row.get("revoked");
            let expires_at: Option<String> = row.get("expires_at");
            if revoked {
                return Ok(false);
            }
            if let Some(exp) = expires_at {
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

    pub async fn revoke_token(&self, token: &str, audit_devices: &Vec<Box<dyn AuditDevice>>, user: &str) -> Result<()> {
        sqlx::query("UPDATE tokens SET revoked = 1 WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        log_audit(audit_devices, user, "revoke_token", token, "success");
        Ok(())
    }

    pub async fn create_lease_db(&self, lease: &Lease) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS leases (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                issued_at TIMESTAMPTZ NOT NULL,
                expired_at TIMESTAMPTZ NOT NULL,
                status TEXT NOT NULL
            )"#
        ).execute(&self.pool).await?;
        sqlx::query(
            "INSERT INTO leases (id, user, resource, resource_type, issued_at, expired_at, status) VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(&lease.id)
        .bind(&lease.user)
        .bind(&lease.resource)
        .bind(&lease.resource_type)
        .bind(lease.issued_at)
        .bind(lease.expired_at)
        .bind(&lease.status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    pub async fn get_lease_db(&self, id: &str) -> Result<Option<Lease>> {
        let row = sqlx::query(
            "SELECT id, user, resource, resource_type, issued_at, expired_at, status FROM leases WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = row {
            Ok(Some(Lease {
                id: row.get("id"),
                user: row.get("user"),
                resource: row.get("resource"),
                resource_type: row.get("resource_type"),
                issued_at: row.get("issued_at"),
                expired_at: row.get("expired_at"),
                status: row.get("status"),
            }))
        } else {
            Ok(None)
        }
    }
    pub async fn update_lease_db(&self, lease: &Lease) -> Result<()> {
        sqlx::query(
            "UPDATE leases SET user = $2, resource = $3, resource_type = $4, issued_at = $5, expired_at = $6, status = $7 WHERE id = $1"
        )
        .bind(&lease.id)
        .bind(&lease.user)
        .bind(&lease.resource)
        .bind(&lease.resource_type)
        .bind(lease.issued_at)
        .bind(lease.expired_at)
        .bind(&lease.status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    pub async fn revoke_lease_db(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE leases SET status = 'revoked' WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn get_expired_leases(&self) -> Result<Vec<Lease>> {
        let now = chrono::Utc::now();
        let rows = sqlx::query(
            "SELECT id, user, resource, resource_type, issued_at, expired_at, status FROM leases WHERE expired_at < $1 AND status = 'active'"
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
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
            });
        }
        Ok(leases)
    }

    pub async fn get_audit_logs(&self, user: Option<String>, action: Option<String>, status: Option<String>, limit: u32) -> Result<Vec<AuditLog>> {
        let mut query = String::from("SELECT user, action, path, status, timestamp FROM audit_logs WHERE 1=1");
        let mut params: Vec<(usize, &dyn sqlx::types::Type)> = Vec::new();
        let mut idx = 1;
        if let Some(ref u) = user {
            query.push_str(&format!(" AND user = ${}", idx)); idx += 1;
        }
        if let Some(ref a) = action {
            query.push_str(&format!(" AND action = ${}", idx)); idx += 1;
        }
        if let Some(ref s) = status {
            query.push_str(&format!(" AND status = ${}", idx)); idx += 1;
        }
        query.push_str(&format!(" ORDER BY timestamp DESC LIMIT {}", limit));
        let mut q = sqlx::query(&query);
        let mut param_idx = 1;
        if let Some(u) = user {
            q = q.bind(u);
            param_idx += 1;
        }
        if let Some(a) = action {
            q = q.bind(a);
            param_idx += 1;
        }
        if let Some(s) = status {
            q = q.bind(s);
            param_idx += 1;
        }
        let rows = q.fetch_all(&self.pool).await?;
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

    pub fn pool(&self) -> &sqlx::SqlitePool {
        &self.pool
    }

    pub async fn create_namespace(&self, name: &str) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS namespaces (
                name TEXT PRIMARY KEY
            )"#
        ).execute(&self.pool).await?;
        sqlx::query("INSERT INTO namespaces (name) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn list_namespaces(&self) -> Result<Vec<String>> {
        sqlx::query("CREATE TABLE IF NOT EXISTS namespaces (name TEXT PRIMARY KEY)")
            .execute(&self.pool)
            .await?;
        let rows = sqlx::query("SELECT name FROM namespaces")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|row| row.get("name")).collect())
    }
    pub async fn delete_namespace(&self, name: &str) -> Result<()> {
        sqlx::query("DELETE FROM namespaces WHERE name = $1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_ca(&self, ca: &PkiCa) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS pki_ca (
                id SERIAL PRIMARY KEY,
                namespace TEXT NOT NULL,
                common_name TEXT NOT NULL,
                pem TEXT NOT NULL,
                private_key TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            )"#
        ).execute(&self.pool).await?;
        sqlx::query("INSERT INTO pki_ca (namespace, common_name, pem, private_key, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(&ca.namespace)
            .bind(&ca.common_name)
            .bind(&ca.pem)
            .bind(&ca.private_key)
            .bind(ca.created_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn get_ca(&self, namespace: &str, common_name: &str) -> Result<Option<PkiCa>> {
        let row = sqlx::query("SELECT id, namespace, common_name, pem, private_key, created_at FROM pki_ca WHERE namespace = $1 AND common_name = $2 ORDER BY created_at DESC LIMIT 1")
            .bind(namespace)
            .bind(common_name)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
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
        sqlx::query(
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
            )"#
        ).execute(&self.pool).await?;
        sqlx::query("INSERT INTO pki_cert (namespace, common_name, pem, private_key, ca_id, serial, issued_at, expires_at, revoked) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
            .bind(&cert.namespace)
            .bind(&cert.common_name)
            .bind(&cert.pem)
            .bind(&cert.private_key)
            .bind(cert.ca_id)
            .bind(&cert.serial)
            .bind(cert.issued_at)
            .bind(cert.expires_at)
            .bind(cert.revoked)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn get_cert(&self, namespace: &str, serial: &str) -> Result<Option<PkiCert>> {
        let row = sqlx::query("SELECT id, namespace, common_name, pem, private_key, ca_id, serial, issued_at, expires_at, revoked FROM pki_cert WHERE namespace = $1 AND serial = $2")
            .bind(namespace)
            .bind(serial)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
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
            }))
        } else {
            Ok(None)
        }
    }
    pub async fn revoke_cert(&self, namespace: &str, serial: &str) -> Result<()> {
        sqlx::query("UPDATE pki_cert SET revoked = TRUE WHERE namespace = $1 AND serial = $2")
            .bind(namespace)
            .bind(serial)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_sentinel_policy(&self, policy: &SentinelPolicy) -> Result<()> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS sentinel_policy (
                id SERIAL PRIMARY KEY,
                namespace TEXT NOT NULL,
                name TEXT NOT NULL,
                policy_type TEXT NOT NULL,
                source_code TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            )"#
        ).execute(&self.pool).await?;
        sqlx::query("INSERT INTO sentinel_policy (namespace, name, policy_type, source_code, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(&policy.namespace)
            .bind(&policy.name)
            .bind(&policy.policy_type)
            .bind(&policy.source_code)
            .bind(policy.created_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn list_sentinel_policies(&self, namespace: &str) -> Result<Vec<SentinelPolicy>> {
        let rows = sqlx::query("SELECT id, namespace, name, policy_type, source_code, created_at FROM sentinel_policy WHERE namespace = $1")
            .bind(namespace)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|row| SentinelPolicy {
            id: row.get("id"),
            namespace: row.get("namespace"),
            name: row.get("name"),
            policy_type: row.get("policy_type"),
            source_code: row.get("source_code"),
            created_at: row.get("created_at"),
        }).collect())
    }
    pub async fn delete_sentinel_policy(&self, namespace: &str, name: &str) -> Result<()> {
        sqlx::query("DELETE FROM sentinel_policy WHERE namespace = $1 AND name = $2")
            .bind(namespace)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
} 