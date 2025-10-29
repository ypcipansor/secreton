//! Storage system for Secreton
//!
//! This module provides a comprehensive storage system with multiple backends
//! and a unified interface for data persistence.

// Re-export storage modules
pub mod mfa;
pub mod secure;
pub mod types;
pub mod traits;
pub mod storage;

// Re-export types and traits
pub use mfa::{MfaRecoveryCodes, MfaSecret, MfaStorage};
pub use secure::{SecureStorage, SharedSecureStorage};
pub use types::*;
pub use traits::*;
pub use storage::*;

// Type alias for backward compatibility
pub type MemoryStorage = Storage;
pub use storage::Storage;

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

        rows.first()
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
            .first()
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

        if let Some(row) = rows.first() {
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

#[async_trait]
// Re-export for backward compatibility
pub use storage::Storage;
