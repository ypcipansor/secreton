//! Database secret engine for dynamic credential generation

use crate::error::DatabaseError;
use crate::model::{DatabaseConfig, DatabaseRole, DatabaseType};
#[cfg(feature = "postgres")]
use deadpool_postgres::{Manager, ManagerConfig, Pool as PgPool, RecyclingMethod};
#[cfg(feature = "mysql")]
use mysql_async::{Opts, Pool as MySqlPool};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use tokio::sync::Mutex;
#[cfg(feature = "postgres")]
use tokio_postgres::{Config, NoTls};
#[cfg(feature = "postgres")]
use tokio_postgres::types::ToSql;

/// Database secret engine for dynamic credentials
pub struct DatabaseEngine {
    config: DatabaseConfig,
    enabled: bool,
    roles: HashMap<String, DatabaseRole>,
    #[cfg(feature = "postgres")]
    pg_pool: Mutex<Option<PgPool>>,
    #[cfg(feature = "mysql")]
    mysql_pool: Mutex<Option<MySqlPool>>,
}

impl DatabaseEngine {
    pub fn new(config: DatabaseConfig) -> Self {
        Self {
            config,
            enabled: false,
            roles: HashMap::new(),
            #[cfg(feature = "postgres")]
            pg_pool: Mutex::new(None),
            #[cfg(feature = "mysql")]
            mysql_pool: Mutex::new(None),
        }
    }

    /// Generate database credentials for a role
    pub async fn generate_credentials(
        &self,
        role_name: &str,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        if !self.enabled {
            return Err(DatabaseError::EngineDisabled);
        }

        // Get role configuration
        let role = self.roles.get(role_name).ok_or_else(|| {
            DatabaseError::RoleNotFound(format!("Role '{}' not found", role_name))
        })?;

        // Determine database type from connection URL
        let db_type = self.detect_database_type(&self.config.connection_url)?;

        // Generate credentials based on database type
        match db_type {
            #[cfg(feature = "postgres")]
            DatabaseType::PostgreSQL => {
                self.generate_postgres_credentials(role_name, &role.sql, role.default_ttl)
                    .await
            }
            #[cfg(not(feature = "postgres"))]
            DatabaseType::PostgreSQL => Err(DatabaseError::InvalidConfiguration("PostgreSQL feature disabled".to_string())),

            #[cfg(feature = "mysql")]
            DatabaseType::MySQL => self.generate_mysql_credentials(role_name, &role.sql, role.default_ttl).await,
            #[cfg(not(feature = "mysql"))]
            DatabaseType::MySQL => Err(DatabaseError::InvalidConfiguration("MySQL feature disabled".to_string())),

            DatabaseType::MongoDB => {
                self.generate_mongodb_credentials(role_name, &role.sql)
                    .await
            }
            DatabaseType::Redis => self.generate_redis_credentials(role_name).await,
        }
    }

    /// Get or create PostgreSQL connection pool
    #[cfg(feature = "postgres")]
    async fn get_pg_pool(&self) -> Result<PgPool, DatabaseError> {
        let mut lock = self.pg_pool.lock().await;
        if let Some(pool) = &*lock {
            return Ok(pool.clone());
        }

        // Parse connection URL
        let mut pg_config = Config::from_str(&self.config.connection_url).map_err(|e| {
            DatabaseError::InvalidConfiguration(format!("Invalid PostgreSQL connection URL: {}", e))
        })?;

        // Override with explicit config if present
        if let Some(username) = &self.config.username {
            pg_config.user(username);
        }
        if let Some(password) = &self.config.password {
            pg_config.password(password);
        }
        if let Some(dbname) = &self.config.database_name {
            pg_config.dbname(dbname);
        }
        if let Some(timeout) = self.config.connection_timeout {
            pg_config.connect_timeout(std::time::Duration::from_secs(timeout));
        }

        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        // TODO: Implement TLS support (e.g. using rustls or native-tls)
        let mgr = Manager::from_config(pg_config, NoTls, mgr_config);
        let pool = PgPool::builder(mgr)
            .max_size(self.config.max_open_connections.unwrap_or(10) as usize)
            .build()
            .map_err(|e| {
                DatabaseError::ConnectionFailed(format!("Failed to create PostgreSQL pool: {}", e))
            })?;

        *lock = Some(pool.clone());
        Ok(pool)
    }

    /// Get or create MySQL connection pool
    #[cfg(feature = "mysql")]
    async fn get_mysql_pool(&self) -> Result<MySqlPool, DatabaseError> {
        let mut lock = self.mysql_pool.lock().await;
        if let Some(pool) = &*lock {
            return Ok(pool.clone());
        }

        let mut opts = Opts::from_url(&self.config.connection_url).map_err(|e| {
            DatabaseError::InvalidConfiguration(format!("Invalid MySQL connection URL: {}", e))
        })?;

        // Manual overrides if provided in config
        if self.config.username.is_some() || self.config.password.is_some() || self.config.database_name.is_some() {
             let mut builder = mysql_async::OptsBuilder::from_opts(opts);
             if let Some(username) = &self.config.username {
                 builder = builder.user(Some(username));
             }
             if let Some(password) = &self.config.password {
                 builder = builder.pass(Some(password));
             }
             if let Some(dbname) = &self.config.database_name {
                 builder = builder.db_name(Some(dbname));
             }
             // Apply pool limits
             if self.config.max_open_connections.is_some() || self.config.max_idle_connections.is_some() {
                 let min = self.config.max_idle_connections.unwrap_or(5) as usize;
                 let max = self.config.max_open_connections.unwrap_or(10) as usize;
                 let constraints = mysql_async::PoolConstraints::new(min, max).ok_or_else(|| {
                     DatabaseError::InvalidConfiguration("Invalid pool constraints: min > max".to_string())
                 })?;
                 builder = builder.pool_opts(mysql_async::PoolOpts::default().with_constraints(constraints));
             }

             opts = builder.into();
        } else if self.config.max_open_connections.is_some() || self.config.max_idle_connections.is_some() {
             // Even if no overrides, we might need to apply pool options to the base opts
             let mut builder = mysql_async::OptsBuilder::from_opts(opts);
             let min = self.config.max_idle_connections.unwrap_or(5) as usize;
             let max = self.config.max_open_connections.unwrap_or(10) as usize;
             let constraints = mysql_async::PoolConstraints::new(min, max).ok_or_else(|| {
                 DatabaseError::InvalidConfiguration("Invalid pool constraints: min > max".to_string())
             })?;
             builder = builder.pool_opts(mysql_async::PoolOpts::default().with_constraints(constraints));
             opts = builder.into();
        }

        let pool = MySqlPool::new(opts);
        *lock = Some(pool.clone());
        Ok(pool)
    }

    /// Generate PostgreSQL credentials
    #[cfg(feature = "postgres")]
    async fn generate_postgres_credentials(
        &self,
        role_name: &str,
        role_sql: &str,
        default_ttl: u64,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        let username = self.generate_username();
        let password = self.generate_password();
        let expiration = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(default_ttl as i64))
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339();

        // Get connection
        let pool = self.get_pg_pool().await?;
        let client = pool.get().await.map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to get PostgreSQL connection: {}", e))
        })?;

        // Create user
        let create_user_sql = format!(
            "CREATE USER \"{}\" WITH LOGIN PASSWORD '{}' VALID UNTIL '{}'",
            username, password, expiration
        );

        let params: &[&(dyn ToSql + Sync)] = &[];
        client
            .execute(&create_user_sql, params)
            .await
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to create user: {}", e)))?;

        // Execute role SQL statements
        let statements = self.replace_placeholders(role_sql, &username, &password, &expiration);

        // Execute each statement in the role definition
        // Note: This split is naive and does not handle semicolons within string literals.
        // Complex SQL should be avoided in role definitions or handled with a proper parser.
        for statement in statements.split(';') {
            let stmt = statement.trim();
            if stmt.is_empty() {
                continue;
            }

            if let Err(e) = client.execute(stmt, params).await {
                // Attempt cleanup on failure (best effort)
                let _ = client
                    .execute(&format!("DROP USER IF EXISTS \"{}\"", username), params)
                    .await;
                return Err(DatabaseError::QueryFailed(format!(
                    "Failed to execute role statement '{}': {}",
                    stmt, e
                )));
            }
        }

        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String(username));
        data.insert("password".to_string(), Value::String(password));
        data.insert("role".to_string(), Value::String(role_name.to_string()));
        data.insert(
            "connection_string".to_string(),
            Value::String(self.sanitize_connection_url(&self.config.connection_url)),
        );
        data.insert("expiration".to_string(), Value::String(expiration));

        Ok(data)
    }

    fn replace_placeholders(
        &self,
        sql: &str,
        username: &str,
        password: &str,
        expiration: &str,
    ) -> String {
        sql.replace("{{name}}", username)
            .replace("{{password}}", password)
            .replace("{{expiration}}", expiration)
    }

    /// Generate MySQL credentials
    #[cfg(feature = "mysql")]
    async fn generate_mysql_credentials(
        &self,
        role_name: &str,
        role_sql: &str,
        default_ttl: u64,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        let username = self.generate_username();
        let password = self.generate_password();
        // MySQL doesn't strictly require valid until in CREATE USER, but we might want to handle expiration
        // by a scheduled job or event scheduler. For now, we just create the user.
        // If the role_sql contains expiration logic (e.g. event creation), it will be executed.
        let expiration = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(default_ttl as i64))
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339();

        let pool = self.get_mysql_pool().await?;
        let mut conn = pool.get_conn().await.map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to get MySQL connection: {}", e))
        })?;

        // Create user
        // We use % as host to allow connections from anywhere (standard for dynamic secrets)
        // or we could make it configurable. Defaults to %.
        // WARNING: Ensure username and password are safe from SQL injection.
        // `generate_username` and `generate_password` use strictly Alphanumeric characters,
        // so direct interpolation here is safe.
        let create_user_sql = format!(
            "CREATE USER '{}'@'%' IDENTIFIED BY '{}'",
            username, password
        );

        use mysql_async::prelude::Queryable;

        conn.query_drop(create_user_sql).await.map_err(|e| {
             DatabaseError::QueryFailed(format!("Failed to create MySQL user: {}", e))
        })?;

        // Execute role SQL statements
        let statements = self.replace_placeholders(role_sql, &username, &password, &expiration);

        // Execute each statement
        // Note: This split is naive and does not handle semicolons within string literals.
        // Complex SQL should be avoided in role definitions or handled with a proper parser.
        for statement in statements.split(';') {
            let stmt = statement.trim();
            if stmt.is_empty() {
                continue;
            }

            if let Err(e) = conn.query_drop(stmt).await {
                // Attempt cleanup
                let _ = conn.query_drop(format!("DROP USER IF EXISTS '{}'@'%'", username)).await;
                return Err(DatabaseError::QueryFailed(format!(
                    "Failed to execute role statement '{}': {}",
                    stmt, e
                )));
            }
        }

        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String(username));
        data.insert("password".to_string(), Value::String(password));
        data.insert("role".to_string(), Value::String(role_name.to_string()));
        data.insert(
            "connection_string".to_string(),
            Value::String(self.sanitize_connection_url(&self.config.connection_url)),
        );
        data.insert("expiration".to_string(), Value::String(expiration));

        Ok(data)
    }

    /// Generate MongoDB credentials
    async fn generate_mongodb_credentials(
        &self,
        role_name: &str,
        _role_sql: &str,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        let username = self.generate_username();
        let password = self.generate_password();

        let mut data = HashMap::new();
        data.insert("username".to_string(), Value::String(username));
        data.insert("password".to_string(), Value::String(password));
        data.insert("role".to_string(), Value::String(role_name.to_string()));
        data.insert(
            "connection_string".to_string(),
            Value::String(self.sanitize_connection_url(&self.config.connection_url)),
        );

        Ok(data)
    }

    /// Generate Redis credentials
    async fn generate_redis_credentials(
        &self,
        role_name: &str,
    ) -> Result<HashMap<String, Value>, DatabaseError> {
        let password = self.generate_password();

        let mut data = HashMap::new();
        data.insert("password".to_string(), Value::String(password));
        data.insert("role".to_string(), Value::String(role_name.to_string()));
        data.insert(
            "connection_string".to_string(),
            Value::String(self.sanitize_connection_url(&self.config.connection_url)),
        );

        Ok(data)
    }

    /// Generate a random username (prefixed with 's_' for safety)
    /// Uses Alphanumeric charset to ensure safety in SQL string literals without escaping.
    fn generate_username(&self) -> String {
        use rand::{Rng, distributions::Alphanumeric};
        let suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        format!("s_{}", suffix)
    }

    /// Generate a random password
    /// Uses Alphanumeric charset to ensure safety in SQL string literals without escaping.
    /// This guarantees that passwords do not contain characters that could break SQL syntax or cause injection.
    fn generate_password(&self) -> String {
        use rand::{Rng, distributions::Alphanumeric};
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    /// Detect database type from connection URL
    fn detect_database_type(&self, connection_url: &str) -> Result<DatabaseType, DatabaseError> {
        if connection_url.starts_with("postgresql://") || connection_url.starts_with("postgres://")
        {
            Ok(DatabaseType::PostgreSQL)
        } else if connection_url.starts_with("mysql://") {
            Ok(DatabaseType::MySQL)
        } else if connection_url.starts_with("mongodb://") {
            Ok(DatabaseType::MongoDB)
        } else if connection_url.starts_with("redis://") {
            Ok(DatabaseType::Redis)
        } else {
            Err(DatabaseError::UnsupportedDatabaseType(format!(
                "Unsupported database type in URL: {}",
                connection_url
            )))
        }
    }

    /// Add a database role
    pub fn add_role(&mut self, name: String, role: DatabaseRole) {
        self.roles.insert(name, role);
    }

    /// Remove a database role
    pub fn remove_role(&mut self, name: &str) {
        self.roles.remove(name);
    }

    /// List all roles
    pub fn list_roles(&self) -> Vec<String> {
        self.roles.keys().cloned().collect()
    }

    /// Enable the engine
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the engine
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if engine is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sanitize connection URL to remove credentials
    fn sanitize_connection_url(&self, url: &str) -> String {
        // Simple heuristic: if url contains @, replace user:pass section
        if let Some(at_pos) = url.rfind('@') {
            if let Some(scheme_end) = url.find("://") {
                let prefix = &url[0..scheme_end + 3];
                let suffix = &url[at_pos + 1..];
                return format!("{}****:****@{}", prefix, suffix);
            }
        }
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_placeholders() {
        let config = DatabaseConfig::default();
        let engine = DatabaseEngine::new(config);

        let sql = "CREATE ROLE \"{{name}}\" WITH PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';";
        let username = "user123";
        let password = "secretPassWord";
        let expiration = "2025-01-01T00:00:00Z";

        let result = engine.replace_placeholders(sql, username, password, expiration);

        assert_eq!(
            result,
            "CREATE ROLE \"user123\" WITH PASSWORD 'secretPassWord' VALID UNTIL '2025-01-01T00:00:00Z';"
        );
    }

    #[test]
    fn test_generate_username_format() {
        let config = DatabaseConfig::default();
        let engine = DatabaseEngine::new(config);
        let username = engine.generate_username();
        assert!(username.starts_with("s_"));
        assert_eq!(username.len(), 18); // s_ + 16 chars
    }
}
