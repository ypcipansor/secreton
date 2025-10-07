// Database Connection Strings - Template-based connection string generation
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("Template error: {0}")]
    TemplateError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Generation error: {0}")]
    GenerationError(String),
}

pub type Result<T> = std::result::Result<T, ConnectionError>;

/// Database type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    MongoDB,
    Redis,
    MSSQL,
    Oracle,
}

/// Connection template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTemplate {
    pub template_id: String,
    pub name: String,
    pub database_type: DatabaseType,
    pub template_string: String, // e.g., "{{username}}:{{password}}@{{host}}:{{port}}/{{database}}"
    pub default_port: u16,
    pub ssl_enabled: bool,
    pub connection_options: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

/// Connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
    pub ssl_enabled: bool,
    pub pool_size: Option<u32>,
    pub timeout_seconds: Option<u32>,
    pub additional_params: HashMap<String, String>,
}

/// Generated connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedConnection {
    pub connection_id: String,
    pub template_id: String,
    pub connection_string: String,
    pub database_type: DatabaseType,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Database Connection Strings
pub struct DatabaseConnectionStrings {
    templates: Arc<RwLock<HashMap<String, ConnectionTemplate>>>,
    connections: Arc<RwLock<HashMap<String, GeneratedConnection>>>,
}

impl DatabaseConnectionStrings {
    pub fn new() -> Self {
        Self {
            templates: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register template
    pub async fn register_template(&self, template: ConnectionTemplate) -> Result<()> {
        // Validate template placeholders
        self.validate_template(&template.template_string)?;

        let mut templates = self.templates.write().await;
        templates.insert(template.template_id.clone(), template);

        Ok(())
    }

    /// Generate connection string
    pub async fn generate_connection_string(
        &self,
        template_id: &str,
        config: ConnectionConfig,
        ttl_seconds: i64,
    ) -> Result<GeneratedConnection> {
        let templates = self.templates.read().await;
        let template = templates
            .get(template_id)
            .ok_or_else(|| ConnectionError::TemplateError("Template not found".to_string()))?;

        // Generate connection string from template
        let connection_string = self.render_template(template, &config)?;

        let connection_id = uuid::Uuid::new_v4().to_string();

        let mut metadata = HashMap::new();
        metadata.insert("template_name".to_string(), template.name.clone());
        metadata.insert("database_type".to_string(), format!("{:?}", template.database_type));

        let connection = GeneratedConnection {
            connection_id: connection_id.clone(),
            template_id: template_id.to_string(),
            connection_string,
            database_type: template.database_type.clone(),
            host: config.host.clone(),
            port: config.port,
            database: config.database.clone(),
            username: config.username.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(ttl_seconds),
            metadata,
        };

        let mut connections = self.connections.write().await;
        connections.insert(connection_id.clone(), connection.clone());

        Ok(connection)
    }

    /// Render template with config
    fn render_template(
        &self,
        template: &ConnectionTemplate,
        config: &ConnectionConfig,
    ) -> Result<String> {
        let mut rendered = template.template_string.clone();

        // Replace placeholders
        rendered = rendered.replace("{{username}}", &config.username);
        rendered = rendered.replace("{{password}}", &config.password);
        rendered = rendered.replace("{{host}}", &config.host);
        rendered = rendered.replace("{{port}}", &config.port.to_string());
        rendered = rendered.replace("{{database}}", &config.database);

        // Add SSL parameter if enabled
        if config.ssl_enabled {
            match template.database_type {
                DatabaseType::MySQL => {
                    rendered.push_str("?ssl-mode=REQUIRED");
                }
                DatabaseType::PostgreSQL => {
                    rendered.push_str("?sslmode=require");
                }
                DatabaseType::MongoDB => {
                    rendered.push_str("?ssl=true");
                }
                _ => {}
            }
        }

        // Add additional parameters
        for (key, value) in &config.additional_params {
            if rendered.contains('?') {
                rendered.push_str(&format!("&{}={}", key, value));
            } else {
                rendered.push_str(&format!("?{}={}", key, value));
            }
        }

        Ok(rendered)
    }

    /// Validate template
    fn validate_template(&self, template: &str) -> Result<()> {
        let required_placeholders = vec![
            "{{username}}",
            "{{password}}",
            "{{host}}",
            "{{port}}",
            "{{database}}",
        ];

        for placeholder in &required_placeholders {
            if !template.contains(placeholder) {
                return Err(ConnectionError::ValidationError(format!(
                    "Missing required placeholder: {}",
                    placeholder
                )));
            }
        }

        Ok(())
    }

    /// Test connection
    pub async fn test_connection(&self, connection_id: &str) -> Result<bool> {
        let connections = self.connections.read().await;
        let connection = connections
            .get(connection_id)
            .ok_or_else(|| ConnectionError::GenerationError("Connection not found".to_string()))?;

        // Mock connection test
        // Real implementation would attempt to connect to database
        let is_valid = !connection.connection_string.is_empty()
            && connection.host != "invalid"
            && connection.port > 0;

        Ok(is_valid)
    }

    /// Revoke connection
    pub async fn revoke_connection(&self, connection_id: &str) -> Result<()> {
        let mut connections = self.connections.write().await;
        connections
            .remove(connection_id)
            .ok_or_else(|| ConnectionError::GenerationError("Connection not found".to_string()))?;

        Ok(())
    }

    /// List templates
    pub async fn list_templates(&self) -> Vec<ConnectionTemplate> {
        let templates = self.templates.read().await;
        templates.values().cloned().collect()
    }

    /// Get template
    pub async fn get_template(&self, template_id: &str) -> Option<ConnectionTemplate> {
        let templates = self.templates.read().await;
        templates.get(template_id).cloned()
    }

    /// Delete template
    pub async fn delete_template(&self, template_id: &str) -> Result<()> {
        let mut templates = self.templates.write().await;
        templates
            .remove(template_id)
            .ok_or_else(|| ConnectionError::TemplateError("Template not found".to_string()))?;

        Ok(())
    }

    /// List active connections
    pub async fn list_connections(&self) -> Vec<GeneratedConnection> {
        let connections = self.connections.read().await;
        connections.values().cloned().collect()
    }

    /// Cleanup expired connections
    pub async fn cleanup_expired(&self) -> usize {
        let mut connections = self.connections.write().await;
        let now = Utc::now();

        let expired: Vec<String> = connections
            .iter()
            .filter(|(_, c)| c.expires_at < now)
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();

        for id in expired {
            connections.remove(&id);
        }

        count
    }
}

impl Default for DatabaseConnectionStrings {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_mysql_template() -> ConnectionTemplate {
        ConnectionTemplate {
            template_id: "mysql-standard".to_string(),
            name: "MySQL Standard".to_string(),
            database_type: DatabaseType::MySQL,
            template_string: "mysql://{{username}}:{{password}}@{{host}}:{{port}}/{{database}}"
                .to_string(),
            default_port: 3306,
            ssl_enabled: false,
            connection_options: HashMap::new(),
            created_at: Utc::now(),
        }
    }

    fn create_postgres_template() -> ConnectionTemplate {
        ConnectionTemplate {
            template_id: "postgres-standard".to_string(),
            name: "PostgreSQL Standard".to_string(),
            database_type: DatabaseType::PostgreSQL,
            template_string:
                "postgresql://{{username}}:{{password}}@{{host}}:{{port}}/{{database}}"
                    .to_string(),
            default_port: 5432,
            ssl_enabled: true,
            connection_options: HashMap::new(),
            created_at: Utc::now(),
        }
    }

    fn create_test_config() -> ConnectionConfig {
        ConnectionConfig {
            host: "localhost".to_string(),
            port: 3306,
            database: "myapp".to_string(),
            username: "appuser".to_string(),
            password: "secret123".to_string(),
            ssl_enabled: false,
            pool_size: Some(10),
            timeout_seconds: Some(30),
            additional_params: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_register_template() {
        let db_conn = DatabaseConnectionStrings::new();
        let template = create_mysql_template();

        db_conn.register_template(template).await.unwrap();

        let templates = db_conn.list_templates().await;
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].name, "MySQL Standard");
    }

    #[tokio::test]
    async fn test_generate_mysql_connection() {
        let db_conn = DatabaseConnectionStrings::new();
        let template = create_mysql_template();

        db_conn.register_template(template).await.unwrap();

        let config = create_test_config();
        let connection = db_conn
            .generate_connection_string("mysql-standard", config, 3600)
            .await
            .unwrap();

        assert_eq!(connection.database_type, DatabaseType::MySQL);
        assert!(connection
            .connection_string
            .contains("mysql://appuser:secret123@localhost:3306/myapp"));
        assert_eq!(connection.host, "localhost");
        assert_eq!(connection.port, 3306);
    }

    #[tokio::test]
    async fn test_generate_postgres_with_ssl() {
        let db_conn = DatabaseConnectionStrings::new();
        let template = create_postgres_template();

        db_conn.register_template(template).await.unwrap();

        let mut config = create_test_config();
        config.port = 5432;
        config.ssl_enabled = true;

        let connection = db_conn
            .generate_connection_string("postgres-standard", config, 3600)
            .await
            .unwrap();

        assert_eq!(connection.database_type, DatabaseType::PostgreSQL);
        assert!(connection.connection_string.contains("postgresql://"));
        assert!(connection.connection_string.contains("sslmode=require"));
    }

    #[tokio::test]
    async fn test_template_validation() {
        let db_conn = DatabaseConnectionStrings::new();

        let invalid_template = ConnectionTemplate {
            template_id: "invalid".to_string(),
            name: "Invalid".to_string(),
            database_type: DatabaseType::MySQL,
            template_string: "mysql://{{username}}@{{host}}".to_string(), // Missing placeholders
            default_port: 3306,
            ssl_enabled: false,
            connection_options: HashMap::new(),
            created_at: Utc::now(),
        };

        let result = db_conn.register_template(invalid_template).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connection_test() {
        let db_conn = DatabaseConnectionStrings::new();
        let template = create_mysql_template();

        db_conn.register_template(template).await.unwrap();

        let config = create_test_config();
        let connection = db_conn
            .generate_connection_string("mysql-standard", config, 3600)
            .await
            .unwrap();

        let is_valid = db_conn
            .test_connection(&connection.connection_id)
            .await
            .unwrap();

        assert!(is_valid);
    }
}
