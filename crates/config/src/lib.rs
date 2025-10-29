//! # Secreton Config
//!
//! Shared configuration patterns and utilities for all Secreton crates.
//! Provides consistent configuration loading, validation, and management.

use secreton_common::{Result, SecurityLevel};
use secreton_errors::{SecretonError, Result as SecretonResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

/// Base configuration trait that all config structs should implement
pub trait Config: for<'de> Deserialize<'de> + Serialize + Clone + Default {
    /// Load configuration from a file
    fn load_from_file<P: AsRef<Path>>(path: P) -> SecretonResult<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| SecretonError::Configuration {
                message: format!("Failed to read config file: {}", e),
            })?;

        let config: Self = toml::from_str(&content)
            .map_err(|e| SecretonError::Parse {
                message: format!("Failed to parse config: {}", e),
            })?;

        config.validate()?;
        Ok(config)
    }

    /// Load configuration from environment variables
    fn load_from_env() -> SecretonResult<Self> {
        let mut config = Self::default();

        // This would be implemented by each config struct
        // For now, return default
        config.validate()?;
        Ok(config)
    }

    /// Load configuration with layered sources (file + env + defaults)
    fn load() -> SecretonResult<Self> {
        let mut settings = config::Config::builder()
            .add_source(config::File::with_name("config/default"))
            .add_source(
                config::File::with_name("config/local")
                    .required(false)
            )
            .add_source(config::Environment::with_prefix("SECRETON"))
            .build()
            .map_err(|e| SecretonError::Configuration {
                message: format!("Failed to build config: {}", e),
            })?;

        let config: Self = settings
            .try_deserialize()
            .map_err(|e| SecretonError::Configuration {
                message: format!("Failed to deserialize config: {}", e),
            })?;

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> SecretonResult<()>;

    /// Get configuration as a map for debugging
    fn as_map(&self) -> HashMap<String, serde_json::Value> {
        serde_json::to_value(self)
            .unwrap_or(serde_json::Value::Null)
            .as_object()
            .unwrap_or(&serde_json::Map::new())
            .clone()
            .into_iter()
            .collect()
    }
}

/// Server configuration - shared across multiple crates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
    /// Request timeout in seconds
    pub request_timeout: u64,
    /// Maximum request body size in bytes
    pub max_body_size: usize,
    /// CORS configuration
    pub cors: Option<CorsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8200,
            tls: None,
            request_timeout: 30,
            max_body_size: 10 * 1024 * 1024, // 10MB
            cors: Some(CorsConfig::default()),
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: String,
    /// Path to private key file
    pub key_path: String,
    /// Client certificate authentication
    pub client_auth: bool,
    /// CA certificate path for client auth
    pub ca_cert_path: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: "certs/server.crt".to_string(),
            key_path: "certs/server.key".to_string(),
            client_auth: false,
            ca_cert_path: None,
        }
    }
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    /// Allow credentials
    pub allow_credentials: bool,
    /// Max age for preflight requests
    pub max_age: Option<u64>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Vault-Token".to_string(),
            ],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "PATCH".to_string(),
                "OPTIONS".to_string(),
            ],
            allow_credentials: true,
            max_age: Some(86400), // 24 hours
        }
    }
}

/// Database configuration - shared across storage crates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL
    pub url: String,
    /// Connection pool size
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connect_timeout: u64,
    /// Query timeout in seconds
    pub query_timeout: u64,
    /// Enable SSL/TLS
    pub ssl_mode: String,
    /// Database schema/migrations
    pub schema: Option<String>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://localhost/secreton".to_string(),
            max_connections: 10,
            connect_timeout: 30,
            query_timeout: 30,
            ssl_mode: "prefer".to_string(),
            schema: Some("public".to_string()),
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// JWT secret key
    pub jwt_secret: String,
    /// JWT expiration time in seconds
    pub jwt_expiration: u64,
    /// Enable MFA
    pub mfa_enabled: bool,
    /// MFA issuer name
    pub mfa_issuer: String,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Maximum login attempts
    pub max_login_attempts: u32,
    /// Lockout duration in seconds
    pub lockout_duration: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "change-this-in-production".to_string(),
            jwt_expiration: 3600, // 1 hour
            mfa_enabled: true,
            mfa_issuer: "Secreton".to_string(),
            session_timeout: 28800, // 8 hours
            max_login_attempts: 5,
            lockout_duration: 900, // 15 minutes
        }
    }
}

/// Metrics and monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,
    /// Metrics endpoint port
    pub port: u16,
    /// Enable Prometheus metrics
    pub prometheus_enabled: bool,
    /// Prometheus endpoint path
    pub prometheus_path: String,
    /// Enable health checks
    pub health_checks_enabled: bool,
    /// Health check interval in seconds
    pub health_check_interval: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9090,
            prometheus_enabled: true,
            prometheus_path: "/metrics".to_string(),
            health_checks_enabled: true,
            health_check_interval: 30,
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Master encryption key for data encryption
    pub encryption_key: String,
    /// Enable audit logging
    pub audit_enabled: bool,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            encryption_key: "default-encryption-key-32-chars-long".to_string(),
            audit_enabled: true,
            tls: Some(TlsConfig::default()),
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (debug, info, warn, error)
    pub level: String,
    /// Log format (json, text)
    pub format: String,
    /// Enable file logging
    pub file_enabled: bool,
    /// Log file path
    pub file_path: Option<String>,
    /// Maximum log file size in MB
    pub max_file_size: u64,
    /// Maximum number of log files to keep
    pub max_files: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            file_enabled: true,
            file_path: Some("logs/secreton.log".to_string()),
            max_file_size: 100,
            max_files: 10,
        }
    }
}

/// Authentication methods configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethodsConfig {
    /// AppRole authentication configuration
    pub approle: Option<AppRoleConfig>,
    /// LDAP authentication configuration
    pub ldap: Option<LdapConfig>,
    /// OIDC authentication configuration
    pub oidc: Option<OidcConfig>,
    /// OAuth2 authentication configuration
    pub oauth2: Option<OAuth2Config>,
    /// Kubernetes authentication configuration
    pub kubernetes: Option<KubernetesConfig>,
    /// AWS IAM authentication configuration
    pub aws: Option<AwsConfig>,
    /// RADIUS authentication configuration
    pub radius: Option<RadiusConfig>,
}

impl Default for AuthMethodsConfig {
    fn default() -> Self {
        Self {
            approle: None,
            ldap: None,
            oidc: None,
            oauth2: None,
            kubernetes: None,
            aws: None,
            radius: None,
        }
    }
}

/// AppRole authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleConfig {
    pub role_id: String,
    pub secret_id: Option<String>,
    pub policies: Vec<String>,
    pub token_ttl: Option<u64>,
    pub token_max_ttl: Option<u64>,
    pub secret_id_ttl: Option<u64>,
    pub secret_id_num_uses: Option<u32>,
    pub token_num_uses: Option<u32>,
    pub bind_secret_id: bool,
    pub bound_cidr_list: Option<Vec<String>>,
}

impl Default for AppRoleConfig {
    fn default() -> Self {
        Self {
            role_id: String::new(),
            secret_id: None,
            policies: vec![],
            token_ttl: None,
            token_max_ttl: None,
            secret_id_ttl: None,
            secret_id_num_uses: None,
            token_num_uses: None,
            bind_secret_id: true,
            bound_cidr_list: None,
        }
    }
}

/// LDAP authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub user_dn: String,
    pub user_attr: String,
    pub group_dn: Option<String>,
    pub group_attr: Option<String>,
    pub certificate: Option<String>,
    pub insecure_tls: bool,
    pub starttls: bool,
    pub discover_dn: bool,
    pub deny_null_bind: bool,
    pub username_as_alias: bool,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            bind_dn: None,
            bind_password: None,
            user_dn: String::new(),
            user_attr: "cn".to_string(),
            group_dn: None,
            group_attr: None,
            certificate: None,
            insecure_tls: false,
            starttls: false,
            discover_dn: false,
            deny_null_bind: true,
            username_as_alias: false,
        }
    }
}

/// OIDC authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub default_role: String,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scopes: vec!["openid".to_string()],
            default_role: String::new(),
        }
    }
}

/// OAuth2 authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub authorization_url: String,
    pub token_url: String,
    pub user_info_url: Option<String>,
    pub default_role: String,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            provider: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scopes: vec![],
            authorization_url: String::new(),
            token_url: String::new(),
            user_info_url: None,
            default_role: String::new(),
        }
    }
}

/// Kubernetes authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    pub kubernetes_host: String,
    pub kubernetes_ca_cert: Option<String>,
    pub token_reviewer_jwt: Option<String>,
    pub pem_keys: Option<Vec<String>>,
    pub issuer: Option<String>,
    pub disable_iss_validation: bool,
    pub disable_local_ca_jwt: bool,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            kubernetes_host: "https://kubernetes.default.svc".to_string(),
            kubernetes_ca_cert: None,
            token_reviewer_jwt: None,
            pem_keys: None,
            issuer: None,
            disable_iss_validation: false,
            disable_local_ca_jwt: false,
        }
    }
}

/// AWS IAM authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    pub identity_document_url: Option<String>,
    pub role_arn: Option<String>,
    pub allowed_account_ids: Option<Vec<String>>,
    pub disallowed_account_ids: Option<Vec<String>>,
    pub allowed_role_arns: Option<Vec<String>>,
    pub disallowed_role_arns: Option<Vec<String>>,
    pub allowed_ec2_endpoints: Option<Vec<String>>,
    pub disallowed_ec2_endpoints: Option<Vec<String>>,
    pub iam_server_id_header_value: Option<String>,
    pub max_retries: Option<i32>,
    pub region: Option<String>,
}

impl Default for AwsConfig {
    fn default() -> Self {
        Self {
            identity_document_url: None,
            role_arn: None,
            allowed_account_ids: None,
            disallowed_account_ids: None,
            allowed_role_arns: None,
            disallowed_role_arns: None,
            allowed_ec2_endpoints: None,
            disallowed_ec2_endpoints: None,
            iam_server_id_header_value: None,
            max_retries: Some(3),
            region: None,
        }
    }
}

/// RADIUS authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusConfig {
    pub host: String,
    pub port: Option<u16>,
    pub secret: String,
    pub nas_identifier: Option<String>,
    pub nas_port: Option<u32>,
    pub dial_timeout: Option<u32>,
    pub read_timeout: Option<u32>,
}

impl Default for RadiusConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: Some(1812),
            secret: String::new(),
            nas_identifier: None,
            nas_port: None,
            dial_timeout: Some(10),
            read_timeout: Some(10),
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend type
    pub backend_type: StorageBackendType,
    /// File backend configuration
    pub file: Option<FileBackendConfig>,
    /// PostgreSQL backend configuration
    pub postgres: Option<PostgresBackendConfig>,
    /// Redis backend configuration
    pub redis: Option<RedisBackendConfig>,
    /// Raft backend configuration
    pub raft: Option<RaftConfig>,
    /// Consul backend configuration
    pub consul: Option<ConsulStorageConfig>,
    /// S3 backend configuration
    pub s3: Option<S3StorageConfig>,
    /// etcd backend configuration
    pub etcd: Option<EtcdStorageConfig>,
    /// DynamoDB backend configuration
    pub dynamodb: Option<DynamoDBStorageConfig>,
    /// MySQL backend configuration
    pub mysql: Option<MySQLStorageConfig>,
    /// CockroachDB backend configuration
    pub cockroachdb: Option<CockroachDBConfig>,
    /// Cassandra backend configuration
    pub cassandra: Option<CassandraConfig>,
    /// MongoDB backend configuration
    pub mongodb: Option<MongoDBConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend_type: StorageBackendType::Memory,
            file: None,
            postgres: None,
            redis: None,
            raft: None,
            consul: None,
            s3: None,
            etcd: None,
            dynamodb: None,
            mysql: None,
            cockroachdb: None,
            cassandra: None,
            mongodb: None,
        }
    }
}

/// Storage backend type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackendType {
    /// File-based storage
    File,
    /// In-memory storage (for testing)
    Memory,
    /// PostgreSQL database
    Postgres,
    /// Redis cache
    Redis,
    /// Raft distributed storage
    Raft,
    /// Consul KV storage
    Consul,
    /// PostgreSQL storage (new implementation)
    PostgreSQL,
    /// etcd storage
    Etcd,
    /// Amazon S3
    S3,
    /// AWS DynamoDB
    DynamoDB,
    /// MySQL database
    MySQL,
    /// CockroachDB storage
    CockroachDB,
    /// Cassandra storage
    Cassandra,
    /// MongoDB storage
    MongoDB,
}

/// File backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBackendConfig {
    pub base_path: String,
}

impl Default for FileBackendConfig {
    fn default() -> Self {
        Self {
            base_path: "./data".to_string(),
        }
    }
}

/// PostgreSQL backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresBackendConfig {
    pub connection_string: String,
}

impl Default for PostgresBackendConfig {
    fn default() -> Self {
        Self {
            connection_string: "postgres://localhost/secreton".to_string(),
        }
    }
}

/// Redis backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisBackendConfig {
    pub url: String,
}

impl Default for RedisBackendConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
        }
    }
}

/// Raft backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftConfig {
    pub node_id: String,
    pub peers: Vec<String>,
    pub log_dir: String,
    pub snapshot_dir: String,
    pub max_log_entries: u64,
    pub heartbeat_timeout: u64,
    pub election_timeout_min: u64,
    pub election_timeout_max: u64,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            node_id: "node1".to_string(),
            peers: vec![],
            log_dir: "./raft/logs".to_string(),
            snapshot_dir: "./raft/snapshots".to_string(),
            max_log_entries: 10000,
            heartbeat_timeout: 1000,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
        }
    }
}

/// Consul backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulStorageConfig {
    pub address: String,
    pub token: Option<String>,
    pub path: String,
    pub scheme: String,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub tls_skip_verify: bool,
}

impl Default for ConsulStorageConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:8500".to_string(),
            token: None,
            path: "secreton".to_string(),
            scheme: "http".to_string(),
            ca_cert: None,
            client_cert: None,
            client_key: None,
            tls_skip_verify: false,
        }
    }
}

/// S3 backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3StorageConfig {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    pub bucket: String,
    pub endpoint: Option<String>,
    pub kms_key_id: Option<String>,
    pub sse_algorithm: Option<String>,
    pub disable_ssl: bool,
    pub force_path_style: bool,
}

impl Default for S3StorageConfig {
    fn default() -> Self {
        Self {
            access_key: String::new(),
            secret_key: String::new(),
            region: "us-east-1".to_string(),
            bucket: String::new(),
            endpoint: None,
            kms_key_id: None,
            sse_algorithm: None,
            disable_ssl: false,
            force_path_style: false,
        }
    }
}

/// etcd backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtcdStorageConfig {
    pub endpoints: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub tls_skip_verify: bool,
    pub prefix: String,
}

impl Default for EtcdStorageConfig {
    fn default() -> Self {
        Self {
            endpoints: vec!["http://localhost:2379".to_string()],
            username: None,
            password: None,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            tls_skip_verify: false,
            prefix: "secreton".to_string(),
        }
    }
}

/// DynamoDB backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamoDBStorageConfig {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    pub table_name: String,
    pub endpoint: Option<String>,
    pub max_retries: Option<i32>,
    pub read_capacity: Option<i64>,
    pub write_capacity: Option<i64>,
}

impl Default for DynamoDBStorageConfig {
    fn default() -> Self {
        Self {
            access_key: String::new(),
            secret_key: String::new(),
            region: "us-east-1".to_string(),
            table_name: "secreton".to_string(),
            endpoint: None,
            max_retries: Some(3),
            read_capacity: Some(5),
            write_capacity: Some(5),
        }
    }
}

/// MySQL backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySQLStorageConfig {
    pub connection_string: String,
    pub max_connections: Option<u32>,
    pub connect_timeout: Option<u64>,
    pub query_timeout: Option<u64>,
}

impl Default for MySQLStorageConfig {
    fn default() -> Self {
        Self {
            connection_string: "mysql://root:password@localhost/secreton".to_string(),
            max_connections: Some(10),
            connect_timeout: Some(30),
            query_timeout: Some(30),
        }
    }
}

/// CockroachDB backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CockroachDBConfig {
    pub connection_string: String,
    pub max_connections: Option<u32>,
    pub connect_timeout: Option<u64>,
    pub query_timeout: Option<u64>,
}

impl Default for CockroachDBConfig {
    fn default() -> Self {
        Self {
            connection_string: "postgresql://root@localhost:26257/secreton".to_string(),
            max_connections: Some(10),
            connect_timeout: Some(30),
            query_timeout: Some(30),
        }
    }
}

/// Cassandra backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CassandraConfig {
    pub contact_points: Vec<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub keyspace: String,
    pub consistency: Option<String>,
    pub tls_ca_cert: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

impl Default for CassandraConfig {
    fn default() -> Self {
        Self {
            contact_points: vec!["localhost:9042".to_string()],
            port: Some(9042),
            username: None,
            password: None,
            keyspace: "secreton".to_string(),
            consistency: Some("LOCAL_QUORUM".to_string()),
            tls_ca_cert: None,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// MongoDB backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoDBConfig {
    pub connection_string: String,
    pub database: String,
    pub collection: String,
    pub max_connections: Option<u32>,
    pub connect_timeout: Option<u64>,
}

impl Default for MongoDBConfig {
    fn default() -> Self {
        Self {
            connection_string: "mongodb://localhost:27017".to_string(),
            database: "secreton".to_string(),
            collection: "secrets".to_string(),
            max_connections: Some(10),
            connect_timeout: Some(30),
        }
    }
}

/// Infrastructure configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureConfig {
    /// Monitoring configuration
    pub monitoring: Option<MonitoringConfig>,
    /// Connection pooling configuration
    pub connection_pooling: Option<PoolConfig>,
    /// Plugin system configuration
    pub plugin_system: Option<SandboxConfig>,
    /// Log streaming configuration
    pub log_streaming: Option<LogStreamConfig>,
    /// Rotation scheduler configuration
    pub rotation_scheduler: Option<RotationConfig>,
    /// Webhooks configuration
    pub webhooks: Option<WebhookSystemConfig>,
    /// Distributed tracing configuration
    pub distributed_tracing: Option<TracingConfig>,
}

impl Default for InfrastructureConfig {
    fn default() -> Self {
        Self {
            monitoring: None,
            connection_pooling: None,
            plugin_system: None,
            log_streaming: None,
            rotation_scheduler: None,
            webhooks: None,
            distributed_tracing: None,
        }
    }
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub metrics_port: u16,
    pub health_check_port: u16,
    pub prometheus_endpoint: String,
    pub collection_interval: u64,
    pub retention_period: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            metrics_port: 9090,
            health_check_port: 8080,
            prometheus_endpoint: "/metrics".to_string(),
            collection_interval: 60,
            retention_period: 86400,
        }
    }
}

/// Connection pooling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: u64,
    pub idle_timeout: u64,
    pub max_lifetime: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 1,
            connect_timeout: 30,
            idle_timeout: 300,
            max_lifetime: 3600,
        }
    }
}

/// Plugin system sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub enabled: bool,
    pub memory_limit: String,
    pub cpu_limit: String,
    pub network_access: bool,
    pub file_access: bool,
    pub allowed_paths: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            memory_limit: "128Mi".to_string(),
            cpu_limit: "100m".to_string(),
            network_access: false,
            file_access: false,
            allowed_paths: vec![],
        }
    }
}

/// Log streaming configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStreamConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub batch_size: usize,
    pub flush_interval: u64,
    pub compression: bool,
}

impl Default for LogStreamConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            batch_size: 100,
            flush_interval: 30,
            compression: true,
        }
    }
}

/// Rotation scheduler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    pub enabled: bool,
    pub interval: u64,
    pub max_age: u64,
    pub backup_count: u32,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: 86400,
            max_age: 604800,
            backup_count: 7,
        }
    }
}

/// Webhooks system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSystemConfig {
    pub enabled: bool,
    pub max_retries: u32,
    pub retry_interval: u64,
    pub timeout: u64,
    pub webhooks: Vec<WebhookConfig>,
}

impl Default for WebhookSystemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_retries: 3,
            retry_interval: 60,
            timeout: 30,
            webhooks: vec![],
        }
    }
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub events: Vec<String>,
    pub headers: HashMap<String, String>,
    pub secret: Option<String>,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            events: vec![],
            headers: HashMap::new(),
            secret: None,
        }
    }
}

/// Distributed tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub service_name: String,
    pub collector_endpoint: String,
    pub sampling_rate: f64,
    pub jaeger_enabled: bool,
    pub zipkin_enabled: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            service_name: "secreton".to_string(),
            collector_endpoint: "http://localhost:14268/api/traces".to_string(),
            sampling_rate: 1.0,
            jaeger_enabled: false,
            zipkin_enabled: false,
        }
    }
}

/// Crypto configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Integration configuration
    pub integration: Option<CryptoIntegrationConfig>,
    /// KMIP server configuration
    pub kmip: Option<KmipConfig>,
    /// Transform engine configuration
    pub transform: Option<TransformConfig>,
    /// Post-quantum cryptography configuration
    pub pqc: Option<PQCConfig>,
    /// Key rotation configuration
    pub key_rotation: Option<KeyRotationConfig>,
    /// Barrier encryption configuration
    pub barrier: Option<BarrierConfig>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            integration: None,
            kmip: None,
            transform: None,
            pqc: None,
            key_rotation: None,
            barrier: None,
        }
    }
}

/// Crypto integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoIntegrationConfig {
    pub api: ApiConfig,
    pub storage: CryptoStorageConfig,
    pub rate_limit: RateLimitConfig,
    pub performance: PerformanceConfig,
}

impl Default for CryptoIntegrationConfig {
    fn default() -> Self {
        Self {
            api: ApiConfig::default(),
            storage: CryptoStorageConfig::default(),
            rate_limit: RateLimitConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

/// API configuration for crypto
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub port: u16,
    pub host: String,
    pub tls_enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            host: "127.0.0.1".to_string(),
            tls_enabled: false,
            cert_path: None,
            key_path: None,
        }
    }
}

/// Storage configuration for crypto
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoStorageConfig {
    pub backend: String,
    pub path: String,
    pub encryption_enabled: bool,
}

impl Default for CryptoStorageConfig {
    fn default() -> Self {
        Self {
            backend: "file".to_string(),
            path: "./crypto".to_string(),
            encryption_enabled: true,
        }
    }
}

/// Rate limiting configuration for crypto
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_limit: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 1000,
            burst_limit: 100,
        }
    }
}

/// Performance configuration for crypto
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub thread_pool_size: usize,
    pub queue_size: usize,
    pub timeout: u64,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            thread_pool_size: 4,
            queue_size: 1000,
            timeout: 30,
        }
    }
}

/// KMIP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipConfig {
    pub port: u16,
    pub host: String,
    pub tls_enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub ca_cert_path: Option<String>,
    pub client_auth: bool,
}

impl Default for KmipConfig {
    fn default() -> Self {
        Self {
            port: 5696,
            host: "127.0.0.1".to_string(),
            tls_enabled: true,
            cert_path: Some("certs/kmip.crt".to_string()),
            key_path: Some("certs/kmip.key".to_string()),
            ca_cert_path: Some("certs/ca.crt".to_string()),
            client_auth: true,
        }
    }
}

/// Transform engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformConfig {
    pub enabled: bool,
    pub transformations: Vec<String>,
    pub key_derivation: String,
}

impl Default for TransformConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transformations: vec![],
            key_derivation: "pbkdf2".to_string(),
        }
    }
}

/// Post-quantum cryptography configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCConfig {
    pub enabled: bool,
    pub algorithms: Vec<String>,
    pub key_size: usize,
    pub signature_scheme: String,
}

impl Default for PQCConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithms: vec!["kyber512".to_string()],
            key_size: 512,
            signature_scheme: "dilithium2".to_string(),
        }
    }
}

/// Key rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationConfig {
    pub enabled: bool,
    pub interval_days: u32,
    pub max_versions: u32,
    pub auto_rotate: bool,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_days: 90,
            max_versions: 10,
            auto_rotate: true,
        }
    }
}

/// Barrier encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BarrierConfig {
    pub enabled: bool,
    pub algorithm: String,
    pub key_size: usize,
    pub iterations: u32,
}

impl Default for BarrierConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: "aes256-gcm".to_string(),
            key_size: 32,
            iterations: 10000,
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPoliciesConfig {
    /// Rate limiting configuration
    pub rate_limiting: Option<RateLimitConfig>,
    /// Seal configuration
    pub seal: Option<SealConfig>,
    /// Secret scanning configuration
    pub secret_scanning: Option<ScanConfig>,
    /// Control groups configuration
    pub control_groups: Option<ControlGroupConfig>,
    /// Audit streaming configuration
    pub audit_streaming: Option<StreamConfig>,
    /// Quotas configuration
    pub quotas: Option<QuotaConfig>,
}

impl Default for SecurityPoliciesConfig {
    fn default() -> Self {
        Self {
            rate_limiting: None,
            seal: None,
            secret_scanning: None,
            control_groups: None,
            audit_streaming: None,
            quotas: None,
        }
    }
}

/// Seal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealConfig {
    pub seal_type: String,
    pub key_shares: u32,
    pub key_threshold: u32,
    pub pgp_keys: Option<Vec<String>>,
    pub nonce: Option<String>,
}

impl Default for SealConfig {
    fn default() -> Self {
        Self {
            seal_type: "shamir".to_string(),
            key_shares: 5,
            key_threshold: 3,
            pgp_keys: None,
            nonce: None,
        }
    }
}

/// Secret scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub enabled: bool,
    pub scan_interval: u64,
    pub patterns: Vec<String>,
    pub exclude_paths: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval: 3600,
            patterns: vec![],
            exclude_paths: vec![],
        }
    }
}

/// Control groups configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroupConfig {
    pub enabled: bool,
    pub max_requests: u32,
    pub max_time: u64,
    pub groups: Vec<String>,
}

impl Default for ControlGroupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_requests: 100,
            max_time: 60,
            groups: vec![],
        }
    }
}

/// Audit streaming configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub format: String,
    pub buffer_size: usize,
    pub flush_interval: u64,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: String::new(),
            format: "json".to_string(),
            buffer_size: 1000,
            flush_interval: 30,
        }
    }
}

/// Quotas configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaConfig {
    pub enabled: bool,
    pub max_secrets: u32,
    pub max_versions: u32,
    pub rate_limit: u32,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_secrets: 1000,
            max_versions: 100,
            rate_limit: 100,
        }
    }
}

/// Integrations configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationsConfig {
    /// General integration settings
    pub general: Option<IntegrationConfig>,
    /// Advanced backup recovery
    pub backup_recovery: Option<BackupConfig>,
    /// CI/CD pipeline integration
    pub cicd_pipeline: Option<PipelineConfig>,
    /// Distributed tracing
    pub distributed_tracing: Option<TracingConfig>,
    /// Secret migration
    pub secret_migration: Option<BackendConfig>,
    /// Plugin system
    pub plugin: Option<PluginConfig>,
    /// Kubernetes external secrets
    pub kubernetes_external_secrets: Option<ExternalSecretsConfig>,
    /// AWS secrets manager
    pub aws_secrets_manager: Option<AWSSecretsConfig>,
    /// Smart secret recommendations
    pub smart_recommendations: Option<RecommendationConfig>,
    /// Service mesh integration
    pub service_mesh: Option<ServiceMeshConfig>,
    /// Disaster recovery
    pub disaster_recovery: Option<DRConfig>,
    /// Secret performance optimizer
    pub performance_optimizer: Option<CacheConfig>,
    /// Secret discovery and classification
    pub discovery_classification: Option<ScanConfig>,
    /// ACME PKI
    pub acme_pki: Option<ACMEConfig>,
    /// Azure Key Vault backend
    pub azure_key_vault: Option<AzureKeyVaultConfig>,
    /// Certificate revocation
    pub certificate_revocation: Option<CRLConfig>,
    /// Consul service mesh
    pub consul_service_mesh: Option<ConsulConfig>,
}

impl Default for IntegrationsConfig {
    fn default() -> Self {
        Self {
            general: None,
            backup_recovery: None,
            cicd_pipeline: None,
            distributed_tracing: None,
            secret_migration: None,
            plugin: None,
            kubernetes_external_secrets: None,
            aws_secrets_manager: None,
            smart_recommendations: None,
            service_mesh: None,
            disaster_recovery: None,
            performance_optimizer: None,
            discovery_classification: None,
            acme_pki: None,
            azure_key_vault: None,
            certificate_revocation: None,
            consul_service_mesh: None,
        }
    }
}

/// General integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub enabled: bool,
    pub timeout: u64,
    pub retry_count: u32,
    pub retry_delay: u64,
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout: 30,
            retry_count: 3,
            retry_delay: 5,
        }
    }
}

/// Advanced backup recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub enabled: bool,
    pub schedule: String,
    pub retention_days: u32,
    pub compression: bool,
    pub encryption: bool,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: "0 2 * * *".to_string(),
            retention_days: 30,
            compression: true,
            encryption: true,
        }
    }
}

/// CI/CD pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub enabled: bool,
    pub providers: Vec<String>,
    pub webhook_url: String,
    pub secret_prefix: String,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            providers: vec![],
            webhook_url: String::new(),
            secret_prefix: "SECRETON_".to_string(),
        }
    }
}

/// Secret migration backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub source_backend: String,
    pub target_backend: String,
    pub batch_size: usize,
    pub concurrency: usize,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            source_backend: String::new(),
            target_backend: String::new(),
            batch_size: 100,
            concurrency: 4,
        }
    }
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
    pub directory: String,
    pub allowed_plugins: Vec<String>,
    pub sandbox_enabled: bool,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory: "./plugins".to_string(),
            allowed_plugins: vec![],
            sandbox_enabled: true,
        }
    }
}

/// Kubernetes external secrets configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalSecretsConfig {
    pub enabled: bool,
    pub namespace: String,
    pub service_account: String,
    pub cluster_role: String,
}

impl Default for ExternalSecretsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            namespace: "external-secrets-system".to_string(),
            service_account: "external-secrets-sa".to_string(),
            cluster_role: "external-secrets-role".to_string(),
        }
    }
}

/// AWS secrets manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AWSSecretsConfig {
    pub enabled: bool,
    pub region: String,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub rotation: AwsSecretsRotationConfig,
}

impl Default for AWSSecretsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            region: "us-east-1".to_string(),
            access_key: None,
            secret_key: None,
            rotation: AwsSecretsRotationConfig::default(),
        }
    }
}

/// AWS secrets rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsSecretsRotationConfig {
    pub enabled: bool,
    pub interval_days: u32,
    pub max_versions: u32,
}

impl Default for AwsSecretsRotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_days: 90,
            max_versions: 10,
        }
    }
}

/// Smart secret recommendations configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationConfig {
    pub enabled: bool,
    pub min_confidence: f64,
    pub max_suggestions: usize,
    pub categories: Vec<String>,
}

impl Default for RecommendationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_confidence: 0.8,
            max_suggestions: 10,
            categories: vec!["security".to_string(), "performance".to_string()],
        }
    }
}

/// Service mesh configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMeshConfig {
    pub enabled: bool,
    pub provider: String,
    pub spiffe: SPIFFEConfig,
}

impl Default for ServiceMeshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "istio".to_string(),
            spiffe: SPIFFEConfig::default(),
        }
    }
}

/// SPIFFE configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SPIFFEConfig {
    pub trust_domain: String,
    pub workload_api_socket: String,
    pub svid_ttl: u64,
}

impl Default for SPIFFEConfig {
    fn default() -> Self {
        Self {
            trust_domain: "example.org".to_string(),
            workload_api_socket: "unix:///tmp/spire-agent/public/api.sock".to_string(),
            svid_ttl: 3600,
        }
    }
}

/// Disaster recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRConfig {
    pub enabled: bool,
    pub primary_cluster: String,
    pub secondary_clusters: Vec<String>,
    pub replication_interval: u64,
}

impl Default for DRConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            primary_cluster: String::new(),
            secondary_clusters: vec![],
            replication_interval: 60,
        }
    }
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub ttl: u64,
    pub max_size: usize,
    pub eviction_policy: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl: 3600,
            max_size: 10000,
            eviction_policy: "lru".to_string(),
        }
    }
}

/// ACME PKI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ACMEConfig {
    pub enabled: bool,
    pub directory_url: String,
    pub email: String,
    pub dns_provider: String,
}

impl Default for ACMEConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            email: String::new(),
            dns_provider: "route53".to_string(),
        }
    }
}

/// Azure Key Vault configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureKeyVaultConfig {
    pub enabled: bool,
    pub vault_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub tenant_id: String,
    pub sync: SyncConfig,
}

impl Default for AzureKeyVaultConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            vault_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            tenant_id: String::new(),
            sync: SyncConfig::default(),
        }
    }
}

/// Sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    pub enabled: bool,
    pub interval: u64,
    pub batch_size: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: 300,
            batch_size: 100,
        }
    }
}

/// Certificate revocation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CRLConfig {
    pub enabled: bool,
    pub expiry: u64,
    pub disable: bool,
    pub ocsp_disable: bool,
    pub ocsp_expiry: u64,
}

impl Default for CRLConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            expiry: 168,
            disable: false,
            ocsp_disable: false,
            ocsp_expiry: 168,
        }
    }
}

/// Consul service mesh configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulConfig {
    pub enabled: bool,
    pub address: String,
    pub token: Option<String>,
    pub datacenter: String,
    pub scheme: String,
}

impl Default for ConsulConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: "127.0.0.1:8500".to_string(),
            token: None,
            datacenter: "dc1".to_string(),
            scheme: "http".to_string(),
        }
    }
}

/// Main application configuration (extended)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Server configuration
    pub server: ServerConfig,
    /// Database configuration
    pub database: DatabaseConfig,
    /// Authentication configuration
    pub auth: AuthConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Metrics configuration
    pub metrics: MetricsConfig,
    /// Authentication methods configuration
    pub auth_methods: AuthMethodsConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Infrastructure configuration
    pub infrastructure: InfrastructureConfig,
    /// Crypto configuration
    pub crypto: CryptoConfig,
    /// Security policies configuration
    pub security_policies: SecurityPoliciesConfig,
    /// Integrations configuration
    pub integrations: IntegrationsConfig,
    /// Additional custom configuration
    pub custom: HashMap<String, serde_json::Value>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            auth: AuthConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            metrics: MetricsConfig::default(),
            auth_methods: AuthMethodsConfig::default(),
            storage: StorageConfig::default(),
            infrastructure: InfrastructureConfig::default(),
            crypto: CryptoConfig::default(),
            security_policies: SecurityPoliciesConfig::default(),
            integrations: IntegrationsConfig::default(),
            custom: HashMap::new(),
        }
    }
}

impl Config for AppConfig {
    fn validate(&self) -> SecretonResult<()> {
        // Validate server config
        if self.server.port == 0 {
            return Err(SecretonError::Validation {
                message: "Server port cannot be 0".to_string(),
            });
        }

        // Validate database config
        if self.database.url.is_empty() {
            return Err(SecretonError::Validation {
                message: "Database URL cannot be empty".to_string(),
            });
        }

        // Validate auth config
        if self.auth.jwt_secret.len() < 32 {
            return Err(SecretonError::Validation {
                message: "JWT secret must be at least 32 characters".to_string(),
            });
        }

        // Validate security config
        if self.security.encryption_key.len() < 32 {
            return Err(SecretonError::Validation {
                message: "Encryption key must be at least 32 characters".to_string(),
            });
        }

        Ok(())
    }
}

/// Configuration utilities
pub mod utils {
    use super::*;

    /// Load configuration from multiple sources with precedence
    pub fn load_config<T: Config>(config_paths: &[&str]) -> SecretonResult<T> {
        let mut builder = config::Config::builder();

        // Add default configuration
        builder = builder.add_source(config::File::from_str(
            &toml::to_string(&T::default()).unwrap(),
            config::FileFormat::Toml,
        ));

        // Add configuration files in order
        for path in config_paths {
            builder = builder.add_source(
                config::File::with_name(path).required(false)
            );
        }

        // Add environment variables
        builder = builder.add_source(
            config::Environment::with_prefix("SECRETON")
                .separator("_")
        );

        let settings = builder.build().map_err(|e| {
            SecretonError::Configuration {
                message: format!("Failed to build configuration: {}", e),
            }
        })?;

        let config: T = settings.try_deserialize().map_err(|e| {
            SecretonError::Configuration {
                message: format!("Failed to deserialize configuration: {}", e),
            }
        })?;

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a file
    pub fn save_config<T: Config>(config: &T, path: &str) -> SecretonResult<()> {
        let toml_string = toml::to_string_pretty(config)
            .map_err(|e| SecretonError::TomlSerialization(e))?;

        fs::write(path, toml_string)
            .map_err(|e| SecretonError::Io(e))?;

        Ok(())
    }

    /// Get configuration value from environment or default
    pub fn get_env_or_default(key: &str, default: &str) -> String {
        env::var(key).unwrap_or_else(|_| default.to_string())
    }

    /// Get configuration value from environment as u16 or default
    pub fn get_env_u16_or_default(key: &str, default: u16) -> u16 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Get configuration value from environment as bool or default
    pub fn get_env_bool_or_default(key: &str, default: bool) -> bool {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }
}