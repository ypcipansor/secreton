//! Data models and DTOs for secret engines

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Core secret data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub path: String,
    pub data: HashMap<String, serde_json::Value>,
    pub metadata: SecretMetadata,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Secret metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretMetadata {
    pub version: u64,
    pub created_by: String,
    pub updated_by: String,
    pub lease_id: Option<String>,
    pub lease_duration: Option<u64>,
    pub tags: HashMap<String, String>,
}

/// Secret version for versioning support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub version: u64,
    pub data: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub deleted: bool,
}

/// Lease information for dynamic secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub id: String,
    pub path: String,
    pub data: HashMap<String, serde_json::Value>,
    pub issue_time: DateTime<Utc>,
    pub expire_time: DateTime<Utc>,
    pub renewable: bool,
}

/// Engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub name: String,
    pub engine_type: EngineType,
    pub config: HashMap<String, serde_json::Value>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Supported secret engine types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EngineType {
    Kv,
    Transit,
    Database,
    Aws,
    Pki,
    Ssh,
    Totp,
    Rabbitmq,
    Mongodb,
    Ldap,
}

/// Key-value secret engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvConfig {
    pub version: KvVersion,
    pub max_versions: u32,
    pub cas_required: bool,
    pub delete_version_after: Option<u64>,
}

/// KV engine versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KvVersion {
    V1,
    V2,
}

/// Transit engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitConfig {
    pub default_key_type: KeyType,
    pub allow_plaintext_backup: bool,
    pub enforce_sign_verify: bool,
}

/// Supported key types for transit engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
    Aes128Gcm96,
    Aes256Gcm96,
    ChaCha20Poly1305,
}

/// Database engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default)]
    pub plugin_name: String,
    pub connection_url: String,
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub max_open_connections: Option<u32>,
    pub max_idle_connections: Option<u32>,
    pub max_connection_lifetime: Option<u64>,
}

/// AWS engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    pub iam_endpoint: Option<String>,
    pub sts_endpoint: Option<String>,
    pub max_retries: Option<u32>,
    pub default_lease_ttl: u64,
}

/// PKI engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiConfig {
    pub default_lease_ttl: u64,
    pub max_lease_ttl: u64,
    pub ca_private_key: Option<String>,
    pub ca_cert: Option<String>,
    pub enable_acme: bool,
}

/// SSH engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub default_lease_ttl: u64,
    pub max_lease_ttl: u64,
    pub allowed_users: Vec<String>,
    pub allowed_extensions: Vec<String>,
}

/// TOTP engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    pub issuer: String,
    pub period: u32,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
}

/// TOTP algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// RabbitMQ engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitmqConfig {
    pub connection_uri: String,
    pub username: String,
    pub password: String,
    pub vhost: Option<String>,
    pub verify_connection: bool,
    pub default_lease_ttl: u64,
}

/// MongoDB engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongodbConfig {
    pub connection_uri: String,
    pub username: String,
    pub password: String,
    pub verify_connection: bool,
    pub default_lease_ttl: u64,
}

/// LDAP engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_dn: String,
    pub user_attr: String,
    pub group_dn: Option<String>,
    pub group_attr: Option<String>,
    pub certificate: Option<String>,
    pub insecure_tls: bool,
    pub starttls: bool,
    pub default_lease_ttl: u64,
}
