//! PKI models and data structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PKI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiConfig {
    /// Default lease TTL for certificates
    pub default_lease_ttl: i64,
    /// Maximum lease TTL for certificates
    pub max_lease_ttl: i64,
    /// Certificate authority certificate
    pub ca_cert: Option<String>,
    /// Certificate authority private key
    pub ca_key: Option<String>,
    /// Certificate revocation list
    pub crl: Option<String>,
}

/// Certificate request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    /// Common name
    pub common_name: String,
    /// Alternative names (DNS names, IP addresses)
    #[serde(default)]
    pub alt_names: Vec<String>,
    /// IP addresses
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    /// Email addresses
    #[serde(default)]
    pub email_addresses: Vec<String>,
    /// Organization
    pub organization: Option<String>,
    /// Organizational unit
    pub organizational_unit: Option<String>,
    /// Country
    pub country: Option<String>,
    /// State/province
    pub state: Option<String>,
    /// Locality
    pub locality: Option<String>,
    /// Key usage extensions
    #[serde(default)]
    pub key_usages: Vec<String>,
    /// Extended key usage extensions
    #[serde(default)]
    pub extended_key_usages: Vec<String>,
    /// TTL in seconds
    pub ttl: Option<i64>,
}

/// Certificate response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResponse {
    /// Certificate in PEM format
    pub certificate: String,
    /// Private key in PEM format
    pub private_key: String,
    /// Certificate serial number
    pub serial_number: String,
    /// Issuing CA certificate
    pub issuing_ca: String,
    /// CA chain
    pub ca_chain: Vec<String>,
    /// Expiration time
    pub expiration: DateTime<Utc>,
    /// Revocation time (if revoked)
    pub revocation_time: Option<DateTime<Utc>>,
}

/// SSH key types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SshKeyType {
    Rsa,
    Ed25519,
    Ecdsa,
}

impl std::fmt::Display for SshKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshKeyType::Rsa => write!(f, "rsa"),
            SshKeyType::Ed25519 => write!(f, "ed25519"),
            SshKeyType::Ecdsa => write!(f, "ecdsa"),
        }
    }
}

/// SSH key request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyRequest {
    /// Key type
    pub key_type: SshKeyType,
    /// Key size (for RSA)
    pub key_size: Option<usize>,
    /// TTL in seconds
    pub ttl: Option<i64>,
    /// Username for SSH certificate
    pub username: String,
    /// Valid principals
    pub valid_principals: Vec<String>,
}

/// SSH key response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyResponse {
    /// Private key
    pub private_key: String,
    /// Public key
    pub public_key: String,
    /// Certificate (if signed)
    pub certificate: Option<String>,
    /// Key type
    pub key_type: SshKeyType,
    /// Expiration time
    pub expiration: Option<DateTime<Utc>>,
}

/// Certificate revocation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// Certificate serial number
    pub serial_number: String,
    /// Reason for revocation
    pub reason: RevocationReason,
}

/// Certificate revocation reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

/// CRL (Certificate Revocation List) response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlResponse {
    /// CRL in PEM format
    pub crl: String,
    /// Last update time
    pub last_update: DateTime<Utc>,
    /// Next update time
    pub next_update: DateTime<Utc>,
}

/// CA information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaInfo {
    /// CA certificate
    pub certificate: String,
    /// CA public key
    pub public_key: String,
    /// Key type
    pub key_type: String,
    /// Key size/bits
    pub key_bits: usize,
    /// Signature algorithm
    pub signature_algorithm: String,
    /// Subject information
    pub subject: HashMap<String, String>,
    /// Issuer information
    pub issuer: HashMap<String, String>,
    /// Valid from
    pub valid_from: DateTime<Utc>,
    /// Valid until
    pub valid_until: DateTime<Utc>,
}
