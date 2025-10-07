//! SSH Secrets Engine
//!
//! Manages SSH credentials with dynamic generation and automatic rotation.
//! Supports one-time passwords (OTP), dynamic key generation, and certificate authority.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Error types for SSH engine
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("SSH role not found: {0}")]
    RoleNotFound(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("OTP generation failed: {0}")]
    OtpFailed(String),
    
    #[error("Certificate signing failed: {0}")]
    SigningFailed(String),
    
    #[error("Invalid key type: {0}")]
    InvalidKeyType(String),
}

/// SSH credential type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SshCredentialType {
    /// One-time password
    OTP,
    
    /// Dynamic SSH key pair
    DynamicKey,
    
    /// SSH certificate signed by CA
    Certificate,
}

/// SSH key type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SshKeyType {
    RSA2048,
    RSA4096,
    ECDSA256,
    ECDSA384,
    ECDSA521,
    Ed25519,
}

impl SshKeyType {
    pub fn as_str(&self) -> &str {
        match self {
            SshKeyType::RSA2048 => "rsa-2048",
            SshKeyType::RSA4096 => "rsa-4096",
            SshKeyType::ECDSA256 => "ecdsa-256",
            SshKeyType::ECDSA384 => "ecdsa-384",
            SshKeyType::ECDSA521 => "ecdsa-521",
            SshKeyType::Ed25519 => "ed25519",
        }
    }
}

/// SSH role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshRole {
    /// Role name
    pub name: String,
    
    /// Credential type
    pub credential_type: SshCredentialType,
    
    /// Default user for SSH connections
    pub default_user: String,
    
    /// Allowed users
    pub allowed_users: Vec<String>,
    
    /// Default TTL in seconds
    pub default_ttl: u32,
    
    /// Maximum TTL
    pub max_ttl: u32,
    
    /// Key type (for dynamic keys and certificates)
    pub key_type: SshKeyType,
    
    /// Allowed CIDR blocks
    pub cidr_list: Vec<String>,
    
    /// Excluded CIDR blocks
    pub exclude_cidr_list: Vec<String>,
    
    /// Port for SSH
    pub port: u16,
    
    /// Install script (for OTP)
    pub install_script: Option<String>,
    
    /// Key bits (deprecated, use key_type)
    pub key_bits: u32,
    
    /// Algorithm signer (CA name for certificates)
    pub algorithm_signer: Option<String>,
    
    /// Allowed extensions (for certificates)
    pub allowed_extensions: HashMap<String, String>,
    
    /// Default extensions
    pub default_extensions: HashMap<String, String>,
    
    /// Allowed critical options
    pub allowed_critical_options: HashMap<String, String>,
    
    /// Default critical options
    pub default_critical_options: HashMap<String, String>,
}

impl Default for SshRole {
    fn default() -> Self {
        Self {
            name: String::new(),
            credential_type: SshCredentialType::DynamicKey,
            default_user: "ubuntu".to_string(),
            allowed_users: vec!["*".to_string()],
            default_ttl: 3600,
            max_ttl: 86400,
            key_type: SshKeyType::RSA2048,
            cidr_list: vec!["0.0.0.0/0".to_string()],
            exclude_cidr_list: Vec::new(),
            port: 22,
            install_script: None,
            key_bits: 2048,
            algorithm_signer: None,
            allowed_extensions: HashMap::new(),
            default_extensions: HashMap::new(),
            allowed_critical_options: HashMap::new(),
            default_critical_options: HashMap::new(),
        }
    }
}

/// SSH CA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCaConfig {
    /// CA name
    pub name: String,
    
    /// Public key
    pub public_key: String,
    
    /// Private key (encrypted)
    pub private_key: String,
    
    /// Key type
    pub key_type: SshKeyType,
    
    /// Generated at
    pub generated_at: DateTime<Utc>,
}

/// Generated SSH credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCredentials {
    /// Credential ID
    pub id: String,
    
    /// Username
    pub username: String,
    
    /// IP address
    pub ip: String,
    
    /// Port
    pub port: u16,
    
    /// SSH private key (for dynamic keys)
    pub private_key: Option<String>,
    
    /// SSH public key
    pub public_key: Option<String>,
    
    /// OTP (for OTP credentials)
    pub otp: Option<String>,
    
    /// Certificate (for certificate-based auth)
    pub certificate: Option<String>,
    
    /// Key type
    pub key_type: String,
    
    /// Created at
    pub created_at: DateTime<Utc>,
    
    /// Expires at
    pub expires_at: DateTime<Utc>,
    
    /// Role used
    pub role_name: String,
}

/// One-time password entry
#[derive(Debug, Clone)]
struct OtpEntry {
    username: String,
    ip: String,
    otp: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// SSH secrets engine
pub struct SshEngine {
    roles: Arc<RwLock<HashMap<String, SshRole>>>,
    cas: Arc<RwLock<HashMap<String, SshCaConfig>>>,
    credentials: Arc<RwLock<HashMap<String, SshCredentials>>>,
    otps: Arc<RwLock<HashMap<String, OtpEntry>>>,
}

impl SshEngine {
    /// Create new SSH engine
    pub fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
            cas: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
            otps: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Create SSH role
    pub async fn create_role(&self, role: SshRole) -> Result<(), SshError> {
        if role.name.is_empty() {
            return Err(SshError::InvalidConfig("Role name cannot be empty".to_string()));
        }
        
        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);
        Ok(())
    }
    
    /// Generate SSH CA
    pub async fn generate_ca(
        &self,
        name: String,
        key_type: SshKeyType,
    ) -> Result<SshCaConfig, SshError> {
        // Generate key pair (simplified - production would use proper SSH key generation)
        let (public_key, private_key) = self.generate_ssh_keypair(&key_type)?;
        
        let ca = SshCaConfig {
            name: name.clone(),
            public_key,
            private_key,
            key_type,
            generated_at: Utc::now(),
        };
        
        let mut cas = self.cas.write().await;
        cas.insert(name, ca.clone());
        
        Ok(ca)
    }
    
    /// Generate credentials for role
    pub async fn generate_credentials(
        &self,
        role_name: &str,
        username: &str,
        ip: &str,
        ttl: Option<u32>,
    ) -> Result<SshCredentials, SshError> {
        // Get role
        let roles = self.roles.read().await;
        let role = roles.get(role_name)
            .ok_or_else(|| SshError::RoleNotFound(role_name.to_string()))?
            .clone();
        drop(roles);
        
        // Validate username
        if !role.allowed_users.contains(&"*".to_string()) 
            && !role.allowed_users.contains(&username.to_string()) {
            return Err(SshError::InvalidConfig(
                format!("User {} not allowed for role {}", username, role_name)
            ));
        }
        
        // Determine TTL
        let credential_ttl = ttl.unwrap_or(role.default_ttl).min(role.max_ttl);
        
        let now = Utc::now();
        let expires_at = now + Duration::seconds(credential_ttl as i64);
        
        let credentials = match role.credential_type {
            SshCredentialType::OTP => {
                self.generate_otp_credentials(
                    role_name,
                    username,
                    ip,
                    role.port,
                    now,
                    expires_at,
                ).await?
            }
            SshCredentialType::DynamicKey => {
                self.generate_dynamic_key_credentials(
                    role_name,
                    username,
                    ip,
                    role.port,
                    &role.key_type,
                    now,
                    expires_at,
                ).await?
            }
            SshCredentialType::Certificate => {
                self.generate_certificate_credentials(
                    &role,
                    username,
                    ip,
                    now,
                    expires_at,
                ).await?
            }
        };
        
        // Store credentials
        let mut creds_store = self.credentials.write().await;
        creds_store.insert(credentials.id.clone(), credentials.clone());
        
        Ok(credentials)
    }
    
    /// Generate OTP credentials
    async fn generate_otp_credentials(
        &self,
        role_name: &str,
        username: &str,
        ip: &str,
        port: u16,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<SshCredentials, SshError> {
        // Generate OTP
        let otp = self.generate_otp();
        
        // Store OTP for verification
        let otp_entry = OtpEntry {
            username: username.to_string(),
            ip: ip.to_string(),
            otp: otp.clone(),
            created_at,
            expires_at,
        };
        
        let mut otps = self.otps.write().await;
        otps.insert(otp.clone(), otp_entry);
        
        Ok(SshCredentials {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            ip: ip.to_string(),
            port,
            private_key: None,
            public_key: None,
            otp: Some(otp),
            certificate: None,
            key_type: "otp".to_string(),
            created_at,
            expires_at,
            role_name: role_name.to_string(),
        })
    }
    
    /// Generate dynamic key credentials
    async fn generate_dynamic_key_credentials(
        &self,
        role_name: &str,
        username: &str,
        ip: &str,
        port: u16,
        key_type: &SshKeyType,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<SshCredentials, SshError> {
        // Generate SSH key pair
        let (public_key, private_key) = self.generate_ssh_keypair(key_type)?;
        
        Ok(SshCredentials {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            ip: ip.to_string(),
            port,
            private_key: Some(private_key),
            public_key: Some(public_key),
            otp: None,
            certificate: None,
            key_type: key_type.as_str().to_string(),
            created_at,
            expires_at,
            role_name: role_name.to_string(),
        })
    }
    
    /// Generate certificate credentials
    async fn generate_certificate_credentials(
        &self,
        role: &SshRole,
        username: &str,
        ip: &str,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<SshCredentials, SshError> {
        // Get CA
        let ca_name = role.algorithm_signer.as_ref()
            .ok_or_else(|| SshError::InvalidConfig("No CA configured for role".to_string()))?;
        
        let cas = self.cas.read().await;
        let ca = cas.get(ca_name)
            .ok_or_else(|| SshError::InvalidConfig(format!("CA {} not found", ca_name)))?
            .clone();
        drop(cas);
        
        // Generate key pair for user
        let (public_key, private_key) = self.generate_ssh_keypair(&role.key_type)?;
        
        // Sign public key with CA to create certificate
        let certificate = self.sign_ssh_certificate(
            &ca,
            &public_key,
            username,
            &expires_at,
            &role.default_extensions,
            &role.default_critical_options,
        )?;
        
        Ok(SshCredentials {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            ip: ip.to_string(),
            port: role.port,
            private_key: Some(private_key),
            public_key: Some(public_key),
            otp: None,
            certificate: Some(certificate),
            key_type: role.key_type.as_str().to_string(),
            created_at,
            expires_at,
            role_name: role.name.clone(),
        })
    }
    
    /// Generate SSH key pair
    fn generate_ssh_keypair(&self, key_type: &SshKeyType) -> Result<(String, String), SshError> {
        // Simplified key generation (production would use proper SSH key libraries)
        let key_id = Uuid::new_v4().to_string();
        
        let public_key = format!(
            "ssh-{} AAAAB3NzaC1{}... secreton-{}",
            key_type.as_str(),
            key_type.as_str(),
            &key_id[..8]
        );
        
        let private_key = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n\
             [Private key data for {}]\n\
             -----END OPENSSH PRIVATE KEY-----",
            key_type.as_str()
        );
        
        Ok((public_key, private_key))
    }
    
    /// Generate OTP
    fn generate_otp(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Generate 8-character alphanumeric OTP
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..8)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
    
    /// Sign SSH certificate with CA
    fn sign_ssh_certificate(
        &self,
        _ca: &SshCaConfig,
        public_key: &str,
        username: &str,
        expires_at: &DateTime<Utc>,
        _extensions: &HashMap<String, String>,
        _critical_options: &HashMap<String, String>,
    ) -> Result<String, SshError> {
        // Simplified certificate generation (production would use proper SSH cert signing)
        let cert = format!(
            "ssh-rsa-cert-v01@openssh.com AAAAB3...\n\
             Type: ssh-rsa-cert-v01@openssh.com user certificate\n\
             Public key: {}\n\
             Principals: {}\n\
             Valid: from now to {}\n\
             Signature: [CA signature]",
            public_key,
            username,
            expires_at.to_rfc3339()
        );
        
        Ok(cert)
    }
    
    /// Verify OTP
    pub async fn verify_otp(&self, otp: &str, username: &str, ip: &str) -> Result<bool, SshError> {
        let otps = self.otps.read().await;
        
        if let Some(entry) = otps.get(otp) {
            let now = Utc::now();
            
            if now > entry.expires_at {
                return Ok(false);
            }
            
            if entry.username != username || entry.ip != ip {
                return Ok(false);
            }
            
            return Ok(true);
        }
        
        Ok(false)
    }
    
    /// Revoke credentials
    pub async fn revoke_credentials(&self, credential_id: &str) -> Result<(), SshError> {
        let mut credentials = self.credentials.write().await;
        credentials.remove(credential_id);
        Ok(())
    }
    
    /// List roles
    pub async fn list_roles(&self) -> Vec<String> {
        let roles = self.roles.read().await;
        roles.keys().cloned().collect()
    }
    
    /// Get CA public key
    pub async fn get_ca_public_key(&self, ca_name: &str) -> Result<String, SshError> {
        let cas = self.cas.read().await;
        let ca = cas.get(ca_name)
            .ok_or_else(|| SshError::InvalidConfig(format!("CA {} not found", ca_name)))?;
        Ok(ca.public_key.clone())
    }
    
    /// Cleanup expired credentials
    pub async fn cleanup_expired(&self) -> usize {
        let mut count = 0;
        let now = Utc::now();
        
        // Cleanup OTPs
        let mut otps = self.otps.write().await;
        let expired_otps: Vec<String> = otps.iter()
            .filter(|(_, entry)| now > entry.expires_at)
            .map(|(otp, _)| otp.clone())
            .collect();
        
        count += expired_otps.len();
        for otp in expired_otps {
            otps.remove(&otp);
        }
        drop(otps);
        
        // Cleanup credentials
        let mut credentials = self.credentials.write().await;
        let expired_creds: Vec<String> = credentials.iter()
            .filter(|(_, cred)| now > cred.expires_at)
            .map(|(id, _)| id.clone())
            .collect();
        
        count += expired_creds.len();
        for id in expired_creds {
            credentials.remove(&id);
        }
        
        count
    }
}

impl Default for SshEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_role() {
        let engine = SshEngine::new();
        
        let role = SshRole {
            name: "web-servers".to_string(),
            credential_type: SshCredentialType::DynamicKey,
            default_user: "ubuntu".to_string(),
            ..Default::default()
        };
        
        let result = engine.create_role(role).await;
        assert!(result.is_ok());
        assert_eq!(engine.list_roles().await.len(), 1);
    }
    
    #[tokio::test]
    async fn test_generate_ca() {
        let engine = SshEngine::new();
        
        let ca = engine.generate_ca(
            "ssh-ca".to_string(),
            SshKeyType::Ed25519,
        ).await.unwrap();
        
        assert_eq!(ca.name, "ssh-ca");
        assert!(!ca.public_key.is_empty());
        assert!(!ca.private_key.is_empty());
    }
    
    #[tokio::test]
    async fn test_generate_otp_credentials() {
        let engine = SshEngine::new();
        
        let role = SshRole {
            name: "otp-role".to_string(),
            credential_type: SshCredentialType::OTP,
            default_user: "ubuntu".to_string(),
            ..Default::default()
        };
        engine.create_role(role).await.unwrap();
        
        let creds = engine.generate_credentials(
            "otp-role",
            "ubuntu",
            "192.168.1.100",
            None,
        ).await.unwrap();
        
        assert!(creds.otp.is_some());
        assert_eq!(creds.otp.as_ref().unwrap().len(), 8);
    }
    
    #[tokio::test]
    async fn test_generate_dynamic_key_credentials() {
        let engine = SshEngine::new();
        
        let role = SshRole {
            name: "dynamic-role".to_string(),
            credential_type: SshCredentialType::DynamicKey,
            key_type: SshKeyType::RSA2048,
            ..Default::default()
        };
        engine.create_role(role).await.unwrap();
        
        let creds = engine.generate_credentials(
            "dynamic-role",
            "ubuntu",
            "192.168.1.100",
            None,
        ).await.unwrap();
        
        assert!(creds.private_key.is_some());
        assert!(creds.public_key.is_some());
        assert!(creds.private_key.as_ref().unwrap().contains("BEGIN OPENSSH PRIVATE KEY"));
    }
    
    #[tokio::test]
    async fn test_verify_otp() {
        let engine = SshEngine::new();
        
        let role = SshRole {
            name: "otp-role".to_string(),
            credential_type: SshCredentialType::OTP,
            ..Default::default()
        };
        engine.create_role(role).await.unwrap();
        
        let creds = engine.generate_credentials(
            "otp-role",
            "testuser",
            "192.168.1.1",
            None,
        ).await.unwrap();
        
        let otp = creds.otp.as_ref().unwrap();
        
        // Should verify successfully
        let valid = engine.verify_otp(otp, "testuser", "192.168.1.1").await.unwrap();
        assert!(valid);
        
        // Wrong username should fail
        let invalid = engine.verify_otp(otp, "wronguser", "192.168.1.1").await.unwrap();
        assert!(!invalid);
    }
}
