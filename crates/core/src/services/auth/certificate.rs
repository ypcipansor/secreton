//! Certificate Authentication Method
//!
//! mTLS (mutual TLS) certificate-based authentication for Secreton.
//! Authenticates clients using X.509 certificates.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use x509_parser::prelude::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as base64};

use crate::models::auth::{AuthRequest, AuthResponse, UserInfo};

/// Error types for Certificate authentication
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("Certificate parse error: {0}")]
    ParseError(String),
    
    #[error("Certificate validation failed: {0}")]
    ValidationFailed(String),
    
    #[error("Certificate not found for subject: {0}")]
    NotFound(String),
    
    #[error("Certificate expired")]
    Expired,
    
    #[error("Certificate not yet valid")]
    NotYetValid,
    
    #[error("Certificate revoked")]
    Revoked,
    
    #[error("Untrusted certificate authority")]
    UntrustedCA,
    
    #[error("Invalid certificate chain")]
    InvalidChain,
}

/// Certificate authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertConfig {
    /// Trusted CA certificates (PEM format)
    pub trusted_cas: Vec<String>,
    
    /// Certificate revocation list (CRL)
    pub crl: Vec<String>,
    
    /// Require client certificate
    pub require_client_cert: bool,
    
    /// Allowed certificate key usages
    pub allowed_key_usages: Vec<String>,
    
    /// Allowed certificate extended key usages
    pub allowed_ext_key_usages: Vec<String>,
    
    /// Certificate metadata bound to policies
    pub cert_policies: HashMap<String, Vec<String>>,
    
    /// Token TTL in seconds
    pub token_ttl: u32,
    
    /// Maximum token TTL
    pub token_max_ttl: u32,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            trusted_cas: Vec::new(),
            crl: Vec::new(),
            require_client_cert: true,
            allowed_key_usages: vec![
                "DigitalSignature".to_string(),
                "KeyEncipherment".to_string(),
            ],
            allowed_ext_key_usages: vec![
                "ClientAuth".to_string(),
            ],
            cert_policies: HashMap::new(),
            token_ttl: 3600,
            token_max_ttl: 86400,
        }
    }
}

/// Certificate subject information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSubject {
    /// Common Name (CN)
    pub common_name: String,
    
    /// Organization (O)
    pub organization: Option<String>,
    
    /// Organizational Unit (OU)
    pub organizational_unit: Option<String>,
    
    /// Country (C)
    pub country: Option<String>,
    
    /// State/Province (ST)
    pub state: Option<String>,
    
    /// Locality (L)
    pub locality: Option<String>,
    
    /// Email
    pub email: Option<String>,
    
    /// Serial number
    pub serial_number: String,
    
    /// Issuer
    pub issuer: String,
    
    /// Valid from
    pub not_before: DateTime<Utc>,
    
    /// Valid until
    pub not_after: DateTime<Utc>,
    
    /// Subject Alternative Names (SANs)
    pub sans: Vec<String>,
}

/// Certificate authentication service
pub struct CertAuth {
    config: Arc<RwLock<CertConfig>>,
    revoked_serials: Arc<RwLock<Vec<String>>>,
}

impl CertAuth {
    /// Create new certificate authentication service
    pub fn new(config: CertConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            revoked_serials: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    /// Parse certificate from PEM format
    pub fn parse_certificate(&self, pem_data: &str) -> Result<CertificateSubject, CertError> {
        // Remove PEM headers/footers and decode base64
        let pem_lines: Vec<&str> = pem_data
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let pem_body = pem_lines.join("");
        
        let der_data = base64.decode(&pem_body)
            .map_err(|e| CertError::ParseError(format!("Base64 decode error: {}", e)))?;
        
        let (_, cert) = X509Certificate::from_der(&der_data)
            .map_err(|e| CertError::ParseError(format!("DER parse error: {}", e)))?;
        
        // Extract subject information
        let subject = cert.subject();
        let common_name = subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("unknown")
            .to_string();
        
        let organization = subject
            .iter_organization()
            .next()
            .and_then(|o| o.as_str().ok())
            .map(|s| s.to_string());
        
        let organizational_unit = subject
            .iter_organizational_unit()
            .next()
            .and_then(|ou| ou.as_str().ok())
            .map(|s| s.to_string());
        
        let country = subject
            .iter_country()
            .next()
            .and_then(|c| c.as_str().ok())
            .map(|s| s.to_string());
        
        let state = subject
            .iter_state_or_province()
            .next()
            .and_then(|st| st.as_str().ok())
            .map(|s| s.to_string());
        
        let locality = subject
            .iter_locality()
            .next()
            .and_then(|l| l.as_str().ok())
            .map(|s| s.to_string());
        
        // Extract email from SAN extension
        let mut sans = Vec::new();
        let mut email = None;
        
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for san in &san_ext.value.general_names {
                match san {
                    GeneralName::RFC822Name(e) => {
                        if email.is_none() {
                            email = Some(e.to_string());
                        }
                        sans.push(format!("email:{}", e));
                    }
                    GeneralName::DNSName(dns) => {
                        sans.push(format!("dns:{}", dns));
                    }
                    GeneralName::IPAddress(ip) => {
                        sans.push(format!("ip:{}", hex::encode(ip)));
                    }
                    _ => {}
                }
            }
        }
        
        let serial_number = cert
            .serial
            .to_str_radix(16);
        
        let issuer = cert.issuer().to_string();
        
        let not_before = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .unwrap_or_else(|| Utc::now());
        let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or_else(|| Utc::now());
        
        Ok(CertificateSubject {
            common_name,
            organization,
            organizational_unit,
            country,
            state,
            locality,
            email,
            serial_number,
            issuer,
            not_before,
            not_after,
            sans,
        })
    }
    
    /// Validate certificate
    pub async fn validate_certificate(&self, cert: &CertificateSubject) -> Result<(), CertError> {
        let config = self.config.read().await;
        let revoked = self.revoked_serials.read().await;
        
        // Check expiration
        let now = Utc::now();
        if now < cert.not_before {
            return Err(CertError::NotYetValid);
        }
        if now > cert.not_after {
            return Err(CertError::Expired);
        }
        
        // Check revocation
        if revoked.contains(&cert.serial_number) {
            return Err(CertError::Revoked);
        }
        
        // Validate against trusted CAs (simplified - in production would verify chain)
        if config.trusted_cas.is_empty() {
            return Err(CertError::UntrustedCA);
        }
        
        Ok(())
    }
    
    /// Authenticate using certificate
    pub async fn authenticate(&self, pem_data: &str) -> Result<UserInfo, CertError> {
        // Parse certificate
        let cert = self.parse_certificate(pem_data)?;
        
        // Validate certificate
        self.validate_certificate(&cert).await?;
        
        // Get policies for this certificate
        let config = self.config.read().await;
        let policies = config
            .cert_policies
            .get(&cert.common_name)
            .cloned()
            .unwrap_or_else(|| vec!["default".to_string()]);
        
        // Build user info
        let mut metadata = HashMap::new();
        if let Some(org) = &cert.organization {
            metadata.insert("organization".to_string(), org.clone());
        }
        if let Some(ou) = &cert.organizational_unit {
            metadata.insert("organizational_unit".to_string(), ou.clone());
        }
        metadata.insert("serial_number".to_string(), cert.serial_number.clone());
        metadata.insert("issuer".to_string(), cert.issuer.clone());
        
        Ok(UserInfo {
            username: cert.common_name.clone(),
            email: cert.email.clone(),
            display_name: Some(cert.common_name),
            policies,
            metadata,
        })
    }
    
    /// Add certificate policy binding
    pub async fn add_cert_policy(&self, common_name: String, policies: Vec<String>) {
        let mut config = self.config.write().await;
        config.cert_policies.insert(common_name, policies);
    }
    
    /// Revoke certificate by serial number
    pub async fn revoke_certificate(&self, serial_number: String) {
        let mut revoked = self.revoked_serials.write().await;
        if !revoked.contains(&serial_number) {
            revoked.push(serial_number);
        }
    }
    
    /// Unrevoke certificate
    pub async fn unrevoke_certificate(&self, serial_number: &str) {
        let mut revoked = self.revoked_serials.write().await;
        revoked.retain(|s| s != serial_number);
    }
    
    /// List revoked certificates
    pub async fn list_revoked(&self) -> Vec<String> {
        let revoked = self.revoked_serials.read().await;
        revoked.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz8Vv3PuGmDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyW4TXiOt+pRKlPNTuYMO
kYiUa3bQHDn3sVPGWJOsNcTWvJNH4FQCR1234567890abcdefghijk
-----END CERTIFICATE-----"#;

    #[tokio::test]
    async fn test_cert_auth_creation() {
        let config = CertConfig::default();
        let auth = CertAuth::new(config);
        
        // Should be able to create auth instance
        assert!(auth.config.read().await.require_client_cert);
    }
    
    #[tokio::test]
    async fn test_revocation() {
        let config = CertConfig::default();
        let auth = CertAuth::new(config);
        
        // Revoke a certificate
        auth.revoke_certificate("ABC123".to_string()).await;
        
        let revoked = auth.list_revoked().await;
        assert_eq!(revoked.len(), 1);
        assert!(revoked.contains(&"ABC123".to_string()));
        
        // Unrevoke
        auth.unrevoke_certificate("ABC123").await;
        let revoked = auth.list_revoked().await;
        assert_eq!(revoked.len(), 0);
    }
    
    #[tokio::test]
    async fn test_policy_binding() {
        let config = CertConfig::default();
        let auth = CertAuth::new(config);
        
        auth.add_cert_policy(
            "testuser".to_string(),
            vec!["admin".to_string(), "read".to_string()],
        ).await;
        
        let config = auth.config.read().await;
        let policies = config.cert_policies.get("testuser").unwrap();
        assert_eq!(policies.len(), 2);
    }
}
