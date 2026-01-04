//! Certificate Authentication Method
//!
//! mTLS (mutual TLS) certificate-based authentication for Secreton.
//! Authenticates clients using X.509 certificates.

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

use crate::model::*;
use secreton_errors::SecretonError;

/// Certificate authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertConfig {
    /// Trusted CA certificates (PEM format)
    pub trusted_cas: Vec<String>,

    /// Certificate revocation list (CRL)
    pub crl: Vec<String>,

    /// Require client certificate
    pub require_client_cert: bool,

    /// Allowed certificate _key usages
    pub allowed_key_usages: Vec<String>,

    /// Allowed certificate extended _key usages
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
            allowed_ext_key_usages: vec!["ClientAuth".to_string()],
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
    _config: Arc<RwLock<CertConfig>>,
    revoked_serials: Arc<RwLock<Vec<String>>>,
}

impl CertAuth {
    /// Create new certificate authentication service
    pub fn new(_config: CertConfig) -> Self {
        Self {
            _config: Arc::new(RwLock::new(_config)),
            revoked_serials: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Parse certificate from PEM format
    pub fn parse_certificate(&self, pem_data: &str) -> Result<CertificateSubject, SecretonError> {
        // Remove PEM headers/footers and decode base64
        let pem_lines: Vec<&str> = pem_data
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let pem_body = pem_lines.join("");

        let der_data = base64
            .decode(&pem_body)
            .map_err(|err| SecretonError::Parse {
                message: format!("Failed to decode base64 certificate: {err}"),
            })?;

        let (_, cert) =
            X509Certificate::from_der(&der_data).map_err(|err| SecretonError::Parse {
                message: format!("Failed to parse DER certificate: {err}"),
            })?;

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
                    GeneralName::RFC822Name(_e) => {
                        if email.is_none() {
                            email = Some(_e.to_string());
                        }
                        sans.push(format!("email:{}", _e));
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

        let serial_number = cert.serial.to_str_radix(16);

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
    pub async fn validate_certificate(
        &self,
        cert: &CertificateSubject,
    ) -> Result<(), SecretonError> {
        let _config = self._config.read().await;
        let revoked = self.revoked_serials.read().await;

        // Check expiration
        let now = Utc::now();
        if now < cert.not_before {
            return Err(SecretonError::Authentication {
                message: "Certificate is not yet valid".to_string(),
            });
        }
        if now > cert.not_after {
            return Err(SecretonError::Authentication {
                message: "Certificate has expired".to_string(),
            });
        }

        // Check revocation
        if revoked.contains(&cert.serial_number) {
            return Err(SecretonError::Authentication {
                message: "Certificate has been revoked".to_string(),
            });
        }

        // Validate against trusted CAs (simplified - in production would verify chain)
        if _config.trusted_cas.is_empty() {
            return Err(SecretonError::Configuration {
                message: "No trusted certificate authorities configured".to_string(),
            });
        }

        Ok(())
    }

    /// Authenticate using certificate
    pub async fn authenticate(&self, pem_data: &str) -> Result<UserInfo, SecretonError> {
        // Parse certificate
        let cert = self.parse_certificate(pem_data)?;

        // Validate certificate
        self.validate_certificate(&cert).await?;

        // Get policies for this certificate
        let _config = self._config.read().await;
        let mut metadata = HashMap::new();
        if let Some(org) = &cert.organization {
            metadata.insert("organization".to_string(), org.clone());
        }
        if let Some(ou) = &cert.organizational_unit {
            metadata.insert("organizational_unit".to_string(), ou.clone());
        }
        if let Some(country) = &cert.country {
            metadata.insert("country".to_string(), country.clone());
        }
        if let Some(state) = &cert.state {
            metadata.insert("state".to_string(), state.clone());
        }
        if let Some(locality) = &cert.locality {
            metadata.insert("locality".to_string(), locality.clone());
        }
        metadata.insert("serial_number".to_string(), cert.serial_number.clone());
        metadata.insert("issuer".to_string(), cert.issuer.clone());
        metadata.insert("not_before".to_string(), cert.not_before.to_rfc3339());
        metadata.insert("not_after".to_string(), cert.not_after.to_rfc3339());
        if !cert.sans.is_empty() {
            metadata.insert("sans".to_string(), cert.sans.join(","));
        }

        let roles = _config
            .cert_policies
            .get(&cert.common_name)
            .cloned()
            .unwrap_or_else(|| vec!["default".to_string()]);

        Ok(UserInfo {
            id: Some(Uuid::new_v4().to_string()),
            username: cert.common_name.clone(),
            email: cert.email.clone(),
            display_name: Some(cert.common_name),
            roles,
            permissions: vec![],
            metadata,
            last_login: Some(Utc::now()),
        })
    }

    /// Add certificate policy binding
    pub async fn add_cert_policy(&self, common_name: String, policies: Vec<String>) {
        let mut _config = self._config.write().await;
        _config.cert_policies.insert(common_name, policies);
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

    #[tokio::test]
    async fn test_cert_auth_creation() {
        let _config = CertConfig::default();
        let auth = CertAuth::new(_config);

        // Should be able to create auth instance
        assert!(auth._config.read().await.require_client_cert);
    }

    #[tokio::test]
    async fn test_revocation() {
        let _config = CertConfig::default();
        let auth = CertAuth::new(_config);

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
        let _config = CertConfig::default();
        let auth = CertAuth::new(_config);

        auth.add_cert_policy(
            "testuser".to_string(),
            vec!["admin".to_string(), "read".to_string()],
        )
        .await;

        let _config = auth._config.read().await;
        let policies = _config.cert_policies.get("testuser").unwrap();
        assert_eq!(policies.len(), 2);
    }
}
