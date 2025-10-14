// Certificate Authority Management - Internal PKI with certificate templates
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum CAError {
    #[error("CA error: {0}")]
    CAError(String),
    #[error("Certificate error: {0}")]
    CertificateError(String),
    #[error("Template error: {0}")]
    TemplateError(String),
}

pub type Result<T> = std::result::Result<T, CAError>;

/// CA type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CAType {
    Root,
    Intermediate,
}

/// Key type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    RSA,
    EC,
    EdDSA,
}

/// Certificate Authority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    pub ca_id: String,
    pub ca_type: CAType,
    pub key_type: KeyType,
    pub key_bits: u32,
    pub subject: String,
    pub issuer: String,
    pub ca_cert_pem: String,
    pub private_key_pem: String,
    pub serial_number: u64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Certificate template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateTemplate {
    pub template_id: String,
    pub name: String,
    pub allowed_domains: Vec<String>,
    pub allow_subdomains: bool,
    pub allow_wildcard: bool,
    pub max_ttl_seconds: i64,
    pub key_type: KeyType,
    pub key_bits: u32,
    pub key_usage: Vec<String>, // digitalSignature, keyEncipherment, etc.
    pub ext_key_usage: Vec<String>, // serverAuth, clientAuth, etc.
    pub require_cn: bool,
    pub created_at: DateTime<Utc>,
}

/// Signing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    pub csr_pem: String,
    pub template_id: String,
    pub common_name: String,
    pub alt_names: Vec<String>,
    pub ttl_seconds: i64,
    pub metadata: HashMap<String, String>,
}

/// Signed certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCertificate {
    pub certificate_id: String,
    pub serial_number: String,
    pub ca_id: String,
    pub common_name: String,
    pub alt_names: Vec<String>,
    pub cert_pem: String,
    pub ca_chain_pem: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Revocation entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub serial_number: String,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
}

/// CA Management
pub struct CAManagement {
    certificate_authorities: Arc<RwLock<HashMap<String, CertificateAuthority>>>,
    templates: Arc<RwLock<HashMap<String, CertificateTemplate>>>,
    certificates: Arc<RwLock<HashMap<String, SignedCertificate>>>,
    revocation_list: Arc<RwLock<Vec<RevocationEntry>>>,
}

impl CAManagement {
    pub fn new() -> Self {
        Self {
            certificate_authorities: Arc::new(RwLock::new(HashMap::new())),
            templates: Arc::new(RwLock::new(HashMap::new())),
            certificates: Arc::new(RwLock::new(HashMap::new())),
            revocation_list: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create root CA
    pub async fn create_root_ca(
        &self,
        subject: String,
        key_type: KeyType,
        key_bits: u32,
        validity_years: i64,
    ) -> Result<CertificateAuthority> {
        let ca_id = uuid::Uuid::new_v4().to_string();

        // Mock certificate generation
        let ca = CertificateAuthority {
            ca_id: ca_id.clone(),
            ca_type: CAType::Root,
            key_type: key_type.clone(),
            key_bits,
            subject: subject.clone(),
            issuer: subject.clone(), // Self-signed
            ca_cert_pem: self.mock_generate_cert(&subject, &subject),
            private_key_pem: self.mock_generate_private_key(&key_type, key_bits),
            serial_number: 1,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(validity_years * 365),
        };

        let mut cas = self.certificate_authorities.write().await;
        cas.insert(ca_id.clone(), ca.clone());

        Ok(ca)
    }

    /// Generate intermediate CA
    pub async fn generate_intermediate_ca(
        &self,
        root_ca_id: &str,
        subject: String,
        key_type: KeyType,
        key_bits: u32,
        validity_years: i64,
    ) -> Result<CertificateAuthority> {
        // Validate parent CA and get issuer info
        let (issuer_subject, cert_pem) = {
            let cas = self.certificate_authorities.read().await;
            let root_ca = cas
                .get(root_ca_id)
                .ok_or_else(|| CAError::CAError("Root CA not found".to_string()))?;

            if root_ca.ca_type != CAType::Root {
                return Err(CAError::CAError("Parent CA must be a root CA".to_string()));
            }

            let issuer = root_ca.subject.clone();
            let cert = self.mock_generate_cert(&subject, &root_ca.subject);
            (issuer, cert)
        }; // Lock dropped here

        let ca_id = uuid::Uuid::new_v4().to_string();

        let ca = CertificateAuthority {
            ca_id: ca_id.clone(),
            ca_type: CAType::Intermediate,
            key_type: key_type.clone(),
            key_bits,
            subject: subject.clone(),
            issuer: issuer_subject,
            ca_cert_pem: cert_pem,
            private_key_pem: self.mock_generate_private_key(&key_type, key_bits),
            serial_number: 1,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(validity_years * 365),
        };

        let mut cas = self.certificate_authorities.write().await;
        cas.insert(ca_id.clone(), ca.clone());

        Ok(ca)
    }

    /// Create certificate template
    pub async fn create_template(&self, template: CertificateTemplate) -> Result<()> {
        if template.allowed_domains.is_empty() && template.require_cn {
            return Err(CAError::TemplateError(
                "Must specify allowed domains or disable require_cn".to_string(),
            ));
        }

        let mut templates = self.templates.write().await;
        templates.insert(template.template_id.clone(), template);

        Ok(())
    }

    /// Sign certificate
    pub async fn sign_certificate(
        &self,
        ca_id: &str,
        request: SigningRequest,
    ) -> Result<SignedCertificate> {
        // Validate template
        let templates = self.templates.read().await;
        let template = templates
            .get(&request.template_id)
            .ok_or_else(|| CAError::TemplateError("Template not found".to_string()))?;

        // Validate domain
        if !self.validate_domain(
            &request.common_name,
            &template.allowed_domains,
            template.allow_subdomains,
        ) {
            return Err(CAError::CertificateError(
                "Domain not allowed by template".to_string(),
            ));
        }

        // Validate TTL
        if request.ttl_seconds > template.max_ttl_seconds {
            return Err(CAError::CertificateError(
                "TTL exceeds template maximum".to_string(),
            ));
        }

        drop(templates);

        // Get CA
        let mut cas = self.certificate_authorities.write().await;
        let ca = cas
            .get_mut(ca_id)
            .ok_or_else(|| CAError::CAError("CA not found".to_string()))?;

        // Generate certificate
        let serial_number = ca.serial_number;
        ca.serial_number += 1;

        drop(cas);

        let certificate_id = uuid::Uuid::new_v4().to_string();

        let cert = SignedCertificate {
            certificate_id: certificate_id.clone(),
            serial_number: format!("{:016x}", serial_number),
            ca_id: ca_id.to_string(),
            common_name: request.common_name.clone(),
            alt_names: request.alt_names.clone(),
            cert_pem: self.mock_generate_signed_cert(&request.common_name),
            ca_chain_pem: "-----BEGIN CERTIFICATE-----\nCA_CHAIN\n-----END CERTIFICATE-----"
                .to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(request.ttl_seconds),
            revoked: false,
            revoked_at: None,
        };

        let mut certificates = self.certificates.write().await;
        certificates.insert(certificate_id.clone(), cert.clone());

        Ok(cert)
    }

    /// Revoke certificate
    pub async fn revoke_certificate(&self, certificate_id: &str, reason: String) -> Result<()> {
        let mut certificates = self.certificates.write().await;
        let cert = certificates
            .get_mut(certificate_id)
            .ok_or_else(|| CAError::CertificateError("Certificate not found".to_string()))?;

        if cert.revoked {
            return Err(CAError::CertificateError(
                "Certificate already revoked".to_string(),
            ));
        }

        cert.revoked = true;
        cert.revoked_at = Some(Utc::now());

        let entry = RevocationEntry {
            serial_number: cert.serial_number.clone(),
            revoked_at: Utc::now(),
            reason,
        };

        drop(certificates);

        let mut revocation_list = self.revocation_list.write().await;
        revocation_list.push(entry);

        Ok(())
    }

    /// Get CRL (Certificate Revocation List)
    pub async fn get_crl(&self, ca_id: &str) -> String {
        let certificates = self.certificates.read().await;
        let revocation_list = self.revocation_list.read().await;

        let mut crl = format!(
            "-----BEGIN X509 CRL-----\nCA: {}\nGenerated: {}\n\n",
            ca_id,
            Utc::now()
        );

        for cert in certificates.values() {
            if cert.ca_id == ca_id && cert.revoked {
                if let Some(entry) = revocation_list
                    .iter()
                    .find(|e| e.serial_number == cert.serial_number)
                {
                    crl.push_str(&format!(
                        "Serial: {}\nRevoked: {}\nReason: {}\n\n",
                        entry.serial_number, entry.revoked_at, entry.reason
                    ));
                }
            }
        }

        crl.push_str("-----END X509 CRL-----");
        crl
    }

    /// List templates
    pub async fn list_templates(&self) -> Vec<String> {
        let templates = self.templates.read().await;
        templates.keys().cloned().collect()
    }

    /// Get template
    pub async fn get_template(&self, template_id: &str) -> Option<CertificateTemplate> {
        let templates = self.templates.read().await;
        templates.get(template_id).cloned()
    }

    /// List CAs
    pub async fn list_cas(&self) -> Vec<String> {
        let cas = self.certificate_authorities.read().await;
        cas.keys().cloned().collect()
    }

    /// Get certificate
    pub async fn get_certificate(&self, certificate_id: &str) -> Option<SignedCertificate> {
        let certificates = self.certificates.read().await;
        certificates.get(certificate_id).cloned()
    }

    // Helper methods
    fn validate_domain(&self, domain: &str, allowed: &[String], allow_subdomains: bool) -> bool {
        for allowed_domain in allowed {
            if domain == allowed_domain {
                return true;
            }

            if allow_subdomains && domain.ends_with(&format!(".{}", allowed_domain)) {
                return true;
            }
        }

        false
    }

    fn mock_generate_cert(&self, subject: &str, issuer: &str) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\nSubject: {}\nIssuer: {}\n-----END CERTIFICATE-----",
            subject, issuer
        )
    }

    fn mock_generate_signed_cert(&self, common_name: &str) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\nCN={}\n-----END CERTIFICATE-----",
            common_name
        )
    }

    fn mock_generate_private_key(&self, key_type: &KeyType, key_bits: u32) -> String {
        format!(
            "-----BEGIN PRIVATE KEY-----\nType: {:?}\nBits: {}\n-----END PRIVATE KEY-----",
            key_type, key_bits
        )
    }
}

impl Default for CAManagement {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_root_ca() {
        let ca_mgmt = CAManagement::new();

        let ca = ca_mgmt
            .create_root_ca(
                "CN=Root CA,O=Vault,C=US".to_string(),
                KeyType::RSA,
                4096,
                10,
            )
            .await
            .unwrap();

        assert_eq!(ca.ca_type, CAType::Root);
        assert_eq!(ca.key_type, KeyType::RSA);
        assert_eq!(ca.key_bits, 4096);
        assert_eq!(ca.subject, ca.issuer); // Self-signed
        assert!(ca.ca_cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn test_generate_intermediate_ca() {
        let ca_mgmt = CAManagement::new();

        let root_ca = ca_mgmt
            .create_root_ca(
                "CN=Root CA,O=Vault,C=US".to_string(),
                KeyType::RSA,
                4096,
                10,
            )
            .await
            .unwrap();

        let intermediate = ca_mgmt
            .generate_intermediate_ca(
                &root_ca.ca_id,
                "CN=Intermediate CA,O=Vault,C=US".to_string(),
                KeyType::RSA,
                2048,
                5,
            )
            .await
            .unwrap();

        assert_eq!(intermediate.ca_type, CAType::Intermediate);
        assert_eq!(intermediate.issuer, root_ca.subject);
    }

    #[tokio::test]
    async fn test_create_template() {
        let ca_mgmt = CAManagement::new();

        let template = CertificateTemplate {
            template_id: "web-server".to_string(),
            name: "Web Server Template".to_string(),
            allowed_domains: vec!["example.com".to_string()],
            allow_subdomains: true,
            allow_wildcard: false,
            max_ttl_seconds: 2592000, // 30 days
            key_type: KeyType::RSA,
            key_bits: 2048,
            key_usage: vec![
                "digitalSignature".to_string(),
                "keyEncipherment".to_string(),
            ],
            ext_key_usage: vec!["serverAuth".to_string()],
            require_cn: true,
            created_at: Utc::now(),
        };

        ca_mgmt.create_template(template).await.unwrap();

        let templates = ca_mgmt.list_templates().await;
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0], "web-server");
    }

    #[tokio::test]
    async fn test_sign_certificate() {
        let ca_mgmt = CAManagement::new();

        let ca = ca_mgmt
            .create_root_ca(
                "CN=Root CA,O=Vault,C=US".to_string(),
                KeyType::RSA,
                4096,
                10,
            )
            .await
            .unwrap();

        let template = CertificateTemplate {
            template_id: "web-server".to_string(),
            name: "Web Server Template".to_string(),
            allowed_domains: vec!["example.com".to_string()],
            allow_subdomains: true,
            allow_wildcard: false,
            max_ttl_seconds: 2592000,
            key_type: KeyType::RSA,
            key_bits: 2048,
            key_usage: vec!["digitalSignature".to_string()],
            ext_key_usage: vec!["serverAuth".to_string()],
            require_cn: true,
            created_at: Utc::now(),
        };

        ca_mgmt.create_template(template).await.unwrap();

        let request = SigningRequest {
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----"
                .to_string(),
            template_id: "web-server".to_string(),
            common_name: "www.example.com".to_string(),
            alt_names: vec!["example.com".to_string()],
            ttl_seconds: 86400,
            metadata: HashMap::new(),
        };

        let cert = ca_mgmt.sign_certificate(&ca.ca_id, request).await.unwrap();

        assert_eq!(cert.common_name, "www.example.com");
        assert!(!cert.revoked);
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn test_revoke_certificate() {
        let ca_mgmt = CAManagement::new();

        let ca = ca_mgmt
            .create_root_ca(
                "CN=Root CA,O=Vault,C=US".to_string(),
                KeyType::RSA,
                4096,
                10,
            )
            .await
            .unwrap();

        let template = CertificateTemplate {
            template_id: "web-server".to_string(),
            name: "Web Server Template".to_string(),
            allowed_domains: vec!["example.com".to_string()],
            allow_subdomains: true,
            allow_wildcard: false,
            max_ttl_seconds: 2592000,
            key_type: KeyType::RSA,
            key_bits: 2048,
            key_usage: vec!["digitalSignature".to_string()],
            ext_key_usage: vec!["serverAuth".to_string()],
            require_cn: true,
            created_at: Utc::now(),
        };

        ca_mgmt.create_template(template).await.unwrap();

        let request = SigningRequest {
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----"
                .to_string(),
            template_id: "web-server".to_string(),
            common_name: "www.example.com".to_string(),
            alt_names: vec![],
            ttl_seconds: 86400,
            metadata: HashMap::new(),
        };

        let cert = ca_mgmt.sign_certificate(&ca.ca_id, request).await.unwrap();

        ca_mgmt
            .revoke_certificate(&cert.certificate_id, "Key compromised".to_string())
            .await
            .unwrap();

        let revoked_cert = ca_mgmt.get_certificate(&cert.certificate_id).await.unwrap();
        assert!(revoked_cert.revoked);
        assert!(revoked_cert.revoked_at.is_some());
    }

    #[tokio::test]
    async fn test_get_crl() {
        let ca_mgmt = CAManagement::new();

        let ca = ca_mgmt
            .create_root_ca(
                "CN=Root CA,O=Vault,C=US".to_string(),
                KeyType::RSA,
                4096,
                10,
            )
            .await
            .unwrap();

        let template = CertificateTemplate {
            template_id: "web-server".to_string(),
            name: "Web Server Template".to_string(),
            allowed_domains: vec!["example.com".to_string()],
            allow_subdomains: true,
            allow_wildcard: false,
            max_ttl_seconds: 2592000,
            key_type: KeyType::RSA,
            key_bits: 2048,
            key_usage: vec!["digitalSignature".to_string()],
            ext_key_usage: vec!["serverAuth".to_string()],
            require_cn: true,
            created_at: Utc::now(),
        };

        ca_mgmt.create_template(template).await.unwrap();

        let request = SigningRequest {
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----"
                .to_string(),
            template_id: "web-server".to_string(),
            common_name: "www.example.com".to_string(),
            alt_names: vec![],
            ttl_seconds: 86400,
            metadata: HashMap::new(),
        };

        let cert = ca_mgmt.sign_certificate(&ca.ca_id, request).await.unwrap();

        ca_mgmt
            .revoke_certificate(&cert.certificate_id, "Superseded".to_string())
            .await
            .unwrap();

        let crl = ca_mgmt.get_crl(&ca.ca_id).await;

        assert!(crl.contains("BEGIN X509 CRL"));
        assert!(crl.contains(&cert.serial_number));
        assert!(crl.contains("Superseded"));
    }
}
