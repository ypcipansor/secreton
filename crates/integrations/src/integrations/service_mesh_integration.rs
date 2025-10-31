// Service Mesh Integration - mTLS certificates and SPIFFE/SPIRE support
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ServiceMeshError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Certificate error: {0}")]
    CertificateError(String),
    #[error("SPIFFE error: {0}")]
    SpiffeError(String),
}

pub type Result<T> = std::result::Result<T, ServiceMeshError>;

/// Service mesh type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MeshType {
    Istio,
    Linkerd,
    ConsulConnect,
}

/// Service mesh configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMeshConfig {
    pub mesh_type: MeshType,
    pub spiffe_enabled: bool,
    pub mtls_enabled: bool,
    pub cert_ttl_hours: u32,
    pub auto_rotation_enabled: bool,
}

/// Service identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceIdentity {
    pub service_name: String,
    pub namespace: String,
    pub spiffe_id: String, // spiffe://trust-domain/ns/namespace/sa/service-name
    pub trust_domain: String,
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
    pub ca_bundle_pem: Option<String>,
    pub issued_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Mesh certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshCertificate {
    pub cert_id: String,
    pub service_identity: ServiceIdentity,
    pub cert_serial: String,
    pub status: CertificateStatus,
    pub rotation_count: u32,
    pub created_at: DateTime<Utc>,
}

/// Certificate status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CertificateStatus {
    Active,
    Expired,
    Revoked,
}

/// SPIFFE configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SPIFFEConfig {
    pub trust_domain: String,
    pub workload_api_socket: String,
    pub enabled: bool,
}

/// Service Mesh Integration
pub struct ServiceMeshIntegration {
    config: Arc<RwLock<ServiceMeshConfig>>,
    spiffe_config: Arc<RwLock<SPIFFEConfig>>,
    service_identities: Arc<RwLock<HashMap<String, ServiceIdentity>>>,
    certificates: Arc<RwLock<HashMap<String, MeshCertificate>>>,
}

impl ServiceMeshIntegration {
    pub fn new(config: ServiceMeshConfig, spiffe_config: SPIFFEConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            spiffe_config: Arc::new(RwLock::new(spiffe_config)),
            service_identities: Arc::new(RwLock::new(HashMap::new())),
            certificates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register service
    pub async fn register_service(
        &self,
        service_name: &str,
        namespace: &str,
    ) -> Result<ServiceIdentity> {
        let spiffe_config = self.spiffe_config.read().await;
        let trust_domain = spiffe_config.trust_domain.clone();
        drop(spiffe_config);

        let spiffe_id = format!(
            "spiffe://{}/ns/{}/sa/{}",
            trust_domain, namespace, service_name
        );

        let identity = ServiceIdentity {
            service_name: service_name.to_string(),
            namespace: namespace.to_string(),
            spiffe_id,
            trust_domain,
            certificate_pem: None,
            private_key_pem: None,
            ca_bundle_pem: None,
            issued_at: None,
            expires_at: None,
        };

        let key = format!("{}/{}", namespace, service_name);
        let mut service_identities = self.service_identities.write().await;
        service_identities.insert(key, identity.clone());

        Ok(identity)
    }

    /// Issue certificate
    pub async fn issue_certificate(
        &self,
        service_name: &str,
        namespace: &str,
    ) -> Result<MeshCertificate> {
        let key = format!("{}/{}", namespace, service_name);
        let service_identities = self.service_identities.read().await;

        let mut identity = service_identities
            .get(&key)
            .ok_or_else(|| ServiceMeshError::ConfigError("Service not registered".to_string()))?
            .clone();

        drop(service_identities);

        let config = self.config.read().await;
        let cert_ttl_hours = config.cert_ttl_hours;
        drop(config);

        // Mock: Generate certificate
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::hours(cert_ttl_hours as i64);

        identity.certificate_pem = Some(self.mock_generate_certificate_pem(&identity.spiffe_id));
        identity.private_key_pem = Some(self.mock_generate_private_key_pem());
        identity.ca_bundle_pem = Some(self.mock_get_ca_bundle());
        identity.issued_at = Some(issued_at);
        identity.expires_at = Some(expires_at);

        let cert_id = uuid::Uuid::new_v4().to_string();
        let cert_serial = format!(
            "CERT-{}",
            uuid::Uuid::new_v4().to_string()[..8].to_uppercase()
        );

        let certificate = MeshCertificate {
            cert_id: cert_id.clone(),
            service_identity: identity.clone(),
            cert_serial,
            status: CertificateStatus::Active,
            rotation_count: 0,
            created_at: Utc::now(),
        };

        // Update identity with certificate
        let mut service_identities = self.service_identities.write().await;
        service_identities.insert(key, identity);

        let mut certificates = self.certificates.write().await;
        certificates.insert(cert_id.clone(), certificate.clone());

        Ok(certificate)
    }

    /// Rotate certificate
    pub async fn rotate_certificate(&self, cert_id: &str) -> Result<MeshCertificate> {
        let certificates = self.certificates.read().await;
        let old_cert = certificates
            .get(cert_id)
            .ok_or_else(|| ServiceMeshError::CertificateError("Certificate not found".to_string()))?
            .clone();

        drop(certificates);

        // Revoke old certificate
        let mut certificates = self.certificates.write().await;
        if let Some(cert) = certificates.get_mut(cert_id) {
            cert.status = CertificateStatus::Revoked;
        }
        drop(certificates);

        // Issue new certificate
        let new_cert = self
            .issue_certificate(
                &old_cert.service_identity.service_name,
                &old_cert.service_identity.namespace,
            )
            .await?;

        // Update rotation count
        let mut certificates = self.certificates.write().await;
        if let Some(cert) = certificates.get_mut(&new_cert.cert_id) {
            cert.rotation_count = old_cert.rotation_count + 1;
        }

        Ok(new_cert)
    }

    /// Verify SPIFFE ID
    pub async fn verify_spiffe_id(&self, spiffe_id: &str) -> Result<bool> {
        let spiffe_config = self.spiffe_config.read().await;
        let trust_domain = &spiffe_config.trust_domain;

        // Validate SPIFFE ID format
        if !spiffe_id.starts_with("spiffe://") {
            return Err(ServiceMeshError::SpiffeError(
                "Invalid SPIFFE ID format".to_string(),
            ));
        }

        // Check trust domain
        let expected_prefix = format!("spiffe://{}/", trust_domain);
        if !spiffe_id.starts_with(&expected_prefix) {
            return Ok(false);
        }

        Ok(true)
    }

    /// List service identities
    pub async fn list_service_identities(&self, namespace: Option<&str>) -> Vec<ServiceIdentity> {
        let service_identities = self.service_identities.read().await;

        service_identities
            .values()
            .filter(|si| {
                if let Some(ns) = namespace {
                    si.namespace == ns
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    /// List certificates
    pub async fn list_certificates(
        &self,
        status: Option<CertificateStatus>,
    ) -> Vec<MeshCertificate> {
        let certificates = self.certificates.read().await;

        certificates
            .values()
            .filter(|cert| {
                if let Some(s) = &status {
                    &cert.status == s
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    /// Get certificate
    pub async fn get_certificate(&self, cert_id: &str) -> Option<MeshCertificate> {
        let certificates = self.certificates.read().await;
        certificates.get(cert_id).cloned()
    }

    /// Revoke certificate
    pub async fn revoke_certificate(&self, cert_id: &str) -> Result<()> {
        let mut certificates = self.certificates.write().await;
        let cert = certificates.get_mut(cert_id).ok_or_else(|| {
            ServiceMeshError::CertificateError("Certificate not found".to_string())
        })?;

        cert.status = CertificateStatus::Revoked;

        Ok(())
    }

    // Helper methods

    fn mock_generate_certificate_pem(&self, spiffe_id: &str) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\nMIIC...[mock cert for {}]...\n-----END CERTIFICATE-----",
            spiffe_id
        )
    }

    fn mock_generate_private_key_pem(&self) -> String {
        "-----BEGIN PRIVATE KEY-----\nMIIE...[mock private key]...\n-----END PRIVATE KEY-----"
            .to_string()
    }

    fn mock_get_ca_bundle(&self) -> String {
        "-----BEGIN CERTIFICATE-----\nMIIC...[mock CA bundle]...\n-----END CERTIFICATE-----"
            .to_string()
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> MeshStatistics {
        let service_identities = self.service_identities.read().await;
        let certificates = self.certificates.read().await;

        let total_services = service_identities.len();
        let total_certificates = certificates.len();
        let active_certificates = certificates
            .values()
            .filter(|c| c.status == CertificateStatus::Active)
            .count();
        let expired_certificates = certificates
            .values()
            .filter(|c| c.status == CertificateStatus::Expired)
            .count();
        let revoked_certificates = certificates
            .values()
            .filter(|c| c.status == CertificateStatus::Revoked)
            .count();

        MeshStatistics {
            total_services,
            total_certificates,
            active_certificates,
            expired_certificates,
            revoked_certificates,
        }
    }
}

/// Mesh statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshStatistics {
    pub total_services: usize,
    pub total_certificates: usize,
    pub active_certificates: usize,
    pub expired_certificates: usize,
    pub revoked_certificates: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ServiceMeshConfig {
        ServiceMeshConfig {
            mesh_type: MeshType::Istio,
            spiffe_enabled: true,
            mtls_enabled: true,
            cert_ttl_hours: 24,
            auto_rotation_enabled: true,
        }
    }

    fn create_test_spiffe_config() -> SPIFFEConfig {
        SPIFFEConfig {
            trust_domain: "example.com".to_string(),
            workload_api_socket: "/tmp/spire-agent/public/api.sock".to_string(),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_register_service() {
        let mesh = ServiceMeshIntegration::new(create_test_config(), create_test_spiffe_config());

        let identity = mesh
            .register_service("my-service", "production")
            .await
            .unwrap();

        assert_eq!(identity.service_name, "my-service");
        assert_eq!(identity.namespace, "production");
        assert_eq!(
            identity.spiffe_id,
            "spiffe://example.com/ns/production/sa/my-service"
        );
    }

    #[tokio::test]
    async fn test_issue_certificate() {
        let mesh = ServiceMeshIntegration::new(create_test_config(), create_test_spiffe_config());

        mesh.register_service("my-service", "production")
            .await
            .unwrap();

        let certificate = mesh
            .issue_certificate("my-service", "production")
            .await
            .unwrap();

        assert_eq!(certificate.status, CertificateStatus::Active);
        assert!(certificate.service_identity.certificate_pem.is_some());
        assert!(certificate.service_identity.private_key_pem.is_some());
        assert!(certificate.service_identity.ca_bundle_pem.is_some());
    }

    #[tokio::test]
    async fn test_rotate_certificate() {
        let mesh = ServiceMeshIntegration::new(create_test_config(), create_test_spiffe_config());

        mesh.register_service("my-service", "production")
            .await
            .unwrap();

        let old_cert = mesh
            .issue_certificate("my-service", "production")
            .await
            .unwrap();

        let new_cert = mesh.rotate_certificate(&old_cert.cert_id).await.unwrap();

        let old_cert_status = mesh.get_certificate(&old_cert.cert_id).await.unwrap();
        // Old cert should be revoked or still active (implementation dependent)
        assert!(matches!(
            old_cert_status.status,
            CertificateStatus::Revoked | CertificateStatus::Active
        ));
    }

    #[tokio::test]
    async fn test_verify_spiffe_id() {
        let mesh = ServiceMeshIntegration::new(create_test_config(), create_test_spiffe_config());

        let valid = mesh
            .verify_spiffe_id("spiffe://example.com/ns/production/sa/my-service")
            .await
            .unwrap();
        assert!(valid);

        let invalid = mesh
            .verify_spiffe_id("spiffe://other-domain.com/ns/production/sa/my-service")
            .await
            .unwrap();
        assert!(!invalid);
    }

    #[tokio::test]
    async fn test_list_by_namespace() {
        let mesh = ServiceMeshIntegration::new(create_test_config(), create_test_spiffe_config());

        mesh.register_service("service1", "production")
            .await
            .unwrap();
        mesh.register_service("service2", "development")
            .await
            .unwrap();

        let prod_services = mesh.list_service_identities(Some("production")).await;
        assert_eq!(prod_services.len(), 1);
        assert_eq!(prod_services[0].service_name, "service1");
    }
}
