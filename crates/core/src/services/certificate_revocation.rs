// Certificate CRL/OCSP - PKI certificate revocation checking
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("Certificate not found: {0}")]
    CertNotFound(String),
    #[error("CRL not found: {0}")]
    CRLNotFound(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Certificate already revoked: {0}")]
    AlreadyRevoked(String),
    #[error("OCSP responder error: {0}")]
    OCSPError(String),
}

pub type Result<T> = std::result::Result<T, RevocationError>;

/// Revocation reason codes (RFC 5280)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CACompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCRL,
    PrivilegeWithdrawn,
    AACompromise,
}

impl RevocationReason {
    pub fn to_code(&self) -> u8 {
        match self {
            RevocationReason::Unspecified => 0,
            RevocationReason::KeyCompromise => 1,
            RevocationReason::CACompromise => 2,
            RevocationReason::AffiliationChanged => 3,
            RevocationReason::Superseded => 4,
            RevocationReason::CessationOfOperation => 5,
            RevocationReason::CertificateHold => 6,
            RevocationReason::RemoveFromCRL => 8,
            RevocationReason::PrivilegeWithdrawn => 9,
            RevocationReason::AACompromise => 10,
        }
    }
}

/// Revoked certificate entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedCertificate {
    pub serial_number: String,
    pub revocation_time: DateTime<Utc>,
    pub reason: RevocationReason,
    pub issuer: String,
    pub revoked_by: Option<String>,
}

/// Certificate Revocation List (CRL)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CRL {
    pub id: String,
    pub issuer: String,
    pub this_update: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub revoked_certificates: Vec<RevokedCertificate>,
    pub crl_number: u64,
    pub signature: Vec<u8>, // DER-encoded signature
    pub distribution_point: Option<String>,
}

impl CRL {
    pub fn new(issuer: String, crl_number: u64) -> Self {
        let now = Utc::now();
        
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            issuer,
            this_update: now,
            next_update: now + Duration::days(7), // Default 7 day validity
            revoked_certificates: Vec::new(),
            crl_number,
            signature: Vec::new(),
            distribution_point: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.next_update
    }

    pub fn add_revoked(&mut self, cert: RevokedCertificate) {
        self.revoked_certificates.push(cert);
    }

    pub fn is_revoked(&self, serial_number: &str) -> Option<&RevokedCertificate> {
        self.revoked_certificates
            .iter()
            .find(|c| c.serial_number == serial_number)
    }

    pub fn sign(&mut self, _key: &[u8]) {
        // In production, would generate actual signature
        self.signature = vec![0; 256];
    }
}

/// OCSP request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSPRequest {
    pub id: String,
    pub cert_serial: String,
    pub issuer: String,
    pub requester: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// OCSP response status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OCSPStatus {
    Good,
    Revoked { time: DateTime<Utc>, reason: RevocationReason },
    Unknown,
}

/// OCSP response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSPResponse {
    pub request_id: String,
    pub cert_serial: String,
    pub status: OCSPStatus,
    pub this_update: DateTime<Utc>,
    pub next_update: Option<DateTime<Utc>>,
    pub produced_at: DateTime<Utc>,
    pub responder_id: String,
    pub signature: Vec<u8>,
}

impl OCSPResponse {
    pub fn good(request_id: String, cert_serial: String, responder_id: String) -> Self {
        let now = Utc::now();
        
        Self {
            request_id,
            cert_serial,
            status: OCSPStatus::Good,
            this_update: now,
            next_update: Some(now + Duration::hours(24)),
            produced_at: now,
            responder_id,
            signature: Vec::new(),
        }
    }

    pub fn revoked(
        request_id: String,
        cert_serial: String,
        responder_id: String,
        revocation_time: DateTime<Utc>,
        reason: RevocationReason,
    ) -> Self {
        let now = Utc::now();
        
        Self {
            request_id,
            cert_serial,
            status: OCSPStatus::Revoked {
                time: revocation_time,
                reason,
            },
            this_update: now,
            next_update: Some(now + Duration::hours(24)),
            produced_at: now,
            responder_id,
            signature: Vec::new(),
        }
    }

    pub fn unknown(request_id: String, cert_serial: String, responder_id: String) -> Self {
        let now = Utc::now();
        
        Self {
            request_id,
            cert_serial,
            status: OCSPStatus::Unknown,
            this_update: now,
            next_update: None,
            produced_at: now,
            responder_id,
            signature: Vec::new(),
        }
    }

    pub fn sign(&mut self, _key: &[u8]) {
        // In production, would generate actual signature
        self.signature = vec![0; 256];
    }
}

/// CRL distribution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CRLConfig {
    pub issuer: String,
    pub validity_period_days: u64,
    pub auto_rebuild: bool,
    pub distribution_points: Vec<String>,
}

/// OCSP responder configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSPConfig {
    pub responder_id: String,
    pub responder_url: String,
    pub signing_key: Vec<u8>,
    pub cache_responses: bool,
    pub response_validity_hours: u64,
}

/// Certificate revocation service
pub struct CertificateRevocationService {
    crls: Arc<RwLock<HashMap<String, CRL>>>,
    revoked_certs: Arc<RwLock<HashMap<String, RevokedCertificate>>>,
    ocsp_requests: Arc<RwLock<Vec<OCSPRequest>>>,
    ocsp_responses: Arc<RwLock<HashMap<String, OCSPResponse>>>,
    crl_config: Arc<RwLock<HashMap<String, CRLConfig>>>,
    ocsp_config: Arc<RwLock<Option<OCSPConfig>>>,
}

impl CertificateRevocationService {
    pub fn new() -> Self {
        Self {
            crls: Arc::new(RwLock::new(HashMap::new())),
            revoked_certs: Arc::new(RwLock::new(HashMap::new())),
            ocsp_requests: Arc::new(RwLock::new(Vec::new())),
            ocsp_responses: Arc::new(RwLock::new(HashMap::new())),
            crl_config: Arc::new(RwLock::new(HashMap::new())),
            ocsp_config: Arc::new(RwLock::new(None)),
        }
    }

    /// Configure CRL generation for an issuer
    pub async fn configure_crl(&self, config: CRLConfig) -> Result<()> {
        let mut configs = self.crl_config.write().await;
        configs.insert(config.issuer.clone(), config);
        Ok(())
    }

    /// Configure OCSP responder
    pub async fn configure_ocsp(&self, config: OCSPConfig) -> Result<()> {
        let mut ocsp_config = self.ocsp_config.write().await;
        *ocsp_config = Some(config);
        Ok(())
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(
        &self,
        serial_number: String,
        issuer: String,
        reason: RevocationReason,
        revoked_by: Option<String>,
    ) -> Result<()> {
        // Check if already revoked
        let revoked = self.revoked_certs.read().await;
        if revoked.contains_key(&serial_number) {
            return Err(RevocationError::AlreadyRevoked(serial_number));
        }
        drop(revoked);

        // Create revocation entry
        let revoked_cert = RevokedCertificate {
            serial_number: serial_number.clone(),
            revocation_time: Utc::now(),
            reason,
            issuer: issuer.clone(),
            revoked_by,
        };

        // Store revocation
        let mut revoked = self.revoked_certs.write().await;
        revoked.insert(serial_number.clone(), revoked_cert.clone());
        drop(revoked);

        // Update CRL if auto-rebuild enabled
        let configs = self.crl_config.read().await;
        if let Some(config) = configs.get(&issuer) {
            if config.auto_rebuild {
                drop(configs);
                self.rebuild_crl(&issuer).await?;
            }
        }

        Ok(())
    }

    /// Build/rebuild CRL for an issuer
    pub async fn rebuild_crl(&self, issuer: &str) -> Result<CRL> {
        // Get config
        let configs = self.crl_config.read().await;
        let config = configs
            .get(issuer)
            .ok_or_else(|| RevocationError::InvalidConfig(format!("No CRL config for {}", issuer)))?
            .clone();
        drop(configs);

        // Get current CRL number
        let crls = self.crls.read().await;
        let crl_number = crls
            .get(issuer)
            .map(|c| c.crl_number + 1)
            .unwrap_or(1);
        drop(crls);

        // Create new CRL
        let mut crl = CRL::new(issuer.to_string(), crl_number);
        crl.next_update = Utc::now() + Duration::days(config.validity_period_days as i64);

        if !config.distribution_points.is_empty() {
            crl.distribution_point = Some(config.distribution_points[0].clone());
        }

        // Add all revoked certificates for this issuer
        let revoked = self.revoked_certs.read().await;
        for cert in revoked.values() {
            if cert.issuer == issuer {
                crl.add_revoked(cert.clone());
            }
        }
        drop(revoked);

        // Sign CRL
        crl.sign(&[]);

        // Store CRL
        let mut crls = self.crls.write().await;
        crls.insert(issuer.to_string(), crl.clone());

        Ok(crl)
    }

    /// Get CRL for an issuer
    pub async fn get_crl(&self, issuer: &str) -> Result<CRL> {
        let crls = self.crls.read().await;
        crls.get(issuer)
            .cloned()
            .ok_or_else(|| RevocationError::CRLNotFound(issuer.to_string()))
    }

    /// Check if certificate is revoked via CRL
    pub async fn check_crl(&self, serial_number: &str, issuer: &str) -> Result<Option<RevokedCertificate>> {
        let crl = self.get_crl(issuer).await?;
        
        if crl.is_expired() {
            // CRL expired, rebuild
            self.rebuild_crl(issuer).await?;
            let new_crl = self.get_crl(issuer).await?;
            Ok(new_crl.is_revoked(serial_number).cloned())
        } else {
            Ok(crl.is_revoked(serial_number).cloned())
        }
    }

    /// Process OCSP request
    pub async fn process_ocsp_request(
        &self,
        cert_serial: String,
        issuer: String,
        requester: Option<String>,
    ) -> Result<OCSPResponse> {
        // Get OCSP config
        let ocsp_config = self.ocsp_config.read().await;
        let config = ocsp_config
            .as_ref()
            .ok_or_else(|| RevocationError::OCSPError("OCSP not configured".to_string()))?;
        
        let responder_id = config.responder_id.clone();
        drop(ocsp_config);

        // Create request
        let request = OCSPRequest {
            id: uuid::Uuid::new_v4().to_string(),
            cert_serial: cert_serial.clone(),
            issuer,
            requester,
            created_at: Utc::now(),
        };

        let request_id = request.id.clone();

        // Store request
        let mut requests = self.ocsp_requests.write().await;
        requests.push(request);
        drop(requests);

        // Check revocation status
        let revoked = self.revoked_certs.read().await;
        let response = if let Some(revoked_cert) = revoked.get(&cert_serial) {
            OCSPResponse::revoked(
                request_id.clone(),
                cert_serial.clone(),
                responder_id,
                revoked_cert.revocation_time,
                revoked_cert.reason.clone(),
            )
        } else {
            // Check if certificate exists (in production, would query certificate store)
            OCSPResponse::good(request_id.clone(), cert_serial.clone(), responder_id)
        };
        drop(revoked);

        // Sign response
        let mut signed_response = response;
        signed_response.sign(&[]);

        // Cache response
        let mut responses = self.ocsp_responses.write().await;
        responses.insert(request_id, signed_response.clone());

        Ok(signed_response)
    }

    /// Get OCSP response from cache
    pub async fn get_ocsp_response(&self, request_id: &str) -> Option<OCSPResponse> {
        let responses = self.ocsp_responses.read().await;
        responses.get(request_id).cloned()
    }

    /// Check if certificate is revoked (checks local store)
    pub async fn is_revoked(&self, serial_number: &str) -> bool {
        let revoked = self.revoked_certs.read().await;
        revoked.contains_key(serial_number)
    }

    /// Get revoked certificate information
    pub async fn get_revoked_cert(&self, serial_number: &str) -> Result<RevokedCertificate> {
        let revoked = self.revoked_certs.read().await;
        revoked
            .get(serial_number)
            .cloned()
            .ok_or_else(|| RevocationError::CertNotFound(serial_number.to_string()))
    }

    /// List all revoked certificates
    pub async fn list_revoked(&self, issuer: Option<&str>) -> Vec<RevokedCertificate> {
        let revoked = self.revoked_certs.read().await;
        
        revoked
            .values()
            .filter(|c| issuer.map_or(true, |iss| c.issuer == iss))
            .cloned()
            .collect()
    }

    /// Unrevoke certificate (for CertificateHold reason)
    pub async fn unrevoke_certificate(&self, serial_number: &str) -> Result<()> {
        let revoked = self.revoked_certs.read().await;
        let cert = revoked
            .get(serial_number)
            .ok_or_else(|| RevocationError::CertNotFound(serial_number.to_string()))?;

        if cert.reason != RevocationReason::CertificateHold {
            return Err(RevocationError::InvalidConfig(
                "Can only unrevoke certificates with CertificateHold reason".to_string(),
            ));
        }

        let issuer = cert.issuer.clone();
        drop(revoked);

        let mut revoked = self.revoked_certs.write().await;
        revoked.remove(serial_number);
        drop(revoked);

        // Rebuild CRL
        self.rebuild_crl(&issuer).await?;

        Ok(())
    }

    /// Get OCSP statistics
    pub async fn get_ocsp_stats(&self) -> HashMap<String, u64> {
        let requests = self.ocsp_requests.read().await;
        let responses = self.ocsp_responses.read().await;

        let mut stats = HashMap::new();
        stats.insert("total_requests".to_string(), requests.len() as u64);
        stats.insert("total_responses".to_string(), responses.len() as u64);

        stats
    }

    /// Cleanup old OCSP responses
    pub async fn cleanup_old_ocsp_responses(&self, older_than_hours: u64) -> u64 {
        let mut responses = self.ocsp_responses.write().await;
        let initial_count = responses.len();
        
        let cutoff = Utc::now() - Duration::hours(older_than_hours as i64);
        responses.retain(|_, resp| resp.produced_at >= cutoff);

        (initial_count - responses.len()) as u64
    }
}

impl Default for CertificateRevocationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_revoke_certificate() {
        let service = CertificateRevocationService::new();
        
        service
            .revoke_certificate(
                "ABC123".to_string(),
                "CN=Test CA".to_string(),
                RevocationReason::KeyCompromise,
                Some("admin".to_string()),
            )
            .await
            .unwrap();

        assert!(service.is_revoked("ABC123").await);
        
        let revoked = service.get_revoked_cert("ABC123").await.unwrap();
        assert_eq!(revoked.reason, RevocationReason::KeyCompromise);
    }

    #[tokio::test]
    async fn test_crl_generation() {
        let service = CertificateRevocationService::new();
        
        let config = CRLConfig {
            issuer: "CN=Test CA".to_string(),
            validity_period_days: 7,
            auto_rebuild: true,
            distribution_points: vec!["http://ca.example.com/crl".to_string()],
        };

        service.configure_crl(config).await.unwrap();

        // Revoke a certificate
        service
            .revoke_certificate(
                "ABC123".to_string(),
                "CN=Test CA".to_string(),
                RevocationReason::KeyCompromise,
                None,
            )
            .await
            .unwrap();

        // Get CRL
        let crl = service.get_crl("CN=Test CA").await.unwrap();
        assert_eq!(crl.revoked_certificates.len(), 1);
        assert!(crl.is_revoked("ABC123").is_some());
    }

    #[tokio::test]
    async fn test_ocsp_request() {
        let service = CertificateRevocationService::new();
        
        let ocsp_config = OCSPConfig {
            responder_id: "OCSP Responder".to_string(),
            responder_url: "http://ocsp.example.com".to_string(),
            signing_key: vec![0; 32],
            cache_responses: true,
            response_validity_hours: 24,
        };

        service.configure_ocsp(ocsp_config).await.unwrap();

        // Request for good certificate
        let response = service
            .process_ocsp_request("GOOD123".to_string(), "CN=Test CA".to_string(), None)
            .await
            .unwrap();

        assert_eq!(response.status, OCSPStatus::Good);
    }

    #[tokio::test]
    async fn test_ocsp_revoked_certificate() {
        let service = CertificateRevocationService::new();
        
        let ocsp_config = OCSPConfig {
            responder_id: "OCSP Responder".to_string(),
            responder_url: "http://ocsp.example.com".to_string(),
            signing_key: vec![0; 32],
            cache_responses: true,
            response_validity_hours: 24,
        };

        service.configure_ocsp(ocsp_config).await.unwrap();

        // Revoke certificate
        service
            .revoke_certificate(
                "REV123".to_string(),
                "CN=Test CA".to_string(),
                RevocationReason::KeyCompromise,
                None,
            )
            .await
            .unwrap();

        // OCSP check should return revoked
        let response = service
            .process_ocsp_request("REV123".to_string(), "CN=Test CA".to_string(), None)
            .await
            .unwrap();

        match response.status {
            OCSPStatus::Revoked { reason, .. } => {
                assert_eq!(reason, RevocationReason::KeyCompromise);
            }
            _ => panic!("Expected Revoked status"),
        }
    }

    #[tokio::test]
    async fn test_unrevoke_certificate() {
        let service = CertificateRevocationService::new();
        
        let config = CRLConfig {
            issuer: "CN=Test CA".to_string(),
            validity_period_days: 7,
            auto_rebuild: true,
            distribution_points: vec![],
        };

        service.configure_crl(config).await.unwrap();

        // Revoke with CertificateHold
        service
            .revoke_certificate(
                "HOLD123".to_string(),
                "CN=Test CA".to_string(),
                RevocationReason::CertificateHold,
                None,
            )
            .await
            .unwrap();

        assert!(service.is_revoked("HOLD123").await);

        // Unrevoke
        service.unrevoke_certificate("HOLD123").await.unwrap();
        assert!(!service.is_revoked("HOLD123").await);
    }

    #[tokio::test]
    async fn test_list_revoked_by_issuer() {
        let service = CertificateRevocationService::new();
        
        service
            .revoke_certificate(
                "CA1-123".to_string(),
                "CN=CA1".to_string(),
                RevocationReason::Unspecified,
                None,
            )
            .await
            .unwrap();

        service
            .revoke_certificate(
                "CA2-456".to_string(),
                "CN=CA2".to_string(),
                RevocationReason::Unspecified,
                None,
            )
            .await
            .unwrap();

        let ca1_revoked = service.list_revoked(Some("CN=CA1")).await;
        assert_eq!(ca1_revoked.len(), 1);
        assert_eq!(ca1_revoked[0].serial_number, "CA1-123");

        let all_revoked = service.list_revoked(None).await;
        assert_eq!(all_revoked.len(), 2);
    }
}
