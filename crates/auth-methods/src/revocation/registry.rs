//! Revocation registry management

use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};

use super::certificate::*;
use crate::error::*;

/// Revocation registry trait
#[async_trait]
pub trait RevocationRegistry: Send + Sync {
    /// Revoke a certificate
    async fn revoke_certificate(&self, request: CertificateRevocationRequest, issuer: String) -> Result<(), AuthMethodError>;

    /// Check certificate status
    async fn check_certificate_status(&self, request: CertificateStatusRequest) -> Result<CertificateStatusResponse, AuthMethodError>;

    /// Get CRL for an issuer
    async fn get_crl(&self, issuer: String) -> Result<Option<CertificateRevocationList>, AuthMethodError>;

    /// Update CRL next update time
    async fn update_crl(&self, issuer: String, next_update: DateTime<Utc>) -> Result<(), AuthMethodError>;

    /// Clean up expired CRLs
    async fn cleanup_expired_crls(&self) -> Result<usize, AuthMethodError>;
}

/// In-memory revocation registry implementation
pub struct InMemoryRevocationRegistry {
    crls: RwLock<HashMap<String, CertificateRevocationList>>,
    crl_validity_period: Duration,
}

impl InMemoryRevocationRegistry {
    pub fn new(crl_validity_period: Duration) -> Self {
        Self {
            crls: RwLock::new(HashMap::new()),
            crl_validity_period,
        }
    }

    /// Get or create CRL for an issuer
    async fn get_or_create_crl(&self, issuer: String) -> CertificateRevocationList {
        let mut crls = self.crls.write().await;

        if let Some(crl) = crls.get(&issuer) {
            crl.clone()
        } else {
            let crl = CertificateRevocationList {
                id: Uuid::new_v4(),
                issuer: issuer.clone(),
                this_update: Utc::now(),
                next_update: Utc::now() + self.crl_validity_period,
                revoked_certificates: Vec::new(),
                version: 1,
            };
            crls.insert(issuer, crl.clone());
            crl
        }
    }
}

#[async_trait]
impl RevocationRegistry for InMemoryRevocationRegistry {
    async fn revoke_certificate(&self, request: CertificateRevocationRequest, issuer: String) -> Result<(), AuthMethodError> {
        let mut crls = self.crls.write().await;

        let crl = crls.entry(issuer.clone()).or_insert_with(|| CertificateRevocationList {
            id: Uuid::new_v4(),
            issuer: issuer.clone(),
            this_update: Utc::now(),
            next_update: Utc::now() + self.crl_validity_period,
            revoked_certificates: Vec::new(),
            version: 1,
        });

        let revocation = CertificateRevocation {
            serial_number: request.serial_number,
            revocation_date: Utc::now(),
            reason: request.reason,
            issuer,
            invalidity_date: request.invalidity_date,
        };

        crl.add_revocation(revocation);
        Ok(())
    }

    async fn check_certificate_status(&self, request: CertificateStatusRequest) -> Result<CertificateStatusResponse, AuthMethodError> {
        let crls = self.crls.read().await;

        if let Some(crl) = crls.get(&request.issuer) {
            if let Some(revocation) = crl.is_revoked(&request.serial_number) {
                Ok(CertificateStatusResponse {
                    serial_number: request.serial_number,
                    status: CertificateStatus::Revoked,
                    revocation_info: Some(revocation.clone()),
                })
            } else {
                Ok(CertificateStatusResponse {
                    serial_number: request.serial_number,
                    status: CertificateStatus::Valid,
                    revocation_info: None,
                })
            }
        } else {
            // If no CRL exists for this issuer, assume valid
            Ok(CertificateStatusResponse {
                serial_number: request.serial_number,
                status: CertificateStatus::Valid,
                revocation_info: None,
            })
        }
    }

    async fn get_crl(&self, issuer: String) -> Result<Option<CertificateRevocationList>, AuthMethodError> {
        let crls = self.crls.read().await;
        Ok(crls.get(&issuer).cloned())
    }

    async fn update_crl(&self, issuer: String, next_update: DateTime<Utc>) -> Result<(), AuthMethodError> {
        let mut crls = self.crls.write().await;

        if let Some(crl) = crls.get_mut(&issuer) {
            crl.next_update = next_update;
            crl.this_update = Utc::now();
            crl.version += 1;
        }

        Ok(())
    }

    async fn cleanup_expired_crls(&self) -> Result<usize, AuthMethodError> {
        let mut crls = self.crls.write().await;
        let now = Utc::now();

        let expired_issuers: Vec<String> = crls.values()
            .filter(|crl| crl.next_update < now)
            .map(|crl| crl.issuer.clone())
            .collect();

        for issuer in expired_issuers {
            crls.remove(&issuer);
        }

        Ok(crls.len())
    }
}