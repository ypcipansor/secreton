//! Certificate revocation structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Certificate revocation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CertificateStatus {
    Valid,
    Revoked,
    Expired,
}

/// Certificate revocation reason
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Certificate revocation entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRevocation {
    pub serial_number: String,
    pub revocation_date: DateTime<Utc>,
    pub reason: RevocationReason,
    pub issuer: String,
    pub invalidity_date: Option<DateTime<Utc>>,
}

/// Certificate revocation list (CRL)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    pub id: Uuid,
    pub issuer: String,
    pub this_update: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub revoked_certificates: Vec<CertificateRevocation>,
    pub version: u32,
}

/// Certificate revocation request
#[derive(Debug, Deserialize)]
pub struct CertificateRevocationRequest {
    pub serial_number: String,
    pub reason: RevocationReason,
    pub invalidity_date: Option<DateTime<Utc>>,
}

/// Certificate status request
#[derive(Debug, Deserialize)]
pub struct CertificateStatusRequest {
    pub serial_number: String,
    pub issuer: String,
}

/// Certificate status response
#[derive(Debug, Serialize)]
pub struct CertificateStatusResponse {
    pub serial_number: String,
    pub status: CertificateStatus,
    pub revocation_info: Option<CertificateRevocation>,
}

impl CertificateRevocationList {
    /// Check if a certificate is revoked
    pub fn is_revoked(&self, serial_number: &str) -> Option<&CertificateRevocation> {
        self.revoked_certificates
            .iter()
            .find(|rev| rev.serial_number == serial_number)
    }

    /// Add a revocation entry
    pub fn add_revocation(&mut self, revocation: CertificateRevocation) {
        // Remove any existing revocation for this serial number
        self.revoked_certificates
            .retain(|rev| rev.serial_number != revocation.serial_number);
        self.revoked_certificates.push(revocation);
        self.this_update = Utc::now();
    }

    /// Remove a revocation entry
    pub fn remove_revocation(&mut self, serial_number: &str) {
        self.revoked_certificates
            .retain(|rev| rev.serial_number != serial_number);
        self.this_update = Utc::now();
    }
}
