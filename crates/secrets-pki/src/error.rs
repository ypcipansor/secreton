//! PKI-specific errors

use thiserror::Error;

/// PKI-specific errors
#[derive(Error, Debug)]
pub enum PkiError {
    #[error("Certificate generation failed: {0}")]
    CertificateGeneration(String),

    #[error("Certificate signing failed: {0}")]
    CertificateSigning(String),

    #[error("Invalid certificate request: {0}")]
    InvalidCertificateRequest(String),

    #[error("Certificate not found: {0}")]
    CertificateNotFound(String),

    #[error("Certificate already revoked: {0}")]
    CertificateAlreadyRevoked(String),

    #[error("Invalid CA configuration: {0}")]
    InvalidCaConfiguration(String),

    #[error("SSH key generation failed: {0}")]
    SshKeyGeneration(String),

    #[error("CRL generation failed: {0}")]
    CrlGeneration(String),

    #[error("Key usage validation failed: {0}")]
    KeyUsageValidation(String),

    #[error("Certificate parsing failed: {0}")]
    CertificateParsing(String),

    #[error("Storage error: {0}")]
    Storage(#[from] Box<dyn std::error::Error + Send + Sync>),
}
