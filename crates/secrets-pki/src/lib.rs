//! PKI and Certificate Management Secret Engines
//!
//! This crate provides PKI (Public Key Infrastructure) and certificate management
//! functionality for the Secreton secrets management system. It includes:
//!
//! - Certificate generation and signing
//! - Certificate revocation
//! - SSH key management
//! - CA (Certificate Authority) operations

pub mod engine;
pub mod error;
pub mod model;
pub mod service;

// Re-export main types
pub use engine::{CertificateMetadata, PkiEngine};
pub use error::PkiError;
pub use model::{CertificateRequest, CertificateResponse, PkiConfig};
pub use service::PkiService;
