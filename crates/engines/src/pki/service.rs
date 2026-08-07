//! PKI service layer

use super::engine::PkiEngine;
use super::error::PkiError;
use super::model::{
    CertificateRequest, CertificateResponse, PkiConfig, RevocationRequest, SshKeyRequest,
    SshKeyResponse,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// PKI service for certificate and key management
pub struct PkiService {
    /// PKI engine
    engine: Arc<RwLock<PkiEngine>>,
}

impl PkiService {
    /// Create a new PKI service
    pub fn new(config: PkiConfig) -> Self {
        let engine = Arc::new(RwLock::new(PkiEngine::new(config)));

        Self { engine }
    }

    /// Generate a certificate
    pub async fn generate_certificate(
        &self,
        request: CertificateRequest,
    ) -> Result<CertificateResponse, PkiError> {
        let engine = self.engine.read().await;
        engine.generate_certificate(&request).await
    }

    /// Generate SSH keys
    pub async fn generate_ssh_key(
        &self,
        request: SshKeyRequest,
    ) -> Result<SshKeyResponse, PkiError> {
        let engine = self.engine.read().await;
        engine.generate_ssh_key(&request).await
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(&self, request: RevocationRequest) -> Result<(), PkiError> {
        let engine = self.engine.read().await;
        engine.revoke_certificate(&request).await
    }

    /// Get CA information
    pub async fn get_ca_info(&self) -> Result<super::model::CaInfo, PkiError> {
        let engine = self.engine.read().await;
        engine.get_ca_info().await
    }
}
