//! Unified revocation service

use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use super::certificate::*;
use super::registry::*;
use crate::service::AuthMethodResult;
use secreton_domain::SecretonError;

/// Revocation service trait
#[async_trait]
pub trait RevocationService: Send + Sync {
    /// Revoke a certificate
    async fn revoke_certificate(
        &self,
        request: CertificateRevocationRequest,
        issuer: String,
    ) -> AuthMethodResult<()>;

    /// Check certificate status
    async fn check_certificate_status(
        &self,
        request: CertificateStatusRequest,
    ) -> AuthMethodResult<CertificateStatusResponse>;

    /// Get CRL for an issuer
    async fn get_crl(&self, issuer: String) -> AuthMethodResult<Option<CertificateRevocationList>>;

    /// Revoke a token (delegates to token service)
    async fn revoke_token(&self, token_id: Uuid) -> AuthMethodResult<()>;

    /// Revoke all tokens for an entity (delegates to token service)
    async fn revoke_entity_tokens(&self, entity_id: Uuid) -> AuthMethodResult<()>;

    /// Perform maintenance (cleanup expired entries)
    async fn perform_maintenance(&self) -> AuthMethodResult<MaintenanceResult>;
}

/// Maintenance result
#[derive(Debug)]
pub struct MaintenanceResult {
    pub expired_crls_cleaned: usize,
    pub expired_tokens_cleaned: usize,
}

/// Combined revocation service implementation
pub struct CombinedRevocationService {
    certificate_registry: Arc<dyn RevocationRegistry>,
    token_revocation_service:
        Option<Arc<dyn super::super::token::revocation::TokenRevocationService>>,
}

impl CombinedRevocationService {
    pub fn new(
        certificate_registry: Arc<dyn RevocationRegistry>,
        token_revocation_service: Option<
            Arc<dyn super::super::token::revocation::TokenRevocationService>,
        >,
    ) -> Self {
        Self {
            certificate_registry,
            token_revocation_service,
        }
    }
}

#[async_trait]
impl RevocationService for CombinedRevocationService {
    async fn revoke_certificate(
        &self,
        request: CertificateRevocationRequest,
        issuer: String,
    ) -> AuthMethodResult<()> {
        self.certificate_registry
            .revoke_certificate(request, issuer)
            .await
    }

    async fn check_certificate_status(
        &self,
        request: CertificateStatusRequest,
    ) -> AuthMethodResult<CertificateStatusResponse> {
        self.certificate_registry
            .check_certificate_status(request)
            .await
    }

    async fn get_crl(&self, issuer: String) -> AuthMethodResult<Option<CertificateRevocationList>> {
        self.certificate_registry.get_crl(issuer).await
    }

    async fn revoke_token(&self, token_id: Uuid) -> AuthMethodResult<()> {
        if let Some(token_service) = &self.token_revocation_service {
            let request = super::super::token::TokenRevocationRequest { token_id };
            token_service.revoke_token(request).await
        } else {
            Err(SecretonError::Configuration {
                message: "Token revocation service not available".to_string(),
            })
        }
    }

    async fn revoke_entity_tokens(&self, entity_id: Uuid) -> AuthMethodResult<()> {
        if let Some(token_service) = &self.token_revocation_service {
            token_service.revoke_entity_tokens(entity_id).await
        } else {
            Err(SecretonError::Configuration {
                message: "Token revocation service not available".to_string(),
            })
        }
    }

    async fn perform_maintenance(&self) -> AuthMethodResult<MaintenanceResult> {
        let expired_crls_cleaned = self.certificate_registry.cleanup_expired_crls().await?;

        // Note: Token cleanup would be handled by the token service directly
        // We don't have access to the token service's cleanup method here
        let expired_tokens_cleaned = 0;

        Ok(MaintenanceResult {
            expired_crls_cleaned,
            expired_tokens_cleaned,
        })
    }
}
