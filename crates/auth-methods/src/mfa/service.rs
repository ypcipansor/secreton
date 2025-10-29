//! Unified MFA service combining all MFA methods

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use super::totp::*;
use super::sms::*;
use super::email::*;
use super::hardware::*;
use crate::error::*;

/// MFA method types
#[derive(Debug, Clone, PartialEq)]
pub enum MfaMethod {
    Totp,
    Sms,
    Email,
    Hardware,
}

/// MFA enrollment status
#[derive(Debug, Clone)]
pub struct MfaEnrollment {
    pub entity_id: Uuid,
    pub methods: Vec<MfaMethod>,
    pub required_methods: Vec<MfaMethod>,
    pub enrolled_at: DateTime<Utc>,
}

/// MFA validation request
#[derive(Debug)]
pub struct MfaValidationRequest {
    pub entity_id: Uuid,
    pub method: MfaMethod,
    pub code: Option<String>,
    pub hardware_request: Option<HardwareAuthenticationRequest>,
}

/// MFA service trait
#[async_trait]
pub trait MfaService: Send + Sync {
    /// Enroll an entity for MFA with specific methods
    async fn enroll_entity(&self, entity_id: Uuid, methods: Vec<MfaMethod>) -> AuthMethodResult<MfaEnrollment>;

    /// Get MFA enrollment for an entity
    async fn get_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<Option<MfaEnrollment>>;

    /// Update MFA enrollment for an entity
    async fn update_enrollment(&self, entity_id: Uuid, methods: Vec<MfaMethod>) -> AuthMethodResult<MfaEnrollment>;

    /// Remove MFA enrollment for an entity
    async fn remove_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<()>;

    /// Validate MFA code for an entity
    async fn validate(&self, request: MfaValidationRequest) -> AuthMethodResult<bool>;

    /// Check if MFA is required for an entity
    async fn is_mfa_required(&self, entity_id: Uuid) -> AuthMethodResult<bool>;
}

/// Combined MFA service implementation
pub struct CombinedMfaService {
    totp_service: Arc<dyn TotpService>,
    sms_service: Arc<dyn SmsService>,
    email_service: Arc<dyn EmailService>,
    hardware_service: Arc<dyn HardwareService>,
    enrollments: RwLock<HashMap<Uuid, MfaEnrollment>>,
}

impl CombinedMfaService {
    pub fn new(
        totp_service: Arc<dyn TotpService>,
        sms_service: Arc<dyn SmsService>,
        email_service: Arc<dyn EmailService>,
        hardware_service: Arc<dyn HardwareService>,
    ) -> Self {
        Self {
            totp_service,
            sms_service,
            email_service,
            hardware_service,
            enrollments: RwLock::new(HashMap::new()),
        }
    }

    /// Validate based on MFA method
    async fn validate_method(&self, request: &MfaValidationRequest) -> Result<bool, AuthMethodError> {
        match &request.method {
            MfaMethod::Totp => {
                if let Some(code) = &request.code {
                    let totp_request = TotpValidationRequest {
                        entity_id: request.entity_id,
                        code: code.clone(),
                    };
                    self.totp_service.validate(totp_request).await
                        .map_err(|e| e.into())
                } else {
                    Ok(false)
                }
            }
            MfaMethod::Sms => {
                if let Some(code) = &request.code {
                    let sms_request = SmsValidationRequest {
                        entity_id: request.entity_id,
                        code: code.clone(),
                    };
                    self.sms_service.validate(sms_request).await
                } else {
                    Ok(false)
                }
            }
            MfaMethod::Email => {
                if let Some(code) = &request.code {
                    let email_request = EmailValidationRequest {
                        entity_id: request.entity_id,
                        code: code.clone(),
                    };
                    self.email_service.validate(email_request).await
                } else {
                    Ok(false)
                }
            }
            MfaMethod::Hardware => {
                if let Some(hw_request) = &request.hardware_request {
                    self.hardware_service.authenticate(hw_request.clone()).await
                        .map_err(|e| e.into())
                } else {
                    Ok(false)
                }
            }
        }
    }
}

#[async_trait]
impl MfaService for CombinedMfaService {
    async fn enroll_entity(&self, entity_id: Uuid, methods: Vec<MfaMethod>) -> AuthMethodResult<MfaEnrollment> {
        let enrollment = MfaEnrollment {
            entity_id,
            methods: methods.clone(),
            required_methods: methods, // All enrolled methods are required by default
            enrolled_at: Utc::now(),
        };

        let mut enrollments = self.enrollments.write().await;
        enrollments.insert(entity_id, enrollment.clone());

        Ok(enrollment)
    }

    async fn validate(&self, request: MfaValidationRequest) -> Result<bool, AuthMethodError> {
        let enrollments = self.enrollments.read().await;

        if let Some(enrollment) = enrollments.get(&request.entity_id) {
            // Check if the requested method is enrolled
            if !enrollment.methods.contains(&request.method) {
                return Ok(false);
            }

            // Validate using the specific method
            self.validate_method(&request).await
        } else {
            Ok(false)
        }
    }

    async fn get_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<Option<MfaEnrollment>> {
        let enrollments = self.enrollments.read().await;
        Ok(enrollments.get(&entity_id).cloned())
    }

    async fn update_enrollment(&self, entity_id: Uuid, methods: Vec<MfaMethod>) -> AuthMethodResult<MfaEnrollment> {
        let mut enrollments = self.enrollments.write().await;

        if let Some(enrollment) = enrollments.get_mut(&entity_id) {
            enrollment.methods = methods.clone();
            enrollment.required_methods = methods;
            Ok(enrollment.clone())
        } else {
            Err(AuthMethodError::UserNotFound(format!("MFA enrollment for entity {}", entity_id)))
        }
    }

    async fn remove_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<()> {
        let mut enrollments = self.enrollments.write().await;
        enrollments.remove(&entity_id);

        // Also remove from individual services
        let _ = self.totp_service.remove_enrollment(entity_id).await;
        let _ = self.sms_service.remove_enrollment(entity_id).await;
        let _ = self.email_service.remove_enrollment(entity_id).await;

        // Remove all hardware enrollments for this entity
        if let Ok(hw_enrollments) = self.hardware_service.list_enrollments(entity_id).await {
            for enrollment in hw_enrollments {
                let _ = self.hardware_service.remove_enrollment(entity_id, enrollment.credential_id).await;
            }
        }

        Ok(())
    }

    async fn is_mfa_required(&self, entity_id: Uuid) -> Result<bool, AuthMethodError> {
        let enrollments = self.enrollments.read().await;
        Ok(enrollments.contains_key(&entity_id))
    }
}