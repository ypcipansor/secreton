//! Hardware token MFA implementation (FIDO U2F/WebAuthn, etc.)

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::*;

/// Hardware token types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HardwareTokenType {
    U2f,
    WebAuthn,
    Fido2,
    SmartCard,
}

/// Hardware token enrollment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEnrollment {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub token_type: HardwareTokenType,
    pub credential_id: String,
    pub public_key: String,
    pub sign_count: u32,
    pub creation_time: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

/// Hardware token registration request
#[derive(Debug, Deserialize)]
pub struct HardwareRegistrationRequest {
    pub entity_id: Uuid,
    pub token_type: HardwareTokenType,
    pub credential_id: String,
    pub public_key: String,
    pub attestation_object: Option<String>, // For WebAuthn
}

/// Hardware token authentication request
#[derive(Debug, Clone, Deserialize)]
pub struct HardwareAuthenticationRequest {
    pub entity_id: Uuid,
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

/// Hardware service trait
#[async_trait]
pub trait HardwareService: Send + Sync {
    /// Register a hardware token
    async fn register(
        &self,
        request: HardwareRegistrationRequest,
    ) -> Result<HardwareEnrollment, AuthMethodError>;

    /// Authenticate with a hardware token
    async fn authenticate(
        &self,
        request: HardwareAuthenticationRequest,
    ) -> Result<bool, AuthMethodError>;

    /// Get enrollment for an entity
    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<HardwareEnrollment>, AuthMethodError>;

    /// List all enrollments for an entity
    async fn list_enrollments(
        &self,
        entity_id: Uuid,
    ) -> Result<Vec<HardwareEnrollment>, AuthMethodError>;

    /// Remove hardware token enrollment
    async fn remove_enrollment(
        &self,
        entity_id: Uuid,
        credential_id: String,
    ) -> Result<(), AuthMethodError>;
}

/// In-memory hardware service implementation
pub struct InMemoryHardwareService {
    enrollments: RwLock<HashMap<String, HardwareEnrollment>>, // Key: credential_id
    entity_enrollments: RwLock<HashMap<Uuid, Vec<String>>>,   // entity_id -> credential_ids
}

impl InMemoryHardwareService {
    pub fn new() -> Self {
        Self {
            enrollments: RwLock::new(HashMap::new()),
            entity_enrollments: RwLock::new(HashMap::new()),
        }
    }

    /// Verify WebAuthn/FIDO2 signature (simplified implementation)
    async fn verify_signature(
        &self,
        _request: &HardwareAuthenticationRequest,
    ) -> Result<bool, AuthMethodError> {
        // In a real implementation, this would:
        // 1. Parse the authenticator data
        // 2. Verify the signature using the stored public key
        // 3. Check signature counters
        // 4. Validate client data JSON
        //
        // For this example, we'll just return true for demonstration
        Ok(true)
    }
}

#[async_trait]
impl HardwareService for InMemoryHardwareService {
    async fn register(
        &self,
        request: HardwareRegistrationRequest,
    ) -> Result<HardwareEnrollment, AuthMethodError> {
        let enrollment = HardwareEnrollment {
            id: Uuid::new_v4(),
            entity_id: request.entity_id,
            token_type: request.token_type,
            credential_id: request.credential_id.clone(),
            public_key: request.public_key,
            sign_count: 0,
            creation_time: Utc::now(),
            last_used: None,
        };

        let mut enrollments = self.enrollments.write().await;
        let mut entity_enrollments = self.entity_enrollments.write().await;

        enrollments.insert(request.credential_id.clone(), enrollment.clone());
        entity_enrollments
            .entry(request.entity_id)
            .or_insert_with(Vec::new)
            .push(request.credential_id);

        Ok(enrollment)
    }

    async fn authenticate(
        &self,
        request: HardwareAuthenticationRequest,
    ) -> Result<bool, AuthMethodError> {
        let enrollments = self.enrollments.read().await;

        if let Some(_enrollment) = enrollments.get(&request.credential_id) {
            // Verify the signature
            if self.verify_signature(&request).await? {
                // Update last used time and sign count
                drop(enrollments);
                let mut enrollments = self.enrollments.write().await;
                if let Some(enrollment) = enrollments.get_mut(&request.credential_id) {
                    enrollment.last_used = Some(Utc::now());
                    enrollment.sign_count += 1;
                }
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<HardwareEnrollment>, AuthMethodError> {
        let entity_enrollments = self.entity_enrollments.read().await;
        let enrollments = self.enrollments.read().await;

        if let Some(credential_ids) = entity_enrollments.get(&entity_id) {
            if let Some(first_credential_id) = credential_ids.first() {
                return Ok(enrollments.get(first_credential_id).cloned());
            }
        }

        Ok(None)
    }

    async fn list_enrollments(
        &self,
        entity_id: Uuid,
    ) -> Result<Vec<HardwareEnrollment>, AuthMethodError> {
        let entity_enrollments = self.entity_enrollments.read().await;
        let enrollments = self.enrollments.read().await;

        let mut result = Vec::new();
        if let Some(credential_ids) = entity_enrollments.get(&entity_id) {
            for credential_id in credential_ids {
                if let Some(enrollment) = enrollments.get(credential_id) {
                    result.push(enrollment.clone());
                }
            }
        }

        Ok(result)
    }

    async fn remove_enrollment(
        &self,
        entity_id: Uuid,
        credential_id: String,
    ) -> Result<(), AuthMethodError> {
        let mut enrollments = self.enrollments.write().await;
        let mut entity_enrollments = self.entity_enrollments.write().await;

        enrollments.remove(&credential_id);

        if let Some(credential_ids) = entity_enrollments.get_mut(&entity_id) {
            credential_ids.retain(|id| id != &credential_id);
            if credential_ids.is_empty() {
                entity_enrollments.remove(&entity_id);
            }
        }

        Ok(())
    }
}
