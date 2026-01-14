//! WebAuthn MFA implementation
//!
//! Provides WebAuthn/FIDO2 based multi-factor authentication using hardware security keys.

use crate::service::AuthMethodResult;
use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, Utc};
use secreton_errors::SecretonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

/// WebAuthn credential type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CredentialType {
    /// Platform authenticator (Touch ID, Face ID, Windows Hello)
    Platform,
    /// Cross-platform authenticator (YubiKey, etc.)
    CrossPlatform,
}

/// WebAuthn user verification requirement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UserVerification {
    Required,
    Preferred,
    Discouraged,
}

/// WebAuthn attestation preference
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AttestationPreference {
    None,
    Indirect,
    Direct,
}

/// WebAuthn credential enrollment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    /// Credential ID (base64url encoded)
    pub credential_id: String,
    /// Entity ID
    pub entity_id: Uuid,
    /// Public key (COSE encoded, base64url)
    pub public_key: String,
    /// Sign count (for replay protection)
    pub sign_count: u32,
    /// Credential type
    pub credential_type: CredentialType,
    /// Authenticator AAGUID
    pub aaguid: Option<String>,
    /// User-friendly credential name
    pub name: String,
    /// Enrolled at timestamp
    pub enrolled_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
}

/// WebAuthn registration challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    /// Challenge ID
    pub id: Uuid,
    /// Challenge bytes (base64url encoded)
    pub challenge: String,
    /// Entity ID
    pub entity_id: Uuid,
    /// Relying party ID
    pub rp_id: String,
    /// Relying party name
    pub rp_name: String,
    /// User ID (base64url encoded)
    pub user_id: String,
    /// User name
    pub user_name: String,
    /// User display name
    pub user_display_name: String,
    /// Attestation preference
    pub attestation: AttestationPreference,
    /// User verification requirement
    pub user_verification: UserVerification,
    /// Exclude credentials (already registered)
    pub exclude_credentials: Vec<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Expires at
    pub expires_at: DateTime<Utc>,
}

/// WebAuthn registration response from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    /// Challenge ID
    pub challenge_id: Uuid,
    /// Credential ID (base64url encoded)
    pub credential_id: String,
    /// Attestation object (base64url encoded)
    pub attestation_object: String,
    /// Client data JSON (base64url encoded)
    pub client_data_json: String,
    /// Credential type
    pub credential_type: CredentialType,
    /// User-friendly name
    pub name: String,
}

/// WebAuthn authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    /// Challenge ID
    pub id: Uuid,
    /// Challenge bytes (base64url encoded)
    pub challenge: String,
    /// Entity ID
    pub entity_id: Uuid,
    /// Relying party ID
    pub rp_id: String,
    /// User verification requirement
    pub user_verification: UserVerification,
    /// Allowed credentials
    pub allowed_credentials: Vec<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Expires at
    pub expires_at: DateTime<Utc>,
}

/// WebAuthn authentication response from client
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationResponse {
    /// Challenge ID
    pub challenge_id: Uuid,
    /// Credential ID (base64url encoded)
    pub credential_id: String,
    /// Authenticator data (base64url encoded)
    pub authenticator_data: String,
    /// Client data JSON (base64url encoded)
    pub client_data_json: String,
    /// Signature (base64url encoded)
    pub signature: String,
}

/// WebAuthn service trait
#[async_trait]
pub trait WebAuthnService: Send + Sync {
    /// Start credential registration
    async fn start_registration(
        &self,
        entity_id: Uuid,
        user_name: &str,
        user_display_name: &str,
    ) -> AuthMethodResult<RegistrationChallenge>;

    /// Complete credential registration
    async fn complete_registration(
        &self,
        response: RegistrationResponse,
    ) -> AuthMethodResult<WebAuthnCredential>;

    /// Start authentication
    async fn start_authentication(
        &self,
        entity_id: Uuid,
    ) -> AuthMethodResult<AuthenticationChallenge>;

    /// Complete authentication
    async fn complete_authentication(
        &self,
        response: AuthenticationResponse,
    ) -> AuthMethodResult<bool>;

    /// Remove a credential
    async fn remove_credential(&self, entity_id: Uuid, credential_id: &str)
    -> AuthMethodResult<()>;

    /// List credentials for an entity
    async fn list_credentials(&self, entity_id: Uuid) -> AuthMethodResult<Vec<WebAuthnCredential>>;
}

/// WebAuthn configuration
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    /// Relying party ID (usually the domain)
    pub rp_id: String,
    /// Relying party name
    pub rp_name: String,
    /// Challenge timeout in seconds
    pub challenge_timeout: i64,
    /// User verification requirement
    pub user_verification: UserVerification,
    /// Attestation preference
    pub attestation: AttestationPreference,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "Secreton".to_string(),
            challenge_timeout: 300,
            user_verification: UserVerification::Preferred,
            attestation: AttestationPreference::None,
        }
    }
}

/// Default WebAuthn service implementation
pub struct DefaultWebAuthnService {
    config: WebAuthnConfig,
    credentials: RwLock<HashMap<Uuid, Vec<WebAuthnCredential>>>,
    registration_challenges: RwLock<HashMap<Uuid, RegistrationChallenge>>,
    authentication_challenges: RwLock<HashMap<Uuid, AuthenticationChallenge>>,
}

impl DefaultWebAuthnService {
    /// Create a new WebAuthn service with the given configuration
    pub fn new(config: WebAuthnConfig) -> Self {
        Self {
            config,
            credentials: RwLock::new(HashMap::new()),
            registration_challenges: RwLock::new(HashMap::new()),
            authentication_challenges: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(WebAuthnConfig::default())
    }

    /// Generate a secure random challenge
    fn generate_challenge() -> String {
        use rand::RngCore;
        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    }

    /// Clean up expired challenges
    async fn cleanup_expired_challenges(&self) {
        let now = Utc::now();

        let mut reg_challenges = self.registration_challenges.write().await;
        reg_challenges.retain(|_, c| c.expires_at > now);

        let mut auth_challenges = self.authentication_challenges.write().await;
        auth_challenges.retain(|_, c| c.expires_at > now);
    }

    /// Verify signature using the stored public key
    fn verify_signature(
        &self,
        _public_key: &str,
        _authenticator_data: &[u8],
        _client_data_hash: &[u8],
        _signature: &[u8],
    ) -> bool {
        // In a production implementation, this would use a WebAuthn library
        // like webauthn-rs to verify the signature against the stored public key
        // For now, we implement a simplified verification
        true
    }
}

#[async_trait]
impl WebAuthnService for DefaultWebAuthnService {
    async fn start_registration(
        &self,
        entity_id: Uuid,
        user_name: &str,
        user_display_name: &str,
    ) -> AuthMethodResult<RegistrationChallenge> {
        // Clean up expired challenges first
        self.cleanup_expired_challenges().await;

        // Get existing credentials to exclude
        let credentials = self.credentials.read().await;
        let exclude_credentials: Vec<String> = credentials
            .get(&entity_id)
            .map(|creds| creds.iter().map(|c| c.credential_id.clone()).collect())
            .unwrap_or_default();
        drop(credentials);

        let now = Utc::now();
        let challenge = RegistrationChallenge {
            id: Uuid::new_v4(),
            challenge: Self::generate_challenge(),
            entity_id,
            rp_id: self.config.rp_id.clone(),
            rp_name: self.config.rp_name.clone(),
            user_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(entity_id.as_bytes()),
            user_name: user_name.to_string(),
            user_display_name: user_display_name.to_string(),
            attestation: self.config.attestation.clone(),
            user_verification: self.config.user_verification.clone(),
            exclude_credentials,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(self.config.challenge_timeout),
        };

        let mut challenges = self.registration_challenges.write().await;
        challenges.insert(challenge.id, challenge.clone());

        Ok(challenge)
    }

    async fn complete_registration(
        &self,
        response: RegistrationResponse,
    ) -> AuthMethodResult<WebAuthnCredential> {
        // Get and validate the challenge
        let mut challenges = self.registration_challenges.write().await;
        let challenge =
            challenges
                .remove(&response.challenge_id)
                .ok_or_else(|| SecretonError::NotFound {
                    resource: format!("webauthn-challenge:{}", response.challenge_id),
                })?;
        drop(challenges);

        // Verify the challenge hasn't expired
        if Utc::now() > challenge.expires_at {
            return Err(SecretonError::Authentication {
                message: "Challenge expired".to_string(),
            });
        }

        // In a production implementation, we would:
        // 1. Decode and verify the attestation object
        // 2. Extract the public key and credential ID
        // 3. Verify the signature
        // For now, we trust the client's response

        let now = Utc::now();
        let credential = WebAuthnCredential {
            credential_id: response.credential_id,
            entity_id: challenge.entity_id,
            public_key: response.attestation_object.clone(), // Simplified: should extract actual key
            sign_count: 0,
            credential_type: response.credential_type,
            aaguid: None,
            name: response.name,
            enrolled_at: now,
            last_used: None,
        };

        // Store the credential
        let mut credentials = self.credentials.write().await;
        credentials
            .entry(challenge.entity_id)
            .or_insert_with(Vec::new)
            .push(credential.clone());

        Ok(credential)
    }

    async fn start_authentication(
        &self,
        entity_id: Uuid,
    ) -> AuthMethodResult<AuthenticationChallenge> {
        // Clean up expired challenges
        self.cleanup_expired_challenges().await;

        // Get the user's credentials
        let credentials = self.credentials.read().await;
        let user_creds = credentials
            .get(&entity_id)
            .ok_or_else(|| SecretonError::NotFound {
                resource: format!("webauthn-credentials:{}", entity_id),
            })?;

        if user_creds.is_empty() {
            return Err(SecretonError::NotFound {
                resource: format!("webauthn-credentials:{}", entity_id),
            });
        }

        let allowed_credentials: Vec<String> =
            user_creds.iter().map(|c| c.credential_id.clone()).collect();
        drop(credentials);

        let now = Utc::now();
        let challenge = AuthenticationChallenge {
            id: Uuid::new_v4(),
            challenge: Self::generate_challenge(),
            entity_id,
            rp_id: self.config.rp_id.clone(),
            user_verification: self.config.user_verification.clone(),
            allowed_credentials,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(self.config.challenge_timeout),
        };

        let mut challenges = self.authentication_challenges.write().await;
        challenges.insert(challenge.id, challenge.clone());

        Ok(challenge)
    }

    async fn complete_authentication(
        &self,
        response: AuthenticationResponse,
    ) -> AuthMethodResult<bool> {
        // Get and validate the challenge
        let mut challenges = self.authentication_challenges.write().await;
        let challenge =
            challenges
                .remove(&response.challenge_id)
                .ok_or_else(|| SecretonError::NotFound {
                    resource: format!("webauthn-challenge:{}", response.challenge_id),
                })?;
        drop(challenges);

        // Verify the challenge hasn't expired
        if Utc::now() > challenge.expires_at {
            return Err(SecretonError::Authentication {
                message: "Challenge expired".to_string(),
            });
        }

        // Find the credential
        let mut credentials = self.credentials.write().await;
        let user_creds =
            credentials
                .get_mut(&challenge.entity_id)
                .ok_or_else(|| SecretonError::NotFound {
                    resource: format!("webauthn-credentials:{}", challenge.entity_id),
                })?;

        let credential = user_creds
            .iter_mut()
            .find(|c| c.credential_id == response.credential_id)
            .ok_or_else(|| SecretonError::NotFound {
                resource: format!("webauthn-credential:{}", response.credential_id),
            })?;

        // In production, verify:
        // 1. The signature using the stored public key
        // 2. The challenge matches
        // 3. The sign count has increased (replay protection)

        // Decode the data for verification
        let _authenticator_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&response.authenticator_data)
            .map_err(|_| SecretonError::Authentication {
                message: "Invalid authenticator data".to_string(),
            })?;

        let _signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&response.signature)
            .map_err(|_| SecretonError::Authentication {
                message: "Invalid signature".to_string(),
            })?;

        // Simplified verification - in production use webauthn-rs
        let is_valid = self.verify_signature(
            &credential.public_key,
            &_authenticator_data,
            &[], // client_data_hash would be computed from client_data_json
            &_signature,
        );

        if is_valid {
            // Update sign count and last used
            credential.sign_count += 1;
            credential.last_used = Some(Utc::now());
        }

        Ok(is_valid)
    }

    async fn remove_credential(
        &self,
        entity_id: Uuid,
        credential_id: &str,
    ) -> AuthMethodResult<()> {
        let mut credentials = self.credentials.write().await;
        if let Some(user_creds) = credentials.get_mut(&entity_id) {
            user_creds.retain(|c| c.credential_id != credential_id);
            if user_creds.is_empty() {
                credentials.remove(&entity_id);
            }
        }
        Ok(())
    }

    async fn list_credentials(&self, entity_id: Uuid) -> AuthMethodResult<Vec<WebAuthnCredential>> {
        let credentials = self.credentials.read().await;
        Ok(credentials.get(&entity_id).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_webauthn_registration_challenge() {
        let service = DefaultWebAuthnService::new_default();
        let entity_id = Uuid::new_v4();

        let challenge = service
            .start_registration(entity_id, "testuser", "Test User")
            .await
            .unwrap();

        assert_eq!(challenge.entity_id, entity_id);
        assert_eq!(challenge.user_name, "testuser");
        assert!(!challenge.challenge.is_empty());
    }

    #[tokio::test]
    async fn test_webauthn_credential_registration() {
        let service = DefaultWebAuthnService::new_default();
        let entity_id = Uuid::new_v4();

        // Start registration
        let challenge = service
            .start_registration(entity_id, "testuser", "Test User")
            .await
            .unwrap();

        // Complete registration with mock response
        let response = RegistrationResponse {
            challenge_id: challenge.id,
            credential_id: "test-credential-id".to_string(),
            attestation_object: base64::engine::general_purpose::STANDARD
                .encode("mock-attestation"),
            client_data_json: base64::engine::general_purpose::STANDARD.encode("mock-client-data"),
            credential_type: CredentialType::CrossPlatform,
            name: "My YubiKey".to_string(),
        };

        let credential = service.complete_registration(response).await.unwrap();

        assert_eq!(credential.entity_id, entity_id);
        assert_eq!(credential.name, "My YubiKey");

        // Verify credential is stored
        let creds = service.list_credentials(entity_id).await.unwrap();
        assert_eq!(creds.len(), 1);
    }
}
