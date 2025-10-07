// Advanced MFA - FIDO2, WebAuthn, biometric authentication
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum MFAError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Authentication error: {0}")]
    AuthError(String),
    #[error("Credential error: {0}")]
    CredentialError(String),
}

pub type Result<T> = std::result::Result<T, MFAError>;

/// MFA method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MFAMethod {
    TOTP,
    FIDO2,
    WebAuthn,
    Push,
    Biometric,
}

/// MFA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MFAConfig {
    pub required_factors: u8,
    pub supported_methods: Vec<MFAMethod>,
    pub adaptive_enabled: bool,
    pub risk_scoring_enabled: bool,
}

/// FIDO2 credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FIDO2Credential {
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
}

/// WebAuthn credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub attestation_type: String, // packed, tpm, android-key, etc.
    pub transports: Vec<String>,  // usb, nfc, ble, internal
    pub user_id: String,
    pub created_at: DateTime<Utc>,
}

/// Push notification status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PushStatus {
    Sent,
    Delivered,
    Approved,
    Denied,
    Expired,
}

/// Push notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushNotification {
    pub notification_id: String,
    pub user_id: String,
    pub device_token: String,
    pub status: PushStatus,
    pub sent_at: DateTime<Utc>,
    pub responded_at: Option<DateTime<Utc>>,
}

/// Biometric type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BiometricType {
    Fingerprint,
    FaceID,
    IrisScanner,
    VoiceRecognition,
}

/// Biometric credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricCredential {
    pub credential_id: String,
    pub biometric_type: BiometricType,
    pub template_hash: String,
    pub user_id: String,
    pub enrolled_at: DateTime<Utc>,
}

/// Risk level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub risk_score: u8,    // 0-100
    pub risk_level: RiskLevel,
    pub factors_required: u8,
    pub ip_reputation: String,
    pub device_trust_score: u8,
    pub behavior_anomaly: bool,
}

/// Advanced MFA
pub struct AdvancedMFA {
    config: Arc<RwLock<MFAConfig>>,
    fido2_credentials: Arc<RwLock<HashMap<String, FIDO2Credential>>>,
    webauthn_credentials: Arc<RwLock<HashMap<String, WebAuthnCredential>>>,
    push_notifications: Arc<RwLock<HashMap<String, PushNotification>>>,
    biometric_credentials: Arc<RwLock<HashMap<String, BiometricCredential>>>,
}

impl AdvancedMFA {
    pub fn new(config: MFAConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            fido2_credentials: Arc::new(RwLock::new(HashMap::new())),
            webauthn_credentials: Arc::new(RwLock::new(HashMap::new())),
            push_notifications: Arc::new(RwLock::new(HashMap::new())),
            biometric_credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register FIDO2 credential
    pub async fn register_fido2(&self, user_id: String, public_key: Vec<u8>) -> Result<String> {
        let credential_id = uuid::Uuid::new_v4().to_string();

        let credential = FIDO2Credential {
            credential_id: credential_id.clone(),
            public_key,
            counter: 0,
            user_id,
            created_at: Utc::now(),
        };

        let mut credentials = self.fido2_credentials.write().await;
        credentials.insert(credential_id.clone(), credential);

        Ok(credential_id)
    }

    /// Verify FIDO2 authentication
    pub async fn verify_fido2(&self, credential_id: &str, _signature: &[u8]) -> Result<bool> {
        let mut credentials = self.fido2_credentials.write().await;
        let credential = credentials
            .get_mut(credential_id)
            .ok_or_else(|| MFAError::CredentialError("Credential not found".to_string()))?;

        // Mock signature verification
        // Real implementation would verify signature with public_key

        // Increment counter
        credential.counter += 1;

        Ok(true)
    }

    /// Register WebAuthn credential
    pub async fn register_webauthn(
        &self,
        user_id: String,
        public_key: Vec<u8>,
        attestation_type: String,
    ) -> Result<String> {
        let credential_id = uuid::Uuid::new_v4().to_string();

        let credential = WebAuthnCredential {
            credential_id: credential_id.clone(),
            public_key,
            counter: 0,
            attestation_type,
            transports: vec!["usb".to_string(), "nfc".to_string()],
            user_id,
            created_at: Utc::now(),
        };

        let mut credentials = self.webauthn_credentials.write().await;
        credentials.insert(credential_id.clone(), credential);

        Ok(credential_id)
    }

    /// Send push notification
    pub async fn send_push_notification(&self, user_id: String, device_token: String) -> Result<String> {
        let notification_id = uuid::Uuid::new_v4().to_string();

        let notification = PushNotification {
            notification_id: notification_id.clone(),
            user_id,
            device_token,
            status: PushStatus::Sent,
            sent_at: Utc::now(),
            responded_at: None,
        };

        let mut notifications = self.push_notifications.write().await;
        notifications.insert(notification_id.clone(), notification);

        // Mock push via Firebase/APNs
        // Real implementation would send to FCM or APNs

        Ok(notification_id)
    }

    /// Approve push notification
    pub async fn approve_push_notification(&self, notification_id: &str) -> Result<()> {
        let mut notifications = self.push_notifications.write().await;
        let notification = notifications
            .get_mut(notification_id)
            .ok_or_else(|| MFAError::AuthError("Notification not found".to_string()))?;

        notification.status = PushStatus::Approved;
        notification.responded_at = Some(Utc::now());

        Ok(())
    }

    /// Register biometric credential
    pub async fn register_biometric(
        &self,
        user_id: String,
        biometric_type: BiometricType,
        template_data: &[u8],
    ) -> Result<String> {
        let credential_id = uuid::Uuid::new_v4().to_string();

        // Mock template hashing
        let template_hash = format!("sha256:{:x}", md5::compute(template_data));

        let credential = BiometricCredential {
            credential_id: credential_id.clone(),
            biometric_type,
            template_hash,
            user_id,
            enrolled_at: Utc::now(),
        };

        let mut credentials = self.biometric_credentials.write().await;
        credentials.insert(credential_id.clone(), credential);

        Ok(credential_id)
    }

    /// Verify biometric
    pub async fn verify_biometric(&self, credential_id: &str, _template_data: &[u8]) -> Result<bool> {
        let credentials = self.biometric_credentials.read().await;
        let _credential = credentials
            .get(credential_id)
            .ok_or_else(|| MFAError::CredentialError("Credential not found".to_string()))?;

        // Mock biometric matching
        // Real implementation would compare template with stored hash

        Ok(true)
    }

    /// Calculate risk score
    pub async fn calculate_risk_score(
        &self,
        user_id: &str,
        ip_address: &str,
        device_id: &str,
    ) -> Result<RiskAssessment> {
        let config = self.config.read().await;

        if !config.risk_scoring_enabled {
            return Ok(RiskAssessment {
                risk_score: 0,
                risk_level: RiskLevel::Low,
                factors_required: config.required_factors,
                ip_reputation: "clean".to_string(),
                device_trust_score: 100,
                behavior_anomaly: false,
            });
        }

        // Mock risk scoring
        let mut risk_score = 0u8;

        // Check IP reputation
        let ip_reputation = if ip_address.starts_with("192.168.") {
            "trusted"
        } else {
            risk_score += 20;
            "unknown"
        };

        // Check device trust
        let device_trust_score = if device_id.contains("known") {
            100
        } else {
            risk_score += 30;
            50
        };

        // Check behavior anomaly
        let behavior_anomaly = user_id.contains("suspicious");
        if behavior_anomaly {
            risk_score += 50;
        }

        let risk_level = match risk_score {
            0..=30 => RiskLevel::Low,
            31..=70 => RiskLevel::Medium,
            _ => RiskLevel::High,
        };

        let factors_required = match risk_level {
            RiskLevel::Low => 1,
            RiskLevel::Medium => 2,
            RiskLevel::High => 3,
        };

        Ok(RiskAssessment {
            risk_score,
            risk_level,
            factors_required,
            ip_reputation: ip_reputation.to_string(),
            device_trust_score,
            behavior_anomaly,
        })
    }

    /// Get credential count
    pub async fn get_credential_count(&self, user_id: &str) -> usize {
        let fido2 = self.fido2_credentials.read().await;
        let webauthn = self.webauthn_credentials.read().await;
        let biometric = self.biometric_credentials.read().await;

        fido2.values().filter(|c| c.user_id == user_id).count()
            + webauthn.values().filter(|c| c.user_id == user_id).count()
            + biometric.values().filter(|c| c.user_id == user_id).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> MFAConfig {
        MFAConfig {
            required_factors: 2,
            supported_methods: vec![
                MFAMethod::FIDO2,
                MFAMethod::WebAuthn,
                MFAMethod::Push,
                MFAMethod::Biometric,
            ],
            adaptive_enabled: true,
            risk_scoring_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_fido2_registration() {
        let mfa = AdvancedMFA::new(create_test_config());

        let public_key = vec![1, 2, 3, 4];
        let credential_id = mfa
            .register_fido2("user123".to_string(), public_key.clone())
            .await
            .unwrap();

        let credentials = mfa.fido2_credentials.read().await;
        let credential = credentials.get(&credential_id).unwrap();

        assert_eq!(credential.public_key, public_key);
        assert_eq!(credential.counter, 0);
        assert_eq!(credential.user_id, "user123");
    }

    #[tokio::test]
    async fn test_fido2_verification() {
        let mfa = AdvancedMFA::new(create_test_config());

        let public_key = vec![1, 2, 3, 4];
        let credential_id = mfa
            .register_fido2("user123".to_string(), public_key)
            .await
            .unwrap();

        // First verification
        let verified = mfa.verify_fido2(&credential_id, &[5, 6, 7]).await.unwrap();
        assert!(verified);

        let credentials = mfa.fido2_credentials.read().await;
        let credential = credentials.get(&credential_id).unwrap();
        assert_eq!(credential.counter, 1);
        drop(credentials);

        // Second verification
        mfa.verify_fido2(&credential_id, &[8, 9, 10]).await.unwrap();

        let credentials = mfa.fido2_credentials.read().await;
        let credential = credentials.get(&credential_id).unwrap();
        assert_eq!(credential.counter, 2);
    }

    #[tokio::test]
    async fn test_webauthn_registration() {
        let mfa = AdvancedMFA::new(create_test_config());

        let public_key = vec![10, 20, 30];
        let credential_id = mfa
            .register_webauthn("user456".to_string(), public_key, "packed".to_string())
            .await
            .unwrap();

        let credentials = mfa.webauthn_credentials.read().await;
        let credential = credentials.get(&credential_id).unwrap();

        assert_eq!(credential.attestation_type, "packed");
        assert!(credential.transports.contains(&"usb".to_string()));
    }

    #[tokio::test]
    async fn test_push_notification() {
        let mfa = AdvancedMFA::new(create_test_config());

        let notification_id = mfa
            .send_push_notification("user789".to_string(), "device-token-123".to_string())
            .await
            .unwrap();

        let notifications = mfa.push_notifications.read().await;
        let notification = notifications.get(&notification_id).unwrap();

        assert_eq!(notification.status, PushStatus::Sent);
        assert_eq!(notification.device_token, "device-token-123");
        drop(notifications);

        // Approve notification
        mfa.approve_push_notification(&notification_id).await.unwrap();

        let notifications = mfa.push_notifications.read().await;
        let notification = notifications.get(&notification_id).unwrap();
        assert_eq!(notification.status, PushStatus::Approved);
        assert!(notification.responded_at.is_some());
    }

    #[tokio::test]
    async fn test_risk_assessment() {
        let mfa = AdvancedMFA::new(create_test_config());

        // Low risk: trusted IP and known device
        let assessment = mfa
            .calculate_risk_score("user1", "192.168.1.1", "known-device")
            .await
            .unwrap();

        assert_eq!(assessment.risk_level, RiskLevel::Low);
        assert_eq!(assessment.factors_required, 1);
        assert_eq!(assessment.ip_reputation, "trusted");

        // High risk: unknown IP and suspicious user
        let assessment = mfa
            .calculate_risk_score("suspicious-user", "203.0.113.1", "unknown-device")
            .await
            .unwrap();

        assert_eq!(assessment.risk_level, RiskLevel::High);
        assert_eq!(assessment.factors_required, 3);
        assert!(assessment.risk_score > 70);
    }
}
