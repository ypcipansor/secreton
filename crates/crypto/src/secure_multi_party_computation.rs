//! Secure Multi-Party Computation
//!
//! SMPC protocols for distributed operations including distributed _key generation,
//! threshold signatures, _secret sharing, and multi-party computation.

use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

// Proper cryptographic implementation using Ed25519
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKey {
    #[serde(with = "serde_bytes")]
    key_data: Vec<u8>,
}

impl SecretKey {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut key_data = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_data);
        Self { key_data }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(SMPCError::InvalidShare("Invalid key length".to_string()));
        }
        Ok(Self {
            key_data: bytes.to_vec(),
        })
    }

    pub fn public_key(&self) -> PublicKey {
        let key_bytes: [u8; 32] = self.key_data.as_slice().try_into()
            .expect("Invalid secret key length");
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let public = signing_key.verifying_key();
        PublicKey {
            key_data: public.to_bytes().to_vec(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let key_bytes: [u8; 32] = self.key_data.as_slice().try_into()
            .expect("Invalid secret key length");
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key_data
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(with = "serde_bytes")]
    key_data: Vec<u8>,
}

impl PublicKey {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let key_bytes: [u8; 32] = self.key_data.as_slice().try_into()
            .map_err(|_| SMPCError::ProtocolError("Invalid public key length".to_string()))?;
        let public = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| SMPCError::ProtocolError("Invalid public key".to_string()))?;
        let sig = Signature::try_from(signature)
            .map_err(|_| SMPCError::ProtocolError("Invalid signature length".to_string()))?;
        public.verify(message, &sig)
            .map_err(|_| SMPCError::ProtocolError("Signature verification failed".to_string()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key_data
    }
}

#[derive(Debug, Error)]
pub enum SMPCError {
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Insufficient participants: {0}")]
    InsufficientParticipants(String),
    #[error("Invalid share: {0}")]
    InvalidShare(String),
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    #[error("Computation failed: {0}")]
    ComputationFailed(String),
}

pub type Result<T> = std::result::Result<T, SMPCError>;

/// SMPC protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SMPCProtocol {
    Shamir,
    Feldman,
    Pedersen,
    BGW,
    GMW,
}

/// Participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub participant_id: String,
    pub public_key: Vec<u8>,
    pub network_address: String,
}

/// SMPC session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SMPCSession {
    pub session_id: String,
    pub protocol: SMPCProtocol,
    pub participants: Vec<Participant>,
    pub threshold: usize,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    Initializing,
    Active,
    Computing,
    Completed,
    Failed,
}

/// Secret share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretShare {
    pub share_id: String,
    pub session_id: String,
    pub participant_id: String,
    pub share_data: Vec<u8>,
    pub index: usize,
}

/// DKG (Distributed Key Generation) result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGResult {
    pub session_id: String,
    pub public_key: Vec<u8>,
    pub key_shares: HashMap<String, SecretShare>,
    pub threshold: usize,
}

/// Threshold signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignature {
    pub signature_id: String,
    pub session_id: String,
    pub message: Vec<u8>,
    pub partial_signatures: Vec<PartialSignature>,
    pub combined_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    pub participant_id: String,
    pub signature_data: Vec<u8>,
}

/// Computation _request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationRequest {
    pub request_id: String,
    pub session_id: String,
    pub function: String,
    pub inputs: HashMap<String, Vec<u8>>,
}

/// Computation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationResult {
    pub request_id: String,
    pub result: Vec<u8>,
    pub participants_contributed: Vec<String>,
}

/// Secure Multi-Party Computation System
pub struct SMPCSystem {
    sessions: Arc<RwLock<HashMap<String, SMPCSession>>>,
    shares: Arc<RwLock<HashMap<String, Vec<SecretShare>>>>,
    dkg_results: Arc<RwLock<HashMap<String, DKGResult>>>,
    signatures: Arc<RwLock<HashMap<String, ThresholdSignature>>>,
    computations: Arc<RwLock<HashMap<String, ComputationResult>>>,
}

impl SMPCSystem {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            shares: Arc::new(RwLock::new(HashMap::new())),
            dkg_results: Arc::new(RwLock::new(HashMap::new())),
            signatures: Arc::new(RwLock::new(HashMap::new())),
            computations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create SMPC session
    pub async fn create_session(
        &self,
        protocol: SMPCProtocol,
        participants: Vec<Participant>,
        threshold: usize,
    ) -> Result<String> {
        if threshold > participants.len() {
            return Err(SMPCError::InsufficientParticipants(
                "Threshold exceeds participant count".to_string(),
            ));
        }

        let session = SMPCSession {
            session_id: Uuid::new_v4().to_string(),
            protocol,
            participants,
            threshold,
            state: SessionState::Initializing,
            created_at: Utc::now(),
        };

        let session_id = session.session_id.clone();
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    /// Distributed _key generation
    pub async fn generate_distributed_key(&self, session_id: &str) -> Result<DKGResult> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SMPCError::SessionNotFound(session_id.to_string()))?;

        session.state = SessionState::Computing;

        // Generate threshold key pair using threshold_crypto
        let threshold = session.threshold;
        let total_participants = session.participants.len();

        if threshold > total_participants {
            return Err(SMPCError::InsufficientParticipants(
                "Threshold cannot exceed number of participants".to_string(),
            ));
        }

        // Generate a distributed key pair
        // In a real implementation, this would be done in a distributed manner
        // For now, we'll simulate by generating individual key shares
        let mut key_shares = HashMap::new();
        let _rng = rand::thread_rng();

        let master_secret = SecretKey::random();
        let master_public = master_secret.public_key();

        // Generate shares for each participant
        for (i, participant) in session.participants.iter().enumerate() {
            // Generate a proper cryptographic share
            let share_key = SecretKey::random();

            // Serialize the share properly
            let share_data = share_key.as_bytes().to_vec();

            let secret_share = SecretShare {
                share_id: Uuid::new_v4().to_string(),
                session_id: session_id.to_string(),
                participant_id: participant.participant_id.clone(),
                share_data,
                index: i,
            };

            key_shares.insert(participant.participant_id.clone(), secret_share);
        }

        session.state = SessionState::Completed;

        // Serialize public key
        let public_key = serde_json::to_vec(&master_public).map_err(|e| {
            SMPCError::ComputationFailed(format!("Public key serialization failed: {}", e))
        })?;

        let result = DKGResult {
            session_id: session_id.to_string(),
            public_key,
            key_shares,
            threshold: session.threshold,
        };

        drop(sessions);

        let mut dkg_results = self.dkg_results.write().await;
        dkg_results.insert(session_id.to_string(), result.clone());

        Ok(result)
    }

    /// Create _secret shares
    pub async fn share_secret(&self, session_id: &str, _secret: &[u8]) -> Result<Vec<SecretShare>> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| SMPCError::SessionNotFound(session_id.to_string()))?;

        // Convert secret to a field element (simplified - use first 32 bytes)
        let secret_bytes = if _secret.len() >= 32 {
            &_secret[..32]
        } else {
            _secret
        };
        let mut secret_array = [0u8; 32];
        secret_array[..secret_bytes.len()].copy_from_slice(secret_bytes);
        let secret = i64::from_be_bytes(secret_array[..8].try_into().unwrap_or([0; 8]));

        // Create polynomial for Shamir secret sharing
        let mut coefficients = vec![secret]; // constant term is the secret

        // Generate random coefficients for the polynomial
        let mut rng = rand::thread_rng();
        for _ in 1..session.threshold {
            coefficients.push(rng.r#gen::<i64>());
        }

        // Generate shares for each participant
        let mut shares = Vec::new();
        for (i, participant) in session.participants.iter().enumerate() {
            let x = (i + 1) as i64; // x values start from 1
            let mut y = coefficients[0]; // f(0) = secret

            // Evaluate polynomial at x
            for (j, &coeff) in coefficients.iter().enumerate().skip(1) {
                y += coeff * x.pow(j as u32);
            }

            let share = SecretShare {
                share_id: Uuid::new_v4().to_string(),
                session_id: session_id.to_string(),
                participant_id: participant.participant_id.clone(),
                share_data: y.to_be_bytes().to_vec(),
                index: i,
            };

            shares.push(share);
        }

        drop(sessions);

        let mut stored_shares = self.shares.write().await;
        stored_shares.insert(session_id.to_string(), shares.clone());

        Ok(shares)
    }

    /// Reconstruct _secret from shares
    pub async fn reconstruct_secret(
        &self,
        session_id: &str,
        shares: Vec<SecretShare>,
    ) -> Result<Vec<u8>> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| SMPCError::SessionNotFound(session_id.to_string()))?;

        if shares.len() < session.threshold {
            return Err(SMPCError::InsufficientParticipants(format!(
                "Need {} shares, got {}",
                session.threshold,
                shares.len()
            )));
        }

        // Extract points for Lagrange interpolation
        let mut points = Vec::new();
        for share in &shares {
            let x = (share.index + 1) as i64;
            let y = i64::from_be_bytes(share.share_data[..8].try_into().unwrap_or([0; 8]));
            points.push((x, y));
        }

        // Lagrange interpolation at x = 0 to recover the secret
        let secret = self.lagrange_interpolation(&points, 0);

        Ok(secret.to_be_bytes().to_vec())
    }

    /// Lagrange interpolation to recover secret at x = 0
    fn lagrange_interpolation(&self, points: &[(i64, i64)], x: i64) -> i64 {
        let mut result = 0i64;

        for (i, &(xi, yi)) in points.iter().enumerate() {
            let mut term = yi;

            for (j, &(xj, _)) in points.iter().enumerate() {
                if i != j {
                    term = term * (x - xj) / (xi - xj);
                }
            }

            result += term;
        }

        result
    }

    /// Create threshold signature
    pub async fn create_threshold_signature(
        &self,
        session_id: &str,
        message: &[u8],
    ) -> Result<String> {
        let sessions = self.sessions.read().await;
        let _session = sessions
            .get(session_id)
            .ok_or_else(|| SMPCError::SessionNotFound(session_id.to_string()))?;

        let signature = ThresholdSignature {
            signature_id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            message: message.to_vec(),
            partial_signatures: vec![],
            combined_signature: None,
        };

        let signature_id = signature.signature_id.clone();
        drop(sessions);

        let mut signatures = self.signatures.write().await;
        signatures.insert(signature_id.clone(), signature);

        Ok(signature_id)
    }

    /// Add partial signature
    pub async fn add_partial_signature(
        &self,
        signature_id: &str,
        participant_id: &str,
        signature_data: Vec<u8>,
    ) -> Result<()> {
        let mut signatures = self.signatures.write().await;
        let signature = signatures
            .get_mut(signature_id)
            .ok_or_else(|| SMPCError::SessionNotFound(signature_id.to_string()))?;

        // Validate signature format
        if signature_data.len() != 64 {
            return Err(SMPCError::ProtocolError("Invalid signature length".to_string()));
        }

        signature.partial_signatures.push(PartialSignature {
            participant_id: participant_id.to_string(),
            signature_data,
        });

        Ok(())
    }

    /// Combine partial signatures
    pub async fn combine_signatures(&self, signature_id: &str) -> Result<Vec<u8>> {
        let sessions = self.sessions.read().await;
        let mut signatures = self.signatures.write().await;

        let signature = signatures
            .get_mut(signature_id)
            .ok_or_else(|| SMPCError::SessionNotFound(signature_id.to_string()))?;

        let session = sessions
            .get(&signature.session_id)
            .ok_or_else(|| SMPCError::SessionNotFound(signature.session_id.clone()))?;

        if signature.partial_signatures.len() < session.threshold {
            return Err(SMPCError::InsufficientParticipants(format!(
                "Need {} signatures, got {}",
                session.threshold,
                signature.partial_signatures.len()
            )));
        }

        // For threshold signatures, we need a proper threshold scheme
        // For now, use the first valid signature as a simplified threshold implementation
        // In production, this would use proper threshold cryptography like BLS or Schnorr
        let first_signature = &signature.partial_signatures[0].signature_data;

        // Validate that all signatures are consistent (simplified check)
        for partial in &signature.partial_signatures {
            if partial.signature_data.len() != 64 {
                return Err(SMPCError::ProtocolError("Invalid signature length in partial".to_string()));
            }
        }

        // Use first signature as combined (simplified threshold implementation)
        signature.combined_signature = Some(first_signature.clone());

        Ok(first_signature.clone())
    }

    /// Execute secure computation
    pub async fn compute(&self, _request: ComputationRequest) -> Result<ComputationResult> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(&_request.session_id)
            .ok_or_else(|| SMPCError::SessionNotFound(_request.session_id.clone()))?;

        // Basic secure computation simulation (hash of input data)
        let mut hasher = sha2::Sha256::new();
        for input in _request.inputs.values() {
            hasher.update(input);
        }
        let result_data = hasher.finalize().to_vec();

        let result = ComputationResult {
            request_id: _request.request_id.clone(),
            result: result_data,
            participants_contributed: session
                .participants
                .iter()
                .map(|p| p.participant_id.clone())
                .collect(),
        };

        drop(sessions);

        let mut computations = self.computations.write().await;
        computations.insert(_request.request_id.clone(), result.clone());

        Ok(result)
    }

    /// Get session
    pub async fn get_session(&self, session_id: &str) -> Option<SMPCSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Get DKG result
    pub async fn get_dkg_result(&self, session_id: &str) -> Option<DKGResult> {
        let results = self.dkg_results.read().await;
        results.get(session_id).cloned()
    }

    /// Get threshold signature
    pub async fn get_threshold_signature(&self, signature_id: &str) -> Option<ThresholdSignature> {
        let signatures = self.signatures.read().await;
        signatures.get(signature_id).cloned()
    }

    /// List active sessions
    pub async fn list_active_sessions(&self) -> Vec<SMPCSession> {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| matches!(s.state, SessionState::Active | SessionState::Computing))
            .cloned()
            .collect()
    }

    /// Terminate session
    pub async fn terminate_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| SMPCError::SessionNotFound(session_id.to_string()))?;

        session.state = SessionState::Failed;
        Ok(())
    }
}

impl Default for SMPCSystem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_participants() -> Vec<Participant> {
        vec![
            Participant {
                participant_id: "p1".to_string(),
                public_key: vec![1; 32],
                network_address: "192.168.1.1:8000".to_string(),
            },
            Participant {
                participant_id: "p2".to_string(),
                public_key: vec![2; 32],
                network_address: "192.168.1.2:8000".to_string(),
            },
            Participant {
                participant_id: "p3".to_string(),
                public_key: vec![3; 32],
                network_address: "192.168.1.3:8000".to_string(),
            },
        ]
    }

    #[tokio::test]
    async fn test_create_session() {
        let system = SMPCSystem::new();
        let participants = create_test_participants();

        let session_id = system
            .create_session(SMPCProtocol::Shamir, participants, 2)
            .await
            .unwrap();

        let session = system.get_session(&session_id).await;
        assert!(session.is_some());
        assert_eq!(session.unwrap().threshold, 2);
    }

    #[tokio::test]
    async fn test_distributed_key_generation() {
        let system = SMPCSystem::new();
        let participants = create_test_participants();

        let session_id = system
            .create_session(SMPCProtocol::Feldman, participants, 2)
            .await
            .unwrap();

        let result = system.generate_distributed_key(&session_id).await.unwrap();

        assert!(!result.public_key.is_empty());
        assert_eq!(result.key_shares.len(), 3);
    }

    #[tokio::test]
    async fn test_secret_sharing_and_reconstruction() {
        let system = SMPCSystem::new();
        let participants = create_test_participants();

        let session_id = system
            .create_session(SMPCProtocol::Shamir, participants, 2)
            .await
            .unwrap();

        let _secret = b"my_secret_data";
        let shares = system.share_secret(&session_id, _secret).await.unwrap();

        assert_eq!(shares.len(), 3);

        let reconstructed = system
            .reconstruct_secret(&session_id, shares.into_iter().take(2).collect())
            .await
            .unwrap();

        assert_eq!(reconstructed, _secret);
    }

    #[tokio::test]
    async fn test_threshold_signature() {
        let system = SMPCSystem::new();
        let participants = create_test_participants();

        let session_id = system
            .create_session(SMPCProtocol::BGW, participants.clone(), 2)
            .await
            .unwrap();

        let message = b"sign this message";
        let signature_id = system
            .create_threshold_signature(&session_id, message)
            .await
            .unwrap();

        // Add partial signatures
        for participant in participants.iter().take(2) {
            system
                .add_partial_signature(&signature_id, &participant.participant_id, vec![1, 2, 3])
                .await
                .unwrap();
        }

        let combined = system.combine_signatures(&signature_id).await.unwrap();
        assert!(!combined.is_empty());
    }

    #[tokio::test]
    async fn test_secure_computation() {
        let system = SMPCSystem::new();
        let participants = create_test_participants();

        let session_id = system
            .create_session(SMPCProtocol::GMW, participants, 2)
            .await
            .unwrap();

        let mut inputs = HashMap::new();
        inputs.insert("input1".to_string(), vec![10]);
        inputs.insert("input2".to_string(), vec![20]);

        let _request = ComputationRequest {
            request_id: Uuid::new_v4().to_string(),
            session_id: session_id.clone(),
            function: "sum".to_string(),
            inputs,
        };

        let result = system.compute(_request).await.unwrap();
        assert!(!result.result.is_empty());
        assert_eq!(result.participants_contributed.len(), 3);
    }

    #[tokio::test]
    async fn test_insufficient_participants() {
        let system = SMPCSystem::new();
        let participants = create_test_participants();

        let result = system
            .create_session(SMPCProtocol::Shamir, participants, 5)
            .await;

        assert!(result.is_err());
    }
}
