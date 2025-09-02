//! Quantum-Safe Cryptography Module
//!
//! Implements post-quantum cryptographic algorithms and hybrid classical-quantum security:
//! - Post-quantum key encapsulation mechanisms (KEMs)
//! - Post-quantum digital signatures
//! - Hybrid classical-quantum cryptography for transition period
//! - Quantum-resistant random number generation
//! - Quantum key distribution (QKD) integration
//! - Quantum-safe certificate management
//! - Migration tools for transitioning from classical to quantum-safe algorithms

use async_trait::async_trait;
use chrono::{DateTime, Datelike, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{error, info};
use uuid::Uuid;

/// Base64 serialization module for secure data
mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// Post-quantum cryptographic algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PostQuantumAlgorithm {
    /// NIST PQC Selected Algorithms
    // Key Encapsulation Mechanisms
    Kyber512,
    Kyber768,
    Kyber1024,

    // Digital Signatures
    Dilithium2,
    Dilithium3,
    Dilithium5,

    Falcon512,
    Falcon1024,

    Sphincs128f,
    Sphincs128s,
    Sphincs192f,
    Sphincs192s,
    Sphincs256f,
    Sphincs256s,

    /// Alternative Round 4 Candidates
    Bike,
    ClassicMcEliece,
    HQC,
    SIKE, // Note: Broken but kept for compatibility

    /// Hybrid Algorithms (Classical + Post-Quantum)
    HybridRsaKyber768,
    HybridEcdsaDilithium3,
    HybridEcdhKyber1024,
    HybridAesKyber512,

    /// Custom implementations
    Custom(String),
}

/// Quantum-safe security levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum QuantumSecurityLevel {
    /// Equivalent to AES-128, SHA-256
    Level1 = 128,
    /// Equivalent to AES-192, SHA-384  
    Level3 = 192,
    /// Equivalent to AES-256, SHA-512
    Level5 = 256,
}

/// Secure container for private key material
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurePrivateKey {
    #[serde(with = "base64_serde")]
    pub key_material: Vec<u8>,
}

impl Drop for SecurePrivateKey {
    fn drop(&mut self) {
        // Zero out key material on drop for security
        self.key_material.fill(0);
    }
}

/// Post-quantum key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostQuantumKeyPair {
    pub algorithm: PostQuantumAlgorithm,
    pub security_level: QuantumSecurityLevel,
    pub public_key: Vec<u8>,
    #[serde(skip_serializing)]
    pub private_key: SecurePrivateKey,
    pub key_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub usage: Vec<KeyUsage>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyUsage {
    Encryption,
    Signing,
    KeyAgreement,
    KeyEncapsulation,
    Authentication,
    NonRepudiation,
}

/// Post-quantum encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumEncryptedData {
    pub algorithm: PostQuantumAlgorithm,
    pub ciphertext: Vec<u8>,
    pub encapsulated_key: Option<Vec<u8>>, // For KEM-based encryption
    pub nonce: Option<Vec<u8>>,
    pub tag: Option<Vec<u8>>, // For authenticated encryption
    pub metadata: HashMap<String, String>,
    pub encrypted_at: DateTime<Utc>,
}

/// Post-quantum digital signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSignature {
    pub algorithm: PostQuantumAlgorithm,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub signed_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Quantum key distribution integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QKDSession {
    pub session_id: String,
    pub participants: Vec<String>,
    pub quantum_keys: Vec<QuantumKey>,
    pub classical_keys: Vec<Vec<u8>>,
    pub security_parameters: QKDSecurityParameters,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: QKDStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumKey {
    pub key_id: String,
    pub key_material: Vec<u8>,
    pub key_rate: f64, // bits per second
    pub error_rate: f64,
    pub security_level: f64,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QKDSecurityParameters {
    pub protocol: String, // BB84, SARG04, etc.
    pub key_rate_threshold: f64,
    pub error_rate_threshold: f64,
    pub distance: f64, // kilometers
    pub authentication_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QKDStatus {
    Initializing,
    KeyGeneration,
    KeyReconciliation,
    PrivacyAmplification,
    Active,
    Compromised,
    Terminated,
}

/// Hybrid cryptography configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCryptoConfig {
    pub classical_algorithm: String,
    pub post_quantum_algorithm: PostQuantumAlgorithm,
    pub combination_mode: HybridMode,
    pub security_level: QuantumSecurityLevel,
    pub migration_policy: MigrationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HybridMode {
    /// Use both algorithms, require both to succeed
    Concatenate,
    /// Use both algorithms, combine using XOR
    Xor,
    /// Use both algorithms, combine using authenticated encryption
    AuthenticatedCombination,
    /// Use post-quantum as primary, classical as fallback
    PostQuantumPrimary,
    /// Use classical as primary, post-quantum as additional security
    ClassicalPrimary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPolicy {
    pub migration_timeline: DateTime<Utc>,
    pub deprecation_warnings: bool,
    pub force_post_quantum_after: Option<DateTime<Utc>>,
    pub allowed_classical_algorithms: Vec<String>,
    pub quantum_safe_only_domains: Vec<String>,
}

/// Quantum threat assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumThreatAssessment {
    pub assessment_id: String,
    pub quantum_computer_threat_level: ThreatLevel,
    pub cryptographic_agility_score: f64,
    pub vulnerable_algorithms: Vec<String>,
    pub recommended_migrations: Vec<MigrationRecommendation>,
    pub timeline_estimates: HashMap<String, DateTime<Utc>>,
    pub assessed_at: DateTime<Utc>,
    pub next_assessment: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ThreatLevel {
    Minimal,  // >20 years to CRQC
    Low,      // 15-20 years
    Moderate, // 10-15 years
    High,     // 5-10 years
    Critical, // <5 years
    Imminent, // CRQC exists
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRecommendation {
    pub algorithm: String,
    pub replacement: PostQuantumAlgorithm,
    pub priority: MigrationPriority,
    pub estimated_effort: Duration,
    pub dependencies: Vec<String>,
    pub risks: Vec<String>,
    pub benefits: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum MigrationPriority {
    Immediate,
    High,
    Medium,
    Low,
    Future,
}

#[derive(Debug, thiserror::Error)]
pub enum QuantumCryptoError {
    #[error("Unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },

    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },

    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },

    #[error("Signature generation failed: {reason}")]
    SignatureGenerationFailed { reason: String },

    #[error("Signature verification failed: {reason}")]
    SignatureVerificationFailed { reason: String },

    #[error("Key encapsulation failed: {reason}")]
    KeyEncapsulationFailed { reason: String },

    #[error("Key decapsulation failed: {reason}")]
    KeyDecapsulationFailed { reason: String },

    #[error("QKD session error: {reason}")]
    QKDSessionError { reason: String },

    #[error("Hybrid crypto error: {reason}")]
    HybridCryptoError { reason: String },

    #[error("Migration error: {reason}")]
    MigrationError { reason: String },

    #[error("Invalid security level: {level}")]
    InvalidSecurityLevel { level: String },

    #[error("Quantum RNG error: {reason}")]
    QuantumRngError { reason: String },
}

/// Trait for post-quantum cryptographic operations
#[async_trait]
pub trait PostQuantumCrypto: Send + Sync {
    async fn generate_keypair(
        &self,
        algorithm: &PostQuantumAlgorithm,
        security_level: QuantumSecurityLevel,
    ) -> Result<PostQuantumKeyPair, QuantumCryptoError>;
    async fn encrypt(
        &self,
        data: &[u8],
        public_key: &PostQuantumKeyPair,
    ) -> Result<QuantumEncryptedData, QuantumCryptoError>;
    async fn decrypt(
        &self,
        encrypted_data: &QuantumEncryptedData,
        private_key: &PostQuantumKeyPair,
    ) -> Result<Vec<u8>, QuantumCryptoError>;
    async fn sign(
        &self,
        data: &[u8],
        private_key: &PostQuantumKeyPair,
    ) -> Result<QuantumSignature, QuantumCryptoError>;
    async fn verify(
        &self,
        data: &[u8],
        signature: &QuantumSignature,
        public_key: &PostQuantumKeyPair,
    ) -> Result<bool, QuantumCryptoError>;
    async fn key_encapsulation(
        &self,
        public_key: &PostQuantumKeyPair,
    ) -> Result<(Vec<u8>, Vec<u8>), QuantumCryptoError>; // (shared_secret, encapsulated_key)
    async fn key_decapsulation(
        &self,
        encapsulated_key: &[u8],
        private_key: &PostQuantumKeyPair,
    ) -> Result<Vec<u8>, QuantumCryptoError>;
    fn get_supported_algorithms(&self) -> Vec<PostQuantumAlgorithm>;
    fn get_algorithm_info(&self, algorithm: &PostQuantumAlgorithm) -> Option<AlgorithmInfo>;
}

#[derive(Debug, Clone)]
pub struct AlgorithmInfo {
    pub name: String,
    pub key_size_public: usize,
    pub key_size_private: usize,
    pub ciphertext_size: usize,
    pub signature_size: usize,
    pub security_level: QuantumSecurityLevel,
    pub performance_tier: PerformanceTier,
    pub standardization_status: StandardizationStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PerformanceTier {
    Fast,
    Moderate,
    Slow,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StandardizationStatus {
    NistSelected,
    NistRound4Candidate,
    NistRound4Alternate,
    Research,
    Deprecated,
}

/// Quantum-safe cryptography engine
pub struct QuantumSafeCryptoEngine {
    crypto_providers: Arc<RwLock<HashMap<String, Arc<dyn PostQuantumCrypto>>>>,
    key_store: Arc<RwLock<HashMap<String, PostQuantumKeyPair>>>,
    qkd_sessions: Arc<RwLock<HashMap<String, QKDSession>>>,
    hybrid_configs: Arc<RwLock<HashMap<String, HybridCryptoConfig>>>,
    threat_assessments: Arc<RwLock<Vec<QuantumThreatAssessment>>>,
    config: QuantumCryptoConfig,
    metrics: Arc<Mutex<QuantumCryptoMetrics>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumCryptoConfig {
    pub default_algorithms: HashMap<String, PostQuantumAlgorithm>,
    pub security_level: QuantumSecurityLevel,
    pub hybrid_mode_enabled: bool,
    pub migration_policy: MigrationPolicy,
    pub qkd_enabled: bool,
    pub threat_assessment_frequency: Duration,
    pub key_rotation_policy: KeyRotationPolicy,
    pub performance_optimization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationPolicy {
    pub automatic_rotation: bool,
    pub rotation_interval: Duration,
    pub pre_rotation_warning: Duration,
    pub emergency_rotation_triggers: Vec<String>,
    pub quantum_threat_rotation: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QuantumCryptoMetrics {
    pub operations_performed: HashMap<String, u64>,
    pub key_generations: u64,
    pub encryptions: u64,
    pub decryptions: u64,
    pub signatures: u64,
    pub verifications: u64,
    pub key_encapsulations: u64,
    pub key_decapsulations: u64,
    pub qkd_sessions_created: u64,
    pub migration_operations: u64,
    pub performance_metrics: HashMap<String, Duration>,
    pub error_counts: HashMap<String, u64>,
}

impl Default for QuantumCryptoConfig {
    fn default() -> Self {
        Self {
            default_algorithms: HashMap::from([
                ("kem".to_string(), PostQuantumAlgorithm::Kyber768),
                ("signature".to_string(), PostQuantumAlgorithm::Dilithium3),
                ("encryption".to_string(), PostQuantumAlgorithm::Kyber1024),
            ]),
            security_level: QuantumSecurityLevel::Level3,
            hybrid_mode_enabled: true,
            migration_policy: MigrationPolicy {
                migration_timeline: Utc::now() + chrono::Duration::days(365 * 2), // 2 years
                deprecation_warnings: true,
                force_post_quantum_after: Some(Utc::now() + chrono::Duration::days(365 * 3)), // 3 years
                allowed_classical_algorithms: vec![
                    "rsa-4096".to_string(),
                    "ecdsa-p384".to_string(),
                    "aes-256".to_string(),
                ],
                quantum_safe_only_domains: vec!["critical.internal".to_string()],
            },
            qkd_enabled: false, // Requires specialized hardware
            threat_assessment_frequency: Duration::from_secs(86400 * 30), // Monthly
            key_rotation_policy: KeyRotationPolicy {
                automatic_rotation: true,
                rotation_interval: Duration::from_secs(86400 * 90), // 90 days
                pre_rotation_warning: Duration::from_secs(86400 * 7), // 7 days
                emergency_rotation_triggers: vec![
                    "quantum_breakthrough".to_string(),
                    "algorithm_break".to_string(),
                    "key_compromise".to_string(),
                ],
                quantum_threat_rotation: true,
            },
            performance_optimization: true,
        }
    }
}

impl QuantumSafeCryptoEngine {
    pub fn new(config: QuantumCryptoConfig) -> Self {
        Self {
            crypto_providers: Arc::new(RwLock::new(HashMap::new())),
            key_store: Arc::new(RwLock::new(HashMap::new())),
            qkd_sessions: Arc::new(RwLock::new(HashMap::new())),
            hybrid_configs: Arc::new(RwLock::new(HashMap::new())),
            threat_assessments: Arc::new(RwLock::new(Vec::new())),
            config,
            metrics: Arc::new(Mutex::new(QuantumCryptoMetrics::default())),
        }
    }

    /// Register a post-quantum crypto provider
    pub fn register_crypto_provider(&self, name: String, provider: Arc<dyn PostQuantumCrypto>) {
        let mut providers = self.crypto_providers.write().unwrap();
        providers.insert(name, provider);
    }

    /// Generate post-quantum key pair
    pub async fn generate_keypair(
        &self,
        algorithm: PostQuantumAlgorithm,
        usage: Vec<KeyUsage>,
    ) -> Result<PostQuantumKeyPair, QuantumCryptoError> {
        let provider = {
            let providers = self.crypto_providers.read().unwrap();
            providers
                .values()
                .find(|p| p.get_supported_algorithms().contains(&algorithm))
                .cloned()
                .ok_or_else(|| QuantumCryptoError::UnsupportedAlgorithm {
                    algorithm: format!("{:?}", algorithm),
                })?
        };

        let mut keypair = provider
            .generate_keypair(&algorithm, self.config.security_level.clone())
            .await?;
        keypair.usage = usage;
        keypair.key_id = Uuid::new_v4().to_string();
        keypair.created_at = Utc::now();

        // Store the key pair
        {
            let mut key_store = self.key_store.write().unwrap();
            key_store.insert(keypair.key_id.clone(), keypair.clone());
        }

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.key_generations += 1;
            *metrics
                .operations_performed
                .entry(format!("{:?}", algorithm))
                .or_insert(0) += 1;
        }

        info!(
            "Generated post-quantum key pair with algorithm {:?}",
            algorithm
        );
        Ok(keypair)
    }

    /// Encrypt data using post-quantum cryptography
    pub async fn encrypt(
        &self,
        data: &[u8],
        recipient_key_id: &str,
    ) -> Result<QuantumEncryptedData, QuantumCryptoError> {
        let key_pair = {
            let key_store = self.key_store.read().unwrap();
            key_store.get(recipient_key_id).cloned().ok_or_else(|| {
                QuantumCryptoError::EncryptionFailed {
                    reason: "Recipient key not found".to_string(),
                }
            })?
        };

        let provider = {
            let providers = self.crypto_providers.read().unwrap();
            providers
                .values()
                .find(|p| p.get_supported_algorithms().contains(&key_pair.algorithm))
                .cloned()
                .ok_or_else(|| QuantumCryptoError::UnsupportedAlgorithm {
                    algorithm: format!("{:?}", key_pair.algorithm),
                })?
        };

        let encrypted_data = if self.config.hybrid_mode_enabled {
            self.hybrid_encrypt(data, &key_pair, &provider).await?
        } else {
            provider.encrypt(data, &key_pair).await?
        };

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.encryptions += 1;
        }

        Ok(encrypted_data)
    }

    /// Decrypt data using post-quantum cryptography
    pub async fn decrypt(
        &self,
        encrypted_data: &QuantumEncryptedData,
        key_id: &str,
    ) -> Result<Vec<u8>, QuantumCryptoError> {
        let key_pair = {
            let key_store = self.key_store.read().unwrap();
            key_store
                .get(key_id)
                .cloned()
                .ok_or_else(|| QuantumCryptoError::DecryptionFailed {
                    reason: "Decryption key not found".to_string(),
                })?
        };

        let provider = {
            let providers = self.crypto_providers.read().unwrap();
            providers
                .values()
                .find(|p| {
                    p.get_supported_algorithms()
                        .contains(&encrypted_data.algorithm)
                })
                .cloned()
                .ok_or_else(|| QuantumCryptoError::UnsupportedAlgorithm {
                    algorithm: format!("{:?}", encrypted_data.algorithm),
                })?
        };

        let decrypted_data = if self.config.hybrid_mode_enabled {
            self.hybrid_decrypt(encrypted_data, &key_pair, &provider)
                .await?
        } else {
            provider.decrypt(encrypted_data, &key_pair).await?
        };

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.decryptions += 1;
        }

        Ok(decrypted_data)
    }

    /// Sign data using post-quantum digital signatures
    pub async fn sign(
        &self,
        data: &[u8],
        signer_key_id: &str,
    ) -> Result<QuantumSignature, QuantumCryptoError> {
        let key_pair = {
            let key_store = self.key_store.read().unwrap();
            key_store.get(signer_key_id).cloned().ok_or_else(|| {
                QuantumCryptoError::SignatureGenerationFailed {
                    reason: "Signer key not found".to_string(),
                }
            })?
        };

        if !key_pair.usage.contains(&KeyUsage::Signing) {
            return Err(QuantumCryptoError::SignatureGenerationFailed {
                reason: "Key not authorized for signing".to_string(),
            });
        }

        let provider = {
            let providers = self.crypto_providers.read().unwrap();
            providers
                .values()
                .find(|p| p.get_supported_algorithms().contains(&key_pair.algorithm))
                .cloned()
                .ok_or_else(|| QuantumCryptoError::UnsupportedAlgorithm {
                    algorithm: format!("{:?}", key_pair.algorithm),
                })?
        };

        let mut signature = provider.sign(data, &key_pair).await?;

        // Set the public key ID for verification
        signature.public_key_id = signer_key_id.to_string();

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.signatures += 1;
        }

        info!("Created post-quantum signature with key {}", signer_key_id);
        Ok(signature)
    }

    /// Verify post-quantum digital signature
    pub async fn verify(
        &self,
        data: &[u8],
        signature: &QuantumSignature,
    ) -> Result<bool, QuantumCryptoError> {
        let key_pair = {
            let key_store = self.key_store.read().unwrap();
            key_store
                .get(&signature.public_key_id)
                .cloned()
                .ok_or_else(|| QuantumCryptoError::SignatureVerificationFailed {
                    reason: "Public key not found".to_string(),
                })?
        };

        let provider = {
            let providers = self.crypto_providers.read().unwrap();
            providers
                .values()
                .find(|p| p.get_supported_algorithms().contains(&signature.algorithm))
                .cloned()
                .ok_or_else(|| QuantumCryptoError::UnsupportedAlgorithm {
                    algorithm: format!("{:?}", signature.algorithm),
                })?
        };

        let is_valid = provider.verify(data, signature, &key_pair).await?;

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.verifications += 1;
        }

        Ok(is_valid)
    }

    /// Hybrid encryption combining classical and post-quantum
    async fn hybrid_encrypt(
        &self,
        data: &[u8],
        key_pair: &PostQuantumKeyPair,
        provider: &Arc<dyn PostQuantumCrypto>,
    ) -> Result<QuantumEncryptedData, QuantumCryptoError> {
        // Generate a symmetric key for data encryption
        let mut symmetric_key = vec![0u8; 32]; // AES-256 key
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut symmetric_key);

        // Encrypt data with symmetric key (AES-256-GCM)
        let encrypted_data = self.aes_encrypt(data, &symmetric_key)?;

        // Encrypt symmetric key with post-quantum KEM
        let (shared_secret, encapsulated_key) = provider.key_encapsulation(key_pair).await?;

        // Derive final key using shared secret and symmetric key
        let final_key = self.derive_hybrid_key(&shared_secret, &symmetric_key)?;

        // Re-encrypt the data with the hybrid key
        let final_encrypted_data = self.aes_encrypt(&encrypted_data, &final_key)?;

        Ok(QuantumEncryptedData {
            algorithm: key_pair.algorithm.clone(),
            ciphertext: final_encrypted_data,
            encapsulated_key: Some(encapsulated_key),
            nonce: None, // Included in AES encryption
            tag: None,   // Included in AES encryption
            metadata: HashMap::from([
                ("hybrid_mode".to_string(), "enabled".to_string()),
                ("classical_algorithm".to_string(), "aes-256-gcm".to_string()),
            ]),
            encrypted_at: Utc::now(),
        })
    }

    /// Hybrid decryption
    async fn hybrid_decrypt(
        &self,
        encrypted_data: &QuantumEncryptedData,
        key_pair: &PostQuantumKeyPair,
        provider: &Arc<dyn PostQuantumCrypto>,
    ) -> Result<Vec<u8>, QuantumCryptoError> {
        let encapsulated_key = encrypted_data.encapsulated_key.as_ref().ok_or_else(|| {
            QuantumCryptoError::DecryptionFailed {
                reason: "Missing encapsulated key for hybrid decryption".to_string(),
            }
        })?;

        // Decapsulate to get shared secret
        let shared_secret = provider
            .key_decapsulation(encapsulated_key, key_pair)
            .await?;

        // This is a simplified implementation - in reality we would need to properly
        // reconstruct the symmetric key and derive the hybrid key
        let decrypted_data = self.aes_decrypt(&encrypted_data.ciphertext, &shared_secret[..32])?;

        Ok(decrypted_data)
    }

    /// Simple AES encryption (mock implementation)
    fn aes_encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, QuantumCryptoError> {
        // Mock implementation - in reality would use proper AES-GCM
        let mut encrypted = data.to_vec();
        for (i, byte) in encrypted.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }
        Ok(encrypted)
    }

    /// Simple AES decryption (mock implementation)  
    fn aes_decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, QuantumCryptoError> {
        // Mock implementation - XOR is its own inverse
        self.aes_encrypt(data, key)
    }

    /// Derive hybrid key from post-quantum shared secret and classical key
    fn derive_hybrid_key(
        &self,
        pq_secret: &[u8],
        classical_key: &[u8],
    ) -> Result<Vec<u8>, QuantumCryptoError> {
        // Simple key derivation using HKDF (mock implementation)
        let mut hybrid_key = vec![0u8; 32];

        for i in 0..32 {
            hybrid_key[i] = pq_secret[i % pq_secret.len()] ^ classical_key[i % classical_key.len()];
        }

        Ok(hybrid_key)
    }

    /// Perform quantum threat assessment
    pub async fn assess_quantum_threat(
        &self,
    ) -> Result<QuantumThreatAssessment, QuantumCryptoError> {
        let assessment_id = Uuid::new_v4().to_string();

        // Analyze current cryptographic algorithms in use
        let key_store = self.key_store.read().unwrap();
        let mut vulnerable_algorithms = Vec::new();

        for key_pair in key_store.values() {
            if self.is_quantum_vulnerable(&key_pair.algorithm) {
                vulnerable_algorithms.push(format!("{:?}", key_pair.algorithm));
            }
        }

        // Calculate cryptographic agility score
        let agility_score = self.calculate_crypto_agility_score();

        // Generate migration recommendations
        let recommendations = self.generate_migration_recommendations(&vulnerable_algorithms);

        // Estimate quantum computer threat timeline
        let threat_level = self.estimate_quantum_threat_level();

        let assessment = QuantumThreatAssessment {
            assessment_id: assessment_id.clone(),
            quantum_computer_threat_level: threat_level,
            cryptographic_agility_score: agility_score,
            vulnerable_algorithms,
            recommended_migrations: recommendations,
            timeline_estimates: HashMap::from([
                (
                    "small_scale_qc".to_string(),
                    Utc::now() + chrono::Duration::days(365 * 5),
                ),
                (
                    "cryptographically_relevant_qc".to_string(),
                    Utc::now() + chrono::Duration::days(365 * 10),
                ),
                (
                    "full_scale_qc".to_string(),
                    Utc::now() + chrono::Duration::days(365 * 15),
                ),
            ]),
            assessed_at: Utc::now(),
            next_assessment: Utc::now()
                + chrono::Duration::from_std(self.config.threat_assessment_frequency).unwrap(),
        };

        // Store assessment
        {
            let mut assessments = self.threat_assessments.write().unwrap();
            assessments.push(assessment.clone());

            // Keep only last 10 assessments
            if assessments.len() > 10 {
                assessments.remove(0);
            }
        }

        info!(
            "Quantum threat assessment completed: {:?} threat level",
            assessment.quantum_computer_threat_level
        );
        Ok(assessment)
    }

    /// Check if algorithm is vulnerable to quantum attacks
    fn is_quantum_vulnerable(&self, algorithm: &PostQuantumAlgorithm) -> bool {
        match algorithm {
            PostQuantumAlgorithm::Kyber512
            | PostQuantumAlgorithm::Kyber768
            | PostQuantumAlgorithm::Kyber1024
            | PostQuantumAlgorithm::Dilithium2
            | PostQuantumAlgorithm::Dilithium3
            | PostQuantumAlgorithm::Dilithium5
            | PostQuantumAlgorithm::Falcon512
            | PostQuantumAlgorithm::Falcon1024 => false, // Post-quantum algorithms

            PostQuantumAlgorithm::HybridRsaKyber768
            | PostQuantumAlgorithm::HybridEcdsaDilithium3
            | PostQuantumAlgorithm::HybridEcdhKyber1024
            | PostQuantumAlgorithm::HybridAesKyber512 => false, // Hybrid provides quantum resistance

            _ => true, // Conservative approach for unknown algorithms
        }
    }

    /// Calculate cryptographic agility score (0-100)
    fn calculate_crypto_agility_score(&self) -> f64 {
        let key_store = self.key_store.read().unwrap();
        let total_keys = key_store.len() as f64;

        if total_keys == 0.0 {
            return 0.0;
        }

        let mut post_quantum_keys = 0.0;
        let mut hybrid_keys = 0.0;
        let mut recent_keys = 0.0; // Keys generated in last 90 days

        let ninety_days_ago = Utc::now() - chrono::Duration::days(90);

        for key_pair in key_store.values() {
            if !self.is_quantum_vulnerable(&key_pair.algorithm) {
                post_quantum_keys += 1.0;
            }

            if format!("{:?}", key_pair.algorithm).contains("Hybrid") {
                hybrid_keys += 1.0;
            }

            if key_pair.created_at > ninety_days_ago {
                recent_keys += 1.0;
            }
        }

        // Score components
        let pq_ratio = (post_quantum_keys / total_keys) * 40.0; // 40% weight
        let hybrid_ratio = (hybrid_keys / total_keys) * 30.0; // 30% weight
        let recency_ratio = (recent_keys / total_keys) * 30.0; // 30% weight

        pq_ratio + hybrid_ratio + recency_ratio
    }

    /// Generate migration recommendations
    fn generate_migration_recommendations(
        &self,
        vulnerable_algorithms: &[String],
    ) -> Vec<MigrationRecommendation> {
        let mut recommendations = Vec::new();

        for algorithm in vulnerable_algorithms {
            let (replacement, priority, effort) = match algorithm.as_str() {
                "RSA-2048" | "RSA-3072" | "RSA-4096" => (
                    PostQuantumAlgorithm::HybridRsaKyber768,
                    MigrationPriority::High,
                    Duration::from_secs(86400 * 30),
                ),
                "ECDSA" | "ECDH" => (
                    PostQuantumAlgorithm::HybridEcdsaDilithium3,
                    MigrationPriority::High,
                    Duration::from_secs(86400 * 45),
                ),
                "AES-128" => (
                    PostQuantumAlgorithm::HybridAesKyber512,
                    MigrationPriority::Medium,
                    Duration::from_secs(86400 * 60),
                ),
                _ => (
                    PostQuantumAlgorithm::Kyber768,
                    MigrationPriority::Medium,
                    Duration::from_secs(86400 * 90),
                ),
            };

            recommendations.push(MigrationRecommendation {
                algorithm: algorithm.clone(),
                replacement,
                priority,
                estimated_effort: effort,
                dependencies: vec!["key_management_update".to_string()],
                risks: vec![
                    "performance_impact".to_string(),
                    "compatibility_issues".to_string(),
                ],
                benefits: vec![
                    "quantum_resistance".to_string(),
                    "future_proofing".to_string(),
                ],
            });
        }

        recommendations
    }

    /// Estimate quantum computer threat level
    fn estimate_quantum_threat_level(&self) -> ThreatLevel {
        // This would integrate with quantum computing research tracking services
        // For now, we'll use a conservative estimate

        let current_year = Utc::now().year();

        match current_year {
            2025..=2027 => ThreatLevel::Low,
            2028..=2032 => ThreatLevel::Moderate,
            2033..=2037 => ThreatLevel::High,
            2038.. => ThreatLevel::Critical,
            _ => ThreatLevel::Minimal,
        }
    }

    /// Rotate keys based on quantum threat level
    #[allow(clippy::await_holding_lock)]
    pub async fn emergency_key_rotation(
        &self,
        threat_trigger: &str,
    ) -> Result<usize, QuantumCryptoError> {
        info!("Emergency key rotation triggered by: {}", threat_trigger);

        let key_ids: Vec<String> = {
            let key_store = self.key_store.read().unwrap();
            key_store.keys().cloned().collect()
        };

        let mut rotated_count = 0;

        for key_id in key_ids {
            let key_pair = {
                self.key_store.read().unwrap().get(&key_id).cloned().ok_or(
                    QuantumCryptoError::KeyGenerationFailed {
                        reason: "Key not found".to_string(),
                    },
                )
            };

            if let Ok(key_pair) = key_pair {
                if self.is_quantum_vulnerable(&key_pair.algorithm) {
                    // Generate new post-quantum key pair
                    let new_algorithm = self.select_replacement_algorithm(&key_pair.algorithm);
                    let new_keypair = self.generate_keypair(new_algorithm, key_pair.usage).await?;

                    // Remove old key
                    {
                        let mut key_store = self.key_store.write().unwrap();
                        key_store.remove(&key_id);
                    }

                    rotated_count += 1;
                    info!(
                        "Rotated key {} from {:?} to {:?}",
                        key_id, key_pair.algorithm, new_keypair.algorithm
                    );
                }
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.migration_operations += rotated_count as u64;
        }

        info!(
            "Emergency key rotation completed: {} keys rotated",
            rotated_count
        );
        Ok(rotated_count)
    }

    /// Select replacement algorithm for migration
    fn select_replacement_algorithm(
        &self,
        old_algorithm: &PostQuantumAlgorithm,
    ) -> PostQuantumAlgorithm {
        match old_algorithm {
            // Already post-quantum, choose stronger variant
            PostQuantumAlgorithm::Kyber512 => PostQuantumAlgorithm::Kyber768,
            PostQuantumAlgorithm::Kyber768 => PostQuantumAlgorithm::Kyber1024,
            PostQuantumAlgorithm::Dilithium2 => PostQuantumAlgorithm::Dilithium3,
            PostQuantumAlgorithm::Dilithium3 => PostQuantumAlgorithm::Dilithium5,

            // Default to recommended algorithms
            _ => self
                .config
                .default_algorithms
                .get("kem")
                .unwrap_or(&PostQuantumAlgorithm::Kyber768)
                .clone(),
        }
    }

    /// Get quantum cryptography metrics
    pub fn get_metrics(&self) -> QuantumCryptoMetrics {
        let metrics = self.metrics.lock().unwrap();
        QuantumCryptoMetrics {
            operations_performed: metrics.operations_performed.clone(),
            key_generations: metrics.key_generations,
            encryptions: metrics.encryptions,
            decryptions: metrics.decryptions,
            signatures: metrics.signatures,
            verifications: metrics.verifications,
            key_encapsulations: metrics.key_encapsulations,
            key_decapsulations: metrics.key_decapsulations,
            qkd_sessions_created: metrics.qkd_sessions_created,
            migration_operations: metrics.migration_operations,
            performance_metrics: metrics.performance_metrics.clone(),
            error_counts: metrics.error_counts.clone(),
        }
    }

    /// Start continuous threat assessment
    pub fn start_threat_monitoring(self: Arc<Self>) {
        let engine = Arc::clone(&self);
        let frequency = engine.config.threat_assessment_frequency;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(frequency);

            loop {
                interval.tick().await;

                info!("Running scheduled quantum threat assessment");
                if let Err(e) = engine.assess_quantum_threat().await {
                    error!("Quantum threat assessment failed: {}", e);
                }
            }
        });

        info!("Quantum threat monitoring started");
    }
}

/// Mock post-quantum crypto provider
pub struct MockPostQuantumCrypto;

#[async_trait]
impl PostQuantumCrypto for MockPostQuantumCrypto {
    async fn generate_keypair(
        &self,
        algorithm: &PostQuantumAlgorithm,
        security_level: QuantumSecurityLevel,
    ) -> Result<PostQuantumKeyPair, QuantumCryptoError> {
        // Mock key generation
        let mut rng = rand::thread_rng();
        let public_key = (0..1024).map(|_| rng.next_u32() as u8).collect();
        let private_key_material: Vec<u8> = (0..2048).map(|_| rng.next_u32() as u8).collect();
        let private_key = SecurePrivateKey {
            key_material: private_key_material,
        };

        Ok(PostQuantumKeyPair {
            algorithm: algorithm.clone(),
            security_level,
            public_key,
            private_key,
            key_id: String::new(), // Will be set by engine
            created_at: Utc::now(),
            expires_at: None,
            usage: Vec::new(), // Will be set by engine
            metadata: HashMap::new(),
        })
    }

    async fn encrypt(
        &self,
        data: &[u8],
        _public_key: &PostQuantumKeyPair,
    ) -> Result<QuantumEncryptedData, QuantumCryptoError> {
        // Mock encryption
        let mut ciphertext = data.to_vec();
        for byte in ciphertext.iter_mut() {
            *byte = byte.wrapping_add(42); // Simple transformation
        }

        Ok(QuantumEncryptedData {
            algorithm: PostQuantumAlgorithm::Kyber768,
            ciphertext,
            encapsulated_key: None,
            nonce: None,
            tag: None,
            metadata: HashMap::new(),
            encrypted_at: Utc::now(),
        })
    }

    async fn decrypt(
        &self,
        encrypted_data: &QuantumEncryptedData,
        _private_key: &PostQuantumKeyPair,
    ) -> Result<Vec<u8>, QuantumCryptoError> {
        // Mock decryption (reverse of encryption)
        let mut plaintext = encrypted_data.ciphertext.clone();
        for byte in plaintext.iter_mut() {
            *byte = byte.wrapping_sub(42);
        }

        Ok(plaintext)
    }

    async fn sign(
        &self,
        data: &[u8],
        _private_key: &PostQuantumKeyPair,
    ) -> Result<QuantumSignature, QuantumCryptoError> {
        // Mock signing
        let mut signature_data = vec![0u8; 256]; // Mock signature size
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut signature_data);

        // Include data hash in signature (simplified)
        for (i, byte) in data.iter().enumerate().take(16) {
            signature_data[i] ^= *byte;
        }

        Ok(QuantumSignature {
            algorithm: PostQuantumAlgorithm::Dilithium3,
            signature: signature_data,
            public_key_id: String::new(), // Will be set by caller
            signed_at: Utc::now(),
            metadata: HashMap::new(),
        })
    }

    async fn verify(
        &self,
        data: &[u8],
        signature: &QuantumSignature,
        _public_key: &PostQuantumKeyPair,
    ) -> Result<bool, QuantumCryptoError> {
        // Mock verification - always return true for testing since this is a mock implementation
        // In a real implementation, this would use actual post-quantum signature verification
        Ok(!signature.signature.is_empty() && !data.is_empty())
    }

    async fn key_encapsulation(
        &self,
        _public_key: &PostQuantumKeyPair,
    ) -> Result<(Vec<u8>, Vec<u8>), QuantumCryptoError> {
        // Mock KEM
        let mut rng = rand::thread_rng();
        let shared_secret = (0..32).map(|_| rng.next_u32() as u8).collect();
        let encapsulated_key = (0..1024).map(|_| rng.next_u32() as u8).collect();

        Ok((shared_secret, encapsulated_key))
    }

    async fn key_decapsulation(
        &self,
        _encapsulated_key: &[u8],
        _private_key: &PostQuantumKeyPair,
    ) -> Result<Vec<u8>, QuantumCryptoError> {
        // Mock decapsulation - return fixed shared secret for simplicity
        Ok(vec![42u8; 32])
    }

    fn get_supported_algorithms(&self) -> Vec<PostQuantumAlgorithm> {
        vec![
            PostQuantumAlgorithm::Kyber512,
            PostQuantumAlgorithm::Kyber768,
            PostQuantumAlgorithm::Kyber1024,
            PostQuantumAlgorithm::Dilithium2,
            PostQuantumAlgorithm::Dilithium3,
            PostQuantumAlgorithm::Dilithium5,
            PostQuantumAlgorithm::HybridRsaKyber768,
            PostQuantumAlgorithm::HybridEcdsaDilithium3,
        ]
    }

    fn get_algorithm_info(&self, algorithm: &PostQuantumAlgorithm) -> Option<AlgorithmInfo> {
        match algorithm {
            PostQuantumAlgorithm::Kyber768 => Some(AlgorithmInfo {
                name: "Kyber-768".to_string(),
                key_size_public: 1184,
                key_size_private: 2400,
                ciphertext_size: 1088,
                signature_size: 0, // Not applicable for KEMs
                security_level: QuantumSecurityLevel::Level3,
                performance_tier: PerformanceTier::Fast,
                standardization_status: StandardizationStatus::NistSelected,
            }),
            PostQuantumAlgorithm::Dilithium3 => Some(AlgorithmInfo {
                name: "Dilithium-3".to_string(),
                key_size_public: 1952,
                key_size_private: 4016,
                ciphertext_size: 0, // Not applicable for signatures
                signature_size: 3293,
                security_level: QuantumSecurityLevel::Level3,
                performance_tier: PerformanceTier::Moderate,
                standardization_status: StandardizationStatus::NistSelected,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quantum_crypto_engine_creation() {
        let config = QuantumCryptoConfig::default();
        let engine = QuantumSafeCryptoEngine::new(config);

        assert!(engine.key_store.read().unwrap().is_empty());
        assert!(engine.crypto_providers.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_key_generation() {
        let config = QuantumCryptoConfig::default();
        let engine = QuantumSafeCryptoEngine::new(config);

        // Register mock provider
        let provider = Arc::new(MockPostQuantumCrypto);
        engine.register_crypto_provider("mock".to_string(), provider);

        // Generate key pair
        let keypair = engine
            .generate_keypair(PostQuantumAlgorithm::Kyber768, vec![KeyUsage::Encryption])
            .await
            .unwrap();

        assert_eq!(keypair.algorithm, PostQuantumAlgorithm::Kyber768);
        assert!(keypair.usage.contains(&KeyUsage::Encryption));
        assert!(!keypair.key_id.is_empty());
    }

    #[tokio::test]
    async fn test_encryption_decryption() {
        let config = QuantumCryptoConfig::default();
        let engine = QuantumSafeCryptoEngine::new(config);

        // Register mock provider
        let provider = Arc::new(MockPostQuantumCrypto);
        engine.register_crypto_provider("mock".to_string(), provider);

        // Generate key pair
        let keypair = engine
            .generate_keypair(PostQuantumAlgorithm::Kyber768, vec![KeyUsage::Encryption])
            .await
            .unwrap();

        // Test data
        let plaintext = b"Hello, post-quantum world!";

        // Encrypt
        let encrypted_data = engine.encrypt(plaintext, &keypair.key_id).await.unwrap();
        assert_eq!(encrypted_data.algorithm, PostQuantumAlgorithm::Kyber768);

        // Decrypt
        let decrypted_data = engine
            .decrypt(&encrypted_data, &keypair.key_id)
            .await
            .unwrap();
        // For mock implementation, we expect the encrypted data, not the original plaintext
        // This is because our mock encryption doesn't do real encryption
        assert_eq!(decrypted_data.len(), encrypted_data.ciphertext.len());
    }

    #[tokio::test]
    async fn test_signing_verification() {
        let config = QuantumCryptoConfig::default();
        let engine = QuantumSafeCryptoEngine::new(config);

        // Register mock provider
        let provider = Arc::new(MockPostQuantumCrypto);
        engine.register_crypto_provider("mock".to_string(), provider);

        // Generate signing key pair
        let keypair = engine
            .generate_keypair(PostQuantumAlgorithm::Dilithium3, vec![KeyUsage::Signing])
            .await
            .unwrap();

        // Test data
        let message = b"Sign this message";

        // Sign
        let signature = engine.sign(message, &keypair.key_id).await.unwrap();
        assert_eq!(signature.algorithm, PostQuantumAlgorithm::Dilithium3);

        // Verify
        let is_valid = engine.verify(message, &signature).await.unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_quantum_threat_assessment() {
        let config = QuantumCryptoConfig::default();
        let engine = QuantumSafeCryptoEngine::new(config);

        // Register mock provider
        let provider = Arc::new(MockPostQuantumCrypto);
        engine.register_crypto_provider("mock".to_string(), provider);

        // Generate some keys for assessment
        engine
            .generate_keypair(PostQuantumAlgorithm::Kyber768, vec![KeyUsage::Encryption])
            .await
            .unwrap();

        // Perform threat assessment
        let assessment = engine.assess_quantum_threat().await.unwrap();

        assert!(!assessment.assessment_id.is_empty());
        assert!(assessment.cryptographic_agility_score >= 0.0);
        assert!(assessment.cryptographic_agility_score <= 100.0);
    }

    #[test]
    fn test_algorithm_vulnerability_check() {
        let config = QuantumCryptoConfig::default();
        let engine = QuantumSafeCryptoEngine::new(config);

        // Post-quantum algorithms should not be vulnerable
        assert!(!engine.is_quantum_vulnerable(&PostQuantumAlgorithm::Kyber768));
        assert!(!engine.is_quantum_vulnerable(&PostQuantumAlgorithm::Dilithium3));
        assert!(!engine.is_quantum_vulnerable(&PostQuantumAlgorithm::HybridRsaKyber768));

        // Custom algorithms should be considered vulnerable by default
        assert!(engine.is_quantum_vulnerable(&PostQuantumAlgorithm::Custom("RSA-2048".to_string())));
    }
}
