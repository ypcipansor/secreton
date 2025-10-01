//! Shamir Secret Sharing Engine
//!
//! Implements M-of-N threshold cryptography for secure key distribution
//! and recovery mechanisms in enterprise environments.

use crate::{
    error::{CryptoError, CryptoResult},
    hashing::{HashAlgorithm, HashProvider},
    kv_engine::{KVEngine, KVMetadata, KVOperation},
    transit::TransitEngine,
};
use async_trait::async_trait;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Shamir Secret Sharing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirConfig {
    /// Default threshold (M) - minimum shares needed for reconstruction
    pub default_threshold: usize,
    /// Default total shares (N) - total shares to generate
    pub default_total_shares: usize,
    /// Maximum allowed threshold
    pub max_threshold: usize,
    /// Maximum allowed total shares
    pub max_total_shares: usize,
    /// Share expiration time in seconds
    pub share_ttl_seconds: u64,
    /// Enable detailed audit logging
    pub enable_audit: bool,
}

impl Default for ShamirConfig {
    fn default() -> Self {
        Self {
            default_threshold: 3,
            default_total_shares: 5,
            max_threshold: 10,
            max_total_shares: 20,
            share_ttl_seconds: 3600, // 1 hour
            enable_audit: true,
        }
    }
}

/// Shamir Secret Sharing Engine
pub struct ShamirEngine {
    config: ShamirConfig,
    kv_engine: Arc<KVEngine>,
    transit_engine: Arc<TransitEngine>,
    hash_provider: Arc<HashProvider>,
    shares: Arc<RwLock<HashMap<String, ShamirShare>>>,
}

    /// Shamir polynomial for secret sharing
    pub struct ShamirPolynomial {
        coefficients: Vec<BigUint>,
        prime: BigUint,
    }

    impl ShamirPolynomial {
        /// Create a new polynomial with the given secret and threshold
        pub fn new(secret: &BigUint, threshold: usize, prime: &BigUint) -> CryptoResult<Self> {
            if threshold == 0 {
                return Err(CryptoError::InvalidInput("Threshold must be greater than 0".to_string()));
            }

            let mut coefficients = vec![secret.clone()];
            let mut rng = thread_rng();

            // Generate random coefficients for degree threshold-1
            for _ in 1..threshold {
                let coeff = rng.gen_biguint_range(&BigUint::one(), prime);
                coefficients.push(coeff);
            }

            Ok(Self {
                coefficients,
                prime: prime.clone(),
            })
        }

        pub fn evaluate(&self, x: &BigUint) -> CryptoResult<BigUint> {
            let mut result = BigUint::zero();

            for (i, coeff) in self.coefficients.iter().enumerate() {
                let term = coeff * x.pow(i as u32) % &self.prime;
                result = (result + term) % &self.prime;
            }

            Ok(result)
        }

        /// Get the constant term (secret)
        pub fn constant_term(&self) -> &BigUint {
            &self.coefficients[0]
        }
    }

    /// Metadata for a Shamir share

impl ShamirEngine {
    /// Create a new Shamir Secret Sharing Engine
    pub fn new(
        config: ShamirConfig,
        kv_engine: Arc<KVEngine>,
        transit_engine: Arc<TransitEngine>,
        hash_provider: Arc<HashProvider>,
    ) -> Self {
        Self {
            config,
            kv_engine,
            transit_engine,
            hash_provider,
            shares: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate Shamir shares for a secret
    pub async fn generate_shares(&self, request: ShamirRequest) -> CryptoResult<Vec<ShamirShare>> {
        // Validate request parameters
        self.validate_request(&request)?;

        // Retrieve the secret data
        let secret_data = self.get_secret_data(&request.secret_path).await?;

        // Generate a safe prime for this operation
        let prime = shamir_math::ShamirMath::generate_safe_prime(256)?;

        // Create polynomial with secret as constant term
        let polynomial = shamir_math::ShamirPolynomial::new(&secret_data, request.threshold, &prime)?;

        // Generate shares at points 1, 2, 3, ..., total_shares
        let mut shares = Vec::new();
        let mut rng = thread_rng();

        for i in 1..=request.total_shares {
            let x = BigUint::from(i as u64);
            let y = polynomial.evaluate(&x)?;

            // Calculate checksum for integrity
            let checksum = self.calculate_checksum(&y)?;

            let share = ShamirShare {
                share_id: Uuid::new_v4(),
                share_index: i,
                share_value: y,
                metadata: ShareMetadata {
                    secret_path: request.secret_path.clone(),
                    threshold: request.threshold,
                    total_shares: request.total_shares,
                    algorithm: "shamir-secret-sharing".to_string(),
                    checksum,
                },
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now()
                    + chrono::Duration::seconds(request.share_ttl_seconds.unwrap_or(self.config.share_ttl_seconds) as i64),
            };

            shares.push(share);
        }

        // Store shares as separate secrets
        for share in &shares {
            self.store_share(share).await?;
        }

        // Store reconstruction metadata
        self.store_reconstruction_metadata(&request.secret_path, request.threshold, request.total_shares, &shares).await?;

        // Cache shares for quick access
        let mut shares_cache = self.shares.write().await;
        for share in &shares {
            shares_cache.insert(share.share_id.to_string(), share.clone());
        }

        Ok(shares)
    }

    /// Reconstruct secret from shares
    pub async fn reconstruct_secret(&self, request: ShamirReconstructionRequest) -> CryptoResult<serde_json::Value> {
        // Validate reconstruction request
        self.validate_reconstruction_request(&request).await?;

        // Retrieve reconstruction metadata
        let metadata = self.get_reconstruction_metadata(&request.secret_path).await?;

        // Validate we have enough shares
        if request.share_paths.len() < metadata.threshold {
            return Err(CryptoError::InvalidInput(format!(
                "Insufficient shares: need at least {}, got {}",
                metadata.threshold,
                request.share_paths.len()
            )));
        }

        // Retrieve and validate shares
        let mut points = Vec::new();
        for share_path in &request.share_paths {
            let share = self.retrieve_share(share_path).await?;

            // Validate share integrity
            self.validate_share(&share)?;

            points.push((share.share_value.clone(), share.share_value));
        }

        // Get the prime used for this secret
        let prime = self.get_prime_for_secret(&request.secret_path).await?;

        // Perform Lagrange interpolation to reconstruct secret
        let secret = shamir_math::LagrangeInterpolator::interpolate(&points, &prime)?;

        // Convert back to original format
        let secret_data = self.biguint_to_bytes(&secret)?;

        // Validate reconstruction
        self.validate_reconstructed_secret(&secret_data)?;

        Ok(serde_json::from_slice(&secret_data)?)
    }

    /// Validate share generation request
    fn validate_request(&self, request: &ShamirRequest) -> CryptoResult<()> {
        if request.threshold == 0 {
            return Err(CryptoError::InvalidInput("Threshold must be greater than 0".to_string()));
        }

        if request.total_shares == 0 {
            return Err(CryptoError::InvalidInput("Total shares must be greater than 0".to_string()));
        }

        if request.threshold > request.total_shares {
            return Err(CryptoError::InvalidInput(
                "Threshold cannot be greater than total shares".to_string()
            ));
        }

        if request.threshold > self.config.max_threshold {
            return Err(CryptoError::InvalidInput(format!(
                "Threshold exceeds maximum allowed: {}",
                self.config.max_threshold
            )));
        }

        if request.total_shares > self.config.max_total_shares {
            return Err(CryptoError::InvalidInput(format!(
                "Total shares exceeds maximum allowed: {}",
                self.config.max_total_shares
            )));
        }

        Ok(())
    }

    /// Validate reconstruction request
    async fn validate_reconstruction_request(&self, request: &ShamirReconstructionRequest) -> CryptoResult<()> {
        // Check if reconstruction metadata exists
        let metadata = self.get_reconstruction_metadata(&request.secret_path).await?;

        if request.share_paths.len() < metadata.threshold {
            return Err(CryptoError::InvalidInput(format!(
                "Insufficient shares for reconstruction: need at least {}, got {}",
                metadata.threshold,
                request.share_paths.len()
            )));
        }

        Ok(())
    }

    /// Generate a cryptographically secure safe prime
    async fn generate_safe_prime(&self) -> CryptoResult<BigUint> {
        let mut rng = thread_rng();

        loop {
            // Generate a random 256-bit number
            let candidate = rng.gen_biguint(256);

            // Check if it's a safe prime (p = 2q + 1 where q is also prime)
            if self.is_safe_prime(&candidate).await? {
                return Ok(candidate);
            }
        }
    }

    /// Check if a number is a safe prime
    async fn is_safe_prime(&self, candidate: &BigUint) -> CryptoResult<bool> {
        // Check if candidate is prime
        if !self.is_prime(candidate).await? {
            return Ok(false);
        }

        // Check if (candidate - 1) / 2 is also prime (Sophie Germain prime)
        let sophie_germain = (candidate - BigUint::one()) / BigUint::from(2u32);
        if !self.is_prime(&sophie_germain).await? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Miller-Rabin primality test
    async fn is_prime(&self, n: &BigUint) -> CryptoResult<bool> {
        if n < &BigUint::from(2u32) {
            return Ok(false);
        }

        if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
            return Ok(true);
        }

        // Write n-1 as 2^s * d
        let mut d = n - BigUint::one();
        let mut s = 0usize;

        while &d % BigUint::from(2u32) == BigUint::zero() {
            d /= BigUint::from(2u32);
            s += 1;
        }

        // Witness loop
        for _ in 0..40 { // 40 rounds for 256-bit numbers
            let mut rng = thread_rng();
            let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - BigUint::from(2u32)));

            let mut x = a.modpow(&d, n);

            if x == BigUint::one() || x == n - BigUint::one() {
                continue;
            }

            let mut next_power = true;
            for _ in 1..s {
                x = x.modpow(&BigUint::from(2u32), n);

                if x == BigUint::one() {
                    return Ok(false);
                }

                if x == n - BigUint::one() {
                    next_power = false;
                    break;
                }
            }

            if next_power {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get secret data from KV engine
    async fn get_secret_data(&self, path: &str) -> CryptoResult<BigUint> {
        let secret = self.kv_engine.read_secret(path).await?;

        // Convert JSON data to BigUint (for simplicity, we'll hash it)
        let data_bytes = serde_json::to_vec(&secret.data)?;
        let hash = self.hash_provider.hash(&data_bytes, HashAlgorithm::Sha256)?;

        // Convert hash to BigUint
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);
        Ok(BigUint::from_bytes_be(&bytes))
    }

    /// Store a share as a separate secret
    async fn store_share(&self, share: &ShamirShare) -> CryptoResult<()> {
        let share_path = format!("{}/share_{}", share.metadata.secret_path, share.share_index);

        // Create metadata for the share
        let metadata = KVMetadata {
            version: 1,
            created_time: share.created_at,
            deletion_time: Some(share.expires_at),
            destroyed: false,
        };

        // Store share data
        let share_data = serde_json::json!({
            "share_id": share.share_id,
            "share_index": share.share_index,
            "share_value": share.share_value.to_string(),
            "threshold": share.metadata.threshold,
            "total_shares": share.metadata.total_shares,
            "checksum": share.metadata.checksum,
        });

        self.kv_engine
            .create_secret(&share_path, share_data, Some(metadata))
            .await?;

        Ok(())
    }

    /// Retrieve a share from storage
    async fn retrieve_share(&self, share_path: &str) -> CryptoResult<ShamirShare> {
        let secret = self.kv_engine.read_secret(share_path).await?;

        // Parse share data
        let share_id = secret.data["share_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| CryptoError::InvalidInput("Invalid share_id".to_string()))?;

        let share_index = secret.data["share_index"]
            .as_u64()
            .ok_or_else(|| CryptoError::InvalidInput("Invalid share_index".to_string()))? as usize;

        let share_value_str = secret.data["share_value"]
            .as_str()
            .ok_or_else(|| CryptoError::InvalidInput("Invalid share_value".to_string()))?;

        let share_value = BigUint::parse_bytes(share_value_str.as_bytes(), 10)
            .ok_or_else(|| CryptoError::InvalidInput("Invalid share_value format".to_string()))?;

        let threshold = secret.data["threshold"]
            .as_u64()
            .ok_or_else(|| CryptoError::InvalidInput("Invalid threshold".to_string()))? as usize;

        let total_shares = secret.data["total_shares"]
            .as_u64()
            .ok_or_else(|| CryptoError::InvalidInput("Invalid total_shares".to_string()))? as usize;

        let checksum = secret.data["checksum"]
            .as_str()
            .ok_or_else(|| CryptoError::InvalidInput("Invalid checksum".to_string()))?;

        // Validate checksum
        let calculated_checksum = self.calculate_checksum(&share_value)?;
        if checksum != calculated_checksum {
            return Err(CryptoError::InvalidInput("Share checksum validation failed".to_string()));
        }

        Ok(ShamirShare {
            share_id,
            share_index,
            share_value,
            metadata: ShareMetadata {
                secret_path: share_path.strip_prefix("/share_").unwrap_or(share_path).to_string(),
                threshold,
                total_shares,
                algorithm: "shamir-secret-sharing".to_string(),
                checksum: checksum.to_string(),
            },
            created_at: secret.metadata.created_time,
            expires_at: secret.metadata.deletion_time.unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(1)),
        })
    }

    /// Store reconstruction metadata
    async fn store_reconstruction_metadata(
        &self,
        secret_path: &str,
        threshold: usize,
        total_shares: usize,
        shares: &[ShamirShare],
    ) -> CryptoResult<()> {
        let metadata_path = format!("{}/.shamir_metadata", secret_path);

        let metadata = serde_json::json!({
            "secret_path": secret_path,
            "threshold": threshold,
            "total_shares": total_shares,
            "share_paths": shares.iter().map(|s| format!("{}/share_{}", secret_path, s.share_index)).collect::<Vec<_>>(),
            "created_at": chrono::Utc::now(),
        });

        let kv_metadata = KVMetadata {
            version: 1,
            created_time: chrono::Utc::now(),
            deletion_time: None,
            destroyed: false,
        };

        self.kv_engine
            .create_secret(&metadata_path, metadata, Some(kv_metadata))
            .await?;

        Ok(())
    }

    /// Get reconstruction metadata
    async fn get_reconstruction_metadata(&self, secret_path: &str) -> CryptoResult<ReconstructionMetadata> {
        let metadata_path = format!("{}/.shamir_metadata", secret_path);
        let secret = self.kv_engine.read_secret(&metadata_path).await?;

        let threshold = secret.data["threshold"]
            .as_u64()
            .ok_or_else(|| CryptoError::InvalidInput("Invalid threshold in metadata".to_string()))? as usize;

        let total_shares = secret.data["total_shares"]
            .as_u64()
            .ok_or_else(|| CryptoError::InvalidInput("Invalid total_shares in metadata".to_string()))? as usize;

        let share_paths: Vec<String> = secret.data["share_paths"]
            .as_array()
            .ok_or_else(|| CryptoError::InvalidInput("Invalid share_paths in metadata".to_string()))?
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect();

        Ok(ReconstructionMetadata {
            secret_path: secret_path.to_string(),
            threshold,
            total_shares,
            share_paths,
        })
    }

    /// Get prime used for a specific secret
    async fn get_prime_for_secret(&self, secret_path: &str) -> CryptoResult<BigUint> {
        // For simplicity, we'll use a deterministic prime based on the secret path
        // In production, this should be stored securely
        let path_hash = self.hash_provider.hash(secret_path.as_bytes(), HashAlgorithm::Sha256)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&path_hash[..32]);

        // Convert hash to a number and make it odd (for better prime generation)
        let mut num = BigUint::from_bytes_be(&bytes);
        if &num % BigUint::from(2u32) == BigUint::zero() {
            num += BigUint::one();
        }

        Ok(num)
    }

    /// Calculate checksum for a share value
    fn calculate_checksum(&self, value: &BigUint) -> CryptoResult<String> {
        let value_bytes = value.to_bytes_be();
        let hash = self.hash_provider.hash(&value_bytes, HashAlgorithm::Sha256)?;
        Ok(hex::encode(&hash[..8])) // Use first 8 bytes as checksum
    }

    /// Convert BigUint to bytes
    fn biguint_to_bytes(&self, value: &BigUint) -> CryptoResult<Vec<u8>> {
        Ok(value.to_bytes_be())
    }

    /// Validate share integrity
    fn validate_share(&self, share: &ShamirShare) -> CryptoResult<()> {
        // Check if share is expired
        if chrono::Utc::now() > share.expires_at {
            return Err(CryptoError::InvalidInput("Share has expired".to_string()));
        }

        // Validate checksum
        let calculated_checksum = self.calculate_checksum(&share.share_value)?;
        if share.metadata.checksum != calculated_checksum {
            return Err(CryptoError::InvalidInput("Share checksum validation failed".to_string()));
        }

        Ok(())
    }

    /// Validate reconstructed secret
    fn validate_reconstructed_secret(&self, secret_data: &[u8]) -> CryptoResult<()> {
        // Basic validation - ensure we have data
        if secret_data.is_empty() {
            return Err(CryptoError::InvalidInput("Reconstructed secret is empty".to_string()));
        }

        Ok(())
    }

/// Metadata for secret reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionMetadata {
    pub secret_path: String,
    pub threshold: usize,
    pub total_shares: usize,
    pub share_paths: Vec<String>,
}

/// Implement the SecretsEngine trait for ShamirEngine
#[async_trait]
impl crate::secrets::engine::SecretsEngine for ShamirEngine {
    fn engine_type(&self) -> &'static str {
        "shamir"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: serde_json::Value,
        _options: Option<serde_json::Value>,
    ) -> Result<crate::secrets::engine::Secret, crate::secrets::engine::SecretsError> {
        // For Shamir engine, creating a secret means generating shares
        let request = ShamirRequest {
            secret_path: path.to_string(),
            threshold: self.config.default_threshold,
            total_shares: self.config.default_total_shares,
            share_ttl_seconds: Some(self.config.share_ttl_seconds),
        };

        let shares = self.generate_shares(request).await
            .map_err(|e| crate::secrets::engine::SecretsError::ExecutionError(e.to_string()))?;

        // Return a secret representing the share generation
        Ok(crate::secrets::engine::Secret {
            id: uuid::Uuid::new_v4(),
            path: path.to_string(),
            data: serde_json::json!({
                "shares_generated": shares.len(),
                "threshold": self.config.default_threshold,
                "total_shares": self.config.default_total_shares,
            }),
            metadata: crate::secrets::engine::SecretMetadata {
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                version: 1,
                ttl: Some(self.config.share_ttl_seconds as i64),
                expired_at: Some(chrono::Utc::now() + chrono::Duration::seconds(self.config.share_ttl_seconds as i64)),
                custom_metadata: None,
            },
        })
    }

    async fn read_secret(&self, path: &str) -> Result<crate::secrets::engine::Secret, crate::secrets::engine::SecretsError> {
        // For Shamir engine, reading could mean reconstructing from shares
        // For now, return metadata about available shares
        let metadata = self.get_reconstruction_metadata(path).await
            .map_err(|e| crate::secrets::engine::SecretsError::NotFound(e.to_string()))?;

        Ok(crate::secrets::engine::Secret {
            id: uuid::Uuid::new_v4(),
            path: path.to_string(),
            data: serde_json::json!({
                "threshold": metadata.threshold,
                "total_shares": metadata.total_shares,
                "available_shares": metadata.share_paths.len(),
            }),
            metadata: crate::secrets::engine::SecretMetadata {
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                version: 1,
                ttl: None,
                expired_at: None,
                custom_metadata: None,
            },
        })
    }

    async fn update_secret(
        &self,
        _path: &str,
        _data: serde_json::Value,
        _options: Option<serde_json::Value>,
    ) -> Result<crate::secrets::engine::Secret, crate::secrets::engine::SecretsError> {
        Err(crate::secrets::engine::SecretsError::InvalidConfiguration(
            "Shamir engine does not support direct secret updates".to_string()
        ))
    }

    async fn delete_secret(&self, path: &str) -> Result<(), crate::secrets::engine::SecretsError> {
        // For Shamir engine, deletion could mean invalidating all shares
        // For now, just return success
        Ok(())
    }

    async fn list_secrets(&self, path: &str) -> Result<Vec<String>, crate::secrets::engine::SecretsError> {
        let metadata = self.get_reconstruction_metadata(path).await
            .map_err(|e| crate::secrets::engine::SecretsError::NotFound(e.to_string()))?;

        Ok(metadata.share_paths)
    }

    async fn collect_metrics(&self) -> Result<crate::secrets::engine::EngineMetrics, crate::secrets::engine::SecretsError> {
        Ok(crate::secrets::engine::EngineMetrics {
            engine_type: "shamir".to_string(),
            secrets_created: 0, // Would need to track this
            secrets_read: 0,
            secrets_updated: 0,
            secrets_deleted: 0,
            avg_response_time_ms: 0.0,
            error_count: 0,
            active_secrets: 0,
            storage_size_bytes: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_config_default() {
        let config = ShamirConfig::default();
        assert_eq!(config.default_threshold, 3);
        assert_eq!(config.default_total_shares, 5);
        assert_eq!(config.max_threshold, 10);
        assert_eq!(config.max_total_shares, 20);
    }

    #[test]
    fn test_polynomial_creation() {
        let secret = BigUint::from(42u32);
        let prime = BigUint::from(101u32); // Small prime for testing
        let poly = shamir_math::ShamirPolynomial::new(&secret, 3, &prime).unwrap();

        assert_eq!(poly.coefficients.len(), 3);
        assert_eq!(poly.coefficients[0], secret);
    }

    #[test]
    fn test_polynomial_evaluation() {
        let secret = BigUint::from(42u32);
        let prime = BigUint::from(101u32);
        let poly = shamir_math::ShamirPolynomial::new(&secret, 3, &prime).unwrap();

        let x = BigUint::from(1u32);
        let y = poly.evaluate(&x).unwrap();

        // Should be different from secret (unless x=0)
        assert_ne!(y, secret);
    }

    #[test]
    fn test_mod_inverse() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);

        let inv = shamir_math::ShamirMath::mod_inverse(&a, &m).unwrap();
        let result = (a * inv) % m;

        assert_eq!(result, BigUint::one());
    }

    #[tokio::test]
    async fn test_lagrange_interpolation() {
        // Simple test case: secret = 42, threshold = 3, points = (1, 50), (2, 58), (3, 66)
        let points = vec![
            (BigUint::from(1u32), BigUint::from(50u32)),
            (BigUint::from(2u32), BigUint::from(58u32)),
            (BigUint::from(3u32), BigUint::from(66u32)),
        ];
        let prime = BigUint::from(101u32);

        let secret = shamir_math::LagrangeInterpolator::interpolate(&points, &prime).unwrap();
        assert_eq!(secret, BigUint::from(42u32));
    }
}
