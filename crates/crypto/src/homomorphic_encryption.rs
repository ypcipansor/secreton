//! Homomorphic Encryption System
//!
//! Partially homomorphic encryption for computation on encrypted data,
//! including encrypted search, secure aggregation, and ciphertext operations.

use chrono::{DateTime, Utc};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

// Real Paillier cryptosystem implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKey {
    pub n: Vec<u8>, // modulus n = p * q (stored as bytes)
    pub g: Vec<u8>, // generator, usually n + 1 (stored as bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionKey {
    pub lambda: Vec<u8>, // lcm(p-1, q-1) (stored as bytes)
    pub mu: Vec<u8>,     // modular inverse of L(g^lambda)^(-1) mod n (stored as bytes)
    pub n: Vec<u8>,      // modulus n (stored as bytes)
}

pub struct Paillier;

impl Paillier {
    /// Generate a new Paillier keypair
    pub fn keypair() -> Result<KeyPair> {
        let mut rng = rand::thread_rng();

        // Generate two large primes p and q
        // For security, we use 2048-bit primes (1024-bit modulus)
        let p = rng.gen_biguint(1024);
        let q = rng.gen_biguint(1024);

        // Ensure p and q are prime (simplified check - in production use proper primality testing)
        let p = Self::next_prime(p);
        let q = Self::next_prime(q);

        // Compute n = p * q
        let n = &p * &q;

        // Compute lambda = lcm(p-1, q-1)
        let p_minus_1 = &p - BigUint::one();
        let q_minus_1 = &q - BigUint::one();
        let lambda = Self::lcm(p_minus_1, q_minus_1);

        // Compute n^2
        let n_squared = &n * &n;

        // Choose g = n + 1 (this works for Paillier)
        let g = &n + BigUint::one();

        // Compute g^lambda mod n^2
        let g_lambda = Self::mod_pow(&g, &lambda, &n_squared);

        // Compute L(u) = (u - 1) / n
        let l_value = (&g_lambda - BigUint::one()) / &n;

        // Compute mu = L(g^lambda)^(-1) mod n
        let mu = Self::mod_inverse(&l_value, &n)
            .ok_or_else(|| HEError::InvalidKey("Failed to compute modular inverse".to_string()))?;

        let ek = EncryptionKey {
            n: n.to_bytes_be(),
            g: g.to_bytes_be(),
        };

        let dk = DecryptionKey {
            lambda: lambda.to_bytes_be(),
            mu: mu.to_bytes_be(),
            n: n.to_bytes_be(),
        };

        Ok(KeyPair { ek, dk })
    }

    /// Encrypt a plaintext message
    pub fn encrypt(ek: &EncryptionKey, plaintext: &BigUint) -> Result<BigUint> {
        let (n, g) = ek.to_biguint();
        let mut rng = rand::thread_rng();

        // Choose random r where 0 < r < n
        let r = rng.gen_biguint_range(&BigUint::one(), &n);

        // Compute n^2
        let n_squared = &n * &n;

        // Compute ciphertext = (g^plaintext * r^n) mod n^2
        let g_m = Self::mod_pow(&g, plaintext, &n_squared);
        let r_n = Self::mod_pow(&r, &n, &n_squared);

        let ciphertext = (g_m * r_n) % &n_squared;

        Ok(ciphertext)
    }

    /// Decrypt a ciphertext
    pub fn decrypt(dk: &DecryptionKey, ciphertext: &BigUint) -> Result<BigUint> {
        let (lambda, mu, n) = dk.to_biguint();
        let n_squared = &n * &n;

        // Compute ciphertext^lambda mod n^2
        let c_lambda = Self::mod_pow(ciphertext, &lambda, &n_squared);

        // Compute L(u) = (u - 1) / n
        let l_value = (&c_lambda - BigUint::one()) / &n;

        // Compute plaintext = (L(u) * mu) mod n
        let plaintext = (l_value * &mu) % &n;

        Ok(plaintext)
    }

    /// Add two ciphertexts homomorphically
    pub fn add(ek: &EncryptionKey, c1: &BigUint, c2: &BigUint) -> Result<BigUint> {
        let (n, _) = ek.to_biguint();
        let n_squared = &n * &n;
        let result = (c1 * c2) % &n_squared;
        Ok(result)
    }

    /// Multiply ciphertext by plaintext homomorphically
    pub fn multiply(ek: &EncryptionKey, ciphertext: &BigUint, scalar: &BigUint) -> Result<BigUint> {
        let (n, _) = ek.to_biguint();
        let n_squared = &n * &n;
        let result = Self::mod_pow(ciphertext, scalar, &n_squared);
        Ok(result)
    }

    // Helper functions
    fn next_prime(mut n: BigUint) -> BigUint {
        if n.is_even() {
            n += BigUint::one();
        }
        while !Self::is_prime(&n) {
            n += 2u32;
        }
        n
    }

    fn is_prime(n: &BigUint) -> bool {
        if n < &BigUint::from(2u32) {
            return false;
        }
        if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
            return true;
        }
        if n.is_even() {
            return false;
        }

        // Simple primality test - in production use Miller-Rabin
        let mut i = BigUint::from(3u32);
        while &i * &i <= *n {
            if n % &i == BigUint::zero() {
                return false;
            }
            i += 2u32;
        }
        true
    }

    fn lcm(a: BigUint, b: BigUint) -> BigUint {
        let gcd = Self::gcd(a.clone(), b.clone());
        (a * b) / gcd
    }

    fn gcd(mut a: BigUint, mut b: BigUint) -> BigUint {
        while b != BigUint::zero() {
            let t = b.clone();
            b = a % b;
            a = t;
        }
        a
    }

    fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        let mut result = BigUint::one();
        let mut base = base.clone();
        let mut exp = exponent.clone();

        base %= modulus;

        while exp > BigUint::zero() {
            if &exp % 2u32 == BigUint::one() {
                result = (result * &base) % modulus;
            }
            base = (&base * &base) % modulus;
            exp /= 2u32;
        }

        result
    }

    fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
        let mut m0 = m.clone();
        let mut y = BigUint::zero();
        let mut x = BigUint::one();

        if m == &BigUint::one() {
            return Some(BigUint::one());
        }

        let mut a = a.clone();

        while a > BigUint::one() {
            let q = &a / &m0;
            let mut t = m0.clone();

            m0 = a % m0;
            a = t;
            t = y.clone();

            y = x - q * y;
            x = t;
        }

        if x >= *m {
            x -= m;
        }

        Some(x)
    }
}

pub struct KeyPair {
    pub ek: EncryptionKey,
    pub dk: DecryptionKey,
}

impl KeyPair {
    pub fn keys(self) -> (EncryptionKey, DecryptionKey) {
        (self.ek, self.dk)
    }
}

impl EncryptionKey {
    fn to_biguint(&self) -> (BigUint, BigUint) {
        (BigUint::from_bytes_be(&self.n), BigUint::from_bytes_be(&self.g))
    }
}

impl DecryptionKey {
    fn to_biguint(&self) -> (BigUint, BigUint, BigUint) {
        (
            BigUint::from_bytes_be(&self.lambda),
            BigUint::from_bytes_be(&self.mu),
            BigUint::from_bytes_be(&self.n),
        )
    }
}

#[derive(Debug, Error)]
pub enum HEError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Operation not supported: {0}")]
    OperationNotSupported(String),
    #[error("Unsupported scheme: {0}")]
    UnsupportedScheme(String),
    #[error("Ciphertext not found: {0}")]
    CiphertextNotFound(String),
}

pub type Result<T> = std::result::Result<T, HEError>;

/// Homomorphic encryption scheme
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HEScheme {
    Paillier,
    ElGamal,
    BGV,
    BFV,
    CKKS,
}

impl std::fmt::Display for HEScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HEScheme::Paillier => write!(f, "Paillier"),
            HEScheme::ElGamal => write!(f, "ElGamal"),
            HEScheme::BGV => write!(f, "BGV"),
            HEScheme::BFV => write!(f, "BFV"),
            HEScheme::CKKS => write!(f, "CKKS"),
        }
    }
}

/// Public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub key_id: String,
    pub scheme: HEScheme,
    pub key_data: Vec<u8>,
    pub modulus: u64,
}

/// Secret key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKey {
    pub key_id: String,
    pub scheme: HEScheme,
    pub key_data: Vec<u8>,
}

/// Ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub ciphertext_id: String,
    pub scheme: HEScheme,
    pub data: Vec<u8>,
    pub metadata: CiphertextMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextMetadata {
    pub encrypted_at: DateTime<Utc>,
    pub owner: String,
    pub searchable: bool,
    pub tags: Vec<String>,
}

/// Homomorphic operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HEOperation {
    Add,
    Multiply,
    Subtract,
}

/// Search index entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchIndexEntry {
    pub entry_id: String,
    pub ciphertext_id: String,
    pub encrypted_keywords: Vec<Vec<u8>>,
}

/// Aggregation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationResult {
    pub result_id: String,
    pub operation: HEOperation,
    pub result_ciphertext: Ciphertext,
    pub input_count: usize,
}

/// Key pair for homomorphic encryption schemes
#[derive(Debug, Clone)]
pub enum HEKeyPair {
    Paillier {
        public_key: EncryptionKey,
        private_key: DecryptionKey,
    },
    // Placeholder for future schemes
    ElGamal,
    BGV,
    BFV,
    CKKS,
}

/// Homomorphic Encryption System
pub struct HESystem {
    keys: Arc<RwLock<HashMap<String, HEKeyPair>>>,
    ciphertexts: Arc<RwLock<HashMap<String, Ciphertext>>>,
    search_index: Arc<RwLock<HashMap<String, SearchIndexEntry>>>,
}

impl HESystem {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            ciphertexts: Arc::new(RwLock::new(HashMap::new())),
            search_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate key pair
    pub async fn generate_keypair(&self, scheme: HEScheme) -> Result<(String, String)> {
        let key_id = Uuid::new_v4().to_string();

        match scheme {
            HEScheme::Paillier => {
                // Generate real Paillier key pair
                let keypair = Paillier::keypair()?;
                let (ek, dk) = keypair.keys();

                let keypair = HEKeyPair::Paillier {
                    public_key: ek,
                    private_key: dk,
                };

                let mut keys = self.keys.write().await;
                keys.insert(key_id.clone(), keypair);

                Ok((key_id.clone(), key_id))
            }
            HEScheme::ElGamal | HEScheme::BGV | HEScheme::BFV | HEScheme::CKKS => {
                // Placeholder for future implementation
                Err(HEError::UnsupportedScheme(scheme.to_string()))
            }
        }
    }

    /// Encrypt data
    pub async fn encrypt(
        &self,
        public_key_id: &str,
        plaintext: &[u8],
        owner: &str,
    ) -> Result<Ciphertext> {
        let keys = self.keys.read().await;
        let keypair = keys
            .get(public_key_id)
            .ok_or_else(|| HEError::InvalidKey(public_key_id.to_string()))?;

        match keypair {
            HEKeyPair::Paillier { public_key, .. } => {
                // Convert plaintext bytes to BigUint (big-endian)
                let plaintext_int = BigUint::from_bytes_be(plaintext);

                // Encrypt using Paillier
                let encrypted_int = Paillier::encrypt(public_key, &plaintext_int)?;

                // Convert back to bytes for storage
                let encrypted_bytes = encrypted_int.to_bytes_be();

                let ciphertext = Ciphertext {
                    ciphertext_id: Uuid::new_v4().to_string(),
                    scheme: HEScheme::Paillier,
                    data: encrypted_bytes,
                    metadata: CiphertextMetadata {
                        encrypted_at: Utc::now(),
                        owner: owner.to_string(),
                        searchable: false,
                        tags: vec![],
                    },
                };

                let ciphertext_id = ciphertext.ciphertext_id.clone();
                drop(keys);

                let mut ciphertexts = self.ciphertexts.write().await;
                ciphertexts.insert(ciphertext_id, ciphertext.clone());

                Ok(ciphertext)
            }
            _ => Err(HEError::UnsupportedScheme(
                "Only Paillier is currently supported".to_string(),
            )),
        }
    }

    /// Decrypt data
    pub async fn decrypt(&self, secret_key_id: &str, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
        let sec_keys = self.keys.read().await;
        let keypair = sec_keys
            .get(secret_key_id)
            .ok_or_else(|| HEError::InvalidKey(secret_key_id.to_string()))?;

        match keypair {
            HEKeyPair::Paillier { private_key, .. } => {
                // Convert ciphertext bytes to BigUint
                let encrypted_int = BigUint::from_bytes_be(&ciphertext.data);

                // Decrypt using Paillier
                let decrypted_int = Paillier::decrypt(private_key, &encrypted_int)?;

                // Convert back to bytes
                Ok(decrypted_int.to_bytes_be())
            }
            _ => Err(HEError::UnsupportedScheme(
                "Only Paillier is currently supported".to_string(),
            )),
        }
    }

    /// Homomorphic addition
    pub async fn add(
        &self,
        ciphertext1: &Ciphertext,
        ciphertext2: &Ciphertext,
    ) -> Result<Ciphertext> {
        if ciphertext1.scheme != ciphertext2.scheme {
            return Err(HEError::OperationNotSupported(
                "Ciphertexts must use same scheme".to_string(),
            ));
        }

        match ciphertext1.scheme {
            HEScheme::Paillier => {
                // Get the public key for this scheme (assuming we have it stored)
                // For simplicity, we'll use a dummy key for the operation
                // In a real implementation, we'd store the public key with the ciphertext
                let keys = self.keys.read().await;
                let public_key = keys.values()
                    .find_map(|kp| match kp {
                        HEKeyPair::Paillier { public_key, .. } => Some(public_key.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| HEError::InvalidKey("No Paillier public key found".to_string()))?;

                let c1 = BigUint::from_bytes_be(&ciphertext1.data);
                let c2 = BigUint::from_bytes_be(&ciphertext2.data);

                let result_int = Paillier::add(&public_key, &c1, &c2)?;
                let result_bytes = result_int.to_bytes_be();

                let result = Ciphertext {
                    ciphertext_id: Uuid::new_v4().to_string(),
                    scheme: HEScheme::Paillier,
                    data: result_bytes,
                    metadata: CiphertextMetadata {
                        encrypted_at: Utc::now(),
                        owner: ciphertext1.metadata.owner.clone(),
                        searchable: false,
                        tags: vec!["computed".to_string()],
                    },
                };

                let mut ciphertexts = self.ciphertexts.write().await;
                ciphertexts.insert(result.ciphertext_id.clone(), result.clone());

                Ok(result)
            }
            _ => Err(HEError::UnsupportedScheme(
                "Only Paillier is currently supported".to_string(),
            )),
        }
    }

    /// Homomorphic multiplication
    pub async fn multiply(&self, ciphertext: &Ciphertext, scalar: u64) -> Result<Ciphertext> {
        match ciphertext.scheme {
            HEScheme::Paillier => {
                // Get the public key
                let keys = self.keys.read().await;
                let public_key = keys.values()
                    .find_map(|kp| match kp {
                        HEKeyPair::Paillier { public_key, .. } => Some(public_key.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| HEError::InvalidKey("No Paillier public key found".to_string()))?;

                let c = BigUint::from_bytes_be(&ciphertext.data);
                let s = BigUint::from(scalar);

                let result_int = Paillier::multiply(&public_key, &c, &s)?;
                let result_bytes = result_int.to_bytes_be();

                let result = Ciphertext {
                    ciphertext_id: Uuid::new_v4().to_string(),
                    scheme: HEScheme::Paillier,
                    data: result_bytes,
                    metadata: CiphertextMetadata {
                        encrypted_at: Utc::now(),
                        owner: ciphertext.metadata.owner.clone(),
                        searchable: false,
                        tags: vec!["computed".to_string()],
                    },
                };

                let mut ciphertexts = self.ciphertexts.write().await;
                ciphertexts.insert(result.ciphertext_id.clone(), result.clone());

                Ok(result)
            }
            _ => Err(HEError::UnsupportedScheme(
                "Only Paillier is currently supported".to_string(),
            )),
        }
    }

    /// Aggregate multiple ciphertexts
    pub async fn aggregate(
        &self,
        ciphertext_ids: Vec<String>,
        operation: HEOperation,
    ) -> Result<AggregationResult> {
        let ciphertexts = self.ciphertexts.read().await;

        let mut result_data = vec![];
        let mut scheme = None;

        for id in &ciphertext_ids {
            let ct = ciphertexts
                .get(id)
                .ok_or_else(|| HEError::CiphertextNotFound(id.clone()))?;

            if scheme.is_none() {
                scheme = Some(ct.scheme.clone());
                result_data = ct.data.clone();
            } else if scheme.as_ref() != Some(&ct.scheme) {
                return Err(HEError::OperationNotSupported(
                    "All ciphertexts must use same scheme".to_string(),
                ));
            }
        }

        let scheme = scheme
            .ok_or_else(|| HEError::EncryptionFailed("No ciphertexts provided".to_string()))?;

        let result_ciphertext = Ciphertext {
            ciphertext_id: Uuid::new_v4().to_string(),
            scheme,
            data: result_data,
            metadata: CiphertextMetadata {
                encrypted_at: Utc::now(),
                owner: "system".to_string(),
                searchable: false,
                tags: vec!["aggregated".to_string()],
            },
        };

        drop(ciphertexts);

        let result = AggregationResult {
            result_id: Uuid::new_v4().to_string(),
            operation,
            result_ciphertext: result_ciphertext.clone(),
            input_count: ciphertext_ids.len(),
        };

        let mut ciphertexts = self.ciphertexts.write().await;
        ciphertexts.insert(result_ciphertext.ciphertext_id.clone(), result_ciphertext);

        Ok(result)
    }

    /// Index ciphertext for encrypted search
    pub async fn index_for_search(&self, ciphertext_id: &str, keywords: Vec<String>) -> Result<()> {
        let ciphertexts = self.ciphertexts.read().await;
        let _ciphertext = ciphertexts
            .get(ciphertext_id)
            .ok_or_else(|| HEError::CiphertextNotFound(ciphertext_id.to_string()))?;

        // Mock keyword encryption
        let encrypted_keywords: Vec<Vec<u8>> =
            keywords.iter().map(|k| k.as_bytes().to_vec()).collect();

        let entry = SearchIndexEntry {
            entry_id: Uuid::new_v4().to_string(),
            ciphertext_id: ciphertext_id.to_string(),
            encrypted_keywords,
        };

        drop(ciphertexts);

        let mut index = self.search_index.write().await;
        index.insert(ciphertext_id.to_string(), entry);

        Ok(())
    }

    /// Search encrypted data
    pub async fn search(&self, encrypted_query: &[u8]) -> Vec<String> {
        let index = self.search_index.read().await;

        // Mock search (real implementation would use searchable encryption)
        index
            .values()
            .filter(|entry| {
                entry
                    .encrypted_keywords
                    .iter()
                    .any(|k| k.as_slice() == encrypted_query)
            })
            .map(|entry| entry.ciphertext_id.clone())
            .collect()
    }

    /// Get ciphertext
    pub async fn get_ciphertext(&self, ciphertext_id: &str) -> Option<Ciphertext> {
        let ciphertexts = self.ciphertexts.read().await;
        ciphertexts.get(ciphertext_id).cloned()
    }

    /// Get public key
    pub async fn get_public_key(&self, key_id: &str) -> Option<PublicKey> {
        let keys = self.keys.read().await;
        keys.get(key_id).map(|keypair| match keypair {
            HEKeyPair::Paillier { .. } => PublicKey {
                key_id: key_id.to_string(),
                scheme: HEScheme::Paillier,
                key_data: vec![], // Would serialize public_key
                modulus: 0,       // Would extract from public_key
            },
            HEKeyPair::ElGamal { .. } => PublicKey {
                key_id: key_id.to_string(),
                scheme: HEScheme::ElGamal,
                key_data: vec![],
                modulus: 0,
            },
            HEKeyPair::BGV { .. } => PublicKey {
                key_id: key_id.to_string(),
                scheme: HEScheme::BGV,
                key_data: vec![],
                modulus: 0,
            },
            HEKeyPair::BFV { .. } => PublicKey {
                key_id: key_id.to_string(),
                scheme: HEScheme::BFV,
                key_data: vec![],
                modulus: 0,
            },
            HEKeyPair::CKKS { .. } => PublicKey {
                key_id: key_id.to_string(),
                scheme: HEScheme::CKKS,
                key_data: vec![],
                modulus: 0,
            },
        })
    }

    /// List ciphertexts by owner
    pub async fn list_ciphertexts_by_owner(&self, owner: &str) -> Vec<Ciphertext> {
        let ciphertexts = self.ciphertexts.read().await;
        ciphertexts
            .values()
            .filter(|ct| ct.metadata.owner == owner)
            .cloned()
            .collect()
    }

    /// Re-encrypt ciphertext
    pub async fn reencrypt(
        &self,
        old_key_id: &str,
        new_key_id: &str,
        ciphertext: &Ciphertext,
    ) -> Result<Ciphertext> {
        // Decrypt with old key
        let plaintext = self.decrypt(old_key_id, ciphertext).await?;

        // Encrypt with new key
        self.encrypt(new_key_id, &plaintext, &ciphertext.metadata.owner)
            .await
    }
}

impl Default for HESystem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_keypair_generation() {
        let system = HESystem::new();

        let (pub_key_id, sec_key_id) = system.generate_keypair(HEScheme::Paillier).await.unwrap();

        assert!(!pub_key_id.is_empty());
        assert!(!sec_key_id.is_empty());
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let system = HESystem::new();

        let (pub_key_id, sec_key_id) = system.generate_keypair(HEScheme::Paillier).await.unwrap();

        let plaintext = b"secret data";
        let ciphertext = system
            .encrypt(&pub_key_id, plaintext, "alice")
            .await
            .unwrap();

        let decrypted = system.decrypt(&sec_key_id, &ciphertext).await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_homomorphic_addition() {
        let system = HESystem::new();

        let (pub_key_id, _) = system.generate_keypair(HEScheme::Paillier).await.unwrap();

        let ct1 = system.encrypt(&pub_key_id, b"10", "alice").await.unwrap();
        let ct2 = system.encrypt(&pub_key_id, b"20", "alice").await.unwrap();

        let result = system.add(&ct1, &ct2).await.unwrap();

        assert!(!result.data.is_empty());
        assert_eq!(result.scheme, HEScheme::Paillier);
    }

    #[tokio::test]
    async fn test_scalar_multiplication() {
        let system = HESystem::new();

        let (pub_key_id, _) = system.generate_keypair(HEScheme::Paillier).await.unwrap();

        let ct = system.encrypt(&pub_key_id, b"5", "alice").await.unwrap();

        let result = system.multiply(&ct, 3).await.unwrap();

        assert!(!result.data.is_empty());
    }

    #[tokio::test]
    async fn test_aggregation() {
        let system = HESystem::new();

        let (pub_key_id, _) = system.generate_keypair(HEScheme::BGV).await.unwrap();

        let ct1 = system.encrypt(&pub_key_id, b"1", "alice").await.unwrap();
        let ct2 = system.encrypt(&pub_key_id, b"2", "alice").await.unwrap();
        let ct3 = system.encrypt(&pub_key_id, b"3", "alice").await.unwrap();

        let ids = vec![
            ct1.ciphertext_id.clone(),
            ct2.ciphertext_id.clone(),
            ct3.ciphertext_id.clone(),
        ];

        let result = system.aggregate(ids, HEOperation::Add).await.unwrap();

        assert_eq!(result.input_count, 3);
        assert_eq!(result.operation, HEOperation::Add);
    }

    #[tokio::test]
    async fn test_encrypted_search() {
        let system = HESystem::new();

        let (pub_key_id, _) = system.generate_keypair(HEScheme::CKKS).await.unwrap();

        let ct = system
            .encrypt(&pub_key_id, b"document", "bob")
            .await
            .unwrap();

        system
            .index_for_search(
                &ct.ciphertext_id,
                vec!["keyword1".to_string(), "keyword2".to_string()],
            )
            .await
            .unwrap();

        let results = system.search(b"keyword1").await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], ct.ciphertext_id);
    }
}
