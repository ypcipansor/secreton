//! Transit key management with RustCrypto integration
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use p256::{SecretKey as P256SecretKey, PublicKey as P256PublicKey, ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey}};
use k256::{SecretKey as K256SecretKey, PublicKey as K256PublicKey, ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey}};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey, Signature as Ed25519Signature};
use x25519_dalek::{EphemeralSecret as X25519Secret, PublicKey as X25519PublicKey};
use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use signature::{Signer, Verifier};

use crate::error::{CryptoResult, CryptoError};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{RngCore, CryptoRng};

// RustCrypto imports
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit, generic_array::GenericArray}};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, Key as ChaChaKey, XNonce};
use p256::{SecretKey as P256SecretKey, PublicKey as P256PublicKey, ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey}};
use k256::{SecretKey as K256SecretKey, PublicKey as K256PublicKey, ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey}};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey, Signature as Ed25519Signature};
use x25519_dalek::{StaticSecret as X25519Secret, PublicKey as X25519PublicKey};
use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};
use digest::Digest;

/// Supported key types for the transit engine
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    /// AES-256-GCM symmetric encryption
    Aes256Gcm,
    /// ChaCha20-Poly1305 symmetric encryption
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305 symmetric encryption (extended nonce)
    XChaCha20Poly1305,
    /// ECDSA key using P-256 curve
    EcdsaP256,
    /// ECDSA key using secp256k1 curve
    EcdsaSecp256k1,
    /// Ed25519 key for signing (recommended for most use cases)
    Ed25519,
    /// X25519 key for key exchange
    X25519,
}

/// Key derivation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyOptions {
    /// Whether key can be exported (default: false)
    pub exportable: bool,
    /// Key usage constraints
    pub usage: Vec<KeyUsage>,
    /// Minimum key version for decryption (default: 1)
    pub min_decryption_version: u32,
    /// Whether to allow plaintext backup (default: false) 
    pub allow_plaintext_backup: bool,
    /// Key derivation context if applicable
    pub context: Option<Vec<u8>>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Default for KeyOptions {
    fn default() -> Self {
        Self {
            exportable: false,
            usage: vec![KeyUsage::Encrypt, KeyUsage::Decrypt],
            min_decryption_version: 1,
            allow_plaintext_backup: false,
            context: None,
            metadata: HashMap::new(),
        }
    }
}

/// Key usage constraints
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyUsage {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Derive,
}

/// Signature algorithms supported
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Ed25519 (recommended for most use cases)
    Ed25519,
    /// ECDSA with SHA-256 (P-256)
    EcdsaP256Sha256,
    /// ECDSA with SHA-512 (P-384)
    EcdsaP384Sha384,
    /// ECDSA with SHA-256 (secp256k1)
    EcdsaSecp256k1Sha256,
}

/// Transit key with versioning and RustCrypto backends
#[derive(Debug)]
pub struct TransitKey {
    /// Key name
    name: String,
    /// Key type
    key_type: KeyType,
    /// Key options
    options: KeyOptions,
    /// Key versions (version -> key material)
    versions: HashMap<u32, KeyVersion>,
    /// Latest version number
    latest_version: u32,
    /// Creation time
    created_at: DateTime<Utc>,
    /// Last rotation time
    last_rotated_at: Option<DateTime<Utc>>,
}

/// Individual key version with cryptographic material
#[derive(Debug, ZeroizeOnDrop)]
struct KeyVersion {
    /// Version number
    version: u32,
    /// Key material (zeroized on drop)
    material: KeyMaterial,
    /// Creation time
    created_at: DateTime<Utc>,
}

/// Cryptographic key material (zeroized on drop)
#[derive(Debug, ZeroizeOnDrop)]
enum KeyMaterial {
    /// AES-256-GCM key
    Aes256Gcm(Box<[u8; 32]>),
    /// ChaCha20-Poly1305 key
    ChaCha20Poly1305(Box<[u8; 32]>),
    /// XChaCha20-Poly1305 key (extended nonce)
    XChaCha20Poly1305(Box<[u8; 32]>),
    /// ECDSA P-256 private key with public key
    EcdsaP256(Box<P256SecretKey>, Box<P256PublicKey>),
    /// ECDSA secp256k1 private key with public key
    EcdsaSecp256k1(Box<K256SecretKey>, Box<K256PublicKey>),
    /// Ed25519 signing key with verifying key (recommended for most use cases)
    Ed25519(Box<Ed25519SigningKey>, Box<Ed25519VerifyingKey>),
    /// X25519 key for key exchange
    X25519(Box<X25519Secret>),
}

impl TransitKey {
    /// Create a new transit key
    pub fn new(name: String, key_type: KeyType, options: KeyOptions) -> CryptoResult<Self> {
        let version = KeyVersion::new(1, &key_type)?;
        let mut versions = HashMap::new();
        versions.insert(1, version);
        
        Ok(Self {
            name,
            key_type,
            options,
            versions,
            latest_version: 1,
            created_at: Utc::now(),
            last_rotated_at: None,
        })
    }
    
    /// Rotate key (create new version)
    pub fn rotate(&mut self) -> CryptoResult<u32> {
        let new_version = self.latest_version + 1;
        let version = KeyVersion::new(new_version, &self.key_type)?;
        
        self.versions.insert(new_version, version);
        self.latest_version = new_version;
        self.last_rotated_at = Some(Utc::now());
        
        Ok(new_version)
    }
    
    /// Get key information
    pub fn info(&self) -> KeyInfo {
        KeyInfo {
            name: self.name.clone(),
            key_type: self.key_type.clone(),
            latest_version: self.latest_version,
            min_decryption_version: self.options.min_decryption_version,
            created_at: self.created_at,
            last_rotated_at: self.last_rotated_at,
            versions: self.versions.keys().copied().collect(),
            usage: self.options.usage.clone(),
            exportable: self.options.exportable,
        }
    }
    
    /// Encrypt data
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        context: Option<&[u8]>,
        key_version: Option<u32>,
    ) -> CryptoResult<String> {
        let version = key_version.unwrap_or(self.latest_version);
        let key_version = self.versions.get(&version)
            .ok_or_else(|| CryptoError::KeyVersionNotFound(version))?;
        
        // Check if encrypt usage is allowed
        if !self.options.usage.contains(&KeyUsage::Encrypt) {
            return Err(CryptoError::InvalidUsage("Encryption not allowed for this key".to_string()));
        }
        
        let ciphertext = match &key_version.material {
            KeyMaterial::Aes256Gcm(key_bytes) => {
                let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
                let cipher = Aes256Gcm::new(key);
                
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                let mut payload = plaintext.to_vec();
                if let Some(ctx) = context {
                    payload.extend_from_slice(ctx);
                }
                
                let encrypted = cipher.encrypt(nonce, payload.as_slice())
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                
                // Format: version:nonce:ciphertext
                let mut result = format!("v{}:", version);
                result.push_str(&base64::encode(&nonce_bytes));
                result.push(':');
                result.push_str(&base64::encode(&encrypted));
                result
            }
            
            KeyMaterial::ChaCha20Poly1305(key_bytes) => {
                let key = chacha20poly1305::Key::from_slice(key_bytes.as_slice());
                let cipher = ChaCha20Poly1305::new(key);
                
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                
                let mut payload = plaintext.to_vec();
                if let Some(ctx) = context {
                    payload.extend_from_slice(ctx);
                }
                
                let encrypted = cipher.encrypt(nonce, payload.as_slice())
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                
                let mut result = format!("v{}:", version);
                result.push_str(&base64::encode(&nonce_bytes));
                result.push(':');
                result.push_str(&base64::encode(&encrypted));
                result
            }
            
            KeyMaterial::XChaCha20Poly1305(key_bytes) => {
                let key = chacha20poly1305::Key::from_slice(key_bytes.as_slice());
                let cipher = XChaCha20Poly1305::new(key);
                
                let mut nonce_bytes = [0u8; 24]; // XChaCha20 uses 192-bit nonce
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
                
                let mut payload = plaintext.to_vec();
                if let Some(ctx) = context {
                    payload.extend_from_slice(ctx);
                }
                
                let encrypted = cipher.encrypt(nonce, payload.as_slice())
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                
                let mut result = format!("v{}:", version);
                result.push_str(&base64::encode(&nonce_bytes));
                result.push(':');
                result.push_str(&base64::encode(&encrypted));
                result
            }
            
            KeyMaterial::Rsa(private_key) => {
                let public_key = RsaPublicKey::from(private_key.as_ref());
                let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
                
                let encrypted = public_key.encrypt(&mut rand::thread_rng(), padding, plaintext)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                
                let mut result = format!("v{}:", version);
                result.push_str(&base64::encode(&encrypted));
                result
            }
            
            _ => {
                return Err(CryptoError::InvalidUsage("Key type does not support encryption".to_string()));
            }
        };
        
        Ok(ciphertext)
    }
    
    /// Decrypt data
    pub fn decrypt(&self, ciphertext: &str, context: Option<&[u8]>) -> CryptoResult<Vec<u8>> {
        // Parse format: v<version>:<nonce>:<ciphertext> or v<version>:<ciphertext>
        let parts: Vec<&str> = ciphertext.split(':').collect();
        if parts.len() < 2 {
            return Err(CryptoError::InvalidCiphertext("Invalid format".to_string()));
        }
        
        // Extract version
        let version_str = parts[0].strip_prefix('v')
            .ok_or_else(|| CryptoError::InvalidCiphertext("Missing version prefix".to_string()))?;
        let version: u32 = version_str.parse()
            .map_err(|_| CryptoError::InvalidCiphertext("Invalid version".to_string()))?;
        
        // Check minimum decryption version
        if version < self.options.min_decryption_version {
            return Err(CryptoError::InvalidUsage("Key version too old for decryption".to_string()));
        }
        
        let key_version = self.versions.get(&version)
            .ok_or_else(|| CryptoError::KeyVersionNotFound(version))?;
        
        // Check if decrypt usage is allowed
        if !self.options.usage.contains(&KeyUsage::Decrypt) {
            return Err(CryptoError::InvalidUsage("Decryption not allowed for this key".to_string()));
        }
        
        let plaintext = match &key_version.material {
            KeyMaterial::Aes256Gcm(key_bytes) => {
                if parts.len() != 3 {
                    return Err(CryptoError::InvalidCiphertext("Invalid AES-GCM format".to_string()));
                }
                
                let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
                let cipher = Aes256Gcm::new(key);
                
                let nonce_bytes = base64::decode(parts[1])
                    .map_err(|_| CryptoError::InvalidCiphertext("Invalid nonce encoding".to_string()))?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                let encrypted_bytes = base64::decode(parts[2])
                    .map_err(|_| CryptoError::InvalidCiphertext("Invalid ciphertext encoding".to_string()))?;
                
                let mut decrypted = cipher.decrypt(nonce, encrypted_bytes.as_slice())
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                
                // Remove context if present
                if let Some(ctx) = context {
                    if decrypted.len() >= ctx.len() && decrypted.ends_with(ctx) {
                        decrypted.truncate(decrypted.len() - ctx.len());
                    }
                }
                
                decrypted
            }
            
            KeyMaterial::ChaCha20Poly1305(key_bytes) => {
                if parts.len() != 3 {
                    return Err(CryptoError::InvalidCiphertext("Invalid ChaCha20Poly1305 format".to_string()));
                }
                
                let key = chacha20poly1305::Key::from_slice(key_bytes.as_slice());
                let cipher = ChaCha20Poly1305::new(key);
                
                let nonce_bytes = base64::decode(parts[1])
                    .map_err(|_| CryptoError::InvalidCiphertext("Invalid nonce encoding".to_string()))?;
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                
                let encrypted_bytes = base64::decode(parts[2])
                    .map_err(|_| CryptoError::InvalidCiphertext("Invalid ciphertext encoding".to_string()))?;
                
                let mut decrypted = cipher.decrypt(nonce, encrypted_bytes.as_slice())
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                
                // Remove context if present
                if let Some(ctx) = context {
                    if decrypted.len() >= ctx.len() && decrypted.ends_with(ctx) {
                        decrypted.truncate(decrypted.len() - ctx.len());
                    }
                }
                
                decrypted
            }
            
            KeyMaterial::Rsa(private_key) => {
                if parts.len() != 2 {
                    return Err(CryptoError::InvalidCiphertext("Invalid RSA format".to_string()));
                }
                
                let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
                let encrypted_bytes = base64::decode(parts[1])
                    .map_err(|_| CryptoError::InvalidCiphertext("Invalid ciphertext encoding".to_string()))?;
                
                private_key.decrypt(padding, &encrypted_bytes)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?
            }
            
            _ => {
                return Err(CryptoError::InvalidUsage("Key type does not support decryption".to_string()));
            }
        };
        
        Ok(plaintext)
    }
    
    /// Sign data
    pub fn sign(
        &self,
        data: &[u8],
        algorithm: Option<SignatureAlgorithm>,
        key_version: Option<u32>,
    ) -> CryptoResult<String> {
        let version = key_version.unwrap_or(self.latest_version);
        let key_version = self.versions.get(&version)
            .ok_or_else(|| CryptoError::KeyVersionNotFound(version))?;
        
        // Check if sign usage is allowed
        if !self.options.usage.contains(&KeyUsage::Sign) {
            return Err(CryptoError::InvalidUsage("Signing not allowed for this key".to_string()));
        }
        
        match &key_version.material {
        KeyMaterial::Ed25519(signing_key) => {
            let signature = signing_key.sign(data);
            Ok(format!("v{}:{}", version, BASE64.encode(signature.to_bytes())))
        }
        _ => Err(CryptoError::InvalidUsage("Key type does not support signing".to_string()))
    }
    
    let encrypted = cipher.encrypt(nonce, payload.as_slice())
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    
    let mut result = format!("v{}:", version);
    result.push_str(&base64::encode(&nonce_bytes));
    result.push(':');
    result.push_str(&base64::encode(&encrypted));
    result
}

KeyMaterial::XChaCha20Poly1305(key_bytes) => {
    let key = chacha20poly1305::Key::from_slice(key_bytes.as_slice());
    let cipher = XChaCha20Poly1305::new(key);
    
    let mut nonce_bytes = [0u8; 24]; // XChaCha20 uses 192-bit nonce
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    
    let mut payload = plaintext.to_vec();
    if let Some(ctx) = context {
        payload.extend_from_slice(ctx);
    }
    
    let encrypted = cipher.encrypt(nonce, payload.as_slice())
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    
    let mut result = format!("v{}:", version);
    result.push_str(&base64::encode(&nonce_bytes));
    result.push(':');
    result.push_str(&base64::encode(&encrypted));
    result
}

KeyMaterial::Ed25519(signing_key) => {
    let signature = signing_key.sign(plaintext);
    let mut result = format!("v{}:", version);
    result.push_str(&base64::encode(&signature.to_bytes()));
    result
}

_ => {
    return Err(CryptoError::InvalidUsage("Key type does not support encryption".to_string()));
}
};

Ok(ciphertext)

/// Decrypt data
pub fn decrypt(&self, ciphertext: &str, context: Option<&[u8]>) -> CryptoResult<Vec<u8>> {
    // Parse format: v<version>:<nonce>:<ciphertext> or v<version>:<ciphertext>
    let parts: Vec<&str> = ciphertext.split(':').collect();
    if parts.len() < 2 {
        return Err(CryptoError::InvalidCiphertext("Invalid format".to_string()));
    }
    
    // Extract version
    let version_str = parts[0].strip_prefix('v')
        .ok_or_else(|| CryptoError::InvalidCiphertext("Missing version prefix".to_string()))?;
    let version: u32 = version_str.parse()
        .map_err(|_| CryptoError::InvalidCiphertext("Invalid version".to_string()))?;
    
    // Check minimum decryption version
    if version < self.options.min_decryption_version {
        return Err(CryptoError::InvalidUsage("Key version too old for decryption".to_string()));
    }
    
    let key_version = self.versions.get(&version)
        .ok_or_else(|| CryptoError::KeyVersionNotFound(version))?;
    
    // Check if decrypt usage is allowed
    if !self.options.usage.contains(&KeyUsage::Decrypt) {
        return Err(CryptoError::InvalidUsage("Decryption not allowed for this key".to_string()));
    }
    
    let plaintext = match &key_version.material {
        KeyMaterial::Aes256Gcm(key_bytes) => {
            if parts.len() != 3 {
                return Err(CryptoError::InvalidCiphertext("Invalid AES-GCM format".to_string()));
            }
            
            let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
            let cipher = Aes256Gcm::new(key);
            
            let nonce_bytes = base64::decode(parts[1])
                .map_err(|_| CryptoError::InvalidCiphertext("Invalid nonce encoding".to_string()))?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            
            let encrypted_bytes = base64::decode(parts[2])
                .map_err(|_| CryptoError::InvalidCiphertext("Invalid ciphertext encoding".to_string()))?;
            
            let mut decrypted = cipher.decrypt(nonce, encrypted_bytes.as_slice())
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            
            // Remove context if present
            if let Some(ctx) = context {
                if decrypted.len() >= ctx.len() && decrypted.ends_with(ctx) {
                    decrypted.truncate(decrypted.len() - ctx.len());
                }
            }
            
            decrypted
        }
        
        KeyMaterial::ChaCha20Poly1305(key_bytes) => {
            if parts.len() != 3 {
                return Err(CryptoError::InvalidCiphertext("Invalid ChaCha20Poly1305 format".to_string()));
            }
            
            let key = chacha20poly1305::Key::from_slice(key_bytes.as_slice());
            let cipher = ChaCha20Poly1305::new(key);
            
            let nonce_bytes = base64::decode(parts[1])
                .map_err(|_| CryptoError::InvalidCiphertext("Invalid nonce encoding".to_string()))?;
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            
            let encrypted_bytes = base64::decode(parts[2])
                .map_err(|_| CryptoError::InvalidCiphertext("Invalid ciphertext encoding".to_string()))?;
            
            let mut decrypted = cipher.decrypt(nonce, encrypted_bytes.as_slice())
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            
            // Remove context if present
            if let Some(ctx) = context {
                if decrypted.len() >= ctx.len() && decrypted.ends_with(ctx) {
                    decrypted.truncate(decrypted.len() - ctx.len());
                }
            }
            
            decrypted
        }
        
        KeyMaterial::Ed25519(_) => {
            if parts.len() != 2 {
                return Err(CryptoError::InvalidCiphertext("Invalid Ed25519 format".to_string()));
            }
            
            let signature_bytes = base64::decode(parts[1])
                .map_err(|_| CryptoError::InvalidCiphertext("Invalid signature encoding".to_string()))?;
            let signature = Ed25519Signature::from_slice(&signature_bytes)
                .map_err(|_| CryptoError::InvalidCiphertext("Invalid Ed25519 signature".to_string()))?;
            
            // Verify signature
            let verifying_key = key_version.material.verifying_key();
            if !verifying_key.verify(plaintext, &signature).is_ok() {
                return Err(CryptoError::InvalidCiphertext("Invalid signature".to_string()));
            }
            
            plaintext.to_vec()
        }
        
        _ => {
            return Err(CryptoError::InvalidUsage("Key type does not support decryption".to_string()));
        }
    };
    
    Ok(plaintext)
}

/// Sign data
pub fn sign(
    &self,
    data: &[u8],
    algorithm: Option<SignatureAlgorithm>,
    key_version: Option<u32>,
) -> CryptoResult<String> {
    let version = key_version.unwrap_or(self.latest_version);
    let key_version = self.versions.get(&version)
        .ok_or_else(|| CryptoError::KeyVersionNotFound(version))?;
    
    // Check if sign usage is allowed
    if !self.options.usage.contains(&KeyUsage::Sign) {
        return Err(CryptoError::InvalidUsage("Signing not allowed for this key".to_string()));
    }
    
    let signature = match &key_version.material {
        KeyMaterial::Ed25519(signing_key, _) => {
            let signature = signing_key.sign(data);
            base64::encode(&signature.to_bytes())
        }
        
        KeyMaterial::EcdsaP256(private_key, _) => {
            let signing_key = P256SigningKey::from_bytes(private_key.to_bytes().as_slice())
                .map_err(|e| CryptoError::SigningError(e.to_string()))?;
            let signature: p256::ecdsa::Signature = signing_key.sign(data);
            base64::encode(signature.to_der())
        }
        
        KeyMaterial::EcdsaSecp256k1(private_key, _) => {
            let signing_key = K256SigningKey::from_bytes(private_key.to_bytes().as_slice())
                .map_err(|e| CryptoError::SigningError(e.to_string()))?;
            let signature: k256::ecdsa::Signature = signing_key.sign(data);
            base64::encode(signature.to_der())
        }
        
        _ => {
            return Err(CryptoError::InvalidUsage("Key type does not support signing".to_string()));
        }
    };
    
    Ok(format!("v{}:{}", version, signature))
}

/// Verify signature using the specified algorithm
pub fn verify(
    &self,
    data: &[u8],
    signature_str: &str,
    algorithm: Option<SignatureAlgorithm>,
) -> CryptoResult<bool> {
    // Parse version and signature
    let parts: Vec<&str> = signature_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(CryptoError::InvalidInput("Invalid signature format".to_string()));
    }
    
    let version_str = parts[0].trim_start_matches('v');
    let version = version_str.parse::<u32>()
        .map_err(|_| CryptoError::InvalidInput("Invalid version in signature".to_string()))?;
    
    let signature_bytes = base64::decode(parts[1])
        .map_err(|e| CryptoError::InvalidInput(format!("Invalid base64 in signature: {}", e)))?;
    
    let key_version = self.versions.get(&version)
        .ok_or_else(|| CryptoError::KeyVersionNotFound(version))?;
    
    // Check if verify usage is allowed
    if !self.options.usage.contains(&KeyUsage::Verify) {
        return Err(CryptoError::InvalidUsage("Verification not allowed for this key".to_string()));
    }
    
    let is_valid = match &key_version.material {
        KeyMaterial::Ed25519(_, public_key) => {
            let signature = Ed25519Signature::from_slice(&signature_bytes)
                .map_err(|_| CryptoError::InvalidInput("Invalid Ed25519 signature".to_string()))?;
            public_key.verify_strict(data, &signature).is_ok()
        }
        
        KeyMaterial::EcdsaP256(private_key, _) => {
            // For ECDSA, we can derive the public key from the private key
            let signing_key = P256SigningKey::from_bytes(private_key.as_slice())
                .map_err(|e| CryptoError::InvalidKey(format!("Invalid P-256 private key: {}", e)))?;
            let verifying_key = signing_key.verifying_key();
                
            let signature = p256::ecdsa::Signature::from_der(&signature_bytes)
                .or_else(|_| p256::ecdsa::Signature::from_slice(&signature_bytes))
                .map_err(|_| CryptoError::InvalidInput("Invalid P-256 signature".to_string()))?;
                
            verifying_key.verify(data, &signature).is_ok()
        }
        
        KeyMaterial::EcdsaSecp256k1(private_key, _) => {
            // For ECDSA, we can derive the public key from the private key
            let signing_key = K256SigningKey::from_bytes(private_key.as_slice())
                .map_err(|e| CryptoError::InvalidKey(format!("Invalid secp256k1 private key: {}", e)))?;
            let verifying_key = signing_key.verifying_key();
                
            let signature = k256::ecdsa::Signature::from_der(&signature_bytes)
                .or_else(|_| k256::ecdsa::Signature::from_slice(&signature_bytes))
                .map_err(|_| CryptoError::InvalidInput("Invalid secp256k1 signature".to_string()))?;
                
            verifying_key.verify(data, &signature).is_ok()
        }
        
        _ => return Err(CryptoError::InvalidUsage("Key type does not support verification".to_string())),
    };
    
    Ok(is_valid)
}

/// Derive key using HKDF
pub fn derive_key(&self, context: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    if !self.options.usage.contains(&KeyUsage::Derive) {
        return Err(CryptoError::InvalidUsage("Key derivation not allowed for this key".to_string()));
    }
    
    let key_version = self.versions.get(&self.latest_version)
        .ok_or_else(|| CryptoError::KeyVersionNotFound(self.latest_version))?;
    
    let derived_key = match &key_version.material {
        KeyMaterial::Aes256Gcm(key_bytes) => {
            let hk = Hkdf::<Sha256>::new(Some(&[]), key_bytes.as_slice());
            let mut okm = vec![0u8; length];
            hk.expand(context, &mut okm)
                .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
            okm
        }
        
        KeyMaterial::ChaCha20Poly1305(key_bytes) => {
            let hk = Hkdf::<Sha256>::new(Some(&[]), key_bytes.as_slice());
            let mut okm = vec![0u8; length];
            hk.expand(context, &mut okm)
                .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
            okm
        }
        
        _ => {
            return Err(CryptoError::InvalidUsage("Key type does not support derivation".to_string()));
        }
    };
    
    Ok(derived_key)
}

impl KeyVersion {
    /// Create new key version with random key material
    fn new(version: u32, key_type: &KeyType) -> CryptoResult<Self> {
        let material = match key_type {
            KeyType::Aes256Gcm => {
                let mut key_bytes = Box::new([0u8; 32]);
                rand::thread_rng().fill_bytes(key_bytes.as_mut());
                KeyMaterial::Aes256Gcm(key_bytes)
            }
            
            KeyType::ChaCha20Poly1305 => {
                let mut key_bytes = Box::new([0u8; 32]);
                rand::thread_rng().fill_bytes(key_bytes.as_mut());
                KeyMaterial::ChaCha20Poly1305(key_bytes)
            }
            
            KeyType::XChaCha20Poly1305 => {
                let mut key_bytes = Box::new([0u8; 32]);
                rand::thread_rng().fill_bytes(key_bytes.as_mut());
                KeyMaterial::XChaCha20Poly1305(key_bytes)
            }
            
            KeyType::Ed25519 => {
                let mut rng = rand::thread_rng();
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                let signing_key = Ed25519SigningKey::from_bytes(&seed)
                    .map_err(|e| CryptoError::KeyGenerationError(e.to_string()))?;
                let verifying_key = signing_key.verifying_key();
                KeyMaterial::Ed25519(Box::new(signing_key), Box::new(verifying_key))
            }
            
            KeyType::EcdsaP256 => {
                let secret_key = P256SecretKey::random(&mut rand::thread_rng());
                let public_key = secret_key.public_key();
                KeyMaterial::EcdsaP256(Box::new(secret_key), Box::new(public_key))
            }
            
            KeyType::EcdsaSecp256k1 => {
                let secret_key = K256SecretKey::random(&mut rand::thread_rng());
                let public_key = secret_key.public_key();
                KeyMaterial::EcdsaSecp256k1(Box::new(secret_key), Box::new(public_key))
            }
            
            
            KeyType::X25519 => {
                let secret = X25519Secret::random_from_rng(&mut rand::thread_rng());
                KeyMaterial::X25519(Box::new(secret))
            }
        };
        
        Ok(Self {
            version,
            material,
            created_at: Utc::now(),
        })
    }
}

/// Key information for external consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub name: String,
    pub key_type: KeyType,
    pub latest_version: u32,
    pub min_decryption_version: u32,
    pub created_at: DateTime<Utc>,
    pub last_rotated_at: Option<DateTime<Utc>>,
    pub versions: Vec<u32>,
    pub usage: Vec<KeyUsage>,
    pub exportable: bool,
}
