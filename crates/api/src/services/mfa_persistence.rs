use std::sync::Arc;
use async_trait::async_trait;
use uuid::Uuid;
use chrono::Utc;
use secreton_storage::{StorageBackend, SecretEntry, EncryptionMetadata, SecurityLevel};
use secreton_auth::mfa::{TotpService, TotpEnrollment, TotpValidationRequest, TotpConfig};
use secreton_errors::SecretonError;
use crate::services::crypto::CryptoService;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use rand::Rng;

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

pub struct PersistentTotpService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    config: TotpConfig,
}

const TOTP_PREFIX: &str = "sys/mfa/totp/";

impl PersistentTotpService {
    pub fn new(storage: Arc<dyn StorageBackend + Send + Sync>, crypto: Arc<CryptoService>, issuer: String) -> Self {
        Self {
            storage,
            crypto,
            config: TotpConfig {
                issuer,
                period: 30,
                digits: 6,
                algorithm: "SHA1".to_string(),
            },
        }
    }

    /// Generate a random secret
    fn generate_secret() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..20).map(|_| rng.r#gen()).collect(); // 20 bytes = 160 bits (standard for SHA1)

        // Minimal Base32 Encode (RFC 4648) without padding
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut result = String::new();
        let mut buffer = 0u64;
        let mut bits_left = 0;

        for byte in bytes {
            buffer = (buffer << 8) | (byte as u64);
            bits_left += 8;
            while bits_left >= 5 {
                result.push(ALPHABET[((buffer >> (bits_left - 5)) & 0x1F) as usize] as char);
                bits_left -= 5;
            }
        }
        if bits_left > 0 {
            result.push(ALPHABET[((buffer << (5 - bits_left)) & 0x1F) as usize] as char);
        }
        result
    }

    /// Generate TOTP code from secret and time
    fn generate_totp(
        secret: &str,
        time: u64,
        period: u32,
        digits: u32,
    ) -> Result<String, SecretonError> {
        // Minimal Base32 Decode
        let mut secret_bytes = Vec::new();
        let mut buffer = 0u64;
        let mut bits_left = 0;

        for c in secret.chars() {
            let val = match c {
                'A'..='Z' => c as u64 - 'A' as u64,
                'a'..='z' => c as u64 - 'a' as u64,
                '2'..='7' => c as u64 - '2' as u64 + 26,
                '=' => continue,
                _ => return Err(SecretonError::Configuration { message: "Invalid base32 char".to_string() }),
            };
            buffer = (buffer << 5) | val;
            bits_left += 5;
            if bits_left >= 8 {
                secret_bytes.push((buffer >> (bits_left - 8)) as u8);
                bits_left -= 8;
            }
        }

        let counter = time / period as u64;

        // HMAC-SHA1
        let mut mac = Hmac::<Sha1>::new_from_slice(&secret_bytes).map_err(|_| {
            SecretonError::Configuration {
                message: "Failed to create HMAC".to_string(),
            }
        })?;

        mac.update(&counter.to_be_bytes());
        let result = mac.finalize().into_bytes();

        // Dynamic truncation
        let offset = (result[19] & 0xf) as usize;
        let code = ((result[offset] & 0x7f) as u32) << 24
            | (u32::from(result[offset + 1])) << 16
            | (u32::from(result[offset + 2])) << 8
            | u32::from(result[offset + 3]);

        let modulus = 10u32.pow(digits);
        let totp = code % modulus;

        Ok(format!("{:0width$}", totp, width = digits as usize))
    }
}

#[async_trait]
impl TotpService for PersistentTotpService {
    async fn enroll(
        &self,
        entity_id: Uuid,
        account_name: String,
    ) -> Result<TotpEnrollment, SecretonError> {
        let secret = Self::generate_secret();

        let url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            self.config.issuer,
            account_name,
            secret,
            self.config.issuer,
            self.config.algorithm,
            self.config.digits,
            self.config.period
        );

        let enrollment = TotpEnrollment {
            id: Uuid::new_v4(),
            entity_id,
            secret: secret.clone(),
            url,
            creation_time: Utc::now(),
            last_used: None,
        };

        // Serialize
        let data = serde_json::to_vec(&enrollment)
            .map_err(|e| SecretonError::Internal { message: format!("Failed to serialize enrollment: {}", e) })?;

        // Encrypt data
        let encrypted_data = self.crypto.encrypt_data(&data).await
            .map_err(|e| SecretonError::Encryption { message: format!("Failed to encrypt TOTP data: {}", e) })?;

        let path = format!("{}{}", TOTP_PREFIX, entity_id);

        let entry = SecretEntry::new(
            path,
            encrypted_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            entity_id,
        );

        self.storage.store(&entry).await
            .map_err(|e| SecretonError::Database { message: format!("Failed to store enrollment: {}", e) })?;

        Ok(enrollment)
    }

    async fn validate(&self, request: TotpValidationRequest) -> Result<bool, SecretonError> {
        let path = format!("{}{}", TOTP_PREFIX, request.entity_id);

        if let Some(entry) = self.storage.get_by_path(&path).await.map_err(|e| SecretonError::Database { message: e.to_string() })? {
            // Decrypt data
            let decrypted_data = self.crypto.decrypt(&entry.encrypted_data).await
                .map_err(|e| SecretonError::Decryption { message: format!("Failed to decrypt TOTP data: {}", e) })?;

            let mut enrollment: TotpEnrollment = serde_json::from_slice(&decrypted_data)
                .map_err(|e| SecretonError::Internal { message: format!("Failed to deserialize enrollment: {}", e) })?;

            let current_time = Utc::now();
            let current_timestamp = current_time.timestamp() as u64;

            // Replay protection: Check last_used against current time window
            // Allow a small grace period or strictly check if used within the same window
            if let Some(last_used) = enrollment.last_used {
                let window_size = self.config.period as i64;
                let time_diff = current_time.signed_duration_since(last_used).num_seconds();

                // If used within the last window (or slightly more to be safe), reject.
                // A stricter check is: (current / period) <= (last_used / period)
                // If last used was in the same or future window (clock skew?), reject.
                let last_window = last_used.timestamp() / window_size;
                let current_window = current_timestamp as i64 / window_size;

                if last_window >= current_window {
                    tracing::warn!("TOTP Replay detected for user {}", request.entity_id);
                    return Ok(false);
                }
            }

            // Check current time window and adjacent windows for clock skew
            for time_offset in [-1i64, 0, 1].iter() {
                let check_time =
                    (current_timestamp as i64 + time_offset * self.config.period as i64) as u64;
                let expected_code = Self::generate_totp(
                    &enrollment.secret,
                    check_time,
                    self.config.period,
                    self.config.digits,
                )?;

                // Constant-time comparison
                if constant_time_eq(expected_code.as_bytes(), request.code.as_bytes()) {
                    // Update last used time
                    enrollment.last_used = Some(current_time);

                    let data = serde_json::to_vec(&enrollment)
                        .map_err(|e| SecretonError::Internal { message: format!("Failed to serialize enrollment: {}", e) })?;

                    // Encrypt again
                    let encrypted_data = self.crypto.encrypt_data(&data).await
                        .map_err(|e| SecretonError::Encryption { message: format!("Failed to encrypt updated TOTP data: {}", e) })?;

                    let mut updated_entry = entry.clone();
                    updated_entry.encrypted_data = encrypted_data;

                    self.storage.store(&updated_entry).await
                        .map_err(|e| SecretonError::Database { message: format!("Failed to update enrollment: {}", e) })?;

                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<TotpEnrollment>, SecretonError> {
        let path = format!("{}{}", TOTP_PREFIX, entity_id);

        if let Some(entry) = self.storage.get_by_path(&path).await.map_err(|e| SecretonError::Database { message: e.to_string() })? {
            // Decrypt data
            let decrypted_data = self.crypto.decrypt(&entry.encrypted_data).await
                .map_err(|e| SecretonError::Decryption { message: format!("Failed to decrypt TOTP data: {}", e) })?;

            let enrollment: TotpEnrollment = serde_json::from_slice(&decrypted_data)
                .map_err(|e| SecretonError::Internal { message: format!("Failed to deserialize enrollment: {}", e) })?;
            Ok(Some(enrollment))
        } else {
            Ok(None)
        }
    }

    async fn remove_enrollment(&self, entity_id: Uuid) -> Result<(), SecretonError> {
        let path = format!("{}{}", TOTP_PREFIX, entity_id);
        self.storage.delete_by_path(&path).await
            .map_err(|e| SecretonError::Database { message: format!("Failed to delete enrollment: {}", e) })?;
        Ok(())
    }
}
