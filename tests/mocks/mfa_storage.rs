use async_trait::async_trait;
use brankas_adhyaksa::{
    auth::mfa::{MfaMethod, MfaStatus, MfaStorage},
    storage::StorageError,
};
use mockall::mock;
use std::collections::HashMap;
use uuid::Uuid;

mock! {
    pub MfaStorage {}

    #[async_trait]
    impl MfaStorage for MfaStorage {
        async fn get_mfa_status(&self, user_id: &str) -> Result<MfaStatus, StorageError>;
        
        async fn save_totp_secret(
            &self,
            user_id: &str,
            secret: &str,
            issuer: &str,
        ) -> Result<(), StorageError>;
        
        async fn verify_totp_code(
            &self,
            user_id: &str,
            code: &str,
        ) -> Result<bool, StorageError>;
        
        async fn save_recovery_codes(
            &self,
            user_id: &str,
            codes: Vec<String>,
        ) -> Result<(), StorageError>;
        
        async fn verify_recovery_code(
            &self,
            user_id: &str,
            code: &str,
        ) -> Result<bool, StorageError>;
        
        async fn disable_mfa(&self, user_id: &str) -> Result<(), StorageError>;
        
        async fn get_mfa_attempts(
            &self,
            user_id: &str,
        ) -> Result<Vec<(String, i64)>, StorageError>;
        
        async fn record_mfa_attempt(
            &self,
            user_id: &str,
            code: &str,
            timestamp: i64,
        ) -> Result<(), StorageError>;
        
        async fn clear_mfa_attempts(&self, user_id: &str) -> Result<(), StorageError>;
    }
}

/// In-memory implementation of MfaStorage for testing
pub struct InMemoryMfaStorage {
    statuses: std::sync::RwLock<HashMap<String, MfaStatus>>,
    totp_secrets: std::sync::RwLock<HashMap<String, String>>,
    recovery_codes: std::sync::RwLock<HashMap<String, Vec<String>>>,
    attempts: std::sync::RwLock<HashMap<String, Vec<(String, i64)>>>,
}

impl Default for InMemoryMfaStorage {
    fn default() -> Self {
        Self {
            statuses: Default::default(),
            totp_secrets: Default::default(),
            recovery_codes: Default::default(),
            attempts: Default::default(),
        }
    }
}

#[async_trait]
impl MfaStorage for InMemoryMfaStorage {
    async fn get_mfa_status(&self, user_id: &str) -> Result<MfaStatus, StorageError> {
        self.statuses
            .read()
            .unwrap()
            .get(user_id)
            .cloned()
            .ok_or_else(|| StorageError::NotFound("MFA status not found".to_string()))
    }

    async fn save_totp_secret(
        &self,
        user_id: &str,
        secret: &str,
        _issuer: &str,
    ) -> Result<(), StorageError> {
        self.totp_secrets
            .write()
            .unwrap()
            .insert(user_id.to_string(), secret.to_string());
        
        // Update status
        let mut statuses = self.statuses.write().unwrap();
        let status = statuses.entry(user_id.to_string()).or_default();
        status.enabled = true;
        if !status.methods.contains(&MfaMethod::Totp) {
            status.methods.push(MfaMethod::Totp);
        }
        
        Ok(())
    }

    async fn verify_totp_code(
        &self,
        user_id: &str,
        code: &str,
    ) -> Result<bool, StorageError> {
        // In a real test, you would implement TOTP verification logic here
        // For testing, we'll just check if the code matches a known value
        Ok(code == "123456") // Test code
    }

    async fn save_recovery_codes(
        &self,
        user_id: &str,
        codes: Vec<String>,
    ) -> Result<(), StorageError> {
        self.recovery_codes
            .write()
            .unwrap()
            .insert(user_id.to_string(), codes);
        
        // Update status
        let mut statuses = self.statuses.write().unwrap();
        let status = statuses.entry(user_id.to_string()).or_default();
        status.recovery_codes = Some(true);
        
        Ok(())
    }

    async fn verify_recovery_code(
        &self,
        user_id: &str,
        code: &str,
    ) -> Result<bool, StorageError> {
        let codes = self.recovery_codes.read().unwrap();
        if let Some(user_codes) = codes.get(user_id) {
            Ok(user_codes.contains(&code.to_string()))
        } else {
            Ok(false)
        }
    }

    async fn disable_mfa(&self, user_id: &str) -> Result<(), StorageError> {
        self.statuses.write().unwrap().remove(user_id);
        self.totp_secrets.write().unwrap().remove(user_id);
        self.recovery_codes.write().unwrap().remove(user_id);
        self.attempts.write().unwrap().remove(user_id);
        Ok(())
    }

    async fn get_mfa_attempts(
        &self,
        user_id: &str,
    ) -> Result<Vec<(String, i64)>, StorageError> {
        Ok(self
            .attempts
            .read()
            .unwrap()
            .get(user_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn record_mfa_attempt(
        &self,
        user_id: &str,
        code: &str,
        timestamp: i64,
    ) -> Result<(), StorageError> {
        self.attempts
            .write()
            .unwrap()
            .entry(user_id.to_string())
            .or_default()
            .push((code.to_string(), timestamp));
        Ok(())
    }

    async fn clear_mfa_attempts(&self, user_id: &str) -> Result<(), StorageError> {
        self.attempts.write().unwrap().remove(user_id);
        Ok(())
    }
}
