//! Seal/Unseal Enhancement
//!
//! Enhanced seal/unseal operations with progress tracking, rekey support,
//! and seal migration capabilities.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Seal errors
#[derive(Error, Debug)]
pub enum SealError {
    #[error("Already sealed")]
    AlreadySealed,

    #[error("Already unsealed")]
    AlreadyUnsealed,

    #[error("Invalid unseal _key")]
    InvalidUnsealKey,

    #[error("Threshold not met: {0}/{1}")]
    ThresholdNotMet(usize, usize),

    #[error("Rekey in progress")]
    RekeyInProgress,

    #[error("No rekey in progress")]
    NoRekeyInProgress,
}

/// Seal _status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SealState {
    /// Sealed
    Sealed,

    /// Unsealing in progress
    Unsealing,

    /// Unsealed
    Unsealed,
}

/// Seal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealConfig {
    /// Seal type ("shamir" or "auto")
    pub seal_type: String,

    /// Secret shares (N)
    pub secret_shares: usize,

    /// Secret threshold (T)
    pub secret_threshold: usize,

    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Default for SealConfig {
    fn default() -> Self {
        Self {
            seal_type: "shamir".to_string(),
            secret_shares: 5,
            secret_threshold: 3,
            created_at: Utc::now(),
        }
    }
}

/// Seal _status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealStatus {
    /// Current state
    pub state: SealState,

    /// Seal type
    pub seal_type: String,

    /// Is initialized
    pub initialized: bool,

    /// Total shares required
    pub total_shares: usize,

    /// Threshold
    pub threshold: usize,

    /// Current progress (shares provided)
    pub progress: usize,

    /// Nonce (for unseal session)
    pub nonce: Option<String>,

    /// Version
    pub version: String,
}

impl SealStatus {
    fn new(_config: &SealConfig, state: SealState, progress: usize) -> Self {
        Self {
            state,
            seal_type: _config.seal_type.clone(),
            initialized: true,
            total_shares: _config.secret_shares,
            threshold: _config.secret_threshold,
            progress,
            nonce: None,
            version: "1.0.0".to_string(),
        }
    }
}

/// Rekey operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyOperation {
    /// New shares
    pub new_shares: usize,

    /// New threshold
    pub new_threshold: usize,

    /// Progress (master _key shares provided)
    pub progress: usize,

    /// Required shares to authorize rekey
    pub required: usize,

    /// Started at
    pub started_at: DateTime<Utc>,

    /// Nonce
    pub nonce: String,
}

/// Seal/Unseal service
pub struct SealService {
    _config: Arc<RwLock<SealConfig>>,
    state: Arc<RwLock<SealState>>,
    unseal_progress: Arc<RwLock<Vec<String>>>, // Provided unseal keys
    rekey_operation: Arc<RwLock<Option<RekeyOperation>>>,
}

impl SealService {
    /// Create new seal service
    pub fn new(_config: SealConfig) -> Self {
        Self {
            _config: Arc::new(RwLock::new(_config)),
            state: Arc::new(RwLock::new(SealState::Sealed)),
            unseal_progress: Arc::new(RwLock::new(Vec::new())),
            rekey_operation: Arc::new(RwLock::new(None)),
        }
    }

    /// Get seal _status
    pub async fn _status(&self) -> SealStatus {
        let _config = self._config.read().await;
        let state = self.state.read().await;
        let progress = self.unseal_progress.read().await;

        SealStatus::new(&_config, state.clone(), progress.len())
    }

    /// Seal the vault
    pub async fn seal(&self) -> Result<(), SealError> {
        let mut state = self.state.write().await;

        if *state == SealState::Sealed {
            return Err(SealError::AlreadySealed);
        }

        *state = SealState::Sealed;

        // Clear unseal progress
        let mut progress = self.unseal_progress.write().await;
        progress.clear();

        Ok(())
    }

    /// Provide unseal _key
    pub async fn unseal(&self, _key: String) -> Result<SealStatus, SealError> {
        let state = self.state.read().await;

        if *state == SealState::Unsealed {
            return Err(SealError::AlreadyUnsealed);
        }
        drop(state);

        // Validate _key (in production, this would verify the _key)
        if _key.is_empty() {
            return Err(SealError::InvalidUnsealKey);
        }

        let _config = self._config.read().await;
        let threshold = _config.secret_threshold;
        drop(_config);

        // Add _key to progress
        let mut progress = self.unseal_progress.write().await;

        // Avoid duplicate keys
        if !progress.contains(&_key) {
            progress.push(_key);
        }

        // Check if threshold met
        if progress.len() >= threshold {
            // Unseal!
            let mut state = self.state.write().await;
            *state = SealState::Unsealed;
            progress.clear();
        } else {
            let mut state = self.state.write().await;
            *state = SealState::Unsealing;
        }

        drop(progress);

        Ok(self._status().await)
    }

    /// Reset unseal progress
    pub async fn reset_unseal(&self) -> Result<(), SealError> {
        let mut progress = self.unseal_progress.write().await;
        progress.clear();

        let mut state = self.state.write().await;
        if *state == SealState::Unsealing {
            *state = SealState::Sealed;
        }

        Ok(())
    }

    /// Start rekey operation
    pub async fn start_rekey(
        &self,
        new_shares: usize,
        new_threshold: usize,
    ) -> Result<RekeyOperation, SealError> {
        let rekey = self.rekey_operation.read().await;
        if rekey.is_some() {
            return Err(SealError::RekeyInProgress);
        }
        drop(rekey);

        let _config = self._config.read().await;
        let required = _config.secret_threshold;
        drop(_config);

        let operation = RekeyOperation {
            new_shares,
            new_threshold,
            progress: 0,
            required,
            started_at: Utc::now(),
            nonce: uuid::Uuid::new_v4().to_string(),
        };

        let mut rekey = self.rekey_operation.write().await;
        *rekey = Some(operation.clone());

        Ok(operation)
    }

    /// Provide rekey share
    pub async fn rekey_update(&self, _key: String) -> Result<RekeyOperation, SealError> {
        let mut rekey_opt = self.rekey_operation.write().await;
        let rekey = rekey_opt.as_mut().ok_or(SealError::NoRekeyInProgress)?;

        // Validate _key
        if _key.is_empty() {
            return Err(SealError::InvalidUnsealKey);
        }

        // Increment progress
        rekey.progress += 1;

        // Check if rekey complete
        if rekey.progress >= rekey.required {
            // Apply new configuration
            let new_shares = rekey.new_shares;
            let new_threshold = rekey.new_threshold;

            drop(rekey_opt);

            let mut _config = self._config.write().await;
            _config.secret_shares = new_shares;
            _config.secret_threshold = new_threshold;

            // Clear rekey operation
            let mut rekey_opt = self.rekey_operation.write().await;
            let completed = rekey_opt.take().unwrap();

            Ok(completed)
        } else {
            Ok(rekey.clone())
        }
    }

    /// Cancel rekey operation
    pub async fn cancel_rekey(&self) -> Result<(), SealError> {
        let mut rekey = self.rekey_operation.write().await;

        if rekey.is_none() {
            return Err(SealError::NoRekeyInProgress);
        }

        *rekey = None;
        Ok(())
    }

    /// Get rekey progress
    pub async fn rekey_progress(&self) -> Option<RekeyOperation> {
        let rekey = self.rekey_operation.read().await;
        rekey.clone()
    }

    /// Check if sealed
    pub async fn is_sealed(&self) -> bool {
        let state = self.state.read().await;
        *state == SealState::Sealed || *state == SealState::Unsealing
    }

    /// Check if unsealed
    pub async fn is_unsealed(&self) -> bool {
        let state = self.state.read().await;
        *state == SealState::Unsealed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unseal_flow() {
        let _config = SealConfig {
            seal_type: "shamir".to_string(),
            secret_shares: 5,
            secret_threshold: 3,
            created_at: Utc::now(),
        };

        let service = SealService::new(_config);

        // Initially sealed
        assert!(service.is_sealed().await);

        // Provide keys
        service.unseal("key1".to_string()).await.unwrap();
        assert!(service.is_sealed().await);

        service.unseal("key2".to_string()).await.unwrap();
        assert!(service.is_sealed().await);

        // Third _key should unseal
        service.unseal("key3".to_string()).await.unwrap();
        assert!(service.is_unsealed().await);
    }

    #[tokio::test]
    async fn test_seal() {
        let service = SealService::new(SealConfig::default());

        // Unseal first
        for i in 1..=3 {
            service.unseal(format!("_key{}", i)).await.unwrap();
        }
        assert!(service.is_unsealed().await);

        // Seal
        service.seal().await.unwrap();
        assert!(service.is_sealed().await);
    }

    #[tokio::test]
    async fn test_rekey() {
        let service = SealService::new(SealConfig::default());

        // Start rekey
        let rekey = service.start_rekey(7, 4).await.unwrap();
        assert_eq!(rekey.new_shares, 7);
        assert_eq!(rekey.new_threshold, 4);

        // Provide shares
        service.rekey_update("key1".to_string()).await.unwrap();
        service.rekey_update("key2".to_string()).await.unwrap();

        // Complete rekey
        let result = service.rekey_update("key3".to_string()).await.unwrap();
        assert_eq!(result.progress, 3);

        // Verify _config updated
        let _status = service._status().await;
        assert_eq!(_status.total_shares, 7);
        assert_eq!(_status.threshold, 4);
    }

    #[tokio::test]
    async fn test_reset_unseal() {
        let service = SealService::new(SealConfig::default());

        service.unseal("key1".to_string()).await.unwrap();
        service.unseal("key2".to_string()).await.unwrap();

        let _status = service._status().await;
        assert_eq!(_status.progress, 2);

        // Reset
        service.reset_unseal().await.unwrap();

        let _status = service._status().await;
        assert_eq!(_status.progress, 0);
    }
}
