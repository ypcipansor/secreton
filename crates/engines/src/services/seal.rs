use crate::services::crypto::CryptoService;
use anyhow::{Result, anyhow};
use secreton_crypto::shamir::{self, Share};
use secreton_crypto::{AlgorithmId, EncryptedData};
use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Seal/Unseal Service
/// Manages the initialization and sealing status of the vault.
pub struct SealService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    // Set after construction (`Services::new` builds auth after seal) and used by
    // `unseal` to record the session that binds the root token it mints.
    auth: std::sync::OnceLock<Arc<crate::services::auth::AuthenticationService>>,
    // Set after construction, like `auth`. Unsealing is the one operation whose success
    // and failure both matter to a reviewer after the fact.
    audit: std::sync::OnceLock<Arc<crate::services::audit::AuditLogger>>,

    // In-memory buffer for unseal shares
    // (share_index, share_data)
    unseal_buffer: Arc<RwLock<Vec<Share>>>,

    // True once the barrier has been opened but before the root credential that grants
    // access to it has been issued. Without this the two events are indistinguishable
    // from outside, and a failure between them leaves a vault that is open and
    // unreachable with no way to ask for the credential again.
    //
    // In-process only, by design. The retry it enables works exactly as long as the root
    // key the barrier was opened with is still in memory: a restart clears that key
    // (`CryptoService::clear_root_key` on drop, and no key in the environment), so there
    // is nothing left to mint a credential from and an unseal must present shares again.
    // Persisting this flag would not change that, so it is not persisted — and every
    // message and document that describes the retry says so.
    bootstrap_pending: Arc<AtomicBool>,

    // Test-only fault injection: when set, the next bootstrap credential issuance fails
    // and the flag clears. This exists because the failure it injects is a transient one
    // (storage or token-service trouble) that cannot otherwise be triggered from a test
    // without weakening a real code path.
    #[cfg(test)]
    fail_next_bootstrap: Arc<AtomicBool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitResponse {
    pub keys: Vec<String>,        // Hex encoded shares
    pub keys_base64: Vec<String>, // Base64 encoded shares
    // Root token removed for security
    pub root_totp_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealResponse {
    pub sealed: bool,
    pub t: usize,
    pub n: usize,
    pub progress: usize,
    pub root_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InitConfig {
    shares: u8,
    threshold: u8,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedRootKey {
    data: EncryptedData,
}

const INIT_PATH: &str = "sys/init";
const ROOT_KEY_PATH: &str = "sys/root_key_enc";

/// Marker written first by `init` and removed only once every initialization artifact
/// is stored. Its presence means an earlier `init` did not finish — whether it returned
/// an error or the process died mid-way — and the next attempt must discard the partial
/// state before starting.
///
/// Initialization cannot be one storage transaction: the root account and its TOTP
/// enrollment are written by the auth and MFA services through their own storage calls,
/// and the file backend has no transactions at all. A staging marker is what makes the
/// sequence recoverable regardless of backend, without ever persisting share, root-key
/// or credential material.
const INIT_STAGING_PATH: &str = "sys/init_staging";

/// Identity of the account `init` created for root, stored beside the init config.
///
/// The init request carries a `root_username`, so hard-coding `"root"` when issuing the
/// unseal credential loses it for every deployment that chose another name: the vault
/// opens and then fails to find the account, which is a vault nobody can reach. The
/// identity is recorded here instead of assumed, and carries the account's id so the
/// lookup does not depend on the username being spelled the same way twice.
const ROOT_IDENTITY_PATH: &str = "sys/root_identity";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RootIdentity {
    id: String,
    username: String,
}

/// What a partially completed `init` records so a later attempt can clean it up.
///
/// Names the account it was about to create and, once known, that account's id — the id
/// is what locates the TOTP enrollment without decrypting anything. It deliberately holds
/// no share, token, password or key: recovery must not require storing any of those.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InitStaging {
    root_username: String,
    /// Set once the root account exists, so cleanup can find its TOTP enrollment by path.
    root_entity_id: Option<String>,
}

impl SealService {
    pub fn new(storage: Arc<dyn StorageBackend + Send + Sync>, crypto: Arc<CryptoService>) -> Self {
        Self {
            storage,
            crypto,
            auth: std::sync::OnceLock::new(),
            audit: std::sync::OnceLock::new(),
            unseal_buffer: Arc::new(RwLock::new(Vec::new())),
            bootstrap_pending: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            fail_next_bootstrap: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Hand the seal service the auth service it needs to open the root session.
    ///
    /// Assigned here rather than passed to `new` because `Services::new` constructs seal
    /// before auth; a `OnceLock` keeps that ordering honest without an `Option` that every
    /// caller has to handle. Called once at startup.
    pub fn with_auth(
        self: Arc<Self>,
        auth: Arc<crate::services::auth::AuthenticationService>,
    ) -> Arc<Self> {
        let _ = self.auth.set(auth);
        self
    }

    /// Hand the seal service the audit logger, for the same reason as [`Self::with_auth`].
    pub fn with_audit(
        self: Arc<Self>,
        audit: Arc<crate::services::audit::AuditLogger>,
    ) -> Arc<Self> {
        let _ = self.audit.set(audit);
        self
    }

    /// Whether an unseal has opened the barrier but its bootstrap credential has not been
    /// issued yet — the state from which a retried unseal can recover the credential
    /// without the shares.
    ///
    /// The retry is in-process: it holds only while the barrier is still open in this
    /// process. After a restart the root key is gone and the shares are required again.
    pub fn bootstrap_is_pending(&self) -> bool {
        self.bootstrap_pending.load(Ordering::SeqCst)
    }

    /// Check if the system is initialized
    ///
    /// The staging marker is the authority on "not finished": the init config is written
    /// before the root identity, so a crash or a cleanup that could not remove every
    /// artifact would otherwise leave a partial initialization looking permanent, and the
    /// [guard in `init`](Self::init) would refuse the retry that is meant to fix it. A
    /// marker present means the vault is treated as uninitialised regardless of what else
    /// is on disk.
    pub async fn is_initialized(&self) -> bool {
        if matches!(
            self.storage.get_by_path(INIT_STAGING_PATH).await,
            Ok(Some(_))
        ) {
            return false;
        }
        self.storage
            .get_by_path(INIT_PATH)
            .await
            .unwrap_or(None)
            .is_some()
    }

    /// Check if the system is sealed
    pub async fn is_sealed(&self) -> bool {
        !self.crypto.is_unsealed().await
    }

    /// Get current seal status
    pub async fn get_status(&self) -> Result<UnsealResponse> {
        let sealed = self.is_sealed().await;

        let (t, n) = if let Ok(Some(entry)) = self.storage.get_by_path(INIT_PATH).await {
            let config: InitConfig = serde_json::from_slice(&entry.encrypted_data)
                .map_err(|_| anyhow!("Failed to parse init config"))?;
            (config.threshold as usize, config.shares as usize)
        } else {
            (0, 0)
        };

        let progress = self.unseal_buffer.read().await.len();

        Ok(UnsealResponse {
            sealed,
            t,
            n,
            progress,
            root_token: None,
        })
    }

    /// Initialize the vault
    /// Generates Master Key, Splits it, Encrypts Root Key.
    /// Also creates the initial Root User with MFA enabled.
    ///
    /// Refactored per comment 3822469315:
    /// - Root has NO password.
    /// - Root auth is only via Unseal (SSS).
    /// - Root manages Admins.
    ///
    /// Initialization is staged so it is recoverable: a failure anywhere after the first
    /// write leaves the vault re-initialisable rather than permanently unusable. The
    /// failure that matters is the one after the init config is stored but before the
    /// shares reach the operator — the vault is not open, the shares are gone, and without
    /// staging the init config would refuse every retry.
    pub async fn init(
        &self,
        shares: u8,
        threshold: u8,
        root_username: &str,
        auth: &crate::services::auth::AuthenticationService,
        mfa: &secreton_auth::mfa::CombinedMfaService,
    ) -> Result<InitResponse> {
        // A vault that is mid-initialisation must be rolled back before the
        // already-initialised guard runs below: a partial attempt has written the init
        // config, so that guard would reject the very retry that is meant to fix it.
        self.discard_partial_initialization().await;

        // A vault that already finished initialising must not be overwritten: the root key
        // in `ROOT_KEY_PATH` is the only thing the existing shares can decrypt.
        if self.is_initialized().await {
            return Err(anyhow!("System already initialized"));
        }

        if threshold > shares {
            return Err(anyhow!("Threshold cannot be greater than shares"));
        }
        if threshold < 2 {
            return Err(anyhow!("Threshold must be at least 2"));
        }

        let outcome = self
            .initialize(shares, threshold, root_username, auth, mfa)
            .await;

        match outcome {
            Ok(response) => Ok(response),
            Err(e) => {
                // The caller gets the original error, but not before the partial state is
                // removed so the next attempt starts clean.
                self.discard_partial_initialization().await;
                Err(e)
            }
        }
    }

    /// The write sequence for a fresh initialization. Writes a staging marker first and
    /// removes it last, so its presence after this returns is the signal that the vault is
    /// mid-initialisation and must be rolled back before any retry.
    async fn initialize(
        &self,
        shares: u8,
        threshold: u8,
        root_username: &str,
        auth: &crate::services::auth::AuthenticationService,
        mfa: &secreton_auth::mfa::CombinedMfaService,
    ) -> Result<InitResponse> {
        // 1. Generate Master Key (32 bytes)
        let master_key = secreton_crypto::generate_key(AlgorithmId::Aes256Gcm)?;

        // 2. Generate Root Key (32 bytes) - The key used by CryptoService
        let root_key = secreton_crypto::generate_key(AlgorithmId::Aes256Gcm)?;

        // 3. Encrypt Root Key with Master Key
        // We use CryptoService's low-level encrypt which doesn't require unsealing
        let encrypted_root = self.crypto.encrypt(&master_key, &root_key, None)?;

        // 4. Split Master Key
        let mut rng = rand::rngs::OsRng;
        let splits = shamir::split(&master_key, threshold as usize, shares as usize, &mut rng)
            .map_err(|e| anyhow!("Shamir split failed: {}", e))?;

        // 5. Staging marker, before any durable artifact of this initialization.
        self.write_staging(&InitStaging {
            root_username: root_username.to_string(),
            root_entity_id: None,
        })
        .await?;

        // 6. Store Init Config
        let config = InitConfig { shares, threshold };
        let config_bytes = serde_json::to_vec(&config)?;

        self.storage
            .store(&SecretEntry::new(
                INIT_PATH.to_string(),
                config_bytes,
                EncryptionMetadata::default(),
                SecurityLevel::Public,
                Uuid::nil(),
            ))
            .await
            .map_err(|e| anyhow!("Failed to store init config: {}", e))?;

        // 7. Store Encrypted Root Key
        let enc_root_bytes = serde_json::to_vec(&EncryptedRootKey {
            data: encrypted_root,
        })?;
        self.storage
            .store(&SecretEntry::new(
                ROOT_KEY_PATH.to_string(),
                enc_root_bytes,
                EncryptionMetadata::default(),
                SecurityLevel::TopSecret,
                Uuid::nil(),
            ))
            .await
            .map_err(|e| anyhow!("Failed to store root key: {}", e))?;

        // 8. Format Response
        //
        // Serialise once and encode the same bytes twice. Each share was previously
        // serialised separately per encoding, with the failure discharged by `unwrap` — in
        // the one path where a panic is least recoverable, since the root key is already
        // stored by this point and a caller that never receives its unseal keys is left
        // with a vault nobody can open.
        let encoded: Vec<Vec<u8>> = splits
            .iter()
            .map(|s| {
                serde_json::to_vec(s)
                    .map_err(|e| anyhow!("Failed to serialise an unseal share: {}", e))
            })
            .collect::<Result<_>>()?;

        let keys_hex: Vec<String> = encoded.iter().map(hex::encode).collect();
        let keys_base64: Vec<String> = encoded
            .iter()
            .map(|bytes| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes))
            .collect();

        // 9. Create Root User and Enable MFA
        // We must temporarily enable the root key so Auth service can encrypt user data
        self.crypto.set_root_key(root_key.clone()).await?;

        // Root has no password. Generate a random unguessable string as placeholder password
        // because register_user expects a password. This effectively disables password login.
        let random_password = Uuid::new_v4().to_string() + &Uuid::new_v4().to_string();

        // Execute user creation and MFA setup.
        // Explicitly annotate result type to avoid inference issues with the error type.
        let result: Result<(secreton_auth::mfa::TotpEnrollment, RootIdentity), anyhow::Error> =
            async {
                let root_user = auth
                    .register_user(
                        root_username,
                        &random_password,
                        Some("root@system.local".to_string()),
                        vec!["root".to_string(), "admin".to_string()],
                        vec!["*".to_string()],
                    )
                    .await
                    .map_err(|e| anyhow!("Failed to create root user: {}", e))?;

                // Enable TOTP for Root
                // IMPORTANT: Must be done BEFORE clearing the root key because PersistentTotpService encrypts the secret!
                let user_uuid = Uuid::parse_str(&root_user.id).unwrap_or_default();
                let totp_config = mfa
                    .enable_totp(user_uuid, root_user.username.clone())
                    .await
                    .map_err(|e| anyhow!("Failed to enable TOTP for root user: {}", e))?;

                let identity = RootIdentity {
                    id: root_user.id.clone(),
                    username: root_user.username.clone(),
                };

                Ok((totp_config, identity))
            }
            .await;

        // The generated root key is no longer needed once the account records are
        // encrypted, and must not survive this call either way. Clear it before examining
        // the result so no early return can skip it.
        self.crypto.clear_root_key().await;
        let (totp_config, root_identity) = result?;

        // Record the account id in staging, so a failure between here and the identity
        // store can still find the TOTP enrollment to clean up.
        self.write_staging(&InitStaging {
            root_username: root_identity.username.clone(),
            root_entity_id: Some(root_identity.id.clone()),
        })
        .await?;

        // Persist the created root identity. Reading it back needs no key of its own — it
        // names an account, it does not authenticate one.
        let bytes = serde_json::to_vec(&root_identity)?;
        self.storage
            .store(&SecretEntry::new(
                ROOT_IDENTITY_PATH.to_string(),
                bytes,
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            ))
            .await
            .map_err(|e| anyhow!("Failed to store root identity: {}", e))?;

        // 10. Initialization is complete: remove the staging marker. Until this succeeds
        // the vault is still treated as mid-initialisation, which is why a failure here
        // rolls back rather than advertising a vault whose shares the operator never saw.
        self.storage
            .delete_by_path(INIT_STAGING_PATH)
            .await
            .map_err(|e| anyhow!("Failed to clear initialization staging marker: {}", e))?;

        tracing::info!(
            root_username = %root_identity.username,
            "Root account created. The unseal response carries its token; no password login exists."
        );

        Ok(InitResponse {
            keys: keys_hex,
            keys_base64,
            root_totp_uri: totp_config.url,
            // Secret removed for security
        })
    }

    /// Record initialization progress under [`INIT_STAGING_PATH`].
    async fn write_staging(&self, staging: &InitStaging) -> Result<()> {
        let bytes = serde_json::to_vec(staging)?;
        self.storage
            .store(&SecretEntry::new(
                INIT_STAGING_PATH.to_string(),
                bytes,
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            ))
            .await
            .map_err(|e| anyhow!("Failed to record initialization progress: {}", e))
    }

    /// Remove whatever an incomplete `init` wrote, so a retry can start from scratch.
    ///
    /// Acts only when the staging marker is present: a vault that is not mid-initialisation
    /// must not have its records touched. Individual removal failures are logged and the
    /// cleanup continues — the caller's original error is the one that matters, and a
    /// backend that refused one delete is unlikely to accept the next. The marker is the
    /// last thing removed, so an interrupted cleanup is retried rather than abandoned.
    ///
    /// Nothing here stores or logs share, token, password or key material: the marker names
    /// the account, and the account's own records are located by path.
    async fn discard_partial_initialization(&self) {
        match self.storage.get_by_path(INIT_STAGING_PATH).await {
            Ok(None) => return,
            Ok(Some(_)) => {}
            Err(e) => {
                // Without the marker's contents the account cannot be located; the durable
                // artifacts are still removed below, and the marker is left for a later
                // attempt rather than cleared blindly.
                tracing::error!(
                    "Could not read the initialization staging marker during cleanup: {}",
                    e
                );
            }
        }

        let staging = match self.storage.get_by_path(INIT_STAGING_PATH).await {
            Ok(Some(entry)) => serde_json::from_slice::<InitStaging>(&entry.encrypted_data).ok(),
            Ok(None) => return,
            Err(_) => None,
        };

        if let Some(staging) = &staging {
            if let Some(entity_id) = &staging.root_entity_id {
                let totp_path = format!(
                    "{}{}",
                    crate::services::mfa_persistence::TOTP_PREFIX,
                    entity_id
                );
                self.remove_and_report(&totp_path).await;
            }
            let user_path = format!(
                "{}{}",
                crate::services::auth::USER_STORAGE_PREFIX,
                staging.root_username
            );
            self.remove_and_report(&user_path).await;
        }

        for path in [
            ROOT_IDENTITY_PATH,
            ROOT_KEY_PATH,
            INIT_PATH,
            INIT_STAGING_PATH,
        ] {
            self.remove_and_report(path).await;
        }

        // The generated root key was installed only to encrypt the account records that
        // were just removed; a completed initialization would not leave it in place.
        self.crypto.clear_root_key().await;
    }

    async fn remove_and_report(&self, path: &str) {
        if let Err(e) = self.storage.delete_by_path(path).await {
            tracing::error!(
                "Failed to remove '{}' while cleaning up an incomplete initialization: {}",
                path,
                e
            );
        }
    }

    /// Submit a share to unseal
    pub async fn unseal(&self, share_str: &str) -> Result<UnsealResponse> {
        if !self.is_initialized().await {
            return Err(anyhow!("System not initialized"));
        }
        if !self.is_sealed().await {
            // The barrier is already open. Normally that means there is nothing to do and
            // the status is all the caller needs. But if a previous unseal opened the
            // barrier and then failed to issue the root credential, this call is the
            // retry: the root key is installed, the root identity was persisted at init,
            // and neither requires the shares that were already discarded. Answering with
            // an empty token here is what left the vault open and unreachable.
            if self.bootstrap_is_pending() {
                return self.issue_bootstrap_credential().await;
            }
            return self.get_status().await;
        }

        // Try decoding hex first, then base64
        let share_bytes = if let Ok(b) = hex::decode(share_str) {
            b
        } else {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, share_str)
                .map_err(|_| anyhow!("Invalid share format (expected hex or base64)"))?
        };

        let share: Share =
            serde_json::from_slice(&share_bytes).map_err(|_| anyhow!("Invalid share structure"))?;

        let mut buffer = self.unseal_buffer.write().await;

        // Add if not exists
        if !buffer.iter().any(|s| s.index == share.index) {
            buffer.push(share);
        }

        // Check threshold
        let (threshold, shares_total) = {
            let entry = self
                .storage
                .get_by_path(INIT_PATH)
                .await
                .map_err(|e| anyhow!("Storage error: {}", e))?
                .ok_or(anyhow!("Init config missing"))?;
            let config: InitConfig = serde_json::from_slice(&entry.encrypted_data)?;
            (config.threshold as usize, config.shares as usize)
        };

        if buffer.len() >= threshold {
            // Reconstruct
            tracing::info!("Threshold reached. Attempting to unseal...");

            // Reconstruct Master Key
            let master_key = match shamir::combine(&buffer) {
                Ok(k) => k,
                Err(e) => {
                    // Wrong shares?
                    tracing::error!("Failed to combine shares: {}", e);
                    return Err(anyhow!("Failed to reconstruct key: {}", e));
                }
            };

            // Get Encrypted Root Key
            let entry = self
                .storage
                .get_by_path(ROOT_KEY_PATH)
                .await
                .map_err(|e| anyhow!("Storage error: {}", e))?
                .ok_or(anyhow!("Root key missing"))?;

            let enc_root: EncryptedRootKey = serde_json::from_slice(&entry.encrypted_data)
                .map_err(|_| anyhow!("Invalid root key data"))?;

            // Decrypt Root Key
            match self.crypto.decrypt_with_key(&master_key, &enc_root.data) {
                Ok(root_key) => {
                    // SUCCESS!
                    self.crypto.set_root_key(root_key).await?;
                    tracing::info!("Vault unsealed successfully.");
                    // The shares have done their job and are the one piece of plaintext
                    // here that must not linger. Dropping the buffer before the credential
                    // is issued is safe because the credential is derived from the root
                    // key and the persisted root identity, never from a share.
                    buffer.clear();
                    drop(buffer);

                    self.issue_bootstrap_credential_with(threshold, shares_total)
                        .await
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to decrypt root key with reconstructed master key. Wrong shares?"
                    );
                    Err(anyhow!(
                        "Failed to decrypt root key. Invalid shares? Error: {}",
                        e
                    ))
                }
            }
        } else {
            drop(buffer);
            self.get_status().await
        }
    }

    /// Issue the root credential for a barrier that is already open, using the identity
    /// `init` recorded rather than a hard-coded username.
    ///
    /// Split for the retry path, which knows neither the threshold nor the share count
    /// because the shares are long gone.
    async fn issue_bootstrap_credential(&self) -> Result<UnsealResponse> {
        let (threshold, shares_total) = self.init_shape().await;
        self.issue_bootstrap_credential_with(threshold, shares_total)
            .await
    }

    /// Mint the root token and record the session it is bound to.
    ///
    /// Failure here leaves the barrier open with [`Self::bootstrap_is_pending`] set, which
    /// is the recoverable state: a later unseal call reaches [`Self::issue_bootstrap_credential`]
    /// and mints the credential without reinitialising the vault or re-presenting shares.
    async fn issue_bootstrap_credential_with(
        &self,
        threshold: usize,
        shares_total: usize,
    ) -> Result<UnsealResponse> {
        self.bootstrap_pending.store(true, Ordering::SeqCst);

        // The identity the audit record names is the one `init` recorded, not a literal:
        // a deployment with a custom root username must not have its audit trail claim
        // the actor was "root".
        let actor = self
            .root_identity()
            .await
            .map(|identity| identity.username)
            .unwrap_or_else(|_| "root".to_string());

        match self.mint_root_credential().await {
            Ok(root_token) => {
                self.bootstrap_pending.store(false, Ordering::SeqCst);
                self.audit_unseal(&actor, true, "unseal", "bootstrap credential issued")
                    .await;
                Ok(UnsealResponse {
                    sealed: false,
                    t: threshold,
                    n: shares_total,
                    progress: 0,
                    root_token: Some(root_token),
                })
            }
            Err(e) => {
                // The vault stays open — closing the barrier here would discard the
                // reconstruction the shares just paid for, and the next restart has the
                // same shares available anyway. The state is reported through
                // `bootstrap_is_pending` so the failure is recoverable rather than final.
                self.audit_unseal(
                    &actor,
                    false,
                    "unseal",
                    &format!("credential issuance failed: {e}"),
                )
                .await;
                Err(anyhow!(
                    "Vault is unsealed but the root credential could not be issued ({e}). \
                     Retry unseal while this process is still running; the barrier is open \
                     in memory and no shares are needed. A restart discards the in-memory \
                     root key, so after one the vault must be unsealed again with its shares."
                ))
            }
        }
    }
    /// Look up the root account the way `init` recorded it.
    async fn mint_root_credential(&self) -> Result<String> {
        #[cfg(test)]
        if self.fail_next_bootstrap.swap(false, Ordering::SeqCst) {
            return Err(anyhow!("injected bootstrap credential failure"));
        }

        let auth = self.auth.get().ok_or_else(|| {
            anyhow!("seal service has no auth service; root login cannot be issued")
        })?;

        let identity = self.root_identity().await?;
        let root_user = auth
            .find_user_by_username(&identity.username)
            .await
            .map_err(|e| anyhow!("Failed to load root user: {}", e))?
            .ok_or_else(|| {
                anyhow!(
                    "the root account '{}' recorded at init is missing; cannot issue a root token",
                    identity.username
                )
            })?;

        // Hand back a usable root credential, not just a signed string.
        //
        // The previous version encoded a JWT here directly and returned it. That token
        // carried a `jti`, but nothing ever wrote the matching session record, and
        // `validate_token` rejects any token whose `jti` has no session — so *every* call
        // made with the token unseal just returned was refused with "token rejected".
        // Unsealing wiped the shares buffer, so there was no way to get another one. The
        // vault was open and unreachable.
        //
        // The TTL is the bootstrap TTL, not the interactive session timeout: the session
        // policy can be raised to a day, and this credential should not inherit that.
        auth.issue_session_token(
            &root_user,
            "unseal".to_string(),
            "seal-service".to_string(),
            crate::services::auth::BOOTSTRAP_TOKEN_TTL_SECS,
        )
        .await
        .map_err(|e| anyhow!("Failed to issue root token: {}", e))
    }

    /// Read the identity `init` persisted for the root account.
    async fn root_identity(&self) -> Result<RootIdentity> {
        let entry = self
            .storage
            .get_by_path(ROOT_IDENTITY_PATH)
            .await
            .map_err(|e| anyhow!("Storage error: {}", e))?
            .ok_or_else(|| {
                anyhow!(
                    "no root identity is recorded for this vault; it was initialised before \
                     the identity was persisted"
                )
            })?;
        serde_json::from_slice(&entry.encrypted_data)
            .map_err(|_| anyhow!("Invalid root identity data"))
    }

    /// The `(threshold, shares)` shape recorded at init, for a status response that must
    /// reflect it.
    async fn init_shape(&self) -> (usize, usize) {
        match self.storage.get_by_path(INIT_PATH).await {
            Ok(Some(entry)) => match serde_json::from_slice::<InitConfig>(&entry.encrypted_data) {
                Ok(config) => (config.threshold as usize, config.shares as usize),
                Err(_) => (0, 0),
            },
            _ => (0, 0),
        }
    }

    async fn audit_unseal(&self, actor: &str, success: bool, operation: &str, detail: &str) {
        if let Some(audit) = self.audit.get() {
            audit
                .log_event(crate::services::audit::SecurityEventType::SealOperation {
                    operation: format!("{operation} ({detail})"),
                    user: actor.to_string(),
                    success,
                })
                .await;
        }
    }

    /// Seal the vault
    pub async fn seal(&self) {
        self.crypto.clear_root_key().await;
        self.unseal_buffer.write().await.clear();
        // Sealing discards the root key, so a credential that was never issued cannot be
        // issued from this state either. Clearing the flag keeps the two in step: after a
        // seal, an unseal must go through the shares again.
        self.bootstrap_pending.store(false, Ordering::SeqCst);
        tracing::info!("Vault sealed.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::performance::SecretPerformanceOptimizer;
    use crate::services::admin::AdminService;
    use crate::services::audit::AuditLogger;
    use crate::services::auth::{AuthenticationService, BOOTSTRAP_TOKEN_TTL_SECS};
    use crate::services::mfa_persistence::PersistentTotpService;
    use secreton_auth::mfa::{
        CombinedMfaService, DefaultPushService, DefaultRecoveryCodeService, DefaultWebAuthnService,
        EmailConfig, InMemoryEmailService, InMemoryHardwareService, InMemorySmsService, SmsConfig,
    };
    use secreton_storage::StorageResult;
    use secreton_storage::backends::MemoryBackend;

    /// A sealed vault with the auth, MFA, audit and admin services wired the way
    /// `Services::new` wires them. Shared by every test here so none of them drifts into
    /// testing a partially connected service graph.
    struct Vault {
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        auth: Arc<AuthenticationService>,
        mfa: Arc<CombinedMfaService>,
        seal: Arc<SealService>,
        admin: Arc<AdminService>,
        audit: Arc<AuditLogger>,
    }

    async fn sealed_vault() -> Vault {
        let storage = Arc::new(MemoryBackend::new());
        sealed_vault_with_storage(storage).await
    }

    /// The same graph as [`sealed_vault`], over a caller-supplied backend so a test can
    /// inject storage faults without a second service wiring.
    async fn sealed_vault_with_storage(storage: Arc<dyn StorageBackend + Send + Sync>) -> Vault {
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());

        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test-secret-1234567890".to_string());

        let persistent_totp = Arc::new(PersistentTotpService::new(
            storage.clone(),
            crypto.clone(),
            "secreton-test".to_string(),
        ));
        let mfa = Arc::new(CombinedMfaService::new(
            persistent_totp,
            Arc::new(InMemorySmsService::new(SmsConfig::default())),
            Arc::new(InMemoryEmailService::new(EmailConfig::default())),
            Arc::new(InMemoryHardwareService::new()),
            Arc::new(DefaultPushService::new_mock()),
            Arc::new(DefaultWebAuthnService::new_default()),
            Arc::new(DefaultRecoveryCodeService::new()),
        ));

        let auth = Arc::new(
            AuthenticationService::new(storage.clone(), crypto.clone(), &config)
                .await
                .unwrap()
                .with_mfa(mfa.clone()),
        );

        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 100, true)
                .await
                .expect("audit logger"),
        );
        let seal = Arc::new(SealService::new(storage.clone(), crypto.clone()))
            .with_auth(Arc::clone(&auth))
            .with_audit(audit.clone());

        let performance = Arc::new(SecretPerformanceOptimizer::default());
        let admin = Arc::new(
            AdminService::new(storage.clone(), auth.clone(), performance, audit.clone())
                .await
                .expect("admin service")
                .with_crypto(crypto.clone()),
        );

        Vault {
            storage,
            crypto,
            auth,
            mfa,
            seal,
            admin,
            audit,
        }
    }

    /// The JWT payload, read without verification — the tests here are asserting what was
    /// *issued*, and the signature is exercised by the token service's own tests.
    fn claims_of(token: &str) -> serde_json::Value {
        use base64::Engine;
        let payload = token.split('.').nth(1).expect("a JWT has three segments");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("payload is base64url");
        serde_json::from_slice(&bytes).expect("payload is JSON")
    }

    #[tokio::test]
    async fn unsealing_with_a_custom_root_username_returns_the_root_credential() {
        // Regression: `unseal` looked up the literal username "root" while `init` accepted
        // any name, so a deployment that chose another name opened the vault and then could
        // not find the account — no credential, and no shares left to ask with.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "vault-operator";
        let init = vault
            .seal
            .init(3, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");

        let partial = vault.seal.unseal(&init.keys[0]).await.expect("share one");
        assert!(partial.sealed);
        assert_eq!(partial.progress, 1);
        assert!(partial.root_token.is_none(), "no token before threshold");

        let complete = vault.seal.unseal(&init.keys[1]).await.expect("share two");
        assert!(!complete.sealed);
        assert_eq!(complete.t, 2);
        assert_eq!(complete.n, 3);

        let token = complete
            .root_token
            .expect("the threshold unseal must hand back a root credential");
        let claims = claims_of(&token);
        assert_eq!(
            claims["username"], ROOT_USERNAME,
            "the token must name the account init created, not a hard-coded 'root'"
        );
    }

    #[tokio::test]
    async fn the_unseal_token_validates_and_reaches_administrative_operations() {
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "operations-root";
        let init = vault
            .seal
            .init(2, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let token = vault
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("share two")
            .root_token
            .expect("root credential");

        // The token survives validation, which requires the session record it was issued
        // with. A signed string with no session is refused by `validate_token`, and that
        // was the original unreachable-vault failure.
        let user = vault
            .auth
            .validate_token(&token)
            .await
            .expect("the unseal token must validate");
        assert_eq!(user.username, ROOT_USERNAME);
        assert!(user.roles.contains(&"root".to_string()), "{:?}", user.roles);
        assert!(
            user.roles.contains(&"admin".to_string()),
            "{:?}",
            user.roles
        );
        assert_eq!(user.policies, vec!["default".to_string()]);
        assert!(user.is_admin(), "the bootstrap identity must be privileged");

        // The session record the validator checked really exists, under the token's jti.
        let claims = claims_of(&token);
        let jti = claims["jti"].as_str().expect("jti");
        assert!(
            vault
                .storage
                .exists(&format!("sys/auth/sessions/{jti}"))
                .await
                .expect("storage"),
            "the token's session record must be persisted"
        );

        // And it can actually do administrative work, not merely pass a role check.
        let looked_up = vault
            .admin
            .get_user(ROOT_USERNAME)
            .await
            .expect("an admin operation the root token authorises");
        assert_eq!(looked_up.username, ROOT_USERNAME);
    }

    #[tokio::test]
    async fn the_unseal_audit_event_names_the_recorded_root_identity() {
        // The audit trail used to hard-code the actor as "root", so a deployment with a
        // custom root username had its most privileged event attributed to a name that
        // does not exist in its user table.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "audit-root";
        let init = vault
            .seal
            .init(2, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        vault.seal.unseal(&init.keys[1]).await.expect("share two");

        let events = vault
            .audit
            .get_entries(crate::services::audit::AuditFilters::default())
            .await
            .expect("audit entries");
        assert!(
            events.iter().any(|e| e.original_user == ROOT_USERNAME),
            "the seal audit event must name the account init created: {:?}",
            events.iter().map(|e| &e.original_user).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn a_failed_bootstrap_credential_is_recoverable_without_reinitialising() {
        // Regression: if `issue_session_token` failed after the barrier opened and the
        // shares were cleared, the vault was open and unreachable, with no retry path.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "recovery-root";
        let init = vault
            .seal
            .init(2, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");

        // Force the next credential issuance to fail, once.
        vault.seal.fail_next_bootstrap.store(true, Ordering::SeqCst);

        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let failed = vault.seal.unseal(&init.keys[1]).await;
        assert!(
            failed.is_err(),
            "the injected failure must surface to the caller"
        );

        // The barrier is open — the shares did their job — and the service records that a
        // credential is still owed. Neither is a state the caller has to guess at.
        assert!(!vault.seal.is_sealed().await);
        assert!(vault.seal.bootstrap_is_pending());

        // Retry without reinitialising and without presenting shares again.
        let retried = vault
            .seal
            .unseal("ignored-because-the-barrier-is-open")
            .await
            .expect("a retry must recover the credential");
        let token = retried.root_token.expect("root credential on retry");
        let user = vault
            .auth
            .validate_token(&token)
            .await
            .expect("the retried token must validate");
        assert_eq!(user.username, ROOT_USERNAME);
        assert!(user.is_admin());
        assert!(
            !vault.seal.bootstrap_is_pending(),
            "the pending flag clears once the credential is issued"
        );

        // Fault injection is single-shot, so the vault is healthy: a further call while
        // the barrier is open returns plain status and mints nothing new.
        let afterwards = vault
            .seal
            .unseal("still-open")
            .await
            .expect("the vault keeps operating");
        assert!(!afterwards.sealed);
        assert!(
            afterwards.root_token.is_none(),
            "a settled vault issues no second credential"
        );
    }

    #[tokio::test]
    async fn the_bootstrap_token_lives_for_the_bootstrap_ttl_not_the_session_policy() {
        // Regression: `issue_session_token` read the effective session timeout, which an
        // operator can raise to 24 hours, so the most privileged credential in the system
        // silently inherited that lifetime.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        // Raise the interactive session policy to the maximum the admin service allows.
        vault
            .storage
            .store(
                &SecretEntry::new(
                    "system/config".to_string(),
                    Vec::new(),
                    EncryptionMetadata::default(),
                    SecurityLevel::Internal,
                    Uuid::nil(),
                )
                .add_metadata(
                    "config_data".to_string(),
                    serde_json::json!({ "session_timeout": 86_400u64 }).to_string(),
                ),
            )
            .await
            .expect("store session policy");

        let init = vault
            .seal
            .init(2, 2, "root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let token = vault
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("share two")
            .root_token
            .expect("root credential");

        let claims = claims_of(&token);
        let issued = claims["iat"].as_u64().expect("iat");
        let expires = claims["exp"].as_u64().expect("exp");
        assert_eq!(
            expires - issued,
            BOOTSTRAP_TOKEN_TTL_SECS,
            "the bootstrap credential must not follow the interactive session policy"
        );
        assert_ne!(
            expires - issued,
            86_400,
            "the credential inherited the 24-hour session timeout"
        );
    }

    #[tokio::test]
    async fn bootstrap_recovery_does_not_survive_a_restart() {
        // The retry documented for a failed credential issuance is deliberately
        // in-process. This pins that boundary: a fresh service graph over the same storage
        // has no pending state and a sealed barrier, so it cannot mint a credential
        // without the shares — and does not pretend it could.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        const ROOT_USERNAME: &str = "restart-root";
        let init = vault
            .seal
            .init(2, 2, ROOT_USERNAME, &vault.auth, &vault.mfa)
            .await
            .expect("init");

        vault.seal.fail_next_bootstrap.store(true, Ordering::SeqCst);
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        assert!(vault.seal.unseal(&init.keys[1]).await.is_err());
        assert!(vault.seal.bootstrap_is_pending());

        // Restart: same durable storage, brand-new in-memory services.
        let restarted = sealed_vault_with_storage(vault.storage.clone()).await;
        assert!(
            !restarted.seal.bootstrap_is_pending(),
            "the pending state is in memory and does not survive a restart"
        );
        assert!(
            restarted.seal.is_sealed().await,
            "a restart drops the in-memory root key, so the barrier is sealed"
        );

        // The barrier is sealed and no credential is owed, so a call without shares is
        // refused rather than answered with a credential the process cannot back.
        let without_shares = restarted.seal.unseal("a string that is not a share").await;
        assert!(
            without_shares.is_err(),
            "a restarted vault must not recover a credential without its shares"
        );

        // And with the shares it unseals exactly as it did the first time.
        restarted
            .seal
            .unseal(&init.keys[0])
            .await
            .expect("share one");
        let complete = restarted
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("share two");
        let token = complete
            .root_token
            .expect("root credential after re-unseal");
        let claims = claims_of(&token);
        assert_eq!(claims["username"], ROOT_USERNAME);
    }

    #[tokio::test]
    async fn sealing_again_clears_the_pending_bootstrap_and_requires_the_shares() {
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        let init = vault
            .seal
            .init(3, 2, "root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        vault.seal.unseal(&init.keys[1]).await.expect("share two");
        assert!(!vault.seal.is_sealed().await);

        // Crypto works while unsealed.
        assert!(vault.crypto.encrypt_data(b"test").await.is_ok());

        vault.seal.seal().await;
        assert!(vault.seal.is_sealed().await);
        assert!(
            !vault.seal.bootstrap_is_pending(),
            "a sealed vault owes no credential"
        );
        assert!(vault.crypto.encrypt_data(b"test").await.is_err());
    }

    #[tokio::test]
    async fn an_initialised_vault_cannot_be_initialised_again() {
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        vault
            .seal
            .init(3, 2, "first-root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        let again = vault
            .seal
            .init(3, 2, "second-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            again.is_err(),
            "re-initialising would discard the existing root key"
        );
    }

    #[tokio::test]
    async fn unseal_before_init_reports_uninitialised_rather_than_decrypting() {
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        assert!(!vault.seal.is_initialized().await);
        let result = vault.seal.unseal("00").await;
        assert!(result.is_err());
    }

    /// A backend that refuses one write and passes everything else through.
    ///
    /// `fail_stores_for` names the exact path whose *next* store returns an error. The
    /// fault is transient and narrow on purpose: it reproduces the failure an operator
    /// cannot retry by hand — a storage hiccup at one step of initialization — without
    /// breaking any other part of the service graph.
    #[derive(Debug)]
    struct OneShotStoreFailure {
        inner: MemoryBackend,
        path: String,
        armed: std::sync::atomic::AtomicBool,
    }

    impl OneShotStoreFailure {
        fn arming(path: &str) -> Self {
            Self {
                inner: MemoryBackend::new(),
                path: path.to_string(),
                armed: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for OneShotStoreFailure {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            if entry.path == self.path
                && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected one-shot store failure".to_string(),
                });
            }
            self.inner.store(entry).await
        }

        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn list(
            &self,
            params: &secreton_storage::QueryParams,
        ) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &secreton_storage::QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn compact(&self) -> StorageResult<()> {
            self.inner.compact().await
        }
        async fn vacuum(&self) -> StorageResult<()> {
            self.inner.vacuum().await
        }
        async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
            self.inner.delete_expired(path_prefix).await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    #[tokio::test]
    async fn a_failed_root_identity_write_leaves_the_vault_reinitialisable() {
        // Regression (severe): `init` stored the init config before the root identity, so a
        // failure writing the identity returned an error *after* the vault looked
        // initialised. No shares reached the operator, `init` refused to run again, and a
        // restart discarded the in-memory root key — a new vault nobody could ever unseal.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(OneShotStoreFailure::arming(ROOT_IDENTITY_PATH));
        let vault = sealed_vault_with_storage(storage).await;

        // 1. The first init fails, and does not hand back any shares.
        let first = vault
            .seal
            .init(3, 2, "recovered-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            first.is_err(),
            "the injected identity-write failure must surface as an init error"
        );

        // 2. The vault is not left in an initialised state, even though the init config
        // was written before the failure.
        assert!(
            !vault.seal.is_initialized().await,
            "a failed init must not advertise an initialised vault"
        );

        // 3. The next init succeeds with no restart and no manual cleanup.
        let second = vault
            .seal
            .init(3, 2, "recovered-root", &vault.auth, &vault.mfa)
            .await
            .expect("a retry must be able to initialise the vault");

        // 4. Its shares open the vault and yield a credential for the account it named.
        vault.seal.unseal(&second.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&second.keys[1]).await.expect("share two");
        let token = complete
            .root_token
            .expect("a recovered initialization must issue a bootstrap credential");
        let claims = claims_of(&token);
        assert_eq!(
            claims["username"], "recovered-root",
            "the credential must name the account the successful init created"
        );

        // 5. The stale artifacts from the failed attempt are gone, so the second
        // initialization is the only one recorded.
        assert!(
            vault
                .storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "a completed init must not leave its staging marker behind"
        );
    }

    #[tokio::test]
    async fn a_leftover_staging_marker_makes_the_vault_look_uninitialised_and_recover() {
        // The crash case: a process dies between writing the init config and completing
        // initialization, so no cleanup runs and both the config and the marker are on
        // disk. The config alone would read as "initialized" and refuse the retry; the
        // marker is what says the work is unfinished, so the retry must be allowed.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let vault = sealed_vault_with_storage(storage.clone()).await;

        let config = serde_json::to_vec(&InitConfig {
            shares: 3,
            threshold: 2,
        })
        .expect("serialise init config");
        storage
            .store(&SecretEntry::new(
                INIT_PATH.to_string(),
                config,
                EncryptionMetadata::default(),
                SecurityLevel::Public,
                Uuid::nil(),
            ))
            .await
            .expect("store a partial init config");
        let staging = serde_json::to_vec(&InitStaging {
            root_username: "crashed-root".to_string(),
            root_entity_id: None,
        })
        .expect("serialise staging");
        storage
            .store(&SecretEntry::new(
                INIT_STAGING_PATH.to_string(),
                staging,
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            ))
            .await
            .expect("store a staging marker");

        assert!(
            !vault.seal.is_initialized().await,
            "a staging marker must override a partial init config"
        );

        // The retry rolls the partial state back and initialises for real, so the shares
        // it hands back are the ones that open this vault.
        let response = vault
            .seal
            .init(3, 2, "crash-recovered-root", &vault.auth, &vault.mfa)
            .await
            .expect("a leftover staging marker must not block a retry");
        vault
            .seal
            .unseal(&response.keys[0])
            .await
            .expect("share one");
        let complete = vault
            .seal
            .unseal(&response.keys[1])
            .await
            .expect("share two");
        let token = complete
            .root_token
            .expect("the recovered initialization must issue a bootstrap credential");
        assert_eq!(claims_of(&token)["username"], "crash-recovered-root");
    }
}
