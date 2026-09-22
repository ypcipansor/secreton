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

    // Serialises initialization within this process.
    //
    // Two concurrent `init` calls each pass the `is_initialized` guard before either has
    // written anything, and then interleave: one call's stale-state cleanup deletes the
    // other's artifacts, or both commit and one caller walks away with shares that do not
    // open the root key that ended up stored. The lock covers the whole sequence —
    // cleanup, the guard, staging, initialization, commit and marker removal — not just
    // the guard, because every one of those steps is what the other call races against.
    //
    // This is an async mutex and is never held across a blocking call. It protects one
    // process only; see `initialize` for the cross-process boundary.
    init_lock: tokio::sync::Mutex<()>,

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

/// What an in-progress `init` records at [`INIT_STAGING_PATH`], so a later attempt can
/// either finish or roll it back.
///
/// Names the account it was about to create and, once known, that account's id — the id
/// is what locates the TOTP enrollment without decrypting anything. It deliberately holds
/// no share, token, password or key: recovery must not require storing any of those.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InitStaging {
    root_username: String,
    /// Set once the root account exists, so cleanup can find its TOTP enrollment by path.
    root_entity_id: Option<String>,
    /// Set once every durable artifact is stored and the marker is the only thing left.
    ///
    /// Its purpose is to stop a retry from destroying a vault that actually committed:
    /// if the process died between the commit and removing the marker, the artifacts are
    /// all present and correct, and cleanup must verify them rather than delete them.
    #[serde(default)]
    committed: bool,
}

/// The username a vault initialised before [`ROOT_IDENTITY_PATH`] existed always used.
///
/// This is a compatibility constant, not an authentication boundary. It is only ever used
/// to *look up a real account* during legacy recovery, and only after confirming that
/// account exists; the persisted [`RootIdentity`] supersedes it from then on.
const LEGACY_ROOT_USERNAME: &str = "root";

impl SealService {
    pub fn new(storage: Arc<dyn StorageBackend + Send + Sync>, crypto: Arc<CryptoService>) -> Self {
        Self {
            storage,
            crypto,
            auth: std::sync::OnceLock::new(),
            audit: std::sync::OnceLock::new(),
            unseal_buffer: Arc::new(RwLock::new(Vec::new())),
            init_lock: tokio::sync::Mutex::new(()),
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
    /// marker for a *partial* attempt means the vault is treated as uninitialised
    /// regardless of what else is on disk. A marker for a *committed* attempt — every
    /// artifact written, only the marker removal failed — is treated as initialised, so a
    /// retry cannot destroy a working vault.
    pub async fn is_initialized(&self) -> bool {
        if let Ok(Some(entry)) = self.storage.get_by_path(INIT_STAGING_PATH).await {
            // A marker recording a committed initialization means every artifact was
            // written and only the marker's removal failed; the vault is initialised.
            // Only a marker for a genuinely partial attempt makes it uninitialised.
            let committed = serde_json::from_slice::<InitStaging>(&entry.encrypted_data)
                .map(|staging| staging.committed)
                .unwrap_or(false);
            if !committed {
                return false;
            }
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
        // Hold the initialization lock for the whole sequence below — stale-state
        // recovery, the initialized guard, staging, the writes, commit and marker
        // removal. Locking only the guard would still let two calls interleave across the
        // writes and delete or overwrite each other's artifacts.
        let _init_guard = self.init_lock.lock().await;

        // Recovery and the guard run under the lock, against a state neither call can
        // change from now on. `recover_partial_initialization` removes a partial attempt
        // before the initialized check, so a mid-initialisation vault can be retried; it
        // must run first or the init config a partial attempt wrote would be read as a
        // finished initialization.
        self.recover_partial_initialization().await?;

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
                // removed so the next attempt starts clean. The lock is still held, so no
                // concurrent attempt can be observing the state being rolled back.
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
            committed: false,
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

        // The root account is created as a non-password-authenticatable identity: no
        // generated password, no stored hash, and `password_login_disabled` persisted on
        // the record. The previous implementation registered it as an ordinary user with a
        // random password and relied on a literal `"root"` username check to keep it out of
        // the password path — which stopped covering it the moment init accepted a custom
        // `root_username`.
        //
        // Execute user creation and MFA setup.
        // Explicitly annotate result type to avoid inference issues with the error type.
        let result: Result<(secreton_auth::mfa::TotpEnrollment, RootIdentity), anyhow::Error> =
            async {
                let root_user = auth
                    .register_bootstrap_root(
                        root_username,
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
            committed: false,
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

        // 10. Commit. Every durable artifact is now stored, so mark the staging entry as
        // committed *before* removing it. If the process dies between the two, the marker
        // still says the vault finished — and recovery must verify and keep it rather than
        // delete a working vault.
        self.write_staging(&InitStaging {
            root_username: root_identity.username.clone(),
            root_entity_id: Some(root_identity.id.clone()),
            committed: true,
        })
        .await?;

        // Removing the marker is the last step and the only one whose failure does not
        // invalidate the result: the vault is committed, the shares are in the response
        // below, and a later recovery recognises a committed marker and clears it. Failing
        // the whole call here would withhold the shares from the operator while leaving the
        // vault initialised — the one combination nobody can recover from.
        if let Err(e) = self.storage.delete_by_path(INIT_STAGING_PATH).await {
            tracing::warn!(
                "Initialization committed but its staging marker could not be removed \
                 ({e}); recovery will verify and clear it on the next attempt."
            );
        }

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
    ///
    /// Uses [`StorageBackend::upsert`] rather than `store`: initialization writes this path
    /// up to three times, and `store` is an insert whose behaviour on a repeat write is not
    /// portable — PostgreSQL refuses the second insert on its `UNIQUE(path)` constraint
    /// while the in-memory backend accepts it, so initialization failed on PostgreSQL and
    /// passed in every test that used memory.
    async fn write_staging(&self, staging: &InitStaging) -> Result<()> {
        let bytes = serde_json::to_vec(staging)?;
        self.storage
            .upsert(&SecretEntry::new(
                INIT_STAGING_PATH.to_string(),
                bytes,
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            ))
            .await
            .map_err(|e| anyhow!("Failed to record initialization progress: {}", e))
    }

    /// Bring a vault that an interrupted `init` left behind to a state a retry can start
    /// from, and fail loudly rather than guess.
    ///
    /// Three cases, distinguished by evidence rather than by assumption:
    ///
    /// - No marker: nothing to recover, including a vault that finished normally.
    /// - Marker with `committed`: every artifact was written and only the marker removal
    ///   failed. It is verified and kept, never deleted — deleting a working vault would
    ///   destroy the only root key its shares can open. If an artifact is missing, that is
    ///   an inconsistency to report, not to paper over.
    /// - Marker without `committed`: a genuine partial attempt, discarded.
    ///
    /// A marker that cannot be read or parsed is an error: it is not the same as "no
    /// marker", and treating it as such would run an initialization against files whose
    /// ownership is unknown.
    async fn recover_partial_initialization(&self) -> Result<()> {
        let Some(staging) = self.read_staging().await? else {
            return Ok(());
        };

        if staging.committed {
            // The attempt finished; only the marker's removal did not. Keep the vault and
            // make it whole again by clearing the marker, which is the single remaining
            // step of a committed initialization.
            if !self.committed_artifacts_present().await? {
                return Err(anyhow!(
                    "the initialization staging marker records a committed vault, but its \
                     artifacts are incomplete; refusing to overwrite a vault that may still \
                     be openable by its shares"
                ));
            }
            self.storage
                .delete_by_path(INIT_STAGING_PATH)
                .await
                .map_err(|e| {
                    anyhow!("Failed to clear the committed initialization staging marker: {e}")
                })?;
            tracing::info!(
                "Completed a previously committed initialization whose staging marker \
                 removal had failed."
            );
            return Ok(());
        }

        // A partial attempt. Cleanup is only successful if the marker is gone; otherwise
        // starting a new initialization on top of stale artifacts is exactly the state
        // this is meant to prevent. Report it and let the operator retry.
        if !self.discard_partial_initialization_summary().await {
            return Err(anyhow!(
                "an incomplete initialization could not be fully cleaned up; retry once \
                 storage is healthy, or the vault may remain uninitialisable"
            ));
        }
        Ok(())
    }

    /// Read and parse the staging marker.
    ///
    /// `Ok(None)` means absent. An unreadable or unparseable marker is an error: a corrupt
    /// record must not be indistinguishable from a record that is not there, or recovery
    /// would proceed against unknown state.
    async fn read_staging(&self) -> Result<Option<InitStaging>> {
        let entry = self
            .storage
            .get_by_path(INIT_STAGING_PATH)
            .await
            .map_err(|e| anyhow!("Failed to read the initialization staging marker: {e}"))?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        let staging = serde_json::from_slice::<InitStaging>(&entry.encrypted_data)
            .map_err(|e| anyhow!("Invalid initialization staging marker: {e}"))?;
        Ok(Some(staging))
    }

    /// Whether a committed initialization's artifacts are all present.
    async fn committed_artifacts_present(&self) -> Result<bool> {
        for path in [INIT_PATH, ROOT_KEY_PATH, ROOT_IDENTITY_PATH] {
            let present = self
                .storage
                .get_by_path(path)
                .await
                .map_err(|e| anyhow!("Failed to verify '{path}' during recovery: {e}"))?
                .is_some();
            if !present {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Remove whatever a partial `init` wrote, marker last.
    ///
    /// Acts only when the staging marker is present: a vault that is not mid-initialisation
    /// must not have its records touched. Every mandatory removal is attempted, and the
    /// marker is removed only if all of them succeeded. A removal that fails leaves the
    /// marker in place so the next `init` retries the cleanup rather than believing the
    /// stale state is gone — which is how a vault becomes permanently uninitialisable.
    ///
    /// Nothing here stores or logs share, token, password or key material: the marker names
    /// the account, and the account's own records are located by path.
    async fn discard_partial_initialization(&self) {
        let _ = self.discard_partial_initialization_summary().await;
    }

    /// The body of [`Self::discard_partial_initialization`], returning whether the marker
    /// was actually removed so the recovery path can report the difference.
    async fn discard_partial_initialization_summary(&self) -> bool {
        let staging = match self.read_staging().await {
            Ok(Some(staging)) => Some(staging),
            // No marker: nothing to do.
            Ok(None) => return true,
            Err(e) => {
                // Cannot read the marker, so cannot locate the account it names. The durable
                // artifacts can still be removed, but the marker must stay so a later
                // attempt with working storage can find the account. Never report success.
                tracing::error!("{e}");
                None
            }
        };

        let mut all_removed = staging.is_some();

        // A committed marker means every artifact was written and the vault is good. Only
        // the marker removal is outstanding; deleting the artifacts would destroy a
        // working vault. This is reachable from the `init` error path if step 10's marker
        // removal failed after the commit was recorded.
        if let Some(staging) = &staging
            && staging.committed
        {
            self.crypto.clear_root_key().await;
            return self.remove_required(INIT_STAGING_PATH).await;
        }

        if let Some(staging) = &staging {
            if let Some(entity_id) = &staging.root_entity_id {
                let totp_path = format!(
                    "{}{}",
                    crate::services::mfa_persistence::TOTP_PREFIX,
                    entity_id
                );
                all_removed &= self.remove_required(&totp_path).await;
            }
            let user_path = format!(
                "{}{}",
                crate::services::auth::USER_STORAGE_PREFIX,
                staging.root_username
            );
            all_removed &= self.remove_required(&user_path).await;
        }

        for path in [ROOT_IDENTITY_PATH, ROOT_KEY_PATH, INIT_PATH] {
            all_removed &= self.remove_required(path).await;
        }

        // The marker goes last, and only once every artifact is gone. If anything above
        // failed, leaving it is exactly what lets the next attempt retry the cleanup.
        if all_removed {
            all_removed = self.remove_required(INIT_STAGING_PATH).await;
        } else {
            tracing::error!(
                "Not removing the initialization staging marker: an artifact could not be \
                 removed, so the partial state is still present and the next attempt must \
                 retry this cleanup."
            );
        }

        // The generated root key was installed only to encrypt the account records that
        // were just removed; a completed initialization would not leave it in place.
        self.crypto.clear_root_key().await;
        all_removed
    }

    /// Delete a path, treating absence as success and a failure as a failure.
    ///
    /// Returns whether the path is now gone. This is the only place cleanup decides, so
    /// "log and carry on" cannot come back by accident.
    async fn remove_required(&self, path: &str) -> bool {
        match self.storage.delete_by_path(path).await {
            Ok(_) => true,
            Err(e) => {
                tracing::error!(
                    "Failed to remove '{}' while cleaning up an incomplete initialization: {}",
                    path,
                    e
                );
                false
            }
        }
    }

    /// Give a legacy vault the root identity it was initialised without.
    ///
    /// Vaults created before [`ROOT_IDENTITY_PATH`] existed have no record naming their
    /// root account, so an unseal opens the barrier and then cannot mint the bootstrap
    /// credential — the vault is open and unreachable, and a retry repeats the same
    /// failure. This repairs that state from evidence, never from a guess:
    ///
    /// - The account must actually exist in storage, read back and deserialized.
    /// - It must already be privileged (`admin`/`root`), so a stray unprivileged account
    ///   named `root` is never elevated into the bootstrap identity.
    /// - Only then is it persisted as the identity, and marked non-password-authenticatable
    ///   to match what a fresh `init` would have written, so the legacy account cannot
    ///   password-login either.
    ///
    /// Called by `unseal` when no identity is recorded, so recovery needs no new endpoint
    /// and no reinitialisation. It is idempotent: once the identity exists it returns
    /// immediately, and it returns the identity it recorded so the caller does not have to
    /// re-read it.
    ///
    /// If no such account exists the error stands — inventing an identity for an account
    /// that is not there would mint a credential for an account that cannot be loaded.
    async fn repair_legacy_root_identity(
        &self,
        auth: &crate::services::auth::AuthenticationService,
    ) -> Result<RootIdentity> {
        // Distinguish "no record" from "record I cannot read". Reading through the
        // storage trait first means a corrupt identity or a storage error is reported as
        // itself and never falls through to adopting an account by name: a damaged record
        // must not silently become a different root.
        let existing = self
            .storage
            .get_by_path(ROOT_IDENTITY_PATH)
            .await
            .map_err(|e| anyhow!("Failed to read the root identity: {e}"))?;
        if let Some(entry) = existing {
            return serde_json::from_slice(&entry.encrypted_data)
                .map_err(|e| anyhow!("corrupt root identity record: {e}"));
        }

        let Some(user) = auth
            .find_user_by_username(LEGACY_ROOT_USERNAME)
            .await
            .map_err(|e| anyhow!("Failed to read the legacy root account: {e}"))?
        else {
            return Err(anyhow!(
                "no root identity is recorded for this vault, and no legacy '{LEGACY_ROOT_USERNAME}' \
                 account exists to adopt; the vault cannot be given a bootstrap credential"
            ));
        };

        if !user.is_admin() {
            return Err(anyhow!(
                "no root identity is recorded for this vault, and the account named \
                 '{LEGACY_ROOT_USERNAME}' is not privileged; refusing to adopt it as the \
                 bootstrap root"
            ));
        }

        // Persist the boundary a fresh init now writes directly, then record the identity.
        // A failure to mark the account is fatal here: continuing would leave a
        // password-authenticatable root, which is the defect this whole path exists to fix.
        auth.mark_password_login_disabled(&user.username)
            .await
            .map_err(|e| {
                anyhow!("Failed to disable password login for the legacy root account: {e}")
            })?;

        let identity = RootIdentity {
            id: user.id.clone(),
            username: user.username.clone(),
        };
        let bytes = serde_json::to_vec(&identity)?;
        // `upsert`: this repair path is documented as idempotent, and two unseals can race
        // to repair the same vault. A concurrent second write must not hit the backend's
        // `UNIQUE(path)` constraint, which `store` would.
        self.storage
            .upsert(&SecretEntry::new(
                ROOT_IDENTITY_PATH.to_string(),
                bytes,
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::nil(),
            ))
            .await
            .map_err(|e| anyhow!("Failed to persist the legacy root identity: {e}"))?;

        tracing::info!(
            root_username = %identity.username,
            "Recovered the root identity for a vault initialised before it was persisted."
        );
        Ok(identity)
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
        // the actor was "root". When no identity is recorded this is a legacy vault, and
        // resolving it here is what lets the repair happen before the credential is minted
        // rather than failing and being retried forever.
        let actor = match self.auth.get().map(|auth| auth.as_ref()) {
            Some(auth) => match self.repair_legacy_root_identity(auth).await {
                Ok(identity) => identity.username,
                Err(_) => "unresolved-root".to_string(),
            },
            None => "unresolved-root".to_string(),
        };

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

        // Resolve the root account, repairing a legacy vault that never recorded its
        // identity. Doing it here, rather than only for the audit label, means the
        // credential is minted for the account the vault actually owns.
        let identity = self.repair_legacy_root_identity(auth).await?;
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

    /// A backend that blocks the first write to one path until the test releases it.
    ///
    /// A `tokio::join!` of two `init` calls is not deterministic: each call may run to
    /// completion before the other starts, so the test passes whether or not the sequence
    /// is guarded. This backend forces the interleaving. `init` writes the staging marker
    /// before any other durable artifact, so pausing there parks the first call inside its
    /// write sequence — after it has passed the `is_initialized` guard and before it has
    /// committed anything — while the test starts a second call. If the sequence is
    /// unguarded, the second call observes the same uninitialised state and interleaves.
    #[derive(Debug)]
    struct PausingStore {
        inner: MemoryBackend,
        pause_on: String,
        reached: tokio::sync::Notify,
        resume: tokio::sync::Notify,
        started: std::sync::atomic::AtomicUsize,
    }

    impl PausingStore {
        fn pausing_on(path: &str) -> Self {
            Self {
                inner: MemoryBackend::new(),
                pause_on: path.to_string(),
                reached: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
                started: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        /// Park the first write to the watched path. Both `store` and `upsert` route
        /// through here because `write_staging` uses `upsert`.
        async fn maybe_pause(&self, path: &str) {
            if path == self.pause_on
                && self
                    .started
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    == 0
            {
                self.reached.notify_one();
                self.resume.notified().await;
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for PausingStore {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.maybe_pause(&entry.path).await;
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
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.maybe_pause(&entry.path).await;
            self.inner.upsert(entry).await
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

    /// A backend that models a well-behaved relational store: a second insert at the same
    /// path is a constraint violation, unlike the in-memory backend, which silently
    /// overwrites. This is the property the memory-only test suite never exercised, and
    /// `write_staging` relied on the overwrite.
    #[derive(Debug)]
    struct UniquePathStore {
        inner: MemoryBackend,
    }

    #[async_trait::async_trait]
    impl StorageBackend for UniquePathStore {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            if self.inner.get_by_path(&entry.path).await?.is_some() {
                return Err(secreton_storage::StorageError::ConstraintViolation {
                    constraint: "UNIQUE(path)".to_string(),
                    message: "a second entry already exists at this path".to_string(),
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
    async fn initialization_writes_its_progress_to_a_unique_path_store() {
        // Regression (severe): `write_staging` used `store` for a path it writes up to
        // three times. Memory accepts the second insert; a relational backend with a
        // `UNIQUE(path)` constraint refuses it, so initialization failed on PostgreSQL
        // while every existing test, which used memory, passed. The injected backend
        // reproduces the constraint without needing a live PostgreSQL in the unit suite.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(UniquePathStore {
            inner: MemoryBackend::new(),
        });
        let vault = sealed_vault_with_storage(storage.clone()).await;

        let init = vault
            .seal
            .init(3, 2, "unique-path-root", &vault.auth, &vault.mfa)
            .await
            .expect("initialization must not depend on store-overwrites-a-path");

        // The vault is genuinely usable, not merely error-free.
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&init.keys[1]).await.expect("share two");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "unique-path-root"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "a completed init must not leave its staging marker behind"
        );
    }

    #[tokio::test]
    async fn cleanup_keeps_the_marker_when_an_artifact_delete_fails() {
        // Regression: `discard_partial_initialization` logged a delete failure and then
        // removed the marker anyway. The next attempt therefore saw no marker, skipped
        // cleanup, and the stale init config made it look initialised — a vault that could
        // never be initialised again.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(OneShotDeleteFailure::arming(INIT_PATH));
        let vault = sealed_vault_with_storage(storage.clone()).await;

        // Simulate a crashed init that left the config and the marker behind.
        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();
        store_partial_init(&storage_dyn, "delete-failure-root", None).await;

        let first = vault
            .seal
            .init(3, 2, "delete-failure-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            first.is_err(),
            "cleanup that could not remove an artifact must fail the init, not proceed"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_some(),
            "the marker must survive so the next attempt retries the cleanup"
        );

        // The delete fault is one-shot; the retry cleans everything and initialises.
        let second = vault
            .seal
            .init(3, 2, "delete-failure-root", &vault.auth, &vault.mfa)
            .await
            .expect("the retry must clear the stale state and initialise");
        vault.seal.unseal(&second.keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&second.keys[1]).await.expect("share two");
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            "delete-failure-root"
        );
        assert!(
            storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the successful retry must clear the marker"
        );
    }

    #[tokio::test]
    async fn concurrent_initializations_admit_exactly_one_winner() {
        // Regression (severe): two `init` calls both passed the `is_initialized` guard
        // before either had written anything, then interleaved — one call's cleanup deleted
        // the other's artifacts, or both committed and one caller received shares that did
        // not open the stored root key. The lock serialises the whole sequence, so exactly
        // one call succeeds and the shares it returns open the vault.
        //
        // The overlap is forced rather than hoped for: the first call is parked inside
        // `write_staging` (past the guard, before anything is committed) while the second
        // call runs to completion. Without the lock the second call sees an uninitialised
        // vault and both proceed. With the lock the second call blocks until the first
        // finishes and is then refused by the guard.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(PausingStore::pausing_on(INIT_STAGING_PATH));
        let vault = Arc::new(sealed_vault_with_storage(storage.clone()).await);

        let first = {
            let vault = vault.clone();
            tokio::spawn(async move {
                vault
                    .seal
                    .init(3, 2, "racer-a", &vault.auth, &vault.mfa)
                    .await
            })
        };

        // Wait until the first call is inside its staging write, then start the second.
        storage.reached.notified().await;
        let second = {
            let vault = vault.clone();
            tokio::spawn(async move {
                vault
                    .seal
                    .init(3, 2, "racer-b", &vault.auth, &vault.mfa)
                    .await
            })
        };

        // Give the second call every chance to reach the guard before releasing the first.
        tokio::task::yield_now().await;
        storage.resume.notify_one();

        let first = first.await.expect("first task");
        let second = second.await.expect("second task");

        let successes: Vec<_> = [&first, &second]
            .into_iter()
            .filter(|r| r.is_ok())
            .collect();
        assert_eq!(
            successes.len(),
            1,
            "exactly one concurrent initialization must succeed; got {:?}",
            [&first, &second].map(|r| r.as_ref().map(|_| ()).map_err(|e| e.to_string()))
        );

        let winner = successes[0];
        let keys = &winner.as_ref().expect("checked").keys;

        // The winning call's shares open the vault the winner initialised, and the
        // credential names the winner's account — not the loser's.
        vault.seal.unseal(&keys[0]).await.expect("share one");
        let complete = vault.seal.unseal(&keys[1]).await.expect("share two");
        let winner_name = if first.is_ok() { "racer-a" } else { "racer-b" };
        assert_eq!(
            claims_of(&complete.root_token.expect("root credential"))["username"],
            winner_name,
            "the shares returned by the winner must open the vault the winner initialised"
        );

        // Final state is consistent: initialised, no marker, and the recorded root identity
        // is the winner's.
        assert!(vault.seal.is_initialized().await);
        assert!(
            vault
                .storage
                .get_by_path(INIT_STAGING_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the winner must not leave a staging marker"
        );
        let identity: RootIdentity = serde_json::from_slice(
            &vault
                .storage
                .get_by_path(ROOT_IDENTITY_PATH)
                .await
                .expect("storage")
                .expect("root identity")
                .encrypted_data,
        )
        .expect("root identity parses");
        assert_eq!(identity.username, winner_name);
    }

    #[tokio::test]
    async fn a_legacy_vault_without_a_root_identity_issues_a_working_credential() {
        // Regression (severe): a vault initialised before the root identity was persisted
        // had no `sys/root_identity` record, so unseal opened the barrier and then could
        // not mint a credential, and every retry failed the same way. The repair adopts the
        // real, privileged `root` account and persists the identity. This builds exactly
        // that legacy state: an initialised vault (its root account named `root`) with the
        // identity record removed, which is what a pre-identity vault looks like.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        let init = vault
            .seal
            .init(2, 2, "root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        // Remove what a pre-identity vault would not have; keep the rest of the state.
        vault
            .storage
            .delete_by_path(ROOT_IDENTITY_PATH)
            .await
            .expect("storage");
        assert!(
            vault
                .storage
                .get_by_path(ROOT_IDENTITY_PATH)
                .await
                .expect("storage")
                .is_none(),
            "the legacy state under test must have no root identity"
        );

        assert!(
            vault
                .seal
                .unseal(&init.keys[0])
                .await
                .expect("share one")
                .sealed,
            "one share of two must not open the vault"
        );
        let complete = vault
            .seal
            .unseal(&init.keys[1])
            .await
            .expect("the legacy vault must unseal");
        let token = complete
            .root_token
            .expect("a legacy vault must recover a root credential");

        // The credential is real: it validates and does administrative work.
        let user = vault.auth.validate_token(&token).await.expect("validates");
        assert_eq!(user.username, "root");
        assert!(user.is_admin());
        vault
            .admin
            .get_user("root")
            .await
            .expect("an admin operation the recovered credential authorises");

        // The identity is now persisted, so the repair does not run again, and the legacy
        // account was made non-password-authenticatable.
        assert!(
            vault
                .storage
                .get_by_path(ROOT_IDENTITY_PATH)
                .await
                .expect("storage")
                .is_some(),
            "recovery must persist the identity so later requests do not depend on the fallback"
        );
        assert!(
            !vault
                .auth
                .verify_password("root", "legacy-generated-password")
                .await
                .expect("verify"),
            "the adopted root account must not be password-authenticatable"
        );
    }

    #[tokio::test]
    async fn a_corrupt_root_identity_is_not_treated_as_a_legacy_vault() {
        // A damaged `sys/root_identity` record must be reported as corrupt, not silently
        // repaired by adopting a `root` account: that would let a damaged record become a
        // different root. The repair only proceeds from a record that is genuinely absent.
        let _env = crate::test_support::without_root_key();
        let vault = sealed_vault().await;

        // Initialise a vault, then create a decoy `root` account through the same storage
        // while the barrier is open, so the test needs no second init.
        let init = vault
            .seal
            .init(2, 2, "corrupt-identity-root", &vault.auth, &vault.mfa)
            .await
            .expect("init");
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        vault.seal.unseal(&init.keys[1]).await.expect("share two");

        let decoy = vault
            .auth
            .register_user(
                "root",
                "some-password",
                Some("root@system.local".to_string()),
                vec!["root".to_string(), "admin".to_string()],
                vec!["*".to_string()],
            )
            .await
            .expect("a decoy root account that must not be adopted");
        assert!(decoy.is_admin());

        // Corrupt the identity record in place.
        let entry = vault
            .storage
            .get_by_path(ROOT_IDENTITY_PATH)
            .await
            .expect("storage")
            .expect("identity");
        let mut corrupted = entry;
        corrupted.encrypted_data = b"not json".to_vec();
        vault.storage.update(&corrupted).await.expect("update");

        // Seal, then unseal again so the credential is reissued from the now-corrupt
        // identity.
        vault.seal.seal().await;
        vault.seal.unseal(&init.keys[0]).await.expect("share one");
        let result = vault.seal.unseal(&init.keys[1]).await;

        assert!(
            result.is_err(),
            "a corrupt identity must fail rather than adopt a different root account"
        );
        // The decoy was not adopted: its password still works because it was never turned
        // into the bootstrap root.
        assert!(
            vault
                .auth
                .verify_password("root", "some-password")
                .await
                .expect("verify"),
            "no repair may run against a corrupt identity"
        );
    }

    #[tokio::test]
    async fn init_refuses_to_start_when_a_partial_state_cannot_be_cleaned() {
        // A storage failure reading or deleting the marker must not be mistaken for "no
        // marker": proceeding would initialize on top of state whose ownership is unknown.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(FailingReadPath::arming(INIT_STAGING_PATH));
        let vault = sealed_vault_with_storage(storage.clone()).await;

        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();
        store_partial_init(&storage_dyn, "unreadable-marker-root", None).await;

        let result = vault
            .seal
            .init(3, 2, "unreadable-marker-root", &vault.auth, &vault.mfa)
            .await;
        assert!(
            result.is_err(),
            "an unreadable staging marker must stop init, not be read as absent"
        );
        assert!(
            !vault.seal.is_initialized().await,
            "the vault must not be left advertising an initialised state"
        );
    }

    /// Write the state a crashed `init` would leave: an init config, and optionally a
    /// staging marker naming the root account it was about to create.
    async fn store_partial_init(
        storage: &Arc<dyn StorageBackend + Send + Sync>,
        root_username: &str,
        root_entity_id: Option<String>,
    ) {
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
            root_username: root_username.to_string(),
            root_entity_id,
            committed: false,
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
    }

    /// A backend that fails the *next* delete of one path, and passes everything else
    /// through. One-shot so a test can prove that a retry after the fault succeeds.
    #[derive(Debug)]
    struct OneShotDeleteFailure {
        inner: MemoryBackend,
        path: String,
        armed: std::sync::atomic::AtomicBool,
    }

    impl OneShotDeleteFailure {
        fn arming(path: &str) -> Self {
            Self {
                inner: MemoryBackend::new(),
                path: path.to_string(),
                armed: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for OneShotDeleteFailure {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
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
            if path == self.path && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected one-shot delete failure".to_string(),
                });
            }
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

    /// A backend whose read of one path fails, to prove a storage failure is not read as
    /// "path absent".
    #[derive(Debug)]
    struct FailingReadPath {
        inner: MemoryBackend,
        path: String,
        armed: std::sync::atomic::AtomicBool,
    }

    impl FailingReadPath {
        fn arming(path: &str) -> Self {
            Self {
                inner: MemoryBackend::new(),
                path: path.to_string(),
                armed: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for FailingReadPath {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            if path == self.path && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected one-shot read failure".to_string(),
                });
            }
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
            committed: false,
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
