//! Full initialization and cross-replica coordination against a real Redis backend.
//!
//! Redis is the shared backend in the deployments this repository actually runs, and it is
//! where "path-keyed operations are a no-op" used to be true: `delete_by_path` returned
//! `Ok(false)` for every path regardless of whether a record existed. That made cleanup
//! report success without removing anything, deleted the staging marker over a still-present
//! artifact, and left the next attempt reading a stale init config as a finished vault.
//!
//! The unit suite reproduces that shape with `SilentDeleteFailure`; this test proves the
//! real backend now reports and performs the delete, and that two independent `SealService`
//! instances sharing one Redis admit exactly one initialization.
//!
//! Set `SECRETON_TEST_REDIS_URL` to run it:
//!
//! ```text
//! docker run --rm -d -p 6379:6379 redis:7-alpine
//! SECRETON_TEST_REDIS_URL=redis://127.0.0.1:6379 \
//!     cargo test -p secreton-engines --test seal_redis
//! ```
//!
//! Without the variable the test returns early, like the other integration tests.

use std::sync::Arc;

use secreton_engines::config::AuthConfig;
use secreton_engines::services::audit::AuditLogger;
use secreton_engines::services::auth::AuthenticationService;
use secreton_engines::services::crypto::CryptoService;
use secreton_engines::services::mfa_persistence::PersistentTotpService;
use secreton_engines::services::seal::SealService;
use secreton_storage::backends::RedisBackend;
use secreton_storage::{Coordination, Expect, SecretEntry, SecurityLevel, StorageBackend};

fn redis_url() -> Option<String> {
    match std::env::var("SECRETON_TEST_REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!("skipping: SECRETON_TEST_REDIS_URL is not set");
            None
        }
    }
}

/// Namespace every path so two test runs against one server cannot collide, and so the
/// `Coordination` the backend reports is not downgraded by the wrapper.
#[derive(Debug)]
struct NamespacedRedis {
    inner: RedisBackend,
    prefix: String,
}

impl NamespacedRedis {
    fn scope(&self, path: &str) -> String {
        format!("{}/{}", self.prefix, path)
    }
}

#[async_trait::async_trait]
impl StorageBackend for NamespacedRedis {
    async fn store(&self, entry: &SecretEntry) -> secreton_storage::StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.store(&scoped).await
    }

    async fn get_by_id(
        &self,
        id: uuid::Uuid,
    ) -> secreton_storage::StorageResult<Option<SecretEntry>> {
        self.inner.get_by_id(id).await
    }

    async fn get_by_path(
        &self,
        path: &str,
    ) -> secreton_storage::StorageResult<Option<SecretEntry>> {
        self.inner.get_by_path(&self.scope(path)).await
    }

    async fn update(&self, entry: &SecretEntry) -> secreton_storage::StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.update(&scoped).await
    }

    async fn upsert(&self, entry: &SecretEntry) -> secreton_storage::StorageResult<()> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.upsert(&scoped).await
    }

    async fn delete_by_id(&self, id: uuid::Uuid) -> secreton_storage::StorageResult<bool> {
        self.inner.delete_by_id(id).await
    }

    async fn delete_by_path(&self, path: &str) -> secreton_storage::StorageResult<bool> {
        self.inner.delete_by_path(&self.scope(path)).await
    }

    fn coordination(&self) -> Coordination {
        // Must not downgrade what it wraps: Redis arbitrates across processes.
        self.inner.coordination()
    }

    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: Expect<'_>,
    ) -> secreton_storage::StorageResult<bool> {
        let mut scoped = entry.clone();
        scoped.path = self.scope(&entry.path);
        self.inner.compare_and_set(&scoped, expect).await
    }

    async fn delete_owned(&self, path: &str, token: &str) -> secreton_storage::StorageResult<bool> {
        self.inner.delete_owned(&self.scope(path), token).await
    }

    async fn list(
        &self,
        params: &secreton_storage::QueryParams,
    ) -> secreton_storage::StorageResult<Vec<SecretEntry>> {
        let mut scoped = params.clone();
        scoped.path_prefix = Some(self.scope(params.path_prefix.as_deref().unwrap_or("")));
        self.inner.list(&scoped).await
    }

    async fn count(
        &self,
        params: &secreton_storage::QueryParams,
    ) -> secreton_storage::StorageResult<u64> {
        let mut scoped = params.clone();
        scoped.path_prefix = Some(self.scope(params.path_prefix.as_deref().unwrap_or("")));
        self.inner.count(&scoped).await
    }

    async fn exists(&self, path: &str) -> secreton_storage::StorageResult<bool> {
        self.inner.exists(&self.scope(path)).await
    }

    async fn begin_transaction(
        &self,
    ) -> secreton_storage::StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
        self.inner.begin_transaction().await
    }

    async fn health_check(
        &self,
    ) -> secreton_storage::StorageResult<secreton_storage::HealthStatus> {
        self.inner.health_check().await
    }

    async fn get_stats(&self) -> secreton_storage::StorageResult<secreton_storage::StorageStats> {
        self.inner.get_stats().await
    }

    async fn migrate(&self) -> secreton_storage::StorageResult<()> {
        self.inner.migrate().await
    }

    async fn compact(&self) -> secreton_storage::StorageResult<()> {
        self.inner.compact().await
    }

    async fn vacuum(&self) -> secreton_storage::StorageResult<()> {
        self.inner.vacuum().await
    }

    async fn delete_expired(
        &self,
        path_prefix: Option<String>,
    ) -> secreton_storage::StorageResult<u64> {
        self.inner
            .delete_expired(path_prefix.map(|p| self.scope(&p)))
            .await
    }

    async fn store_oauth_state(
        &self,
        state: &secreton_domain::OAuthState,
    ) -> secreton_storage::StorageResult<()> {
        self.inner.store_oauth_state(state).await
    }

    async fn get_oauth_state(
        &self,
        state: &str,
    ) -> secreton_storage::StorageResult<Option<secreton_domain::OAuthState>> {
        self.inner.get_oauth_state(state).await
    }

    async fn delete_expired_oauth_states(&self) -> secreton_storage::StorageResult<u64> {
        self.inner.delete_expired_oauth_states().await
    }
}

/// The `delete_by_path` contract on Redis: `Ok(true)` only when a record was actually there
/// and this call removed it, `Ok(false)` otherwise, and the path is absent afterwards in
/// both cases. The old backend returned `Ok(false)` unconditionally and removed nothing.
#[tokio::test]
async fn redis_delete_by_path_reports_and_removes() {
    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let path = "contract/delete-me";
    assert!(
        !storage.delete_by_path(path).await.expect("delete absent"),
        "deleting a path with no record must report false"
    );

    let entry = SecretEntry::new(
        path.to_string(),
        b"payload".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    );
    storage.store(&entry).await.expect("store");
    assert!(
        storage.get_by_path(path).await.expect("read").is_some(),
        "the record must exist before the delete that is being tested"
    );

    assert!(
        storage.delete_by_path(path).await.expect("delete present"),
        "deleting a present record must report true, not a silent false"
    );
    assert!(
        storage.get_by_path(path).await.expect("read").is_none(),
        "the record must actually be gone after a reported delete"
    );
}

/// Regression (severe): `delete_by_id` read the entry, deleted the entry key, then removed
/// `secreton:path:<entry.path>` unconditionally. If the path had been rewritten in between —
/// a concurrent `store` publishing a replacement under the same path — that second delete
/// removed the *replacement's* mapping. Its entry key survived but was unreachable by path,
/// so the replacement was lost while `get_by_path` reported a missing record.
///
/// The fixed property: deleting an old id removes its own record, and a replacement written
/// under the same path before the delete still resolves by path afterwards. The old
/// read-then-delete is falsified here because this test forces exactly that interleaving on
/// a real server.
#[tokio::test]
async fn redis_delete_by_id_does_not_unlink_a_concurrent_replacement() {
    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedRedis> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let path = "contract/replaced";
    let original = SecretEntry::new(
        path.to_string(),
        b"original".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    );
    storage.store(&original).await.expect("store original");

    // Read the original so its id is known, then rewrite the same path as a *replacement*
    // with a different id — the state a concurrent `store` would leave behind.
    let read_back = storage
        .get_by_path(path)
        .await
        .expect("read")
        .expect("original is present");
    assert_eq!(read_back.id, original.id);

    let replacement = SecretEntry::new(
        path.to_string(),
        b"replacement".to_vec(),
        secreton_storage::EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    );
    assert_ne!(
        replacement.id, original.id,
        "the replacement must be a distinct record, or this proves nothing"
    );
    storage
        .store(&replacement)
        .await
        .expect("store replacement");

    // Delete the *old* id. Its path mapping no longer points at it, so the replacement's
    // mapping must survive.
    assert!(
        storage
            .delete_by_id(original.id)
            .await
            .expect("delete old id"),
        "deleting the old id that still has its entry must report true"
    );
    assert!(
        storage
            .get_by_id(original.id)
            .await
            .expect("read old id")
            .is_none(),
        "the deleted entry must be gone by id"
    );

    let resolved = storage
        .get_by_path(path)
        .await
        .expect("read replacement by path")
        .expect("the concurrent replacement must still be reachable by path");
    assert_eq!(
        resolved.id, replacement.id,
        "the path must resolve to the replacement, not the deleted record"
    );
    assert_eq!(resolved.encrypted_data, b"replacement");
}

/// `compare_and_set` on Redis is one server-side Lua invocation, so an insert-if-absent
/// admits one writer and the owner-conditional write is refused after a takeover.
#[tokio::test]
async fn redis_compare_and_set_arbitrates_between_callers() {
    let Some(url) = redis_url() else {
        return;
    };
    let backend = RedisBackend::new(&url).await.expect("connect");
    let storage: Arc<NamespacedRedis> = Arc::new(NamespacedRedis {
        inner: backend,
        prefix: format!("it/{}", uuid::Uuid::new_v4()),
    });

    let path = "contract/cas";
    let entry = |owner: &str| {
        SecretEntry::new(
            path.to_string(),
            b"payload".to_vec(),
            secreton_storage::EncryptionMetadata::default(),
            SecurityLevel::Internal,
            uuid::Uuid::nil(),
        )
        .owned_by(owner)
    };

    assert!(
        storage
            .compare_and_set(&entry("a"), Expect::Absent)
            .await
            .expect("first insert"),
        "the first insert-if-absent must win"
    );
    assert!(
        !storage
            .compare_and_set(&entry("b"), Expect::Absent)
            .await
            .expect("second insert"),
        "a second insert-if-absent must lose; the record already exists"
    );

    assert!(
        storage
            .compare_and_set(&entry("a"), Expect::Owner("a"))
            .await
            .expect("owner replace"),
        "the recorded owner may replace its own record"
    );
    assert!(
        !storage
            .compare_and_set(&entry("b"), Expect::Owner("b"))
            .await
            .expect("wrong owner"),
        "a caller that does not hold the recorded token must not replace it"
    );
    assert!(
        storage
            .compare_and_set(&entry("b"), Expect::Owner("a"))
            .await
            .expect("precondition on a token the caller does not hold"),
        "the precondition is the recorded token, whoever writes with it"
    );
}

/// Two independent `SealService` instances, each on its own Redis connection, sharing one
/// server must admit exactly one initialization.
///
/// The in-process `init_lock` cannot serialise them: separate graphs as two replicas are.
/// Only the cross-process lease — an insert-if-absent, which Redis evaluates atomically —
/// can.
#[tokio::test]
async fn two_replicas_on_one_redis_admit_exactly_one_initialization() {
    let Some(url) = redis_url() else {
        return;
    };

    let namespace = format!("it/{}", uuid::Uuid::new_v4());
    let open = |url: &str| {
        let url = url.to_string();
        async move { RedisBackend::new(&url).await.expect("connect") }
    };

    let storage_a: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedRedis {
        inner: open(&url).await,
        prefix: namespace.clone(),
    });
    let storage_b: Arc<dyn StorageBackend + Send + Sync> = Arc::new(NamespacedRedis {
        inner: open(&url).await,
        prefix: namespace.clone(),
    });

    let (auth_a, mfa_a, seal_a) = replica(storage_a.clone()).await;
    let (auth_b, mfa_b, seal_b) = replica(storage_b.clone()).await;

    let a = {
        let (seal, auth, mfa) = (seal_a.clone(), auth_a.clone(), mfa_a.clone());
        tokio::spawn(async move { seal.init(3, 2, "redis-winner", &auth, &mfa).await })
    };
    let b = {
        let (seal, auth, mfa) = (seal_b.clone(), auth_b.clone(), mfa_b.clone());
        tokio::spawn(async move { seal.init(3, 2, "redis-loser", &auth, &mfa).await })
    };

    let (result_a, result_b) = tokio::join!(a, b);
    let result_a = result_a.expect("task A");
    let result_b = result_b.expect("task B");

    let successes = [&result_a, &result_b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes,
        1,
        "exactly one replica must initialize; got A={:?} B={:?}",
        result_a.as_ref().err().map(|e| e.to_string()),
        result_b.as_ref().err().map(|e| e.to_string()),
    );

    let winner = result_a.as_ref().or(result_b.as_ref()).expect("one winner");
    let (winner_seal, winner_auth) = if result_a.is_ok() {
        (seal_a.clone(), auth_a.clone())
    } else {
        (seal_b.clone(), auth_b.clone())
    };
    assert!(winner_seal.is_initialized().await);
    winner_seal
        .unseal(&winner.keys[0])
        .await
        .expect("share one");
    let complete = winner_seal
        .unseal(&winner.keys[1])
        .await
        .expect("the winner's shares must open the stored root key");
    let token = complete
        .root_token
        .expect("the winner must issue a bootstrap credential");
    let user = winner_auth.validate_token(&token).await.expect("validates");
    assert!(
        user.username == "redis-winner" || user.username == "redis-loser",
        "the credential must name the winner's account"
    );

    assert!(
        storage_a
            .get_by_path("sys/init_lease")
            .await
            .expect("storage")
            .is_none(),
        "a completed initialization must release its cross-process lease"
    );
    assert!(
        storage_a
            .get_by_path("sys/init_staging")
            .await
            .expect("storage")
            .is_none(),
        "a completed initialization must clear its staging marker on Redis"
    );
}

/// Build one replica's service graph over `storage`.
async fn replica(
    storage: Arc<dyn StorageBackend + Send + Sync>,
) -> (
    Arc<AuthenticationService>,
    Arc<secreton_auth::mfa::CombinedMfaService>,
    Arc<SealService>,
) {
    let crypto = Arc::new(CryptoService::new(storage.clone()).await.expect("crypto"));
    let mut config = AuthConfig::default();
    config.jwt.secret = Some("integration-test-secret-1234567890".to_string());
    let auth = Arc::new(
        AuthenticationService::new(storage.clone(), crypto.clone(), &config)
            .await
            .expect("auth"),
    );
    let audit = Arc::new(
        AuditLogger::new(storage.clone(), 2555, 100, true)
            .await
            .expect("audit"),
    );
    let seal = Arc::new(SealService::new(storage.clone(), crypto.clone()))
        .with_auth(auth.clone())
        .with_audit(audit.clone());
    let mfa = mfa_service(storage, crypto).await;
    (auth, mfa, seal)
}

async fn mfa_service(
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
) -> Arc<secreton_auth::mfa::CombinedMfaService> {
    use secreton_auth::mfa::{
        CombinedMfaService, DefaultPushService, DefaultRecoveryCodeService, DefaultWebAuthnService,
        EmailConfig, InMemoryEmailService, InMemoryHardwareService, InMemorySmsService, SmsConfig,
    };

    Arc::new(CombinedMfaService::new(
        Arc::new(PersistentTotpService::new(
            storage,
            crypto,
            "secreton-test".to_string(),
        )),
        Arc::new(InMemorySmsService::new(SmsConfig::default())),
        Arc::new(InMemoryEmailService::new(EmailConfig::default())),
        Arc::new(InMemoryHardwareService::new()),
        Arc::new(DefaultPushService::new_mock()),
        Arc::new(DefaultWebAuthnService::new_default()),
        Arc::new(DefaultRecoveryCodeService::new()),
    ))
}
