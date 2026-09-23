//! The `store_fenced` contract every backend must honour.
//!
//! `check()`-then-write is not a guarantee: an attempt can be fenced the instant after it
//! reads its own lease, so a write authorised only by a preceding check can still land after
//! a takeover. `store_fenced` moves the precondition into the write itself, and these tests
//! pin the three behaviours a correct backend must have:
//!
//! - a write whose fence token matches the lease record succeeds;
//! - a write whose fence token does not match writes nothing and leaves the existing record
//!   exactly as it was — this is the overwrite the finding is about;
//! - a write whose fence record is absent writes nothing, rather than failing open.
//!
//! Memory, file and the cache wrapper are exercised here with no external service. Redis and
//! PostgreSQL have their own tests that connect to a real server (`seal_redis.rs`,
//! `seal_postgres.rs` in `secreton-engines`); Raft is asserted to refuse, because a
//! process-local state machine cannot arbitrate between replicas and a fence it cannot
//! enforce must not be faked.

use std::sync::Arc;
use std::time::Duration;

use secreton_storage::cache::CachedStorage;
use secreton_storage::{
    EncryptionMetadata, FileBackend, MemoryBackend, SecretEntry, SecurityLevel, StorageBackend,
    StorageFence, StorageResult,
};

fn entry(path: &str, owner: &str, payload: &[u8]) -> SecretEntry {
    SecretEntry::new(
        path.to_string(),
        payload.to_vec(),
        EncryptionMetadata::default(),
        SecurityLevel::Internal,
        uuid::Uuid::nil(),
    )
    .owned_by(owner)
}

async fn assert_fenced_contract(backend: &(dyn StorageBackend + Send + Sync), lease: &str) {
    let artifact = "artifact/root_key";

    // The holder of the lease acquires it, then publishes its artifact through the fence.
    backend
        .store(&entry(lease, "winner", b"lease"))
        .await
        .expect("store lease record");
    assert!(
        backend
            .store_fenced(
                &entry(artifact, "winner", b"winner-artifact"),
                StorageFence::new(lease, "winner")
            )
            .await
            .expect("fenced write by the current holder"),
        "the holder of the lease must be able to publish its artifact"
    );
    let winner_id = backend
        .get_by_path(artifact)
        .await
        .expect("read")
        .expect("the artifact is present")
        .id;

    // A stale attempt — its fence token no longer matches the lease — must write nothing.
    assert!(
        !backend
            .store_fenced(
                &entry(artifact, "stale", b"stale-artifact"),
                StorageFence::new(lease, "stale")
            )
            .await
            .expect("fenced write by a stale holder"),
        "an attempt whose fence token is not the lease's must not write"
    );

    let resolved = backend
        .get_by_path(artifact)
        .await
        .expect("read")
        .expect("the winner's artifact must still be present");
    assert_eq!(
        resolved.id, winner_id,
        "a refused fenced write must not replace the winner's record"
    );
    assert_eq!(
        resolved.encrypted_data, b"winner-artifact",
        "a refused fenced write must not overwrite the winner's payload"
    );

    // A fence whose record has been released must refuse too: absence is not consent.
    backend
        .delete_by_path(lease)
        .await
        .expect("release the lease");
    assert!(
        !backend
            .store_fenced(
                &entry(artifact, "winner", b"after-release"),
                StorageFence::new(lease, "winner")
            )
            .await
            .expect("fenced write after the lease is released"),
        "a fence with no lease record must refuse, not fail open"
    );
    assert_eq!(
        backend
            .get_by_path(artifact)
            .await
            .expect("read")
            .expect("the artifact survives")
            .encrypted_data,
        b"winner-artifact",
        "the artifact must be untouched after a refused post-release write"
    );
}

#[tokio::test]
async fn memory_backend_honours_the_fence() {
    let backend = MemoryBackend::new();
    assert_fenced_contract(&backend, "sys/init_lease").await;
}

#[tokio::test]
async fn file_backend_honours_the_fence() {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("file backend");
    assert_fenced_contract(&backend, "sys/init_lease").await;
}

#[tokio::test]
async fn cache_wrapper_preserves_the_fence_contract() {
    use secreton_storage::cache::InMemoryCache;

    let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(CachedStorage::new(
        MemoryBackend::new(),
        InMemoryCache::new(),
        Duration::from_secs(60),
    ));
    assert_fenced_contract(storage.as_ref(), "sys/init_lease").await;
}

/// Raft's state machine is a process-local map no second replica observes, so it must refuse a
/// fence rather than evaluate it against its own memory and report a success it cannot
/// guarantee. A backend that returned `Ok(true)` here would hand the seal service a lock that
/// does not lock.
#[cfg(feature = "raft")]
#[tokio::test]
async fn raft_refuses_a_fence_it_cannot_enforce() {
    use secreton_storage::Coordination;
    use secreton_storage::backends::{RaftConfig, RaftStorageBackend};

    let dir = tempfile::tempdir().expect("temp dir");
    let backend = RaftStorageBackend::new(RaftConfig {
        data_dir: dir.path().to_path_buf(),
        ..RaftConfig::default()
    })
    .await
    .expect("raft backend");

    assert_eq!(
        backend.coordination(),
        Coordination::SingleProcess,
        "a single-node in-memory state machine cannot arbitrate between processes"
    );
    let outcome: StorageResult<bool> = backend
        .store_fenced(
            &entry("artifact/root_key", "winner", b"payload"),
            StorageFence::new("sys/init_lease", "winner"),
        )
        .await;
    assert!(
        outcome.is_err(),
        "a backend that cannot enforce a fence must refuse, not fake one"
    );
}
