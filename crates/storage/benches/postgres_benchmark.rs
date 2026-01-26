use criterion::{criterion_group, criterion_main, Criterion};
use secreton_storage::{SecretEntry, StorageBackend, StorageTransaction, backends::PostgresBackend, EncryptionMetadata, SecurityLevel};
use uuid::Uuid;
use tokio::runtime::Runtime;
use std::env;

async fn setup_postgres() -> Option<PostgresBackend> {
    let url = env::var("SECRETON_DATABASE__URL").unwrap_or_else(|_| "postgres://secreton:secreton-password@localhost:5432/secreton".to_string());

    // Attempt to create backend, return None if fails (to allow bench to run/skip)
    match PostgresBackend::new(&url).await {
        Ok(backend) => Some(backend),
        Err(_) => None,
    }
}

fn bench_postgres_transaction(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // We try to connect, if it fails, we just don't run the benchmark logic effectively
    // In a real environment, this would be set up.
    let backend_opt = rt.block_on(setup_postgres());

    if backend_opt.is_none() {
        println!("Skipping postgres benchmark - backend not available");
        // We still need to register a benchmark function to avoid criterion errors
        c.bench_function("postgres_transaction_noop", |b| {
             b.iter(|| {
                 1 + 1
             })
        });
        return;
    }
    let backend = backend_opt.unwrap();

    // Create dummy entries
    let mut entries = Vec::new();
    for i in 0..10 {
        entries.push(SecretEntry {
            id: Uuid::new_v4(),
            path: format!("bench/path/{}", i),
            encrypted_data: vec![1, 2, 3],
            encryption_metadata: EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "key".to_string(),
                iv: vec![0; 12],
                auth_tag: None,
                aad: None,
                kdf_params: None,
            },
            security_level: SecurityLevel::Internal,
            metadata: std::collections::HashMap::new(),
            tags: vec![],
            version: 1,
            owner_id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        });
    }

    c.bench_function("postgres_transaction_commit_10_ops", |b| {
        b.to_async(&rt).iter(|| async {
            let mut tx = backend.begin_transaction().await.unwrap();
            for entry in &entries {
                tx.store(entry).await.unwrap();
            }
            tx.commit().await.unwrap();
        })
    });
}

criterion_group!(benches, bench_postgres_transaction);
criterion_main!(benches);
