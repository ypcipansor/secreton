use uuid::Uuid;

use secreton_storage::{
    EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend,
    backends::{CassandraStorage, CockroachDBStorage, MongoDBStorage},
};

#[tokio::test]
async fn test_cockroachdb_storage_basic_operations() {
    // Test configuration
    let config = secreton_storage::backends::CockroachDBConfig::default();

    // Create storage instance
    let storage = match CockroachDBStorage::new(config).await {
        Ok(storage) => storage,
        Err(_) => {
            // Skip test if CockroachDB is not available
            println!("Skipping CockroachDB test - not available");
            return;
        }
    };

    // Create test entry
    let owner_id = Uuid::new_v4();
    let entry = SecretEntry::new(
        "test/cockroachdb/path".to_string(),
        vec![1, 2, 3, 4, 5],
        EncryptionMetadata {
            algorithm: "aes-256-gcm".to_string(),
            key_id: "test-key".to_string(),
            iv: vec![0; 12],
            auth_tag: Some(vec![0; 16]),
            aad: None,
            kdf_params: None,
        },
        SecurityLevel::Secret,
        owner_id,
    );

    // Test store
    storage.store(&entry).await.expect("Failed to store entry");

    // Test retrieve by path
    let retrieved = storage
        .get_by_path("test/cockroachdb/path")
        .await
        .expect("Failed to retrieve entry")
        .expect("Entry not found");

    assert_eq!(retrieved.path, entry.path);
    assert_eq!(retrieved.encrypted_data, entry.encrypted_data);
    assert_eq!(retrieved.security_level, entry.security_level);

    // Test exists
    assert!(
        storage
            .exists("test/cockroachdb/path")
            .await
            .expect("Failed to check existence")
    );

    // Test list
    let entries = storage
        .list(&Default::default())
        .await
        .expect("Failed to list entries");
    assert!(!entries.is_empty());

    // Test delete
    assert!(
        storage
            .delete_by_path("test/cockroachdb/path")
            .await
            .expect("Failed to delete")
    );

    // Verify deletion
    assert!(
        !storage
            .exists("test/cockroachdb/path")
            .await
            .expect("Failed to check existence")
    );
}

#[tokio::test]
async fn test_cassandra_storage_basic_operations() {
    // Test configuration
    let config = secreton_storage::backends::CassandraConfig::default();

    // Create storage instance
    let storage = match CassandraStorage::new(config).await {
        Ok(storage) => storage,
        Err(_) => {
            // Skip test if Cassandra is not available
            println!("Skipping Cassandra test - not available");
            return;
        }
    };

    // Create test entry
    let owner_id = Uuid::new_v4();
    let entry = SecretEntry::new(
        "test/cassandra/path".to_string(),
        vec![1, 2, 3, 4, 5],
        EncryptionMetadata {
            algorithm: "aes-256-gcm".to_string(),
            key_id: "test-key".to_string(),
            iv: vec![0; 12],
            auth_tag: Some(vec![0; 16]),
            aad: None,
            kdf_params: None,
        },
        SecurityLevel::Internal,
        owner_id,
    );

    // Test store
    storage.store(&entry).await.expect("Failed to store entry");

    // Test retrieve by path
    let retrieved = storage
        .get_by_path("test/cassandra/path")
        .await
        .expect("Failed to retrieve entry")
        .expect("Entry not found");

    assert_eq!(retrieved.path, entry.path);
    assert_eq!(retrieved.encrypted_data, entry.encrypted_data);
    assert_eq!(retrieved.security_level, entry.security_level);

    // Test exists
    assert!(
        storage
            .exists("test/cassandra/path")
            .await
            .expect("Failed to check existence")
    );

    // Test list
    let entries = storage
        .list(&Default::default())
        .await
        .expect("Failed to list entries");
    assert!(!entries.is_empty());

    // Test delete
    assert!(
        storage
            .delete_by_path("test/cassandra/path")
            .await
            .expect("Failed to delete")
    );

    // Verify deletion
    assert!(
        !storage
            .exists("test/cassandra/path")
            .await
            .expect("Failed to check existence")
    );
}

#[tokio::test]
async fn test_mongodb_storage_basic_operations() {
    // Test configuration
    let config = secreton_storage::backends::MongoDBConfig::default();

    // Create storage instance
    let storage = match MongoDBStorage::new(config).await {
        Ok(storage) => storage,
        Err(_) => {
            // Skip test if MongoDB is not available
            println!("Skipping MongoDB test - not available");
            return;
        }
    };

    // Create test entry
    let owner_id = Uuid::new_v4();
    let entry = SecretEntry::new(
        "test/mongodb/path".to_string(),
        vec![1, 2, 3, 4, 5],
        EncryptionMetadata {
            algorithm: "aes-256-gcm".to_string(),
            key_id: "test-key".to_string(),
            iv: vec![0; 12],
            auth_tag: Some(vec![0; 16]),
            aad: None,
            kdf_params: None,
        },
        SecurityLevel::Confidential,
        owner_id,
    );

    // Test store
    storage.store(&entry).await.expect("Failed to store entry");

    // Test retrieve by path
    let retrieved = storage
        .get_by_path("test/mongodb/path")
        .await
        .expect("Failed to retrieve entry")
        .expect("Entry not found");

    assert_eq!(retrieved.path, entry.path);
    assert_eq!(retrieved.encrypted_data, entry.encrypted_data);
    assert_eq!(retrieved.security_level, entry.security_level);

    // Test exists
    assert!(
        storage
            .exists("test/mongodb/path")
            .await
            .expect("Failed to check existence")
    );

    // Test list
    let entries = storage
        .list(&Default::default())
        .await
        .expect("Failed to list entries");
    assert!(!entries.is_empty());

    // Test delete
    assert!(
        storage
            .delete_by_path("test/mongodb/path")
            .await
            .expect("Failed to delete")
    );

    // Verify deletion
    assert!(
        !storage
            .exists("test/mongodb/path")
            .await
            .expect("Failed to check existence")
    );
}

#[test]
fn test_storage_backend_config_defaults() {
    // Test CockroachDB config default
    let cockroach_config = secreton_storage::backends::CockroachDBConfig::default();
    assert_eq!(
        cockroach_config.connection_string,
        "postgresql://root@localhost:26257/defaultdb?sslmode=disable"
    );
    assert_eq!(cockroach_config.database_name, "defaultdb");
    assert_eq!(cockroach_config.max_connections, 10);

    // Test Cassandra config default
    let cassandra_config = secreton_storage::backends::CassandraConfig::default();
    assert_eq!(cassandra_config.contact_points, "127.0.0.1:9042");
    assert_eq!(cassandra_config.keyspace, "secreton_kv");
    assert!(cassandra_config.username.is_none());
    assert!(cassandra_config.password.is_none());

    // Test MongoDB config default
    let mongodb_config = secreton_storage::backends::MongoDBConfig::default();
    assert_eq!(
        mongodb_config.connection_string,
        "mongodb://localhost:27017"
    );
    assert_eq!(mongodb_config.database_name, "secreton_kv");
    assert_eq!(mongodb_config.collection_name, "entries");
}

#[test]
fn test_secreton_entry_with_all_security_levels() {
    let owner_id = Uuid::new_v4();

    // Test all security levels
    let security_levels = vec![
        SecurityLevel::Public,
        SecurityLevel::Internal,
        SecurityLevel::Confidential,
        SecurityLevel::Secret,
        SecurityLevel::TopSecret,
    ];

    for security_level in security_levels {
        let entry = SecretEntry::new(
            format!("test/security/{:?}", security_level).to_lowercase(),
            vec![1, 2, 3],
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "test-key".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            security_level,
            owner_id,
        );

        assert_eq!(entry.security_level, security_level);
        assert!(!entry.is_expired());
    }
}

#[test]
fn test_secreton_entry_metadata_and_tags() {
    let owner_id = Uuid::new_v4();
    let mut entry = SecretEntry::new(
        "test/metadata".to_string(),
        vec![1, 2, 3],
        EncryptionMetadata {
            algorithm: "aes-256-gcm".to_string(),
            key_id: "test-key".to_string(),
            iv: vec![0; 12],
            auth_tag: Some(vec![0; 16]),
            aad: None,
            kdf_params: None,
        },
        SecurityLevel::Secret,
        owner_id,
    );

    // Add metadata
    entry = entry
        .add_metadata("environment".to_string(), "production".to_string())
        .add_metadata("region".to_string(), "us-west-2".to_string());

    // Add tags
    entry = entry
        .add_tag("database".to_string())
        .add_tag("production".to_string())
        .add_tag("database".to_string()); // Duplicate should be ignored

    assert_eq!(entry.metadata.len(), 2);
    assert_eq!(
        entry.metadata.get("environment"),
        Some(&"production".to_string())
    );
    assert_eq!(entry.metadata.get("region"), Some(&"us-west-2".to_string()));

    assert_eq!(entry.tags.len(), 2);
    assert!(entry.tags.contains(&"database".to_string()));
    assert!(entry.tags.contains(&"production".to_string()));
}
