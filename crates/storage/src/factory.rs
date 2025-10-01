use crate::backends::*;
/// Storage Backend Factory
///
/// Provides easy creation and configuration of different storage backends
use crate::{StorageBackend, StorageError, StorageResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Storage backend type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackendType {
    /// File-based storage
    File,
    /// In-memory storage (for testing)
    Memory,
    /// PostgreSQL database
    Postgres,
    /// Redis cache
    Redis,
    /// Raft distributed storage
    Raft,
    /// Consul KV storage
    Consul,
    /// PostgreSQL storage (new implementation)
    PostgreSQL,
    /// etcd storage
    Etcd,
    /// Amazon S3
    S3,
    /// AWS DynamoDB
    DynamoDB,
    /// MySQL database
    MySQL,
    /// CockroachDB storage
    CockroachDB,
    /// Cassandra storage
    Cassandra,
    /// MongoDB storage
    MongoDB,
    /// Aerospike storage
    Aerospike,
    /// AliCloud OSS storage
    AliCloudOSS,
    /// CouchDB storage
    CouchDB,
    /// FoundationDB storage
    FoundationDB,
    /// Manta storage
    Manta,
    /// Microsoft SQL Server storage
    MSSQL,
    /// OCI storage
    OCI,
    /// Spanner storage
    Spanner,
    /// Swift storage
    Swift,
    /// ZooKeeper storage
    ZooKeeper,
}

/// Unified storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageFactoryConfig {
    /// Backend type to use
    pub backend_type: StorageBackendType,

    /// File backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_config: Option<FileBackendConfig>,

    /// PostgreSQL backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postgres_config: Option<PostgresBackendConfig>,

    /// Redis backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis_config: Option<RedisBackendConfig>,

    /// Raft backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raft_config: Option<RaftConfig>,

    /// Consul backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consul_config: Option<ConsulStorageConfig>,

    /// S3 backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_config: Option<S3StorageConfig>,

    /// etcd backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etcd_config: Option<EtcdStorageConfig>,
    /// DynamoDB backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamodb_config: Option<DynamoDBStorageConfig>,
    /// MySQL backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mysql_config: Option<MySQLStorageConfig>,
    /// CockroachDB backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cockroachdb_config: Option<CockroachDBConfig>,
    /// Cassandra backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cassandra_config: Option<CassandraConfig>,
    /// MongoDB backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mongodb_config: Option<MongoDBConfig>,
    /// Aerospike backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aerospike_config: Option<AerospikeConfig>,
    /// AliCloud OSS backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alicloud_oss_config: Option<AliCloudOSSConfig>,
    /// CouchDB backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub couchdb_config: Option<CouchDBConfig>,
    /// FoundationDB backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foundationdb_config: Option<FoundationDBConfig>,
    /// Manta backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manta_config: Option<MantaConfig>,
    /// MSSQL backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mssql_config: Option<MSSQLConfig>,
    /// OCI backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oci_config: Option<OCIConfig>,
    /// Spanner backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spanner_config: Option<SpannerConfig>,
    /// Swift backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swift_config: Option<SwiftConfig>,
    /// ZooKeeper backend configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zookeeper_config: Option<ZooKeeperConfig>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBackendConfig {
    pub base_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresBackendConfig {
    pub connection_string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisBackendConfig {
    pub url: String,
}

impl Default for StorageFactoryConfig {
    fn default() -> Self {
        Self {
            backend_type: StorageBackendType::Memory,
            file_config: None,
            postgres_config: None,
            redis_config: None,
            raft_config: None,
            consul_config: None,
            s3_config: None,
            dynamodb_config: None,
            mysql_config: None,
            etcd_config: None,
            cockroachdb_config: None,
            cassandra_config: None,
            mongodb_config: None,
            aerospike_config: None,
            alicloud_oss_config: None,
            couchdb_config: None,
            foundationdb_config: None,
            manta_config: None,
            mssql_config: None,
            oci_config: None,
            spanner_config: None,
            swift_config: None,
            zookeeper_config: None,
        }
    }
}

/// Storage factory for creating storage backends
pub struct StorageFactory;

impl StorageFactory {
    /// Create a new storage backend based on configuration
    pub async fn create(config: StorageFactoryConfig) -> StorageResult<Arc<dyn StorageBackend>> {
        match config.backend_type {
            StorageBackendType::Memory => Ok(Arc::new(crate::MockStorageBackend::new())),

            StorageBackendType::Consul => {
                let consul_config =
                    config
                        .consul_config
                        .ok_or_else(|| StorageError::ConfigurationError {
                            message: "Consul configuration is required".to_string(),
                        })?;

                let backend = ConsulStorage::new(consul_config).await?;
                Ok(Arc::new(backend))
            }

            StorageBackendType::PostgreSQL => {
                let pg_config =
                    config
                        .postgres_config
                        .ok_or_else(|| StorageError::ConfigurationError {
                            message: "PostgreSQL configuration is required".to_string(),
                        })?;

                let backend = PostgresBackend::new(&pg_config.connection_string).await?;
                Ok(Arc::new(backend))
            }

            StorageBackendType::MySQL => {
                let mysql_config = config.mysql_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "MySQL configuration is required".to_string(),
                    }
                })?;

                let backend = MySQLStorage::new(mysql_config).await?;
                Ok(Arc::new(backend))
            }

            StorageBackendType::DynamoDB => {
                let dynamodb_config = config.dynamodb_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "DynamoDB configuration is required".to_string(),
                    }
                })?;

                let backend = DynamoDBStorage::new(dynamodb_config).await?;
                Ok(Arc::new(backend))
            }

            StorageBackendType::S3 => {
                let s3_config = config.s3_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "S3 configuration is required".to_string(),
                    }
                })?;

                let backend = S3Storage::new(s3_config).await?;
                Ok(Arc::new(backend))
            }

            StorageBackendType::Etcd => {
                let etcd_config =
                    config
                        .etcd_config
                        .ok_or_else(|| StorageError::ConfigurationError {
                            message: "etcd configuration is required".to_string(),
                        })?;

                let backend = EtcdStorage::new(etcd_config).await?;
                Ok(Arc::new(backend))
            }

            StorageBackendType::File => {
                let file_config = config.file_config.ok_or_else(|| StorageError::ConfigurationError { message: "File configuration is required".to_string() })?;
                let backend = FileBackend::new(&file_config.base_path)?;
                Ok(Arc::new(backend))
            }
            StorageBackendType::Postgres => {
                let pg_config = config.postgres_config.ok_or_else(|| StorageError::ConfigurationError { message: "Postgres configuration is required".to_string() })?;
                let backend = PostgresBackend::new(&pg_config.connection_string).await?;
                Ok(Arc::new(backend))
            }
            StorageBackendType::Redis => {
                let redis_config = config.redis_config.ok_or_else(|| StorageError::ConfigurationError { message: "Redis configuration is required".to_string() })?;
                let backend = RedisBackend::new(&redis_config.url).await?;
                Ok(Arc::new(backend))
            }
            StorageBackendType::Raft => {
                let raft_config = config.raft_config.ok_or_else(|| StorageError::ConfigurationError { message: "Raft configuration is required".to_string() })?;
                let backend = RaftStorageBackend::new(raft_config).await?;
                Ok(Arc::new(backend))
            }
            StorageBackendType::CockroachDB => {
                let cockroachdb_config = config.cockroachdb_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "CockroachDB configuration is required".to_string(),
                    }
                })?;

                let backend = CockroachDBStorage::new(cockroachdb_config).await?;
                Ok(Arc::new(backend))
            }
            StorageBackendType::Cassandra => {
                let cassandra_config = config.cassandra_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Cassandra configuration is required".to_string(),
                    }
                })?;

                let backend = CassandraStorage::new(cassandra_config).await?;
                Ok(Arc::new(backend))
            }
            StorageBackendType::MongoDB => {
                let mongodb_config = config.mongodb_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "MongoDB configuration is required".to_string(),
                    }
                })?;

                let backend = MongoDBStorage::new(mongodb_config).await?;
                Ok(Arc::new(backend))
            }
            StorageBackendType::Aerospike => {
                let aerospike_config = config.aerospike_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Aerospike configuration is required".to_string(),
                    }
                })?;

                let backend = AerospikeStorage::new(aerospike_config);
                Ok(Arc::new(backend))
            }
            StorageBackendType::AliCloudOSS => {
                let alicloud_oss_config = config.alicloud_oss_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "AliCloud OSS configuration is required".to_string(),
                    }
                })?;

                let backend = AliCloudOSSStorage::new(alicloud_oss_config);
                Ok(Arc::new(backend))
            }
            StorageBackendType::CouchDB => {
                let couchdb_config = config.couchdb_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "CouchDB configuration is required".to_string(),
                    }
                })?;

                let backend = CouchDBStorage::new(couchdb_config);
                Ok(Arc::new(backend))
            }
            StorageBackendType::FoundationDB => {
                let foundationdb_config = config.foundationdb_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "FoundationDB configuration is required".to_string(),
                    }
                })?;

                let backend = FoundationDBStorage::new(foundationdb_config);
                Ok(Arc::new(backend))
            }
            StorageBackendType::Manta => {
                let manta_config = config.manta_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Manta configuration is required".to_string(),
                    }
                })?;

                let backend = MantaStorage::new(manta_config);
                Ok(Arc::new(backend))
            }
            StorageBackendType::MSSQL => {
                let mssql_config = config.mssql_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "MSSQL configuration is required".to_string(),
                    }
                })?;

                let backend = MSSQLStorage::new(mssql_config);
                Ok(Arc::new(backend))
            }
            StorageBackendType::OCI => {
                let oci_config = config.oci_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "OCI configuration is required".to_string(),
                    }
                })?;

                let backend = OCIStorage::new(oci_config);
                Ok(Arc::new(backend))
            }
            StorageBackendType::Spanner => {
                let spanner_config = config.spanner_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Spanner configuration is required".to_string(),
                    }
                })?;

                let backend = SpannerStorage::new(spanner_config);
                Ok(Arc::new(backend))
            }
            StorageBackendType::Swift => {
                let swift_config = config.swift_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "Swift configuration is required".to_string(),
                    }
                })?;

                let backend = SwiftStorage::new(swift_config);
                Ok(Arc::new(backend))
            }
            StorageBackendType::ZooKeeper => {
                let zookeeper_config = config.zookeeper_config.ok_or_else(|| {
                    StorageError::ConfigurationError {
                        message: "ZooKeeper configuration is required".to_string(),
                    }
                })?;

                let backend = ZooKeeperStorage::new(zookeeper_config);
                Ok(Arc::new(backend))
            }
            _ => Err(StorageError::ConfigurationError { message: format!("Backend type {:?} not yet implemented in factory", config.backend_type) }),
        }
    }

    /// Create an in-memory mock backend (helper for tests)
    pub fn create_memory() -> Arc<dyn StorageBackend> {
        Arc::new(crate::MockStorageBackend::new())
    }

    /// Create a Consul storage backend with default configuration
    pub async fn create_consul(address: String) -> StorageResult<Arc<dyn StorageBackend>> {
        let config = ConsulStorageConfig {
            address,
            ..Default::default()
        };

        let backend = ConsulStorage::new(config).await?;
        Ok(Arc::new(backend))
    }

    /// Create a DynamoDB storage backend with table name
    pub async fn create_dynamodb(table_name: String) -> StorageResult<Arc<dyn StorageBackend>> {
        let config = DynamoDBStorageConfig {
            table_name,
            ..Default::default()
        };
        
        let backend = DynamoDBStorage::new(config).await?;
        Ok(Arc::new(backend))
    }

    /// Create an S3 storage backend with bucket name
    pub async fn create_s3(bucket_name: String) -> StorageResult<Arc<dyn StorageBackend>> {
        let config = S3StorageConfig {
            bucket_name,
            ..Default::default()
        };
        
        let backend = S3Storage::new(config).await?;
        Ok(Arc::new(backend))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_factory_config_default() {
        let config = StorageFactoryConfig::default();
        assert_eq!(config.backend_type, StorageBackendType::Memory);
    }

    #[test]
    fn test_storage_backend_type_serialization() {
        let backend_type = StorageBackendType::Consul;
        let json = serde_json::to_string(&backend_type).unwrap();
        assert_eq!(json, "\"consul\"");

        let deserialized: StorageBackendType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, StorageBackendType::Consul);
    }

    #[tokio::test]
    async fn test_create_memory_backend() {
        let backend = StorageFactory::create_memory();
        assert!(backend.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_factory_create_memory() {
        let config = StorageFactoryConfig {
            backend_type: StorageBackendType::Memory,
            ..Default::default()
        };

        let result = StorageFactory::create(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_consul_config_serialization() {
        let config = StorageFactoryConfig {
            backend_type: StorageBackendType::Consul,
            consul_config: Some(ConsulStorageConfig::default()),
            ..Default::default()
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("consul"));
    }
}
