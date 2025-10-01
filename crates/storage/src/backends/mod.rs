//! Storage backend implementations

pub mod file;
pub mod postgres;
pub mod raft;
pub mod redis;

// New storage backends
pub mod consul;
pub mod dynamodb;
pub mod etcd;
pub mod mysql;
pub mod s3;
pub mod cockroachdb;
pub mod cassandra;
pub mod mongodb;

// Azure and GCS backends
pub mod azure_blob;
pub mod gcs;

// Additional storage backends
pub mod aerospike;
pub mod alicloud_oss;
pub mod couchdb;
pub mod foundationdb;
pub mod manta;
pub mod mssql;
pub mod oci;
pub mod spanner;
pub mod swift;
pub mod zookeeper;
pub mod additional_backends;

pub use file::FileBackend;
pub use postgres::PostgresBackend;
pub use raft::{RaftConfig, RaftStorageBackend};
pub use redis::RedisBackend;

// Export new backends
pub use consul::{ConsulStorage, ConsulStorageConfig};
pub use dynamodb::{DynamoDBStorage, DynamoDBStorageConfig};
pub use etcd::{EtcdStorage, EtcdStorageConfig};
pub use mysql::{MySQLStorage, MySQLStorageConfig};
pub use s3::{S3Storage, S3StorageConfig};
pub use cockroachdb::CockroachDBStorage;
pub use cassandra::CassandraStorage;
pub use mongodb::MongoDBStorage;

// Export Azure and GCS backends
pub use azure_blob::{AzureBlobStorage, AzureBlobConfig};
pub use gcs::{GoogleCloudStorage, GcsConfig};

// Export additional backends
pub use aerospike::{AerospikeStorage, AerospikeConfig};
pub use alicloud_oss::{AliCloudOSSStorage, AliCloudOSSConfig};
pub use couchdb::{CouchDBStorage, CouchDBConfig};
pub use foundationdb::{FoundationDBStorage, FoundationDBConfig};
pub use manta::{MantaStorage, MantaConfig};
pub use mssql::{MSSQLStorage, MSSQLConfig};
pub use oci::{OCIStorage, OCIConfig};
pub use spanner::{SpannerStorage, SpannerConfig};
pub use swift::{SwiftStorage, SwiftConfig};
pub use zookeeper::{ZooKeeperStorage, ZooKeeperConfig};
