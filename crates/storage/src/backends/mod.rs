//! Storage backend implementations

pub mod file;
pub mod postgres;
pub mod raft;
pub mod redis;

// New storage backends
pub mod consul;
pub mod etcd;

pub use file::FileBackend;
pub use postgres::PostgresBackend;
pub use raft::{RaftConfig, RaftStorageBackend};
pub use redis::RedisBackend;

// Export new backends
pub use consul::{ConsulStorage, ConsulStorageConfig};
pub use etcd::{EtcdStorage, EtcdStorageConfig};
