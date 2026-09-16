//! Storage backend implementations.
//!
//! `memory` and `file` are always compiled; the rest are behind features so a
//! deployment only pays for the backend it actually uses.

pub mod file;
pub mod memory;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "raft")]
pub mod raft;
#[cfg(feature = "redis")]
pub mod redis;

pub use file::FileBackend;
pub use memory::MemoryBackend;
#[cfg(feature = "postgres")]
pub use postgres::PostgresBackend;
#[cfg(feature = "raft")]
pub use raft::{RaftConfig, RaftStorageBackend};
#[cfg(feature = "redis")]
pub use redis::RedisBackend;
