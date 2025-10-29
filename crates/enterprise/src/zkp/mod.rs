//! Zero-Knowledge Proof Module
//!
//! Advanced privacy-preserving authentication and cryptographic protocols
//! for enterprise-grade security requirements.

pub mod privacy_preserving_auth;
pub mod zero_knowledge_proof;

// Re-export main types
pub use privacy_preserving_auth::*;
pub use zero_knowledge_proof::*;