/// SDK libraries module for Secreton
///
/// This module provides SDK implementations for various programming languages
/// and platforms including Go, Python, TypeScript/JavaScript, and Kubernetes.

pub mod types;
pub mod go_sdk;
pub mod python_sdk;
pub mod js_sdk;
pub mod kubernetes;
pub mod generator;

// Re-export common types and traits
pub use types::{SdkConfig, SdkOperationResult, SdkResponse, SdkSecret, SecretonSdk};

// Re-export SDK clients
pub use go_sdk::GoSdkClient;
pub use python_sdk::PythonSdkClient;
pub use js_sdk::JsSdkClient;

// Re-export Kubernetes operator
pub use kubernetes::{KubernetesOperator, KubernetesOperatorConfig};

// Re-export generator utilities
pub use generator::SdkGenerator;

// Re-export SDK generation functions for convenience
pub use go_sdk::generate_go_sdk;
pub use python_sdk::generate_python_sdk;
pub use js_sdk::generate_typescript_sdk;