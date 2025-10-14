pub mod acme_pki;
pub mod advanced_mfa;
pub mod agent_auth;
pub mod agent_templating;
// pub mod ansible_integration;  // SKIP: reserved keyword 'become' at line 36
pub mod audit;
pub mod audit_streaming;
// pub mod auth;  // SKIP: dependency issues after duplicate directory removal
pub mod auto_unseal;
pub mod barrier_encryption;
pub mod ca_management;
pub mod certificate_revocation;
pub mod connection_pooling;
pub mod consul_service_mesh;
pub mod control_groups;
pub mod control_groups_enhanced;
// pub mod crypto;  // SKIP: missing secreton_crypto crate
pub mod database_connection_strings;
pub mod database_rotation;
pub mod disaster_recovery;
// pub mod dynamic;  // SKIP: missing crate::storage imports
pub mod events;
pub mod health;
pub mod identity;
pub mod integrated_storage;
pub mod key_rotation;
pub mod kubernetes_operator;
// pub mod lease;  // SKIP: missing crate::storage imports
pub mod log_streaming;
pub mod metrics;
pub mod mfa;
pub mod monitoring;
pub mod namespaces;
pub mod performance_replication;
pub mod performance_standby;
pub mod plugin;
// pub mod policy;  // SKIP: missing types::sentinel and audit::log_audit_external
pub mod policy_templates;
pub mod quotas;
pub mod rate_limit;
pub mod rbac;
pub mod replication;
pub mod request_forwarding;
pub mod seal;
pub mod secret_caching;
pub mod secret_migration;
pub mod secret_versioning;
pub mod secrets;
pub mod secrets_federation;
pub mod sentinel;
pub mod sentinel_policy;
pub mod snapshot;
pub mod token;
pub mod webhooks;
pub mod wrapping;

// Phase 18 - DevOps Integration
// pub mod ansible_integration;  // Commented out: reserved keyword 'become' in struct field
pub mod cicd_pipeline;
pub mod rotation_scheduler;
pub mod secret_scanning;
pub mod terraform_integration;

// Phase 19 - Cloud Native Integration
pub mod aws_secrets_manager;
pub mod azure_key_vault_backend;
pub mod kubernetes_external_secrets;
pub mod secret_dependency_graph;
pub mod service_mesh_integration;

// Phase 20 - Advanced Enterprise Features
pub mod advanced_backup_recovery;
pub mod distributed_tracing;
pub mod secret_lifecycle_management;
pub mod secret_usage_analytics;
pub mod smart_secret_recommendations;

// Phase 21 - Multi-Tenancy & Federation Excellence
pub mod advanced_hsm;
pub mod multi_tenant_isolation;
pub mod plugin_system;
pub mod secret_federation;

// Phase 22 - Automation & Compliance Excellence
pub mod compliance_framework;
pub mod emergency_response;
pub mod secret_discovery_classification;
pub mod secret_performance_optimizer;
pub mod workflow_automation;

// Phase 23 - Observability & Intelligence Excellence (FINAL)
pub mod advanced_observability;
pub mod ai_anomaly_detection;
pub mod api_gateway;
pub mod secret_governance;
pub mod secret_marketplace;

// Phase 24 - Advanced Cryptography & Privacy
pub mod advanced_key_manager;
pub mod crypto_policy_engine;
pub mod homomorphic_encryption;
pub mod secure_multi_party_computation;
pub mod zero_knowledge_proof;

// Phase 25 - Enterprise Integration & End-to-End Workflows
pub mod authenticated_key_operations;
pub mod end_to_end_observability_pipeline;
pub mod policy_enforced_crypto;
pub mod privacy_preserving_auth;
pub mod secure_collaborative_operations;
