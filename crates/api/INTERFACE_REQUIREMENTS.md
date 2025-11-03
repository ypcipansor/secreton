# Service Interface Requirements

This document outlines the required methods for service implementations used by the API handlers.

## Authentication Service Interface

The authentication service (`AuthenticationService`) must implement the following methods:

### Session Management
```rust
async fn invalidate_token(&self, token: &str) -> Result<(), AuthError>;
async fn extract_session_id(&self, token: &str) -> Result<String, AuthError>;
async fn list_user_sessions(&self, user_id: &str, current_session_id: &str) -> Result<Vec<SessionInfo>, AuthError>;
async fn revoke_session(&self, user_id: &str, session_id: &str) -> Result<(), AuthError>;
```

### MFA Operations
```rust
async fn setup_mfa(&self, user_id: &str, method: &str, phone: Option<&str>, email: Option<&str>) -> Result<MfaSetupResponse, AuthError>;
async fn verify_mfa(&self, user_id: &str, method: &str, code: &str, backup_code: Option<&str>) -> Result<bool, AuthError>;
async fn disable_mfa(&self, user_id: &str) -> Result<String, AuthError>;
```

### OAuth Operations
```rust
async fn store_oauth_state(&self, state: &str, provider: &str, expiry: chrono::Duration) -> Result<(), AuthError>;
async fn verify_oauth_state(&self, state: &str, provider: &str) -> Result<(), AuthError>;
async fn get_oauth_authorization_url(&self, provider: &str, state: &str) -> Result<String, AuthError>;
async fn exchange_oauth_code(&self, provider: &str, code: &str) -> Result<String, AuthError>;
async fn fetch_oauth_user_info(&self, provider: &str, access_token: &str) -> Result<OAuthUserInfo, AuthError>;
async fn oauth_login(&self, user_info: &OAuthUserInfo) -> Result<User, AuthError>;
```

### Security Checks
```rust
async fn check_password_policy_compliance(&self) -> Result<Vec<String>, AuthError>;
async fn check_default_credentials(&self) -> Result<bool, AuthError>;
```

## Vault Service Interface

The vault service must implement the following methods:

### Secret Operations with Metadata
```rust
async fn list_secrets_with_metadata(&self, filter: Option<&str>, user_id: &str) -> Result<Vec<SecretListItem>, VaultError>;
```

### Key Operations
```rust
async fn get_public_key(&self, key_id: &str) -> Result<String, VaultError>;
```

### Encryption/Decryption with Version
```rust
async fn decrypt_with_version(&self, key_id: &str, ciphertext: &str, user_id: &str) -> Result<(Vec<u8>, u32), VaultError>;
```

### Signing Operations
```rust
async fn sign(&self, key_id: &str, data: &str, algorithm: &str, user_id: &str) -> Result<(String, u32), VaultError>;
async fn verify(&self, key_id: &str, data: &str, signature: &str, user_id: &str) -> Result<(bool, u32), VaultError>;
```

## Storage Backend Interface

The storage backend must implement these extended methods beyond the base `StorageBackend` trait:

### Statistics and Monitoring
```rust
async fn count_entries(&self, prefix: &str) -> Result<u64, StorageError>;
async fn get_total_size(&self) -> Result<u64, StorageError>;
async fn get_cache_hit_rate(&self) -> Result<f64, StorageError>;
```

### Maintenance Operations
```rust
async fn cleanup_expired_entries(&self) -> Result<u64, StorageError>;
async fn compact(&self) -> Result<u64, StorageError>;
```

### Backup Operations
```rust
async fn create_backup(&self, backup_id: &str) -> Result<BackupResult, StorageError>;
async fn list_backups(&self) -> Result<Vec<BackupInfo>, StorageError>;
async fn restore_backup(&self, backup_id: &str) -> Result<RestoreResult, StorageError>;
```

### Configuration Management
```rust
async fn set_config(&self, key: &str, value: &serde_json::Value) -> Result<(), StorageError>;
async fn get_config_bool(&self, key: &str) -> Result<bool, StorageError>;
```

### Security Features
```rust
async fn get_expiring_keys(&self, days: u32) -> Result<Vec<String>, StorageError>;
```

## Audit Logger Interface

The audit logger must implement:

```rust
async fn get_request_rate_per_minute(&self) -> Result<f64, AuditError>;
async fn get_recent_failed_authentications(&self, hours: u32) -> Result<Vec<String>, AuditError>;
async fn detect_unusual_access_patterns(&self, days: u32) -> Result<Vec<String>, AuditError>;
```

## Implementation Status

### ✅ Fully Implemented in Handlers
- All handler code assumes these interfaces exist
- Handlers delegate business logic to services
- Proper error handling and audit logging

### ⚠️ Service Implementation Required
These interfaces define the contract that service implementations must fulfill. If a service
doesn't implement these methods, compilation will fail with clear error messages indicating
which methods are missing.

### Migration Strategy

For existing code:
1. Review the interface requirements above
2. Implement missing methods in service layers
3. Ensure proper error handling in all implementations
4. Add tests for each implemented method

For new features:
1. Define the interface requirement in this document
2. Implement in service layer
3. Use from handlers
4. Add integration tests

## Notes

- All async methods should use proper error types (`Result<T, E>`)
- Methods should log important operations for audit purposes
- Use proper authentication/authorization checks in service implementations
- Consider caching where appropriate for performance
- Handle graceful degradation for optional features
