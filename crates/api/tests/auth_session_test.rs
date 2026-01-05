#[cfg(test)]
mod tests {
    use secreton_api::services::auth::{AuthenticationService, Session};
    use secreton_storage::{MockStorageBackend, QueryParams, SecretEntry, StorageBackend};
    use secreton_api::config::AuthConfig;
    use std::sync::Arc;
    use secreton_api::services::crypto::CryptoService;
    use chrono::Utc;

    #[tokio::test]
    async fn test_session_lifecycle() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let config = AuthConfig::default();
        let auth_service = AuthenticationService::new(storage.clone(), crypto, &config).await.expect("Failed to create auth service");

        // 1. Initial State
        let count = auth_service.get_active_session_count().await.expect("Failed to get count");
        assert_eq!(count, 0, "Initial session count should be 0");

        // 2. Login (create session simulation)
        let session_id = "test-session-1";
        let user_id = "user-1";
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(1);

        let session = Session {
            id: session_id.to_string(),
            user_id: user_id.to_string(),
            token: "fake-token".to_string(),
            refresh_token: None,
            ip_address: "127.0.0.1".to_string(),
            user_agent: "test".to_string(),
            created_at: now,
            expires_at,
            last_accessed: now,
        };

        let session_data = serde_json::to_vec(&session).unwrap();
        let entry = SecretEntry::new(
            format!("sys/auth/sessions/{}", session_id),
            session_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            uuid::Uuid::new_v4(),
        ).with_expiration(expires_at);

        storage.store(&entry).await.expect("Failed to store session");

        // 3. Verify count
        let count = auth_service.get_active_session_count().await.expect("Failed to get count");
        assert_eq!(count, 1, "Session count should be 1 after manual insertion");

        // 4. Create expired session
        let expired_session_id = "test-session-expired";
        let expired_at = now - chrono::Duration::hours(1);

        let expired_session = Session {
            id: expired_session_id.to_string(),
            ..session.clone()
        };

        let expired_data = serde_json::to_vec(&expired_session).unwrap();
        let expired_entry = SecretEntry::new(
            format!("sys/auth/sessions/{}", expired_session_id),
            expired_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            uuid::Uuid::new_v4(),
        ).with_expiration(expired_at);

        storage.store(&expired_entry).await.expect("Failed to store expired session");

        // 5. Verify count again (MockStorageBackend filters expired by default in count/list unless specified)
        let count = auth_service.get_active_session_count().await.expect("Failed to get count");
        assert_eq!(count, 1, "Session count should still be 1 (ignoring expired)");

        // 6. Cleanup expired sessions
        let deleted = auth_service.cleanup_expired_sessions().await.expect("Failed to cleanup");
        assert_eq!(deleted, 1, "Should have deleted 1 expired session");

        // 7. Verify storage content
        let params = QueryParams {
            path_prefix: Some("sys/auth/sessions/".to_string()),
            include_expired: true,
            ..Default::default()
        };
        let entries = storage.list(&params).await.expect("Failed to list");
        assert_eq!(entries.len(), 1, "Should only have 1 session left in storage");
        assert_eq!(entries[0].path, format!("sys/auth/sessions/{}", session_id));
    }
}
