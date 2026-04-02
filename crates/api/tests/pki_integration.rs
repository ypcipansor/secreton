#[cfg(test)]
mod tests {
    use secreton_api::services::crypto::CryptoService;
    use secreton_api::services::pki::PkiPersistentService;
    use secreton_secrets_pki::CertificateRequest;
    use secreton_storage::{MockStorageBackend, StorageBackend};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_pki_persistent_flow() {
        // 1. Setup Mock Storage and Crypto
        // Set root key for crypto service auto-unseal
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());

        // 2. Initialize Service
        let service = PkiPersistentService::new(storage.clone(), crypto.clone());
        service.ensure_initialized().await.unwrap();

        // 3. Verify initially uninitialized (no CA)
        let ca_pem = service.get_ca_pem().await.unwrap();
        assert!(ca_pem.is_none());

        // 4. Generate Root CA
        let response = service
            .generate_root_ca("Test Root CA", "Test Org")
            .await
            .unwrap();
        let cert = response.certificate.clone();
        let key = response.private_key;
        assert!(!cert.is_empty());
        assert!(!key.is_empty());

        // 5. Verify CA is persisted and retrievable
        let ca_pem_after = service.get_ca_pem().await.unwrap();
        assert!(ca_pem_after.is_some());
        assert_eq!(ca_pem_after.unwrap(), cert);

        // 6. Verify Persistence across "restarts" (new service instance)
        let service2 = PkiPersistentService::new(storage.clone(), crypto.clone());
        service2.ensure_initialized().await.unwrap();
        let ca_pem_restored = service2.get_ca_pem().await.unwrap();
        assert!(ca_pem_restored.is_some());
        assert_eq!(ca_pem_restored.unwrap(), cert);

        // 7. Issue Certificate
        let req = CertificateRequest {
            common_name: "test.example.com".to_string(),
            alt_names: vec![],
            ip_addresses: vec![],
            email_addresses: vec![],
            organization: Some("Test Org".to_string()),
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
            key_usages: vec![],
            extended_key_usages: vec![],
            ttl: Some(3600),
        };

        let issued = service.issue_certificate(req).await.unwrap();
        assert!(issued.serial_number.len() >= 15 && issued.serial_number.len() <= 16); // Random hex
        assert!(!issued.certificate.is_empty());
        assert!(!issued.private_key.is_empty());

        // 8. Verify Issued Cert is stored (check storage directly)
        let cert_path = format!("sys/pki/certs/{}", issued.serial_number);
        let stored_cert = storage.get_by_path(&cert_path).await.unwrap();
        assert!(stored_cert.is_some());
    }
}
