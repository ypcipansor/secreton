use crate::models::lease::Lease;
use crate::storage::Storage;
use anyhow::Result;
use chrono::{Utc, Duration};
use uuid::Uuid;

pub async fn create_lease(storage: &Storage, user: &str, resource: &str, resource_type: &str, ttl_secs: i64) -> Result<Lease> {
    let now = Utc::now();
    let lease = Lease {
        id: Uuid::new_v4().to_string(),
        user: user.to_string(),
        resource: resource.to_string(),
        resource_type: resource_type.to_string(),
        issued_at: now,
        expired_at: now + Duration::seconds(ttl_secs),
        status: "active".to_string(),
        namespace: "default".to_string(),
    };
    storage.create_lease_db(&lease).await?;
    Ok(lease)
}

pub async fn renew_lease(storage: &Storage, lease_id: &str, ttl_secs: i64) -> Result<Lease> {
    if let Some(mut lease) = storage.get_lease_db(lease_id).await? {
        if lease.status != "active" {
            anyhow::bail!("Lease tidak aktif");
        }
        lease.expired_at = Utc::now() + Duration::seconds(ttl_secs);
        storage.update_lease_db(&lease).await?;
        Ok(lease)
    } else {
        anyhow::bail!("Lease tidak ditemukan");
    }
}

pub async fn revoke_lease(storage: &Storage, lease_id: &str) -> Result<()> {
    if let Some(lease) = storage.get_lease_db(lease_id).await? {
        // Integrasi ke dynamic secrets: revoke credential jika perlu
        match lease.resource_type.as_str() {
            "db" => {
                // TODO: implementasi revoke credential database
                log::info!("Revoke DB credential for resource: {}", lease.resource);
            },
            "aws" => {
                // TODO: implementasi revoke credential AWS
                log::info!("Revoke AWS credential for resource: {}", lease.resource);
            },
            "api_key" => {
                // TODO: implementasi revoke API key
                log::info!("Revoke API key for resource: {}", lease.resource);
            },
            _ => {}
        }
        storage.revoke_lease_db(lease_id).await?;
        crate::services::audit::log_audit(&[], &lease.user, "lease_revoke", &lease.id, "success");
        Ok(())
    } else {
        anyhow::bail!("Lease tidak ditemukan");
    }
}

pub async fn get_expired_leases(storage: &Storage) -> Result<Vec<Lease>> {
    storage.get_expired_leases().await
} 