import re

with open('crates/api/src/services/admin.rs', 'r') as f:
    text = f.read()

get_backup_code = """
    /// Get a specific backup
    pub async fn get_backup(&self, backup_id: &str) -> Result<BackupInfo, AdminError> {
        let backup_path = format!("backups/{}", backup_id);

        let entry_opt: Option<secreton_storage::SecretEntry> = self.storage.get_by_path(&backup_path).await
            .map_err(AdminError::Storage)?;

        let entry = entry_opt.ok_or_else(|| AdminError::NotFound(format!("Backup {} not found", backup_id)))?;

        let size_bytes = entry.metadata.get("data").map(|d: &String| d.len() as u64).unwrap_or(0);
        Ok(BackupInfo {
            id: backup_id.to_string(),
            created_at: entry.created_at,
            size_bytes,
            compressed: true,
            encrypted: true,
            checksum: entry.metadata.get("checksum").cloned().unwrap_or_default(),
            metadata: entry.metadata,
        })
    }

    /// Delete a backup
    pub async fn delete_backup(&self, backup_id: &str) -> Result<bool, AdminError> {
        let backup_path = format!("backups/{}", backup_id);

        let entry_opt: Option<secreton_storage::SecretEntry> = self.storage.get_by_path(&backup_path).await
            .map_err(AdminError::Storage)?;

        if let Some(entry) = entry_opt {
            self.storage.delete_by_id(entry.id).await
                .map_err(AdminError::Storage)?;
            Ok(true)
        } else {
            Err(AdminError::NotFound(format!("Backup {} not found", backup_id)))
        }
    }
"""

if "pub async fn get_backup" not in text:
    text = text.replace("    pub async fn compact_database(&self) -> Result<MaintenanceResult, AdminError> {", get_backup_code + "\n    pub async fn compact_database(&self) -> Result<MaintenanceResult, AdminError> {")

with open('crates/api/src/services/admin.rs', 'w') as f:
    f.write(text)
