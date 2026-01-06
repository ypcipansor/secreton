// Secret Versioning & Audit Trail Module - Maximum Security, Zero Trust, Forever Secret

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256}; // Add SHA256 import for cryptographic hashing
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub version: u64,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub diff: Option<String>, // Optional: diff from previous version
    pub audit_id: String,     // Link to audit log entry
    pub hash: String,         // Hash of this version for chain verification
    pub previous_hash: Option<String>, // Hash of previous version for tamper-evidence
    pub deleted: bool,        // Soft deletion flag
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretHistory {
    pub name: String,
    pub versions: BTreeMap<u64, SecretVersion>, // version -> SecretVersion
    pub current_version: u64,
}

impl SecretHistory {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            versions: BTreeMap::new(),
            current_version: 0,
        }
    }

    pub fn put_secret(
        &mut self,
        value: String,
        created_by: String,
        diff: Option<String>,
        audit_id: String,
    ) -> u64 {
        self.current_version += 1;
        let version = self.current_version;
        let previous_version = self.versions.get(&self.current_version);
        let mut hasher = Sha256::new();
        hasher.update(&created_by);
        hasher.update(Utc::now().timestamp().to_string());
        hasher.update(&value);
        if let Some(prev_version) = previous_version {
            hasher.update(prev_version.hash.as_bytes());
        }
        let hash = format!("{:x}", hasher.finalize());
        let secret_version = SecretVersion {
            version,
            value,
            created_at: Utc::now(),
            created_by,
            diff,
            audit_id,
            hash,
            previous_hash: previous_version.map(|sv| sv.hash.clone()),
            deleted: false,
        };
        self.versions.insert(version, secret_version);
        version
    }

    pub fn get_secret(&self, version: Option<u64>) -> Option<&SecretVersion> {
        match version {
            Some(v) => self.versions.get(&v),
            None => self.versions.get(&self.current_version),
        }
    }

    pub fn list_versions(&self) -> Vec<u64> {
        self.versions.keys().cloned().collect()
    }

    pub fn rollback(&mut self, version: u64, by: String, audit_id: String) -> Option<u64> {
        if let Some(secret) = self.versions.get(&version) {
            let rollback_value = secret.value.clone();
            Some(self.put_secret(
                rollback_value,
                by,
                Some(format!("rollback to v{}", version)),
                audit_id,
            ))
        } else {
            None
        }
    }

    /// Securely delete a secret version by overwriting data and marking as deleted
    pub fn delete_secret(&mut self, version: u64) -> bool {
        if let Some(secret) = self.versions.get_mut(&version) {
            if !secret.deleted {
                // Overwrite value with random bytes for secure deletion
                let random_data: String = (0..secret.value.len())
                    .map(|_| rand::random::<u8>() as char)
                    .collect();
                secret.value = random_data;
                secret.deleted = true;
                true
            } else {
                false // Already deleted
            }
        } else {
            false // Version not found
        }
    }

    /// Verify the integrity of the hash chain
    pub fn verify_chain(&self) -> bool {
        for (version, secret) in &self.versions {
            if *version == 1 {
                // First version has no previous hash to check
                continue;
            }

            // Check that previous_hash matches the actual previous version's hash
            if let Some(prev_hash) = &secret.previous_hash {
                if let Some(prev_version) = self.versions.get(&(version - 1)) {
                    if prev_hash != &prev_version.hash {
                        return false; // Chain broken
                    }
                } else {
                    return false; // Previous version missing
                }
            } else {
                return false; // Missing previous hash
            }
        }
        true
    }
}
