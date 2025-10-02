use libloading::{Library, Symbol};
use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

pub trait VaultPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn register(&self, registry: &mut PluginRegistry);
    fn init(&mut self) {}
    fn shutdown(&mut self) {}
    fn reload(&mut self) {}
    fn as_any(&self) -> &dyn Any;
}

pub trait SecretEnginePlugin: VaultPlugin {
    fn handle_secret(&self, action: &str, params: &serde_json::Value) -> serde_json::Value;
}

pub trait AuthPlugin: VaultPlugin {
    fn authenticate(&self, params: &serde_json::Value) -> bool;
}

pub trait AuditPlugin: VaultPlugin {
    fn audit(&self, event: &serde_json::Value);
}

/// Plugin manifest for signature verification
/// SECURITY: Every plugin must have a .manifest file alongside the .so/.dll
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// SHA-256 hash of the plugin binary
    pub sha256_hash: String,
    /// Ed25519 signature of the hash (signed by trusted key)
    pub signature: String,
    /// Public key fingerprint used for signing
    pub public_key_fingerprint: String,
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn VaultPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }
    pub fn register(&mut self, plugin: Box<dyn VaultPlugin>) {
        self.plugins.insert(plugin.name().to_string(), plugin);
    }
    pub fn get(&self, name: &str) -> Option<&dyn VaultPlugin> {
        self.plugins.get(name).map(|plugin| plugin.as_ref())
    }
    pub fn list(&self) -> Vec<String> {
        self.plugins.keys().cloned().collect()
    }
    pub fn unload(&mut self, name: &str) {
        if let Some(mut plugin) = self.plugins.remove(name) {
            plugin.shutdown();
        }
    }
    pub fn reload(&mut self, name: &str) {
        if let Some(plugin) = self.plugins.get_mut(name) {
            plugin.reload();
        }
    }
    pub fn load(&mut self, mut plugin: Box<dyn VaultPlugin>) {
        let name = plugin.name().to_string();
        plugin.init();
        self.plugins.insert(name, plugin);
    }

    /// Verify plugin signature before loading
    /// SECURITY FIX: Prevents loading of untrusted/malicious plugins
    fn verify_plugin_signature(
        plugin_path: &str,
        manifest_path: &str,
        trusted_public_keys: &[VerifyingKey],
    ) -> Result<(), String> {
        // 1. Read manifest file
        let manifest_content = fs::read_to_string(manifest_path)
            .map_err(|e| format!("Failed to read manifest: {}", e))?;
        
        let manifest: PluginManifest = serde_json::from_str(&manifest_content)
            .map_err(|e| format!("Invalid manifest format: {}", e))?;

        // 2. Calculate SHA-256 hash of plugin binary
        let plugin_bytes = fs::read(plugin_path)
            .map_err(|e| format!("Failed to read plugin: {}", e))?;
        
        let mut hasher = Sha256::new();
        hasher.update(&plugin_bytes);
        let calculated_hash = hex::encode(hasher.finalize());

        // 3. Verify hash matches manifest
        if calculated_hash != manifest.sha256_hash {
            return Err(format!(
                "Plugin hash mismatch! Expected: {}, Got: {}",
                manifest.sha256_hash, calculated_hash
            ));
        }

        // 4. Verify Ed25519 signature
        let signature_bytes = hex::decode(&manifest.signature)
            .map_err(|e| format!("Invalid signature hex: {}", e))?;
        
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| format!("Invalid signature format: {}", e))?;

        // 5. Try all trusted public keys (at least one must verify)
        let mut verified = false;
        for public_key in trusted_public_keys {
            if public_key.verify(manifest.sha256_hash.as_bytes(), &signature).is_ok() {
                verified = true;
                break;
            }
        }

        if !verified {
            return Err("Plugin signature verification failed! No trusted key could verify the signature.".to_string());
        }

        Ok(())
    }

    /// Load a dynamic library plugin with signature verification
    /// # Safety
    /// This function is unsafe because it loads dynamic libraries and calls foreign code.
    /// The caller must ensure that:
    /// - The path points to a valid dynamic library
    /// - The library exports a `plugin_entry` function with the correct signature
    /// - The loaded plugin is memory-safe and ABI-compatible
    /// 
    /// # Security
    /// SECURITY FIX: Now requires Ed25519 signature verification before loading
    /// - Plugin must have accompanying .manifest file with signature
    /// - Hash of binary must match manifest
    /// - Signature must be valid from trusted public key
    pub unsafe fn load_dynamic_library(
        &mut self,
        path: &str,
        trusted_public_keys: &[VerifyingKey],
    ) -> Result<(), String> {
        // SECURITY: Verify signature before loading
        let manifest_path = format!("{}.manifest", path);
        
        if !Path::new(&manifest_path).exists() {
            return Err(format!(
                "SECURITY: Plugin manifest not found at {}. All plugins must have signed manifests.",
                manifest_path
            ));
        }

        Self::verify_plugin_signature(path, &manifest_path, trusted_public_keys)?;

        // Only load if signature verification passed
        let lib = Library::new(path).map_err(|e| format!("load error: {}", e))?;
        
        // Konvensi: plugin expose fn plugin_entry() -> Box<dyn VaultPlugin>
        let func: Symbol<unsafe extern "C" fn() -> Box<dyn VaultPlugin>> = lib
            .get(b"plugin_entry")
            .map_err(|e| format!("symbol error: {}", e))?;
        
        let mut plugin = func();
        let name = plugin.name().to_string();
        plugin.init();
        self.plugins.insert(name, plugin);
        
        // Note: lib harus disimpan jika ingin unload, di sini drop langsung (plugin tetap hidup di registry)
        Ok(())
    }
}
