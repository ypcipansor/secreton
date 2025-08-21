use crate::services::plugin::{VaultPlugin, PluginRegistry};
use std::any::Any;

pub struct KmsPlugin;

impl VaultPlugin for KmsPlugin {
    fn name(&self) -> &'static str { "kms" }
    fn version(&self) -> &'static str { "1.0.0" }
    fn register(&self, registry: &mut PluginRegistry) {
        registry.register(Box::new(Self));
    }
}

impl KmsPlugin {
    pub fn encrypt_with_kms(&self, plaintext: &str, key_id: &str) -> String {
        // Dummy: prepend key_id, base64 encode
        format!("kms:{}:{}", key_id, base64::encode(plaintext))
    }
    pub fn decrypt_with_kms(&self, ciphertext: &str, key_id: &str) -> Option<String> {
        // Dummy: check prefix, base64 decode
        let prefix = format!("kms:{}:", key_id);
        if ciphertext.starts_with(&prefix) {
            let b64 = &ciphertext[prefix.len()..];
            base64::decode(b64).ok().and_then(|v| String::from_utf8(v).ok())
        } else {
            None
        }
    }
    pub fn as_any(&self) -> &dyn Any { self }
} 