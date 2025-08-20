use crate::services::plugin::{VaultPlugin, PluginRegistry};
use std::any::Any;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng, generic_array::GenericArray};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

pub struct SopsFilePlugin;

impl VaultPlugin for SopsFilePlugin {
    fn name(&self) -> &'static str { "sops_file" }
    fn version(&self) -> &'static str { "1.0.0" }
    fn register(&self, registry: &mut PluginRegistry) {
        registry.register(Box::new(Self));
    }
}

impl SopsFilePlugin {
    pub fn encrypt_file(&self, content: &str, key: &[u8]) -> String {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12 bytes
        let ciphertext = cipher.encrypt(&nonce, content.as_bytes()).unwrap();
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        BASE64.encode(&out)
    }
    pub fn decrypt_file(&self, content: &str, key: &[u8]) -> Option<String> {
        let data = BASE64.decode(content).ok()?;
        if data.len() < 12 { return None; }
        let (nonce, ciphertext) = data.split_at(12);
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let plaintext = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext).ok()?;
        String::from_utf8(plaintext).ok()
    }
    pub fn as_any(&self) -> &dyn Any { self }
} 