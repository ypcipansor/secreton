//! Modul rotasi kunci otomatis & notifikasi sederhana untuk Brankas
use chrono::{DateTime, Utc, Duration};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tracing::info;

pub struct KeyManager {
    keys: Arc<Mutex<HashMap<String, (Vec<u8>, DateTime<Utc>)>>>,
    rotation_interval: Duration,
}

impl KeyManager {
    pub fn new(rotation_interval_secs: i64) -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            rotation_interval: Duration::seconds(rotation_interval_secs),
        }
    }

    pub fn get_key(&self, name: &str) -> Vec<u8> {
        let mut keys = self.keys.lock().unwrap();
        let now = Utc::now();
        let entry = keys.entry(name.to_string()).or_insert_with(|| (Self::generate_key(), now));
        // Rotasi jika sudah lewat interval
        if now - entry.1 > self.rotation_interval {
            *entry = (Self::generate_key(), now);
            info!("Key '{}' rotated at {}", name, now);
        }
        entry.0.clone()
    }

    fn generate_key() -> Vec<u8> {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }
}
