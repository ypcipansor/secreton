//! Contoh rotasi kunci otomatis + alert webhook/email
use brankas_adhyaksa::key_rotation::KeyManager;
use tokio::time::{sleep, Duration};
use std::sync::Arc;

// Dummy: ganti dengan URL webhook/email asli
const WEBHOOK_URL: &str = "https://your-alert-webhook";

#[tokio::main]
async fn main() {
    let key_manager = Arc::new(KeyManager::new(3600)); // rotasi tiap 1 jam
    loop {
        let key = key_manager.get_key("master");
        // Simulasi: jika key baru dirotasi, kirim alert
        // (Di KeyManager, info log sudah dicetak saat rotasi)
        send_alert_webhook("Master key rotated!", WEBHOOK_URL).await;
        sleep(Duration::from_secs(3600)).await;
    }
}

async fn send_alert_webhook(message: &str, url: &str) {
    let client = reqwest::Client::new();
    let _ = client.post(url)
        .json(&serde_json::json!({"text": message}))
        .send()
        .await;
}
