# Integrasi Alerting ke Webhook/Email

## Contoh Integrasi Webhook (Rust)
```rust
use reqwest::Client;

pub async fn send_alert_webhook(message: &str, url: &str) {
    let client = Client::new();
    let _ = client.post(url)
        .json(&serde_json::json!({"text": message}))
        .send()
        .await;
}
```

## Contoh Integrasi Email (Rust, via SMTP)
Gunakan crate seperti `lettre` untuk mengirim email alert.

```rust
use lettre::{Message, SmtpTransport, Transport};

pub fn send_alert_email(subject: &str, body: &str, to: &str) {
    let email = Message::builder()
        .from("brankas@yourdomain.com".parse().unwrap())
        .to(to.parse().unwrap())
        .subject(subject)
        .body(body.to_string())
        .unwrap();
    let mailer = SmtpTransport::unencrypted_localhost();
    let _ = mailer.send(&email);
}
```

## Best Practice
- Gunakan webhook/email alert untuk notifikasi anomali, rotasi kunci, atau event security penting.
- Pastikan endpoint webhook/email hanya bisa diakses oleh sistem internal/terpercaya.
- Integrasikan dengan SIEM atau alerting platform (PagerDuty, Opsgenie, dsb) jika perlu.
