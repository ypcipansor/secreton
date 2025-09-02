use chrono::Utc;
use std::fs::OpenOptions;
use std::io::Write;

pub trait AuditDevice: Send + Sync {
    fn log(&self, user: &str, action: &str, path: &str, status: &str);
}

pub enum AuditDeviceType {
    Db,
    File(String),
    // Syslog, Socket, dsb bisa ditambah
}

pub struct DbAuditDevice;
impl AuditDevice for DbAuditDevice {
    fn log(&self, user: &str, action: &str, path: &str, status: &str) {
        // Panggil log_audit DB lama
        crate::services::audit::log_audit_db(user, action, path, status);
    }
}

pub struct FileAuditDevice {
    pub file: String,
}
impl AuditDevice for FileAuditDevice {
    fn log(&self, user: &str, action: &str, path: &str, status: &str) {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file)
            .unwrap();
        let line = format!("{} {} {} {} {}\n", Utc::now(), user, action, path, status);
        let _ = f.write_all(line.as_bytes());
    }
}

// Fungsi utama log_audit
pub fn log_audit(
    devices: &[Box<dyn AuditDevice>],
    user: &str,
    action: &str,
    path: &str,
    status: &str,
) {
    for dev in devices {
        dev.log(user, action, path, status);
    }
}

// Fungsi lama untuk DB
pub fn log_audit_db(_user: &str, _action: &str, _path: &str, _status: &str) {
    // ... existing DB logic ...
}

#[async_trait::async_trait]
pub trait ExternalAuditDevice: Send + Sync {
    async fn send_audit(&self, event: &str, user: &str, resource: &str, status: &str);
}

pub struct WebhookAuditDevice {
    pub url: String,
}

#[async_trait::async_trait]
impl ExternalAuditDevice for WebhookAuditDevice {
    async fn send_audit(&self, event: &str, user: &str, resource: &str, status: &str) {
        let payload = serde_json::json!({
            "event": event,
            "user": user,
            "resource": resource,
            "status": status
        });
        let _ = reqwest::Client::new()
            .post(&self.url)
            .json(&payload)
            .send()
            .await;
    }
}

// Tambahkan ke log_audit agar broadcast ke device eksternal
pub async fn log_audit_external(
    devices: &[Box<dyn ExternalAuditDevice>],
    event: &str,
    user: &str,
    resource: &str,
    status: &str,
) {
    for device in devices {
        device.send_audit(event, user, resource, status).await;
    }
}
