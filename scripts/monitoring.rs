//! Script monitoring & alerting sederhana untuk Brankas
use std::time::Duration;
use tokio::time::sleep;
use brankas_adhyaksa::audit::{AuditLogger, AuditStatus};

/// Contoh: alert jika ada 5x gagal akses secret dalam 1 menit
pub async fn monitor_audit_log(audit_logger: &AuditLogger) {
    loop {
        let logs = audit_logger.backends.iter().flat_map(|b| {
            if let Some(mem) = b.downcast_ref::<brankas_adhyaksa::audit::MemoryBackend>() {
                mem.logs()
            } else { vec![] }
        }).collect::<Vec<_>>();
        let failed: Vec<_> = logs.iter().filter(|l| l.status == AuditStatus::Denied).collect();
        if failed.len() >= 5 {
            println!("[ALERT] Terdeteksi {} akses gagal ke secret!", failed.len());
            // TODO: Integrasi ke email/webhook/alert eksternal
        }
        sleep(Duration::from_secs(60)).await;
    }
}
