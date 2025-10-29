//! System monitor module for the Secreton agent

use crate::config::AgentConfig;
use crate::metrics::MetricPoint;
use secreton_core::CoreResult;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use sysinfo::{System, Disks, Networks};
use tokio::sync::mpsc;

/// System monitor for collecting system metrics
pub struct SystemMonitor {
    config: Arc<AgentConfig>,
    metrics_tx: mpsc::UnboundedSender<MetricPoint>,
    system: System,
    disks: Disks,
    networks: Networks,
    last_network_sent: u64,
    last_network_recv: u64,
    last_measurement_time: SystemTime,
}

impl SystemMonitor {
    /// Create a new system monitor
    pub async fn new(config: &AgentConfig) -> CoreResult<Self> {
        let (metrics_tx, _metrics_rx) = mpsc::unbounded_channel();
        let mut system = System::new_all();
        system.refresh_all();

        let disks = Disks::new_with_refreshed_list();
        let networks = Networks::new_with_refreshed_list();

        Ok(Self {
            config: Arc::new(config.clone()),
            metrics_tx,
            system,
            disks,
            networks,
            last_network_sent: 0,
            last_network_recv: 0,
            last_measurement_time: SystemTime::now(),
        })
    }

    /// Collect system metrics
    pub async fn collect_metrics(&mut self) -> CoreResult<()> {
        // Refresh system information
        self.system.refresh_all();

        let now = SystemTime::now();
        let time_diff = now.duration_since(self.last_measurement_time)
            .unwrap_or(Duration::from_secs(1))
            .as_secs_f64();

        // Collect CPU metrics
        self.collect_cpu_metrics()?;

        // Collect memory metrics
        self.collect_memory_metrics()?;

        // Collect disk metrics
        self.collect_disk_metrics()?;

        // Collect network metrics
        self.collect_network_metrics(time_diff)?;

        // Collect process metrics
        self.collect_process_metrics()?;

        // Collect system uptime
        self.collect_uptime_metrics()?;

        self.last_measurement_time = now;

        tracing::info!("Collected system metrics");
        Ok(())
    }

    /// Report system status
    pub async fn report_status(&mut self) -> CoreResult<()> {
        // Collect current metrics for status report
        self.collect_metrics().await?;

        // Generate status summary
        let cpu_usage = self.system.global_cpu_info().cpu_usage() as f64;
        let memory_used = self.system.used_memory() as f64;
        let memory_total = self.system.total_memory() as f64;
        let memory_usage = if memory_total > 0.0 { (memory_used / memory_total) * 100.0 } else { 0.0 };

        let status = format!(
            "System Status - CPU: {:.1}%, Memory: {:.1}%, Processes: {}",
            cpu_usage,
            memory_usage,
            self.system.processes().len()
        );

        tracing::info!("{}", status);

        // Send status as a metric
        let status_metric = MetricPoint::new(
            "system.status".to_string(),
            crate::metrics::MetricType::Gauge,
            1.0
        ).with_metadata("status_message".to_string(), status);

        if let Err(e) = self.metrics_tx.send(status_metric) {
            tracing::warn!("Failed to send status metric: {}", e);
        }

        Ok(())
    }

    fn collect_cpu_metrics(&mut self) -> CoreResult<()> {
        let cpu_usage = self.system.global_cpu_info().cpu_usage() as f64;

        let metric = MetricPoint::new(
            "system.cpu.usage_percent".to_string(),
            crate::metrics::MetricType::Gauge,
            cpu_usage
        );

        if let Err(e) = self.metrics_tx.send(metric) {
            tracing::warn!("Failed to send CPU metric: {}", e);
        }

        Ok(())
    }

    fn collect_memory_metrics(&mut self) -> CoreResult<()> {
        let total_memory = self.system.total_memory() as f64;
        let used_memory = self.system.used_memory() as f64;
        let available_memory = self.system.available_memory() as f64;

        let memory_usage_percent = if total_memory > 0.0 {
            (used_memory / total_memory) * 100.0
        } else {
            0.0
        };

        // Memory usage percentage
        let metric = MetricPoint::new(
            "system.memory.usage_percent".to_string(),
            crate::metrics::MetricType::Gauge,
            memory_usage_percent
        );
        let _ = self.metrics_tx.send(metric);

        // Total memory
        let metric = MetricPoint::new(
            "system.memory.total_bytes".to_string(),
            crate::metrics::MetricType::Gauge,
            total_memory
        );
        let _ = self.metrics_tx.send(metric);

        // Used memory
        let metric = MetricPoint::new(
            "system.memory.used_bytes".to_string(),
            crate::metrics::MetricType::Gauge,
            used_memory
        );
        let _ = self.metrics_tx.send(metric);

        // Available memory
        let metric = MetricPoint::new(
            "system.memory.available_bytes".to_string(),
            crate::metrics::MetricType::Gauge,
            available_memory
        );
        let _ = self.metrics_tx.send(metric);

        Ok(())
    }

    fn collect_disk_metrics(&mut self) -> CoreResult<()> {
        self.disks.refresh_list();

        for disk in &self.disks {
            let total_space = disk.total_space() as f64;
            let available_space = disk.available_space() as f64;
            let used_space = total_space - available_space;

            let usage_percent = if total_space > 0.0 {
                (used_space / total_space) * 100.0
            } else {
                0.0
            };

            let mount_point = disk.mount_point().to_string_lossy();

            // Disk usage percentage
            let metric = MetricPoint::new(
                format!("system.disk.{}.usage_percent", mount_point),
                crate::metrics::MetricType::Gauge,
                usage_percent
            );
            let _ = self.metrics_tx.send(metric);

            // Total disk space
            let metric = MetricPoint::new(
                format!("system.disk.{}.total_bytes", mount_point),
                crate::metrics::MetricType::Gauge,
                total_space
            );
            let _ = self.metrics_tx.send(metric);

            // Available disk space
            let metric = MetricPoint::new(
                format!("system.disk.{}.available_bytes", mount_point),
                crate::metrics::MetricType::Gauge,
                available_space
            );
            let _ = self.metrics_tx.send(metric);
        }

        Ok(())
    }

    fn collect_network_metrics(&mut self, time_diff: f64) -> CoreResult<()> {
        self.networks.refresh_list();

        let mut total_sent = 0u64;
        let mut total_recv = 0u64;

        for (_interface_name, data) in &self.networks {
            total_sent += data.transmitted();
            total_recv += data.received();
        }

        let sent_per_sec = if time_diff > 0.0 {
            ((total_sent.saturating_sub(self.last_network_sent)) as f64) / time_diff
        } else {
            0.0
        };

        let recv_per_sec = if time_diff > 0.0 {
            ((total_recv.saturating_sub(self.last_network_recv)) as f64) / time_diff
        } else {
            0.0
        };

        // Network bytes sent per second
        let metric = MetricPoint::new(
            "system.network.bytes_sent_per_sec".to_string(),
            crate::metrics::MetricType::Gauge,
            sent_per_sec
        );
        let _ = self.metrics_tx.send(metric);

        // Network bytes received per second
        let metric = MetricPoint::new(
            "system.network.bytes_received_per_sec".to_string(),
            crate::metrics::MetricType::Gauge,
            recv_per_sec
        );
        let _ = self.metrics_tx.send(metric);

        self.last_network_sent = total_sent;
        self.last_network_recv = total_recv;

        Ok(())
    }

    fn collect_process_metrics(&mut self) -> CoreResult<()> {
        let process_count = self.system.processes().len() as f64;

        let metric = MetricPoint::new(
            "system.processes.count".to_string(),
            crate::metrics::MetricType::Gauge,
            process_count
        );
        let _ = self.metrics_tx.send(metric);

        Ok(())
    }

    fn collect_uptime_metrics(&mut self) -> CoreResult<()> {
        let uptime = System::uptime() as f64;

        let metric = MetricPoint::new(
            "system.uptime.seconds".to_string(),
            crate::metrics::MetricType::Counter,
            uptime
        );
        let _ = self.metrics_tx.send(metric);

        Ok(())
    }
}
