use crate::config::{AgentConfig, TemplateConfig};
use anyhow::Result;
use log::*;
use crate::auth::{login_userpass, login_approle, login_k8s};
use crate::template::render_template;
use tokio::time::{sleep, Duration, Instant};
use std::fs;
use std::process::{Command, Child};
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
#[cfg(windows)]
use notify::{Watcher, RecommendedWatcher, RecursiveMode, EventKind};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration as StdDuration;
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;
use axum::{Router, routing::get, response::Json as AxumJson};
use serde::Serialize;
use std::sync::Mutex as StdMutex;
use std::net::SocketAddr;
use std::io::Write as IoWrite;

#[derive(Serialize, Clone, Default)]
struct HealthStatus {
    status: String,
    token_valid: bool,
    child_running: bool,
    last_error: Option<String>,
}

pub async fn run_agent(cfg: AgentConfig) -> Result<()> {
    info!("Agent config: {:?}", cfg);
    let config_path = std::env::args().find(|a| a.ends_with(".yaml") || a.ends_with(".yml")).unwrap_or_else(|| "agent.yaml".to_string());
    let reload_flag = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        let reload_flag = reload_flag.clone();
        tokio::spawn(async move {
            let mut sighup = signal(SignalKind::hangup()).expect("Gagal listen SIGHUP");
            while sighup.recv().await.is_some() {
                reload_flag.store(true, Ordering::SeqCst);
                info!("SIGHUP diterima, akan reload config pada siklus berikutnya");
            }
        });
    }
    #[cfg(windows)]
    {
        let reload_flag = reload_flag.clone();
        let config_path_clone = config_path.clone();
        thread::spawn(move || {
            let (tx, rx) = mpsc::channel();
            let mut watcher: RecommendedWatcher = notify::recommended_watcher(tx).expect("Gagal inisialisasi watcher");
            watcher.watch(&config_path_clone, RecursiveMode::NonRecursive).expect("Gagal watch config");
            let mut last_reload = SystemTime::now();
            loop {
                if let Ok(event) = rx.recv() {
                    if let Ok(EventKind::Modify(_)) = event.kind {
                        // Hindari reload beruntun (debounce 1 detik)
                        if last_reload.elapsed().unwrap_or_default().as_secs() > 1 {
                            reload_flag.store(true, Ordering::SeqCst);
                            info!("Config file berubah (Windows), reload pada siklus berikutnya");
                            last_reload = SystemTime::now();
                        }
                    }
                }
            }
        });
    }
    let mut cfg = cfg;
    let mut token = String::new();
    let mut token_expiry: Option<Instant> = None;
    let mut expires_in_secs: Option<u64> = None;
    let mut login = |cfg: &AgentConfig| async move {
        let servers = if let Some(urls) = &cfg.server_urls {
            if !urls.is_empty() { urls.clone() } else { vec![cfg.server_url.clone()] }
        } else {
            vec![cfg.server_url.clone()]
        };
        let mut last_err = None;
        for server in servers {
            let res = match cfg.auth_method.as_str() {
                "userpass" => {
                    let username = cfg.auth_config.get("username").and_then(|v| v.as_str()).unwrap_or("");
                    let password = cfg.auth_config.get("password").and_then(|v| v.as_str()).unwrap_or("");
                    if username.is_empty() || password.is_empty() {
                        error!("Config userpass: username/password wajib diisi");
                        return Err(anyhow::anyhow!("Config userpass: username/password wajib diisi"));
                    }
                    login_userpass_with_expiry(username, password, &server).await
                },
                "approle" => {
                    let role_id = cfg.auth_config.get("role_id").and_then(|v| v.as_str()).unwrap_or("");
                    let secret_id = cfg.auth_config.get("secret_id").and_then(|v| v.as_str()).unwrap_or("");
                    if role_id.is_empty() || secret_id.is_empty() {
                        error!("Config approle: role_id/secret_id wajib diisi");
                        return Err(anyhow::anyhow!("Config approle: role_id/secret_id wajib diisi"));
                    }
                    login_approle(role_id, secret_id, &server).await
                },
                "k8s" => {
                    let jwt_path = cfg.auth_config.get("jwt_path").and_then(|v| v.as_str()).unwrap_or("/var/run/secrets/kubernetes.io/serviceaccount/token");
                    let role = cfg.auth_config.get("role").and_then(|v| v.as_str()).unwrap_or("");
                    if role.is_empty() {
                        error!("Config k8s: role wajib diisi");
                        return Err(anyhow::anyhow!("Config k8s: role wajib diisi"));
                    }
                    login_k8s(jwt_path, role, &server).await
                },
                _ => {
                    error!("auth_method {} belum didukung", cfg.auth_method);
                    return Err(anyhow::anyhow!("auth_method {} belum didukung", cfg.auth_method));
                }
            };
            match res {
                Ok((token, exp)) => {
                    info!("Login sukses ke server {}", server);
                    return Ok((token, exp, server));
                },
                Err(e) => {
                    error!("Login gagal ke server {}: {}", server, e);
                    send_notify(&cfg, "login_failed", &format!("Login gagal ke server {}: {}", server, e)).await;
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Semua server gagal login")))
    };
    let mut sink_token = |cfg: &AgentConfig, token: &str| -> Option<Child> {
        match &cfg.sink {
            Some(sinks) => {
                let sinks: Vec<&str> = sinks.split(',').map(|s| s.trim()).collect();
                for sink in sinks {
                    match sink {
                        "file" => {
                            let path = "token.txt";
                            if let Err(e) = fs::write(path, token) {
                                error!("Gagal menulis token ke file {}: {}", path, e);
                            } else {
                                info!("Token disimpan ke file {}", path);
                            }
                        },
                        "env" => {
                            let path = ".env";
                            let content = format!("VAULT_TOKEN={}\n", token);
                            if let Err(e) = fs::write(path, content) {
                                error!("Gagal menulis token ke file {}: {}", path, e);
                            } else {
                                info!("Token disimpan ke file {} (format env)", path);
                            }
                        },
                        "child" => {
                            if let Some(run) = &cfg.run {
                                if !run.is_empty() {
                                    let mut cmd = Command::new(&run[0]);
                                    if run.len() > 1 {
                                        cmd.args(&run[1..]);
                                    }
                                    cmd.env("VAULT_TOKEN", token);
                                    match cmd.spawn() {
                                        Ok(child) => {
                                            info!("Child process dijalankan: {:?} (PID: {})", run, child.id());
                                            return Some(child);
                                        },
                                        Err(e) => {
                                            error!("Gagal menjalankan child process {:?}: {}", run, e);
                                        }
                                    }
                                }
                            }
                        },
                        _ => {},
                    }
                }
            },
            None => {},
        }
        None
    };
    let mut spawn_and_monitor_child = |cfg: AgentConfig, token: String| {
        let run = cfg.run.clone();
        let restart = cfg.restart_child.unwrap_or(false);
        let delay = cfg.restart_delay.unwrap_or(5);
        if let Some(run) = run {
            if !run.is_empty() {
                tokio::spawn(async move {
                    loop {
                        let mut cmd = Command::new(&run[0]);
                        if run.len() > 1 {
                            cmd.args(&run[1..]);
                        }
                        cmd.env("VAULT_TOKEN", &token);
                        match cmd.spawn() {
                            Ok(mut child) => {
                                info!("Child process dijalankan: {:?} (PID: {})", run, child.id());
                                match child.wait() {
                                    Ok(status) => {
                                        error!("Child process exit dengan status: {}", status);
                                        send_notify(&cfg, "child_exit", &format!("Child process exit dengan status: {}", status)).await;
                                    },
                                    Err(e) => {
                                        error!("Gagal wait child process: {}", e);
                                        send_notify(&cfg, "child_exit", &format!("Gagal wait child process: {}", e)).await;
                                    }
                                }
                            },
                            Err(e) => {
                                error!("Gagal menjalankan child process {:?}: {}", run, e);
                                send_notify(&cfg, "child_spawn_failed", &format!("Gagal menjalankan child process {:?}: {}", run, e)).await;
                            }
                        }
                        if restart {
                            info!("Restart child process dalam {} detik...", delay);
                            tokio::time::sleep(Duration::from_secs(delay)).await;
                        } else {
                            break;
                        }
                    }
                });
            }
        }
    };
    // Login pertama
    let (t, exp, active_server) = login(&cfg).await?;
    token = t;
    let mut active_server = active_server;
    if let Some(sink) = &cfg.sink {
        if sink.contains("child") {
            spawn_and_monitor_child(cfg.clone(), token.clone());
        } else {
            sink_token(&cfg, &token);
        }
    } else {
        sink_token(&cfg, &token);
    }
    if let Some(secs) = exp {
        token_expiry = Some(Instant::now() + Duration::from_secs(secs));
        expires_in_secs = Some(secs);
    }
    if let Some(interval) = cfg.interval {
        info!("Agent mode: interval {} detik", interval);
        // Status monitoring
        let health_status = Arc::new(StdMutex::new(HealthStatus::default()));
        let health_status_clone = health_status.clone();
        tokio::spawn(async move {
            let app = Router::new().route("/healthz", get(move || {
                let status = health_status_clone.lock().unwrap().clone();
                AxumJson(status)
            }));
            let addr = SocketAddr::from(([0, 0, 0, 0], 9900));
            axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
        });
        loop {
            // Reload config jika flag aktif
            if reload_flag.load(Ordering::SeqCst) {
                match AgentConfig::from_file(&config_path) {
                    Ok(new_cfg) => {
                        info!("Config berhasil di-reload dari {}", config_path);
                        cfg = new_cfg;
                        reload_flag.store(false, Ordering::SeqCst);
                    },
                    Err(e) => {
                        error!("Gagal reload config: {}", e);
                        send_notify(&cfg, "reload_failed", &format!("Gagal reload config: {}", e)).await;
                    }
                }
            }
            // Auto-renew jika sisa waktu < 10% interval
            if let (Some(expiry), Some(ttl)) = (token_expiry, expires_in_secs) {
                let now = Instant::now();
                let remain = expiry.saturating_duration_since(now).as_secs();
                if remain < (ttl / 10).max(30) {
                    info!("Token hampir expired (sisa {} detik), login ulang...", remain);
                    match login(&cfg).await {
                        Ok((t, exp, server)) => {
                            token = t;
                            active_server = server;
                            if let Some(sink) = &cfg.sink {
                                if sink.contains("child") {
                                    spawn_and_monitor_child(cfg.clone(), token.clone());
                                } else {
                                    sink_token(&cfg, &token);
                                }
                            } else {
                                sink_token(&cfg, &token);
                            }
                            if let Some(secs) = exp {
                                token_expiry = Some(Instant::now() + Duration::from_secs(secs));
                                expires_in_secs = Some(secs);
                            }
                            info!("Token berhasil diperbarui");
                        },
                        Err(e) => error!("Auto-renew token gagal: {}", e),
                    }
                }
            }
            for tpl in &cfg.templates {
                match render_template(&tpl.source, &tpl.dest, &token, &active_server).await {
                    Ok(_) => info!('[interval] Render template {} -> {} sukses', tpl.source, tpl.dest),
                    Err(e) => error!('[interval] Render template {} gagal: {}', tpl.source, e),
                }
            }
            sleep(Duration::from_secs(interval)).await;
        }
    } else {
        for tpl in &cfg.templates {
            match render_template(&tpl.source, &tpl.dest, &token, &active_server).await {
                Ok(_) => info!("Render template {} -> {} sukses", tpl.source, tpl.dest),
                Err(e) => error!("Render template {} gagal: {}", tpl.source, e),
            }
        }
    }
    Ok(())
}

async fn send_notify(cfg: &AgentConfig, event: &str, message: &str) {
    if let Some(notify) = &cfg.notify {
        if let Some(webhook) = &notify.webhook {
            let payload = serde_json::json!({
                "event": event,
                "message": message,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });
            let client = reqwest::Client::new();
            let _ = client.post(webhook)
                .json(&payload)
                .send()
                .await;
        }
    }
}

async fn write_audit_event(cfg: &AgentConfig, event: &str, message: &str) {
    if let Some(audit_file) = &cfg.audit_file {
        let mut file = match std::fs::OpenOptions::new().create(true).append(true).open(audit_file) {
            Ok(f) => f,
            Err(e) => {
                error!("Gagal buka file audit {}: {}", audit_file, e);
                return;
            }
        };
        let payload = serde_json::json!({
            "event": event,
            "message": message,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        if let Err(e) = writeln!(file, "{}", payload) {
            error!("Gagal tulis event audit: {}", e);
        }
    }
}

// Helper: login_userpass yang return (token, expires_in)
pub async fn login_userpass_with_expiry(username: &str, password: &str, server_url: &str) -> Result<(String, Option<u64>)> {
    let url = format!("{}/v1/auth/login", server_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client.post(&url)
        .json(&serde_json::json!({"username": username, "password": password}))
        .send()
        .await?;
    if !resp.status().is_success() {
        let err = resp.text().await.unwrap_or_default();
        anyhow::bail!("Login userpass gagal: {}", err);
    }
    let login: serde_json::Value = resp.json().await?;
    let token = login.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let expires_in = login.get("expires_in").and_then(|v| v.as_u64());
    Ok((token, expires_in))
} 