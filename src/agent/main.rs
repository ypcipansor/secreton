mod config;
mod auth;
mod template;
mod runner;

use clap::Parser;
use anyhow::Result;
use log::*;
use flexi_logger::{Logger, Duplicate, Criterion, Naming, Cleanup, LogSpecification, LogTarget, WriteMode, DeferredNow, Record};

fn json_format(w: &mut dyn std::io::Write, now: &mut DeferredNow, record: &Record) -> std::io::Result<()> {
    let msg = serde_json::json!({
        "ts": now.format("%+"),
        "level": record.level().to_string(),
        "target": record.target(),
        "msg": record.args().to_string(),
    });
    writeln!(w, "{}", msg)
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Path ke file konfigurasi YAML
    #[arg(short, long, default_value = "agent.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // Baca config dulu untuk cek log_file
    let cfg = config::AgentConfig::from_file(&args.config)?;
    if let Some(ref log_file) = cfg.log_file {
        let mut logger = Logger::try_with_str(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))?
            .log_to_file()
            .duplicate_to_stdout(Duplicate::All)
            .rotate(Criterion::Size(10_000_000), Naming::Numbers, Cleanup::KeepLogFiles(5))
            .directory(std::path::Path::new(log_file).parent().unwrap_or_else(|| std::path::Path::new(".")));
        if cfg.log_format.as_deref() == Some("json") {
            logger = logger.format(json_format);
        }
        logger.start()?;
    } else {
        if cfg.log_format.as_deref() == Some("json") {
            Logger::try_with_str(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))?
                .log_to_stdout()
                .format(json_format)
                .start()?;
        } else {
            env_logger::init();
        }
    }
    info!("Vault Agent start, config: {}", args.config);
    runner::run_agent(cfg).await?;
    Ok(())
} 