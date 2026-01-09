use anyhow::Result;
use base64::prelude::*;
use clap::{Parser, Subcommand};
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

mod config;

use config::CliConfig;
use secreton_config::Config;

#[derive(Parser)]
#[command(
    name = "secreton-cli",
    about = "Command line interface for Secreton system",
    version = "1.0.0",
    author = "Secreton Team"
)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[arg(short, long, global = true)]
    config: Option<String>,

    #[arg(long, global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// System health and status commands
    Status,
    /// Configuration management
    Config {
        #[command(subcommand)]
        cmd: ConfigCommand,
    },
    /// Transit engine operations (encryption/decryption)
    Transit {
        #[command(subcommand)]
        cmd: TransitCommand,
    },
    /// KV secrets engine operations
    Secret {
        #[command(subcommand)]
        cmd: SecretCommand,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Apply a configuration file to the server
    Apply {
        /// Path to the configuration file (TOML)
        #[arg(short, long)]
        file: String,
    },
}

#[derive(Subcommand)]
enum TransitCommand {
    /// Create a new encryption key
    CreateKey { name: String },
    /// List all encryption keys
    ListKeys,
    /// Encrypt data with a key
    Encrypt {
        key: String,
        #[arg(short, long)]
        data: Option<String>,
    },
    /// Decrypt data with a key
    Decrypt {
        key: String,
        #[arg(short, long)]
        data: Option<String>,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Store a secret
    Put {
        path: String,
        #[arg(short, long)]
        data: Vec<String>, // key=value format
    },
    /// Retrieve a secret
    Get { path: String },
    /// List all secret paths
    List,
    /// Delete a secret
    Delete { path: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();

    tracing::subscriber::set_global_default(subscriber)?;

    // Load configuration
    let mut config = CliConfig::default();
    if let Some(config_path) = &cli.config {
        config = CliConfig::load_from_file(config_path)?;
    }

    // Override server URL if provided via command line
    if let Some(server_url) = &cli.server {
        config.server_url = server_url.clone();
    }

    info!("Using server: {}", config.server_url);

    // Execute commands
    match cli.command {
        Commands::Status => status_command(&config).await,
        Commands::Config { cmd } => config_command(cmd, &config).await,
        Commands::Transit { cmd } => transit_command(cmd, &config).await,
        Commands::Secret { cmd } => secret_command(cmd, &config).await,
    }
}

async fn config_command(cmd: ConfigCommand, config: &CliConfig) -> Result<()> {
    let client = reqwest::Client::new();

    match cmd {
        ConfigCommand::Apply { file } => {
            // Read file
            let content = std::fs::read_to_string(&file)?;

            // Parse as TOML to validate (and potentially convert if we wanted to support other formats,
            // but for now we just assume the server accepts what we send or we send it as a structure)
            // Note: Server endpoint expects the ApiConfig structure as JSON.
            // We should parse TOML locally and send as JSON.

            // We use serde_json::Value to avoid dependency on secreton-api which causes circular deps or missing crate issues
            let toml_value: toml::Value = toml::from_str(&content)
                .map_err(|e| anyhow::anyhow!("Failed to parse TOML config: {}", e))?;

            // Convert TOML Value to JSON Value
            // This is a bit hacky but works for transport
            let json_value: serde_json::Value = serde_json::to_value(toml_value)
                 .map_err(|e| anyhow::anyhow!("Failed to convert config to JSON: {}", e))?;

            let url = format!("{}/sys/config", config.server_url);
            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&json_value)
                .send()
                .await?;

            if response.status().is_success() {
                println!("✅ Configuration applied successfully.");
            } else {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                println!("❌ Failed to apply configuration: {} - {}", status, text);
            }
        }
    }
    Ok(())
}

async fn status_command(config: &CliConfig) -> Result<()> {
    let client = reqwest::Client::new();

    // Check health
    let health_url = format!("{}/health", config.server_url);
    let health_response = client.get(&health_url).send().await?;

    if health_response.status().is_success() {
        let health: serde_json::Value = health_response.json().await?;
        println!("🟢 Secreton Status: HEALTHY");
        println!("   Server: {}", config.server_url);
        println!(
            "   Version: {}",
            health
                .get("version")
                .unwrap_or(&serde_json::Value::String("unknown".to_string()))
        );
        println!(
            "   Timestamp: {}",
            health
                .get("timestamp")
                .unwrap_or(&serde_json::Value::String("unknown".to_string()))
        );
    } else {
        println!("🔴 Secreton Status: UNHEALTHY");
        println!("   HTTP Status: {}", health_response.status());
    }

    Ok(())
}

async fn transit_command(cmd: TransitCommand, config: &CliConfig) -> Result<()> {
    let client = reqwest::Client::new();

    match cmd {
        TransitCommand::CreateKey { name } => {
            let url = format!("{}/v1/transit/keys/{}", config.server_url, name);
            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&serde_json::json!({}))
                .send()
                .await?;

            if response.status().is_success() {
                println!("✅ Created encryption key: {}", name);
            } else {
                println!("❌ Failed to create key: {}", response.status());
            }
        }
        TransitCommand::ListKeys => {
            let url = format!("{}/v1/transit/keys", config.server_url);
            let response = client.get(&url).send().await?;

            if response.status().is_success() {
                let keys: serde_json::Value = response.json().await?;
                println!("🔑 Available encryption keys:");
                if let Some(key_list) = keys.get("keys").and_then(|k| k.as_array()) {
                    for key in key_list {
                        if let Some(key_str) = key.as_str() {
                            println!("   • {}", key_str);
                        }
                    }
                } else {
                    println!("   No keys found");
                }
            } else {
                println!("❌ Failed to list keys: {}", response.status());
            }
        }
        TransitCommand::Encrypt { key, data } => {
            let plaintext = if let Some(d) = data {
                d
            } else {
                // Read from stdin if no data provided
                use std::io::Read;
                let mut buffer = String::new();
                std::io::stdin().read_to_string(&mut buffer)?;
                buffer.trim().to_string()
            };

            // Base64 encode the plaintext
            let encoded_data = BASE64_STANDARD.encode(plaintext.as_bytes());

            let url = format!("{}/v1/transit/encrypt/{}", config.server_url, key);
            let payload = serde_json::json!({
                "plaintext": encoded_data
            });

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(ciphertext) = result.get("ciphertext").and_then(|c| c.as_str()) {
                    println!("🔐 Encrypted data:");
                    println!("{}", ciphertext);
                }
            } else {
                println!("❌ Failed to encrypt: {}", response.status());
            }
        }
        TransitCommand::Decrypt { key, data } => {
            let ciphertext = if let Some(d) = data {
                d
            } else {
                use std::io::Read;
                let mut buffer = String::new();
                std::io::stdin().read_to_string(&mut buffer)?;
                buffer.trim().to_string()
            };

            let url = format!("{}/v1/transit/decrypt/{}", config.server_url, key);
            let payload = serde_json::json!({
                "ciphertext": ciphertext
            });

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(plaintext_b64) = result.get("plaintext").and_then(|p| p.as_str()) {
                    // Base64 decode the result
                    let decoded = BASE64_STANDARD.decode(plaintext_b64)?;
                    let plaintext = String::from_utf8(decoded)?;
                    println!("🔓 Decrypted data:");
                    println!("{}", plaintext);
                }
            } else {
                println!("❌ Failed to decrypt: {}", response.status());
            }
        }
    }

    Ok(())
}

async fn secret_command(cmd: SecretCommand, config: &CliConfig) -> Result<()> {
    let client = reqwest::Client::new();

    match cmd {
        SecretCommand::Put { path, data } => {
            // Parse key=value pairs
            let mut secret_data = serde_json::Map::new();
            for pair in data {
                if let Some((key, value)) = pair.split_once('=') {
                    secret_data.insert(
                        key.to_string(),
                        serde_json::Value::String(value.to_string()),
                    );
                } else {
                    println!("❌ Invalid format '{}'. Use key=value format.", pair);
                    return Ok(());
                }
            }

            let url = format!("{}/v1/secret/data/{}", config.server_url, path);
            let payload = serde_json::json!({
                "data": secret_data
            });

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(version) = result.get("version").and_then(|v| v.as_u64()) {
                    println!("✅ Secret stored at path '{}' (version {})", path, version);
                } else {
                    println!("✅ Secret stored at path '{}'", path);
                }
            } else {
                println!("❌ Failed to store secret: {}", response.status());
            }
        }
        SecretCommand::Get { path } => {
            let url = format!("{}/v1/secret/data/{}", config.server_url, path);
            let response = client.get(&url).send().await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(data) = result.get("data") {
                    println!("🔍 Secret at path '{}':", path);
                    println!("{}", serde_json::to_string_pretty(data)?);
                }
                if let Some(version) = result.get("version").and_then(|v| v.as_u64()) {
                    println!("Version: {}", version);
                }
            } else if response.status() == 404 {
                println!("❌ Secret not found at path '{}'", path);
            } else {
                println!("❌ Failed to retrieve secret: {}", response.status());
            }
        }
        SecretCommand::List => {
            let url = format!("{}/v1/secrets", config.server_url);
            let response = client.get(&url).send().await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(secrets) = result.get("keys").and_then(|s| s.as_array()) {
                    println!("📋 Available secrets:");
                    for secret in secrets {
                        if let Some(path) = secret.as_str() {
                            println!("   • {}", path);
                        }
                    }
                } else {
                    println!("📋 No secrets found");
                }
            } else {
                println!("❌ Failed to list secrets: {}", response.status());
            }
        }
        SecretCommand::Delete { path } => {
            let url = format!("{}/v1/secret/data/{}", config.server_url, path);
            let response = client.delete(&url).send().await?;

            if response.status().is_success() {
                println!("✅ Secret deleted at path '{}'", path);
            } else if response.status() == 404 {
                println!("❌ Secret not found at path '{}'", path);
            } else {
                println!("❌ Failed to delete secret: {}", response.status());
            }
        }
    }

    Ok(())
}
