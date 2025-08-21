use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod commands;
mod config;
mod output;

use commands::*;

#[derive(Parser)]
#[command(
    name = "brankas",
    about = "Brankas Advanced Security System CLI",
    version,
    long_about = "Command-line interface for managing Brankas vaults, secrets, and security policies."
)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[arg(short, long, global = true)]
    quiet: bool,

    #[arg(long, global = true)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init(InitCommand),
    /// Manage vault configuration
    Config(ConfigCommand),
    /// Manage secrets
    Secret(SecretCommand),
    /// Manage security policies
    Policy(PolicyCommand),
    /// Authentication operations
    Auth(AuthCommand),
    /// Generate shell completions
    Completion(CompletionCommand),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let level = if cli.quiet {
        Level::ERROR
    } else if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    info!("Brankas CLI starting");

    match cli.command {
        Commands::Init(cmd) => cmd.run().await,
        Commands::Config(cmd) => cmd.run().await,
        Commands::Secret(cmd) => cmd.run().await,
        Commands::Policy(cmd) => cmd.run().await,
        Commands::Auth(cmd) => cmd.run().await,
        Commands::Completion(cmd) => cmd.run().await,
    }
}
