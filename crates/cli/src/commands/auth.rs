use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct AuthCommand {
    #[command(subcommand)]
    action: AuthAction,
}

#[derive(Subcommand)]
enum AuthAction {
    /// Login to Brankas
    Login {
        /// Username
        #[arg(short, long)]
        username: Option<String>,
    },
    /// Logout from Brankas
    Logout,
    /// Show current authentication status
    Status,
    /// Create a new user
    CreateUser {
        username: String,
        #[arg(short, long)]
        admin: bool,
    },
}

impl AuthCommand {
    pub async fn run(&self) -> Result<()> {
        match &self.action {
            AuthAction::Login { username } => {
                if let Some(user) = username {
                    println!("Logging in as: {}", user);
                } else {
                    println!("Interactive login");
                }
                // TODO: Handle login
                Ok(())
            }
            AuthAction::Logout => {
                println!("Logging out");
                // TODO: Handle logout
                Ok(())
            }
            AuthAction::Status => {
                println!("Authentication status:");
                // TODO: Show auth status
                Ok(())
            }
            AuthAction::CreateUser { username, admin } => {
                println!("Creating user: {} (admin: {})", username, admin);
                // TODO: Create user
                Ok(())
            }
        }
    }
}
