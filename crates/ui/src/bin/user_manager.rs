//! User Management CLI Tool
//!
//! Provides command-line interface for managing users in Secreton

use clap::{Parser, Subcommand};
use secreton_ui::auth::{PasswordPolicy, SessionService};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "secreton-user")]
#[command(about = "Secreton User Management Tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new user
    Create {
        /// Username
        #[arg(short, long)]
        username: String,

        /// Email address
        #[arg(short, long)]
        email: Option<String>,

        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Change user password
    ChangePassword {
        /// Username
        #[arg(short, long)]
        username: String,
    },

    /// List all users
    List,

    /// Show password policy requirements
    Policy,

    /// Initialize default admin user
    InitAdmin,
}

fn read_password(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let password = rpassword::read_password()?;
    Ok(password)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let auth = SessionService::new();

    match cli.command {
        Commands::Create {
            username,
            email,
            password,
        } => {
            let password = match password {
                Some(p) => p,
                None => {
                    let p1 = read_password("Enter password: ")?;
                    let p2 = read_password("Confirm password: ")?;

                    if p1 != p2 {
                        eprintln!("Passwords do not match!");
                        std::process::exit(1);
                    }
                    p1
                }
            };

            match auth
                .register_user(username.clone(), password, email.clone())
                .await
            {
                Ok(user) => {
                    println!("✓ User created successfully!");
                    println!("  Username: {}", user.username);
                    println!("  User ID: {}", user.id);
                    if let Some(email) = user.email {
                        println!("  Email: {}", email);
                    }
                    println!("  Created: {}", user.created_at);
                }
                Err(e) => {
                    eprintln!("✗ Failed to create user: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::ChangePassword { username } => {
            let old_password = read_password("Enter old password: ")?;
            let new_password = read_password("Enter new password: ")?;
            let confirm_password = read_password("Confirm new password: ")?;

            if new_password != confirm_password {
                eprintln!("Passwords do not match!");
                std::process::exit(1);
            }

            match auth
                .change_password(&username, &old_password, &new_password)
                .await
            {
                Ok(_) => {
                    println!("✓ Password changed successfully!");
                }
                Err(e) => {
                    eprintln!("✗ Failed to change password: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::List => match auth.list_users().await {
            users => {
                if users.is_empty() {
                    println!("No users found.");
                } else {
                    println!("Users:");
                    println!(
                        "{:<36} {:<20} {:<30} {:<12} {:<12}",
                        "User ID", "Username", "Email", "Active", "Superuser"
                    );
                    println!("{}", "-".repeat(110));
                    for user in users {
                        println!(
                            "{:<36} {:<20} {:<30} {:<12} {:<12}",
                            user.id, user.username, user.email, user.is_active, user.is_superuser
                        );
                    }
                }
            }
        },

        Commands::Policy => {
            let policy = PasswordPolicy::default();
            println!("Password Policy Requirements:");
            println!("  • Minimum length: {} characters", policy.min_length);
            println!(
                "  • Require uppercase: {}",
                if policy.require_uppercase {
                    "Yes"
                } else {
                    "No"
                }
            );
            println!(
                "  • Require lowercase: {}",
                if policy.require_lowercase {
                    "Yes"
                } else {
                    "No"
                }
            );
            println!(
                "  • Require numbers: {}",
                if policy.require_numbers { "Yes" } else { "No" }
            );
            println!(
                "  • Require special chars: {}",
                if policy.require_special { "Yes" } else { "No" }
            );
            println!("  • Min special chars: {}", policy.min_special_chars);
            println!("\nExample valid password: SecureP@ssw0rd123");
        }

        Commands::InitAdmin => {
            println!("Initializing default admin user...");
            println!("⚠️  WARNING: This should only be used for initial setup!");
            println!();

            let password = read_password("Enter admin password: ")?;
            let confirm = read_password("Confirm admin password: ")?;

            if password != confirm {
                eprintln!("Passwords do not match!");
                std::process::exit(1);
            }

            match auth
                .register_user(
                    "admin".to_string(),
                    password,
                    Some("admin@secreton.local".to_string()),
                )
                .await
            {
                Ok(user) => {
                    println!("✓ Admin user created successfully!");
                    println!("  Username: admin");
                    println!("  User ID: {}", user.id);
                    println!();
                    println!("🔒 IMPORTANT: Please change this password after first login!");
                }
                Err(e) => {
                    eprintln!("✗ Failed to create admin user: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
