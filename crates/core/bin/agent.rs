use clap::Parser;
use reqwest::Client;
use std::fs;
use std::time::Duration;
use tokio::time::sleep;
use handlebars::Handlebars;

#[derive(Parser, Debug)]
#[command(name = "vault-agent")]
struct Args {
    #[arg(long)]
    vault_addr: String,
    #[arg(long)]
    username: String,
    #[arg(long)]
    password: String,
    #[arg(long, default_value = "./vault_token.txt")]
    token_file: String,
    #[arg(long, default_value = "300")]
    renew_interval: u64, // detik
    #[arg(long)]
    template_file: Option<String>,
    #[arg(long)]
    output_file: Option<String>,
    #[arg(long)]
    secret_path: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = Client::new();
    // Login
    let resp = client.post(format!("{}/v1/auth/login", args.vault_addr))
        .json(&serde_json::json!({"username": args.username, "password": args.password}))
        .send().await?;
    let json: serde_json::Value = resp.json().await?;
    let token = json.get("token").and_then(|v| v.as_str()).unwrap_or("");
    fs::write(&args.token_file, token)?;
    println!("[Agent] Token tersimpan di {}", args.token_file);
    // Template rendering (sekali di awal)
    if let (Some(tmpl), Some(out), Some(secret_path)) = (&args.template_file, &args.output_file, &args.secret_path) {
        let secret_resp = client.get(format!("{}/v1/secrets/{}", args.vault_addr, secret_path))
            .bearer_auth(token)
            .send().await?;
        let secret_json: serde_json::Value = secret_resp.json().await?;
        let template = fs::read_to_string(tmpl)?;
        let mut hbs = Handlebars::new();
        hbs.register_template_string("tpl", template)?;
        let rendered = hbs.render("tpl", &secret_json)?;
        fs::write(out, rendered)?;
        println!("[Agent] Template rendered ke {}", out);
    }
    // Auto-renew loop
    loop {
        sleep(Duration::from_secs(args.renew_interval)).await;
        let resp = client.post(format!("{}/v1/auth/renew", args.vault_addr))
            .bearer_auth(token)
            .send().await?;
        if resp.status().is_success() {
            println!("[Agent] Token renewed");
        } else {
            println!("[Agent] Token renew failed: {}", resp.status());
        }
    }
} 