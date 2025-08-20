use anyhow::{Result, Context};
use tera::{Tera, Context as TeraContext};
use std::fs;
use std::path::Path;
use log::*;

pub async fn render_template(source: &str, dest: &str, token: &str, server_url: &str) -> Result<()> {
    let url = format!("{}/v1/secrets/{}", server_url.trim_end_matches('/'), source.trim_start_matches('/'));
    let client = reqwest::Client::new();
    let resp = client.get(&url)
        .bearer_auth(token)
        .send()
        .await
        .context("Gagal request ke Vault")?;
    if !resp.status().is_success() {
        let err = resp.text().await.unwrap_or_default();
        bail!("Gagal fetch secret: {}", err);
    }
    let secret_json: serde_json::Value = resp.json().await.context("Gagal parsing secret JSON")?;
    // Coba cari file template: dest + ".tpl"
    let tpl_path = format!("{}.tpl", dest);
    let rendered = if Path::new(&tpl_path).exists() {
        let tpl_str = fs::read_to_string(&tpl_path).context("Gagal baca file template")?;
        let mut tera = Tera::default();
        tera.add_raw_template("tpl", &tpl_str)?;
        let mut ctx = TeraContext::new();
        if let Some(obj) = secret_json.as_object() {
            for (k, v) in obj {
                ctx.insert(k, v);
            }
        }
        tera.render("tpl", &ctx)?
    } else {
        // Jika tidak ada template, render raw JSON
        serde_json::to_string_pretty(&secret_json)?
    };
    fs::write(dest, rendered).context("Gagal tulis file hasil render")?;
    info!("Template {} dirender ke {}", source, dest);
    Ok(())
} 