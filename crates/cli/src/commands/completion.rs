use anyhow::Result;
use clap::{Args, ValueEnum};
use clap_complete::{generate, Generator, Shell};
use std::io;

#[derive(Args)]
pub struct CompletionCommand {
    /// Shell to generate completions for
    #[arg(value_enum)]
    shell: Shell,
}

impl CompletionCommand {
    pub async fn run(&self) -> Result<()> {
        let mut app = crate::Cli::command();
        generate(self.shell, &mut app, "brankas", &mut io::stdout());
        Ok(())
    }
}
