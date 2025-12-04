use secreton_agent::run_agent;
use secreton_errors::SecretonError;

#[tokio::main]
async fn main() -> Result<(), SecretonError> {
    run_agent().await
}
