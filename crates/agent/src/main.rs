use secreton_agent::run_agent;
use secreton_domain::SecretonError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct AgentStatus {
    version: String,
    uptime: Duration,
    status: String,
}

#[tokio::main]
async fn main() -> Result<(), SecretonError> {
    run_agent().await
}
