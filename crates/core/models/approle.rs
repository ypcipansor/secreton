use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppRole {
    pub role_id: String,
    pub secret_id: String,
    pub policies: Vec<String>,
} 