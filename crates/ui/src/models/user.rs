use serde::{Deserialize, Serialize};
 
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub username: String,
    pub roles: Vec<String>,
} 