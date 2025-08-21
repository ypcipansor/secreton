use crate::models::secret::Secret;

pub fn get_secret_list() -> Vec<Secret> {
    // Dummy data, replace with DB
    vec![
        Secret { path: "myapp/db".to_string(), version: 1, data: serde_json::json!({"user": "dbuser"}) },
        Secret { path: "service/redis".to_string(), version: 1, data: serde_json::json!({"host": "localhost"}) },
    ]
} 