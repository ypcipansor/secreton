use crate::models::approle::AppRole;
use rand::{distributions::Alphanumeric, Rng};

pub fn generate_role(policies: Vec<String>) -> AppRole {
    let role_id: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let secret_id: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    AppRole {
        role_id,
        secret_id,
        policies,
    }
}

pub fn login_approle(role: &AppRole, role_id: &str, secret_id: &str) -> bool {
    role.role_id == role_id && role.secret_id == secret_id
}

pub fn rotate_secret_id(role: &mut AppRole) {
    role.secret_id = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
}
