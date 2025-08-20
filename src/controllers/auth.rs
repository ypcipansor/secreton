use crate::models::user::User;

pub fn authenticate_user(username: &str, password: &str) -> Option<User> {
    // Dummy logic, replace with real DB/auth
    if username == "admin" && password == "admin" {
        Some(User { username: username.to_string(), roles: vec!["admin".to_string()] })
    } else {
        None
    }
} 