/// Hash password using Argon2id via crypto service
pub fn hash_password(password: &str) -> String {
    use crate::hashing::password::hash_password_argon2;

    hash_password_argon2(password)
        .map(|r| r.hash)
        .unwrap_or_else(|e| {
            eprintln!("Password hashing failed: {}", e);
            String::new()
        })
}

/// Verify password using Argon2id via crypto service
pub fn verify_password(hash: &str, password: &str) -> bool {
    use crate::hashing::password::verify_password_argon2;

    verify_password_argon2(password, hash).unwrap_or(false)
}
