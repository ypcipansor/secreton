/// Hash password using Argon2id via crypto service
pub fn hash_password(password: &str) -> String {
    use secreton_crypto::hashing::HashingService;
    
    HashingService::hash_password_argon2(password)
        .map(|r| r.hash)
        .unwrap_or_else(|e| {
            eprintln!("Password hashing failed: {}", e);
            String::new()
        })
}

/// Verify password using Argon2id via crypto service
pub fn verify_password(hash: &str, password: &str) -> bool {
    use secreton_crypto::hashing::HashingService;
    
    HashingService::verify_password_argon2(password, hash)
        .unwrap_or(false)
}
