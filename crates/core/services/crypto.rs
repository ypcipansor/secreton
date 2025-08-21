pub fn hash_password(password: &str) -> String {
    format!("hashed-{}", password)
}
 
pub fn verify_password(hash: &str, password: &str) -> bool {
    hash == &format!("hashed-{}", password)
} 