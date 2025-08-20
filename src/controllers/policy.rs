use crate::models::policy::Policy;
 
pub fn check_policy(user: &str, path: &str, action: &str) -> bool {
    // Dummy logic, replace with real policy check
    user == "admin" && action == "read"
} 