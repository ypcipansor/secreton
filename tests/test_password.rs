use secreton_common::utils::password::{PasswordPolicy, generate_password_with_policy};

fn main() {
    let policy = PasswordPolicy::default();
    let password = generate_password_with_policy(&policy);
    println!("Generated password: {}", password);
}
