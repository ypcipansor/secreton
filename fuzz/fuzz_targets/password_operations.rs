#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_core::services::auth::password;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Split data into password and salt
    let password_data = &data[..data.len() / 2];
    let salt_data = &data[data.len() / 2..];

    if password_data.is_empty() {
        return;
    }

    let password_str = String::from_utf8_lossy(password_data);

    // Test password hashing
    if let Ok(hash) = password::hash_password(&password_str) {
        // Test password verification
        let _is_valid = password::verify_password(&password_str, &hash);

        // Test with wrong password
        let wrong_password = format!("{}x", password_str);
        let _is_invalid = !password::verify_password(&wrong_password, &hash);
    }

    // Test password hashing with custom parameters
    let cost = (data[0] % 10) + 4; // 4-13
    if let Ok(hash_custom) = password::hash_password_with_cost(&password_str, cost) {
        let _is_valid_custom = password::verify_password(&password_str, &hash_custom);
    }

    // Test password strength checking
    let _strength = password::check_password_strength(&password_str);

    // Test password policy validation
    let policy = password::PasswordPolicy {
        min_length: 8,
        require_uppercase: true,
        require_lowercase: true,
        require_digits: true,
        require_special: false,
    };
    let _policy_compliant = password::validate_password_policy(&password_str, &policy);

    // Test multiple password hashing algorithms
    let _bcrypt_hash = password::hash_with_bcrypt(&password_str);
    let _argon2_hash = password::hash_with_argon2(&password_str);

    // Test hash format detection
    if let Ok(hash) = password::hash_password(&password_str) {
        let _format = password::detect_hash_format(&hash);
    }
});
