use secreton_common::*;

fn main() {
    // Test crypto utilities
    let token = crypto::generate_secure_token(32);
    println!("Generated token: {}", token);

    // Test string utilities
    let sanitized = string::sanitize_input("test input").unwrap();
    println!("Sanitized input: {}", sanitized);

    // Test validation utilities
    let is_valid = validation::is_valid_email("test@example.com");
    println!("Email valid: {}", is_valid);

    // Test time utilities
    let now = time::now_utc();
    println!("Current time: {}", now);

    // Test network utilities
    let is_ipv4 = network::is_valid_ipv4("192.168.1.1");
    println!("Is IPv4: {}", is_ipv4);

    // Test system utilities
    let is_docker = system::is_docker();
    println!("Is Docker: {}", is_docker);

    // Test collections utilities
    let items = vec!["a".to_string(), "b".to_string(), "a".to_string()];
    let deduplicated = collections::deduplicate(items);
    println!("Deduplicated: {:?}", deduplicated);

    println!("All utilities working correctly!");
}
