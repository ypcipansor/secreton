#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::random;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Test random number generation with different sizes
    let size = (data[0] as usize % 1024) + 1; // 1-1024 bytes
    let _random_bytes = random::generate_random_bytes(size);

    // Test secure random generation
    let _secure_random = random::generate_secure_random(size);

    // Test random number generation with seed
    let seed = &data[..32.min(data.len())];
    let _seeded_random = random::generate_random_with_seed(seed, size);

    // Test multiple random generations to check for patterns
    let mut randoms = Vec::new();
    for _ in 0..10 {
        randoms.push(random::generate_random_bytes(32));
    }

    // Check that random values are different (with very high probability)
    let mut all_different = true;
    for i in 0..randoms.len() {
        for j in (i+1)..randoms.len() {
            if randoms[i] == randoms[j] {
                all_different = false;
                break;
            }
        }
    }
    let _random_values_unique = all_different;

    // Test random string generation
    let string_length = (data[1] as usize % 100) + 1;
    let _random_string = random::generate_random_string(string_length);

    // Test random password generation
    let password_length = (data[2] as usize % 50) + 8; // 8-57 characters
    let _random_password = random::generate_random_password(password_length);

    // Test entropy estimation
    if let Ok(random_data) = random::generate_random_bytes(1000) {
        let _entropy = random::estimate_entropy(&random_data);
    }
});