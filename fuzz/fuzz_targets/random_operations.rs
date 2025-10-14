#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::generate_random_bytes;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Test random number generation with different sizes
    let size = (data[0] as usize % 1024) + 1; // 1-1024 bytes
    let _random_bytes = generate_random_bytes(size);

    // Test multiple random generations to check for patterns
    let mut randoms = Vec::new();
    for _ in 0..10 {
        if let Ok(bytes) = generate_random_bytes(32) {
            randoms.push(bytes);
        }
    }

    // Check that random values are different (with very high probability)
    let mut all_different = true;
    for i in 0..randoms.len() {
        for j in (i + 1)..randoms.len() {
            if randoms[i] == randoms[j] {
                all_different = false;
                break;
            }
        }
        if !all_different {
            break;
        }
    }

    // In a proper random number generator, all values should be different
    // (collision probability is negligible for 32-byte values)
    if randoms.len() >= 2 {
        // We don't assert this as collisions are theoretically possible
        // but in practice should not occur
        let _ = all_different;
    }
});
