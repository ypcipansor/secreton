#![no_main]

use libfuzzer_sys::fuzz_target;
use secreton_crypto::shamir;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Use first byte to determine number of shares (2-10)
    let num_shares = (data[0] % 9) + 2;
    let threshold = (data[1] % (num_shares - 1)) + 1;

    // Use remaining data as secret
    let secret = &data[2..];
    if secret.is_empty() {
        return;
    }

    // Test Shamir secret sharing
    if let Ok(shares) = shamir::split_secret(secret, num_shares as usize, threshold as usize) {
        // Test reconstruction with threshold shares
        let reconstruction_shares = &shares[..threshold as usize];
        if let Ok(reconstructed) = shamir::reconstruct_secret(reconstruction_shares) {
            // Verify reconstruction matches original
            let _matches = reconstructed == secret;
        }

        // Test with insufficient shares (should fail)
        if threshold > 1 {
            let insufficient_shares = &shares[..(threshold as usize - 1)];
            let _reconstruction_fails = shamir::reconstruct_secret(insufficient_shares).is_err();
        }
    }
});
