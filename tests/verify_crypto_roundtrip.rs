#!/usr/bin/env -S cargo +nightly -Zscript
//! ```cargo
//! [package]
//! name = "crypto-roundtrip-verification"
//! version = "0.1.0"
//! edition = "2021"
//!
//! [dependencies]
//! secreton-core = { path = "../secreton/crates/core" }
//! secreton-crypto = { path = "../secreton/crates/crypto" }
//! num-bigint = "0.4"
//! serde_json = "1.0"
//! tokio = { version = "1.0", features = ["full"] }
//! ```

use num_bigint::BigUint;
use secreton_core::secrets::engine::shamir::*;
use secreton_core::secrets::engine::shamir::shamir_math::*;
use secreton_crypto::pqc::*;
use std::str::FromStr;

fn main() {
    println!("🔐 Verifying Cryptographic Round-Trip Properties");
    println!("================================================\n");

    // Test PQC ML-KEM encapsulation/decapsulation
    test_pqc_mlkem_roundtrip();

    // Test Shamir Secret Sharing round-trip
    test_shamir_roundtrip();

    println!("\n✅ All round-trip tests passed!");
}

fn test_pqc_mlkem_roundtrip() {
    println!("🔄 Testing PQC ML-KEM Round-Trip...");

    // Create ML-KEM provider
    let provider = PQCRegistry::create_mlkem_provider(MLKemVariant::MLKem512);

    // Generate keypair
    let (public_key, private_key) = provider.keypair_generate().unwrap();

    // Alice encapsulates
    let (alice_secret, ciphertext) = provider.encapsulate(&public_key).unwrap();

    // Bob decapsulates
    let bob_secret = provider.decapsulate(&ciphertext, &private_key).unwrap();

    // Verify exact equality
    assert_eq!(alice_secret, bob_secret, "PQC ML-KEM round-trip failed!");

    println!("  ✅ ML-KEM-512: {} bytes shared secret", alice_secret.len());
    println!("  ✅ Encapsulation/decapsulation round-trip verified");
}

fn test_shamir_roundtrip() {
    println!("🔄 Testing Shamir Secret Sharing Round-Trip...");

    // Test parameters
    let original_secret = BigUint::from_str("12345678901234567890").unwrap();
    let threshold = 3;
    let prime = generate_safe_prime(256).unwrap();

    // Create polynomial with secret as constant term
    let polynomial = ShamirPolynomial::new(&original_secret, threshold, &prime).unwrap();

    // Generate shares (points)
    let mut points = Vec::new();
    for i in 1..=5 {
        let x = BigUint::from(i as u64);
        let y = polynomial.evaluate(&x).unwrap();
        points.push((x, y));
    }

    // Reconstruct using threshold shares
    let reconstructed_secret = LagrangeInterpolator::interpolate(&points[..threshold], &prime).unwrap();

    // Verify exact equality - CRITICAL ROUND-TRIP PROPERTY
    assert_eq!(original_secret, reconstructed_secret, "Shamir round-trip failed!");

    println!("  ✅ Shamir (3,5): {} -> {}", original_secret, reconstructed_secret);
    println!("  ✅ Secret sharing/reconstruction round-trip verified");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comprehensive_crypto_verification() {
        main();
    }
}
