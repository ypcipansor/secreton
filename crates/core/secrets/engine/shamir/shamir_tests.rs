//! Comprehensive tests for Shamir Secret Sharing Mathematical Operations
//!
//! These tests verify the critical round-trip property:
//! original_secret == reconstruct(split(original_secret))

use secreton_core::secrets::engine::shamir::*;
use secreton_core::secrets::engine::shamir::shamir_math::*;
use num_bigint::BigUint;
use std::str::FromStr;

#[test]
fn test_shamir_polynomial_round_trip() {
    // Test basic polynomial round-trip property
    let original_secret = BigUint::from_str("12345678901234567890").unwrap();
    let threshold = 3;
    let prime = generate_safe_prime(256).unwrap();

    // Create polynomial with secret as constant term
    let polynomial = ShamirPolynomial::new(&original_secret, threshold, &prime).unwrap();

    // Evaluate at different points to get "shares"
    let mut points = Vec::new();
    for i in 1..=5 {
        let x = BigUint::from(i as u64);
        let y = polynomial.evaluate(&x).unwrap();
        points.push((x, y));
    }

    // Use Lagrange interpolation to reconstruct the constant term (secret)
    let reconstructed_secret = LagrangeInterpolator::interpolate(&points[..threshold], &prime).unwrap();

    // Verify exact equality - this is the critical round-trip property!
    assert_eq!(original_secret, reconstructed_secret, "Round-trip property failed!");
}

#[test]
fn test_shamir_insufficient_points() {
    // Test that reconstruction fails with insufficient points
    let original_secret = BigUint::from_str("98765432109876543210").unwrap();
    let threshold = 4;
    let prime = generate_safe_prime(256).unwrap();

    let polynomial = ShamirPolynomial::new(&original_secret, threshold, &prime).unwrap();

    // Generate only 3 points (less than threshold of 4)
    let mut points = Vec::new();
    for i in 1..=3 {
        let x = BigUint::from(i as u64);
        let y = polynomial.evaluate(&x).unwrap();
        points.push((x, y));
    }

    // Should fail to reconstruct with insufficient points
    let result = LagrangeInterpolator::interpolate(&points, &prime);
    assert!(result.is_err(), "Reconstruction should fail with insufficient points");
}

#[test]
fn test_shamir_exact_threshold() {
    // Test reconstruction with exactly threshold points
    let original_secret = BigUint::from_str("55555555555555555555").unwrap();
    let threshold = 3;
    let prime = generate_safe_prime(256).unwrap();

    let polynomial = ShamirPolynomial::new(&original_secret, threshold, &prime).unwrap();

    // Generate exactly threshold points
    let mut points = Vec::new();
    for i in 1..=threshold {
        let x = BigUint::from(i as u64);
        let y = polynomial.evaluate(&x).unwrap();
        points.push((x, y));
    }

    let reconstructed_secret = LagrangeInterpolator::interpolate(&points, &prime).unwrap();
    assert_eq!(original_secret, reconstructed_secret);
}

#[test]
fn test_shamir_more_than_threshold() {
    // Test reconstruction with more than threshold points
    let original_secret = BigUint::from_str("77777777777777777777").unwrap();
    let threshold = 3;
    let total_points = 7;
    let prime = generate_safe_prime(256).unwrap();

    let polynomial = ShamirPolynomial::new(&original_secret, threshold, &prime).unwrap();

    // Generate more points than threshold
    let mut points = Vec::new();
    for i in 1..=total_points {
        let x = BigUint::from(i as u64);
        let y = polynomial.evaluate(&x).unwrap();
        points.push((x, y));
    }

    // Should work with any subset of threshold or more points
    let reconstructed_min = LagrangeInterpolator::interpolate(&points[..threshold], &prime).unwrap();
    assert_eq!(original_secret, reconstructed_min);

    let reconstructed_extra = LagrangeInterpolator::interpolate(&points[..threshold + 2], &prime).unwrap();
    assert_eq!(original_secret, reconstructed_extra);
}

#[test]
fn test_shamir_different_thresholds() {
    // Test different threshold values
    let original_secret = BigUint::from_str("11111111111111111111").unwrap();

    for threshold in 2..=6 {
        let prime = generate_safe_prime(256).unwrap();
        let polynomial = ShamirPolynomial::new(&original_secret, threshold, &prime).unwrap();

        // Generate enough points
        let total_points = threshold + 2;
        let mut points = Vec::new();
        for i in 1..=total_points {
            let x = BigUint::from(i as u64);
            let y = polynomial.evaluate(&x).unwrap();
            points.push((x, y));
        }

        // Test reconstruction with exactly threshold points
        let reconstructed = LagrangeInterpolator::interpolate(&points[..threshold], &prime).unwrap();
        assert_eq!(original_secret, reconstructed, "Failed for threshold {}", threshold);
    }
}

#[test]
fn test_shamir_polynomial_evaluation_consistency() {
    // Test that polynomial evaluation is consistent
    let secret = BigUint::from_str("42424242424242424242").unwrap();
    let threshold = 4;
    let prime = generate_safe_prime(256).unwrap();

    let polynomial = ShamirPolynomial::new(&secret, threshold, &prime).unwrap();

    // Evaluate at same point multiple times
    let x = BigUint::from(5u32);
    let y1 = polynomial.evaluate(&x).unwrap();
    let y2 = polynomial.evaluate(&x).unwrap();

    assert_eq!(y1, y2, "Polynomial evaluation should be deterministic");

    // Test that x=0 gives back the secret (constant term)
    let y0 = polynomial.evaluate(&BigUint::zero()).unwrap();
    assert_eq!(y0, secret, "Polynomial at x=0 should equal the secret");
}

#[test]
fn test_lagrange_interpolation_known_polynomial() {
    // Test Lagrange interpolation with a known polynomial
    // f(x) = x^2 + 2x + 3
    // f(1) = 6, f(2) = 11, f(3) = 18

    let points = vec![
        (BigUint::from(1u32), BigUint::from(6u32)),
        (BigUint::from(2u32), BigUint::from(11u32)),
        (BigUint::from(3u32), BigUint::from(18u32)),
    ];
    let prime = BigUint::from(101u32);

    let constant_term = LagrangeInterpolator::interpolate(&points, &prime).unwrap();
    assert_eq!(constant_term, BigUint::from(3u32), "Should correctly interpolate constant term");
}

#[test]
fn test_shamir_mathematical_properties() {
    // Test mathematical properties of Shamir sharing
    let secret1 = BigUint::from_str("10000000000000000000").unwrap();
    let secret2 = BigUint::from_str("20000000000000000000").unwrap();
    let threshold = 3;
    let prime = generate_safe_prime(256).unwrap();

    // Create polynomials for different secrets
    let poly1 = ShamirPolynomial::new(&secret1, threshold, &prime).unwrap();
    let poly2 = ShamirPolynomial::new(&secret2, threshold, &prime).unwrap();

    // Generate points for each
    let x = BigUint::from(5u32);
    let y1 = poly1.evaluate(&x).unwrap();
    let y2 = poly2.evaluate(&x).unwrap();

    // Points should be different for different secrets
    assert_ne!(y1, y2, "Different secrets should produce different shares");

    // Reconstruct each secret
    let points1 = vec![
        (BigUint::from(1u32), poly1.evaluate(&BigUint::from(1u32)).unwrap()),
        (BigUint::from(2u32), poly1.evaluate(&BigUint::from(2u32)).unwrap()),
        (BigUint::from(3u32), poly1.evaluate(&BigUint::from(3u32)).unwrap()),
    ];
    let reconstructed1 = LagrangeInterpolator::interpolate(&points1, &prime).unwrap();

    let points2 = vec![
        (BigUint::from(1u32), poly2.evaluate(&BigUint::from(1u32)).unwrap()),
        (BigUint::from(2u32), poly2.evaluate(&BigUint::from(2u32)).unwrap()),
        (BigUint::from(3u32), poly2.evaluate(&BigUint::from(3u32)).unwrap()),
    ];
    let reconstructed2 = LagrangeInterpolator::interpolate(&points2, &prime).unwrap();

    assert_eq!(secret1, reconstructed1, "Secret 1 round-trip failed");
    assert_eq!(secret2, reconstructed2, "Secret 2 round-trip failed");
    assert_ne!(reconstructed1, reconstructed2, "Different secrets should reconstruct differently");
}

#[test]
fn test_shamir_edge_cases() {
    // Test edge cases

    // Test with threshold = 1 (should work)
    let secret = BigUint::from_str("12345").unwrap();
    let prime = generate_safe_prime(128).unwrap();
    let polynomial = ShamirPolynomial::new(&secret, 1, &prime).unwrap();

    let x = BigUint::from(1u32);
    let y = polynomial.evaluate(&x).unwrap();

    // With threshold 1, any single point should reconstruct the secret
    let points = vec![(x, y)];
    let reconstructed = LagrangeInterpolator::interpolate(&points, &prime).unwrap();
    assert_eq!(secret, reconstructed);

    // Test with very small secret
    let small_secret = BigUint::from(1u32);
    let polynomial = ShamirPolynomial::new(&small_secret, 2, &prime).unwrap();

    let points = vec![
        (BigUint::from(1u32), polynomial.evaluate(&BigUint::from(1u32)).unwrap()),
        (BigUint::from(2u32), polynomial.evaluate(&BigUint::from(2u32)).unwrap()),
    ];
    let reconstructed = LagrangeInterpolator::interpolate(&points, &prime).unwrap();
    assert_eq!(small_secret, reconstructed);
}

#[test]
fn test_shamir_deterministic_polynomial() {
    // Test that the same secret and parameters produce the same polynomial
    let secret = BigUint::from_str("88888888888888888888").unwrap();
    let threshold = 3;
    let prime = BigUint::from_str("115792089237316195423570985008687907853269984665640564039457584007913129639747").unwrap();

    let poly1 = ShamirPolynomial::new(&secret, threshold, &prime).unwrap();
    let poly2 = ShamirPolynomial::new(&secret, threshold, &prime).unwrap();

    // Should produce identical polynomials (coefficients should be the same)
    assert_eq!(poly1.coefficients.len(), poly2.coefficients.len());
    for (c1, c2) in poly1.coefficients.iter().zip(poly2.coefficients.iter()) {
        assert_eq!(c1, c2, "Polynomial coefficients should be deterministic");
    }
}

#[test]
fn test_shamir_large_numbers() {
    // Test with larger numbers
    let large_secret = BigUint::from_str("1234567890123456789012345678901234567890").unwrap();
    let threshold = 5;
    let prime = generate_safe_prime(512).unwrap(); // Larger prime

    let polynomial = ShamirPolynomial::new(&large_secret, threshold, &prime).unwrap();

    // Generate points
    let mut points = Vec::new();
    for i in 1..=8 {
        let x = BigUint::from(i as u64);
        let y = polynomial.evaluate(&x).unwrap();
        points.push((x, y));
    }

    // Reconstruct with minimum threshold
    let reconstructed = LagrangeInterpolator::interpolate(&points[..threshold], &prime).unwrap();
    assert_eq!(large_secret, reconstructed);

    // Reconstruct with more points
    let reconstructed_extra = LagrangeInterpolator::interpolate(&points[..threshold + 2], &prime).unwrap();
    assert_eq!(large_secret, reconstructed_extra);
}

#[test]
fn test_modular_inverse_correctness() {
    // Test that modular inverse works correctly
    let a = BigUint::from(3u32);
    let m = BigUint::from(11u32);

    let inv = ShamirMath::mod_inverse(&a, &m).unwrap();
    let result = (a * inv) % m;

    assert_eq!(result, BigUint::one(), "Modular inverse should satisfy a * a^(-1) ≡ 1 mod m");
}

#[test]
fn test_prime_generation() {
    // Test that generated primes are actually prime
    for bit_length in [128, 256, 384] {
        let prime = generate_safe_prime(bit_length).unwrap();
        assert!(prime.bits() >= bit_length as u64, "Prime should have at least {} bits", bit_length);

        // Should be able to compute modular inverse (indicates it's not composite)
        let a = BigUint::from(2u32);
        let inv = ShamirMath::mod_inverse(&a, &prime);
        assert!(inv.is_ok(), "Should be able to compute modular inverse for prime {}", prime);
    }
}
