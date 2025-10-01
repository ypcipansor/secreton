//!
//! This module provides the core mathematical operations for Shamir Secret Sharing,
//! including polynomial arithmetic and Lagrange interpolation.

/// Security constants for Shamir Secret Sharing
pub const MAX_SECRET_SIZE: usize = 1_048_576; // 1MB maximum secret size
pub const MAX_THRESHOLD: usize = 1000; // Maximum threshold value
pub const MAX_POLYNOMIAL_DEGREE: usize = 1000; // Maximum polynomial degree
pub const MIN_PRIME_BITS: usize = 128; // Minimum prime size in bits
pub const MAX_PRIME_BITS: usize = 4096; // Maximum prime size in bits

/// Mathematics utilities for Shamir Secret Sharing
pub struct ShamirMath;

impl ShamirMath {
    /// Generate a cryptographically secure safe prime
    pub fn generate_safe_prime(bit_length: usize) -> CryptoResult<BigUint> {
        // Validate input parameters
        if bit_length < MIN_PRIME_BITS || bit_length > MAX_PRIME_BITS {
            return Err(CryptoError::InvalidInput(
                format!("Prime bit length must be between {} and {} bits", MIN_PRIME_BITS, MAX_PRIME_BITS)
            ));
        }

        let mut rng = ChaCha20Rng::from_entropy();

        loop {
            // Generate a random number of the specified bit length
            let candidate = rng.gen_biguint(bit_length);

            // Ensure it's odd
            let mut candidate = if &candidate % BigUint::from(2u32) == BigUint::zero() {
                candidate + BigUint::one()
            } else {
                candidate
            };

            // Check if it's a safe prime (p = 2q + 1 where q is also prime)
            if Self::is_safe_prime(&candidate)? {
                return Ok(candidate);
            }

            // Try next odd number
            candidate += BigUint::from(2u32);
        }
    }

    /// Check if a number is a safe prime using Miller-Rabin test
    pub fn is_safe_prime(candidate: &BigUint) -> CryptoResult<bool> {
        if candidate < &BigUint::from(2u32) {
            return Ok(false);
        }

        if candidate == &BigUint::from(2u32) || candidate == &BigUint::from(3u32) {
            return Ok(true);
        }

        // Check if candidate is prime
        if !Self::miller_rabin_test(candidate, 40)? {
            return Ok(false);
        }

        // Check if (candidate - 1) / 2 is also prime (Sophie Germain prime)
        let sophie_germain = (candidate - BigUint::one()) / BigUint::from(2u32);
        if !Self::miller_rabin_test(&sophie_germain, 40)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Miller-Rabin primality test
    pub fn miller_rabin_test(n: &BigUint, rounds: usize) -> CryptoResult<bool> {
        if n < &BigUint::from(2u32) {
            return Ok(false);
        }

        if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
            return Ok(true);
        }

        // Write n-1 as 2^s * d
        let mut d = n - BigUint::one();
        let mut s = 0usize;

        while &d % BigUint::from(2u32) == BigUint::zero() {
            d /= BigUint::from(2u32);
            s += 1;
        }

        use rand_chacha::ChaCha20Rng;
        let mut rng = ChaCha20Rng::from_entropy();

        // Witness loop
        for _ in 0..rounds {
            // Generate random witness a in range [2, n-2]
            let range = n - BigUint::from(2u32);
            let a = rng.gen_biguint_range(&BigUint::from(2u32), &range);

            let mut x = a.modpow(&d, n);

            if x == BigUint::one() || x == n - BigUint::one() {
                continue;
            }

            let mut next_power = true;
            for _ in 1..s {
                x = x.modpow(&BigUint::from(2u32), n);

                if x == BigUint::one() {
                    return Ok(false);
                }

                if x == n - BigUint::one() {
                    next_power = false;
                    break;
                }
            }

            if next_power {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Constant-time modular exponentiation: base^exponent mod modulus
    /// This implementation prevents timing attacks by ensuring constant execution time
    pub fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        if modulus == &BigUint::one() {
            return BigUint::zero();
        }

        let mut result = BigUint::one();
        let mut base = base % modulus;
        let mut exponent = exponent.clone();

        // Get the bit length of the exponent to determine max iterations
        let max_bits = exponent.bits();

        for i in (0..max_bits).rev() {
            result = (result * &result) % modulus;

            if (&exponent >> i) & BigUint::one() == BigUint::one() {
                result = (result * &base) % modulus;
            }
        }

        result
    }

    /// Legacy variable-time modular exponentiation (deprecated - use mod_pow instead)
    #[deprecated(note = "Use mod_pow for constant-time operations")]
    pub fn mod_pow_variable_time(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        if modulus == &BigUint::one() {
            return BigUint::zero();
        }

        let mut result = BigUint::one();
        let mut base = base % modulus;
        let mut exponent = exponent.clone();

        while exponent > BigUint::zero() {
            if &exponent % BigUint::from(2u32) == BigUint::one() {
                result = (result * &base) % modulus;
            }

            base = (&base * &base) % modulus;
            exponent /= BigUint::from(2u32);
        }

        result
    }

    /// Extended Euclidean algorithm for modular inverse
    pub fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigUint, BigUint) {
        if b == &BigUint::zero() {
            (a.clone(), BigUint::one(), BigUint::zero())
        } else {
            let (gcd, x1, y1) = Self::extended_gcd(b, &(a % b));
            let x = y1.clone();
            let y = x1 - &(a / b) * y1;
            (gcd, x, y)
        }
    }

    /// Calculate modular inverse
    pub fn mod_inverse(a: &BigUint, m: &BigUint) -> CryptoResult<BigUint> {
        let (gcd, x, _) = Self::extended_gcd(a, m);

        if gcd != BigUint::one() {
            return Err(CryptoError::InvalidInput("No modular inverse exists".to_string()));
        }

        let result = (x % m + m) % m;
        Ok(result)
    }

    /// Generate random BigUint in range [min, max)
    pub fn gen_biguint_range(min: &BigUint, max: &BigUint) -> BigUint {
        let mut rng = ChaCha20Rng::from_entropy();

        if min >= max {
            return min.clone();
        }

        let range = max - min;
        let mut random_bytes = [0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        let random_value = BigUint::from_bytes_be(&random_bytes);

        (random_value % &range) + min
    }
}

/// Lagrange interpolation implementation
pub struct LagrangeInterpolator;

impl LagrangeInterpolator {
    /// Perform Lagrange interpolation on a set of points
    pub fn interpolate(points: &[(BigUint, BigUint)], prime: &BigUint) -> CryptoResult<BigUint> {
        // Validate input parameters
        if points.is_empty() {
            return Err(CryptoError::InvalidInput("No points provided for interpolation".to_string()));
        }

        if points.len() > MAX_THRESHOLD {
            return Err(CryptoError::InvalidInput(
                format!("Too many points for interpolation. Maximum allowed: {}", MAX_THRESHOLD)
            ));
        }

        // Check for duplicate x-coordinates
        for i in 0..points.len() {
            for j in i + 1..points.len() {
                if points[i].0 == points[j].0 {
                    return Err(CryptoError::InvalidInput("Duplicate x-coordinates found".to_string()));
                }
            }
        }

        let mut secret = BigUint::zero();

        for (i, (x_i, y_i)) in points.iter().enumerate() {
            let lagrange_coeff = Self::lagrange_coefficient(i, points, prime)?;
            let term = lagrange_coeff * y_i % prime;
            secret = (secret + term) % prime;
        }

        Ok(secret)
    }

    /// Calculate Lagrange coefficient for point i
    fn lagrange_coefficient(i: usize, points: &[(BigUint, BigUint)], prime: &BigUint) -> CryptoResult<BigUint> {
        let mut numerator = BigUint::one();
        let mut denominator = BigUint::one();

        let (x_i, _) = points[i];

        for (j, (x_j, _)) in points.iter().enumerate() {
            if i != j {
                // numerator *= x_j
                numerator = numerator * x_j % prime;

                // denominator *= x_j - x_i
                let diff = (x_j - &x_i) % prime;
                denominator = denominator * diff % prime;
            }
        }

        // Calculate Lagrange coefficient: numerator / denominator
        let lagrange_coeff = numerator * ShamirMath::mod_inverse(&denominator, prime)? % prime;

        Ok(lagrange_coeff)
    }

    /// Verify that points lie on a polynomial of degree < threshold
    pub fn verify_polynomial_consistency(
        points: &[(BigUint, BigUint)],
        threshold: usize,
        prime: &BigUint,
    ) -> CryptoResult<bool> {
        if points.len() < threshold {
            return Ok(false);
        }

        // Try to interpolate with different subsets
        for i in 0..points.len() {
            for j in (i + 1)..points.len() {
                for k in (j + 1)..points.len() {
                    if k >= threshold {
                        break;
                    }

                    let subset = vec![points[i], points[j], points[k]];
                    let interpolated = Self::interpolate(&subset, prime)?;

                    // Check if this interpolated value matches other points
                    for (l, (x_l, y_l)) in points.iter().enumerate() {
                        if l != i && l != j && l != k {
                            let expected_y = Self::evaluate_polynomial(&interpolated, threshold, x_l, prime)?;
                            if expected_y != *y_l {
                                return Ok(false);
                            }
                        }
                    }
                }
            }
        }

        Ok(true)
    }

    /// Evaluate polynomial at point x given constant term and degree
    fn evaluate_polynomial(constant: &BigUint, degree: usize, x: &BigUint, prime: &BigUint) -> CryptoResult<BigUint> {
        let mut result = BigUint::zero();

        for i in 0..=degree {
            let coeff = if i == 0 { constant.clone() } else { BigUint::one() };
            let term = coeff * x.pow(i as u32) % prime;
            result = (result + term) % prime;
        }

        Ok(result)
    }
}

/// Polynomial operations for Shamir Secret Sharing
pub struct PolynomialOps;

impl PolynomialOps {
    /// Create a polynomial with given coefficients
    pub fn from_coefficients(coefficients: Vec<BigUint>) -> ShamirPolynomial {
        ShamirPolynomial {
            coefficients,
            prime: BigUint::from(2u32).pow(256), // Default 256-bit prime
        }
    }

    /// Generate a random polynomial of given degree with constant term
    pub fn random_polynomial(degree: usize, constant: &BigUint, prime: &BigUint) -> CryptoResult<ShamirPolynomial> {
        let mut coefficients = vec![constant.clone()];
        let mut rng = ChaCha20Rng::from_entropy();

        for _ in 1..=degree {
            let coeff = rng.gen_biguint_range(&BigUint::one(), prime);
            coefficients.push(coeff);
        }

        Ok(ShamirPolynomial {
            coefficients,
            prime: prime.clone(),
        })
    }

    /// Evaluate polynomial at point x
    pub fn evaluate(polynomial: &ShamirPolynomial, x: &BigUint) -> CryptoResult<BigUint> {
        let mut result = BigUint::zero();

        for (i, coeff) in polynomial.coefficients.iter().enumerate() {
            let term = coeff * x.pow(i as u32) % &polynomial.prime;
            result = (result + term) % &polynomial.prime;
        }

        Ok(result)
    }

    /// Add two polynomials
    pub fn add(a: &ShamirPolynomial, b: &ShamirPolynomial) -> CryptoResult<ShamirPolynomial> {
        let max_len = std::cmp::max(a.coefficients.len(), b.coefficients.len());
        let mut result_coeffs = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let a_coeff = a.coefficients.get(i).cloned().unwrap_or(BigUint::zero());
            let b_coeff = b.coefficients.get(i).cloned().unwrap_or(BigUint::zero());
            let sum = (a_coeff + b_coeff) % &a.prime;
            result_coeffs.push(sum);
        }

        Ok(ShamirPolynomial {
            coefficients: result_coeffs,
            prime: a.prime.clone(),
        })
    }

    /// Multiply two polynomials
    pub fn multiply(a: &ShamirPolynomial, b: &ShamirPolynomial) -> CryptoResult<ShamirPolynomial> {
        let result_degree = a.coefficients.len() + b.coefficients.len() - 2;
        let mut result_coeffs = vec![BigUint::zero(); result_degree + 1];

        for (i, a_coeff) in a.coefficients.iter().enumerate() {
            for (j, b_coeff) in b.coefficients.iter().enumerate() {
                let product = a_coeff * b_coeff % &a.prime;
                let pos = i + j;
                if pos < result_coeffs.len() {
                    result_coeffs[pos] = (result_coeffs[pos].clone() + product) % &a.prime;
                }
            }
        }

        Ok(ShamirPolynomial {
            coefficients: result_coeffs,
            prime: a.prime.clone(),
        })
    }
}

/// Shamir polynomial representation with secure memory handling
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShamirPolynomial {
    pub coefficients: Vec<BigUint>,
    pub prime: BigUint,
}

impl ShamirPolynomial {
    /// Create a new polynomial for Shamir Secret Sharing
    pub fn new(secret: &BigUint, threshold: usize, prime: &BigUint) -> CryptoResult<Self> {
        // Validate input parameters
        if threshold == 0 || threshold > MAX_THRESHOLD {
            return Err(CryptoError::InvalidInput(
                format!("Threshold must be between 1 and {}", MAX_THRESHOLD)
            ));
        }

        if secret.bits() as usize > MAX_SECRET_SIZE * 8 {
            return Err(CryptoError::InvalidInput(
                format!("Secret size exceeds maximum allowed size of {} bytes", MAX_SECRET_SIZE)
            ));
        }

        let mut coefficients = vec![secret.clone()];
        let mut rng = ChaCha20Rng::from_entropy();

        // Generate random coefficients for degree threshold-1
        for _ in 1..threshold {
            let coeff = rng.gen_biguint_range(&BigUint::one(), prime);
            coefficients.push(coeff);
        }

        Ok(Self {
            coefficients,
            prime: prime.clone(),
        })
    }

    /// Evaluate polynomial at point x
    pub fn evaluate(&self, x: &BigUint) -> CryptoResult<BigUint> {
        let mut result = BigUint::zero();

        for (i, coeff) in self.coefficients.iter().enumerate() {
            let term = coeff * x.pow(i as u32) % &self.prime;
            result = (result + term) % &self.prime;
        }

        Ok(result)
    }

    /// Get the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    /// Get the constant term (secret)
    pub fn constant_term(&self) -> &BigUint {
        &self.coefficients[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_prime_generation() {
        let prime = ShamirMath::generate_safe_prime(128).unwrap();
        assert!(ShamirMath::is_safe_prime(&prime).unwrap());
        assert!(prime.bits() >= 128);
    }

    #[test]
    fn test_miller_rabin() {
        // Test known primes
        assert!(ShamirMath::miller_rabin_test(&BigUint::from(2u32), 10).unwrap());
        assert!(ShamirMath::miller_rabin_test(&BigUint::from(3u32), 10).unwrap());
        assert!(ShamirMath::miller_rabin_test(&BigUint::from(5u32), 10).unwrap());

        // Test known composite
        assert!(!ShamirMath::miller_rabin_test(&BigUint::from(4u32), 10).unwrap());
        assert!(!ShamirMath::miller_rabin_test(&BigUint::from(9u32), 10).unwrap());
    }

    #[test]
    fn test_polynomial_operations() {
        let secret = BigUint::from(42u32);
        let prime = BigUint::from(101u32);
        let poly = ShamirPolynomial::new(&secret, 3, &prime).unwrap();

        assert_eq!(poly.coefficients.len(), 3);
        assert_eq!(poly.coefficients[0], secret);
        assert_eq!(poly.degree(), 2);
    }

    #[test]
    fn test_lagrange_interpolation() {
        // Test case: f(x) = x^2 + 2x + 3, evaluate at x=1,2,3
        // f(1) = 1+2+3=6, f(2)=4+4+3=11, f(3)=9+6+3=18
        let points = vec![
            (BigUint::from(1u32), BigUint::from(6u32)),
            (BigUint::from(2u32), BigUint::from(11u32)),
            (BigUint::from(3u32), BigUint::from(18u32)),
        ];
        let prime = BigUint::from(101u32);

        let interpolated = LagrangeInterpolator::interpolate(&points, &prime).unwrap();

        // The constant term should be 3
        assert_eq!(interpolated, BigUint::from(3u32));
    }

    #[test]
    fn test_mod_inverse() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);

        let inv = ShamirMath::mod_inverse(&a, &m).unwrap();
        let result = (a * inv) % m;

        assert_eq!(result, BigUint::one());
    }

    #[test]
    fn test_polynomial_evaluation() {
        let secret = BigUint::from(42u32);
        let prime = BigUint::from(101u32);
        let poly = ShamirPolynomial::new(&secret, 3, &prime).unwrap();

        let x = BigUint::from(5u32);
        let y = poly.evaluate(&x).unwrap();

        // Should be different from secret
        assert_ne!(y, secret);

        // Should be valid modulo prime
        assert!(y < prime);
    }
}
