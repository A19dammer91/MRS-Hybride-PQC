```rust
use crate::core::diophantine::MrsInt;
use crypto_bigint::{U256, U64};
use subtle::Choice;
use zeroize::Zeroize;

/// Trait to convert a big integer into a u64 suitable for LWE coefficients.
/// For U64: direct cast. For U256: takes the lowest 64 bits.
pub trait ToLweCoefficient: MrsInt {
    fn to_lwe_u64(&self) -> u64;
}

impl ToLweCoefficient for U64 {
    fn to_lwe_u64(&self) -> u64 {
        self.as_u64()
    }
}

impl ToLweCoefficient for U256 {
    fn to_lwe_u64(&self) -> u64 {
        self.as_u64()
    }
}

/// LWE instance holding the masked chain parameters.
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct LweInstance {
    pub b: Vec<u64>,
    pub public_matrix_a: Vec<Vec<u64>>,
}

/// Masks MRS parameters inside an LWE instance: b = (A·s + e) mod q.
///
/// Generic over `T` so it accepts both `U64` and `U256` chain values.
/// Each `T` is reduced to its lowest 64 bits for the LWE modulus field.
pub fn isolate_chain_parameter<T: ToLweCoefficient>(
    secret_s: &[T],
    noise_e: &[u64],
    modulus_q: u64,
) -> Option<LweInstance> {
    if secret_s.is_empty() || secret_s.len() != noise_e.len() {
        return None;
    }

    let n = secret_s.len();
    let s_u64: Vec<u64> = secret_s.iter().map(|v| v.to_lwe_u64() % modulus_q).collect();

    // Deterministic public matrix A (simplified mock for test vectors)
    let mut matrix_a = vec![vec![0u64; n]; n];
    for i in 0..n {
        for j in 0..n {
            matrix_a[i][j] = ((i * 19 + j * 9) as u64) % modulus_q;
        }
    }

    let mut b_vector = vec![0u64; n];
    for i in 0..n {
        let mut sum = 0u64;
        for j in 0..n {
            let product = (matrix_a[i][j] as u128 * s_u64[j] as u128) % modulus_q as u128;
            sum = (sum + product as u64) % modulus_q;
        }
        b_vector[i] = (sum + noise_e[i]) % modulus_q;
    }

    Some(LweInstance {
        b: b_vector,
        public_matrix_a: matrix_a,
    })
}

// ============================================================================
// Branch-free u64 comparison helpers
// ============================================================================

/// Constant-time `a <= b` for u64.
///
/// Uses only bitwise operations: no branches, no short-circuiting.
#[inline]
fn ct_le_u64(a: u64, b: u64) -> Choice {
    // a <= b  <=>  NOT (b < a)
    // b < a   <=>  (b - a) underflows, i.e. sign bit of (b - a) is 1
    let underflow = b.wrapping_sub(a);
    let is_lt = (underflow >> 63) as u8;
    Choice::from(is_lt ^ 1)
}

/// Constant-time `a == b` for u64.
#[inline]
fn ct_eq_u64(a: u64, b: u64) -> Choice {
    let diff = a ^ b;
    // diff == 0  <=>  all bits zero  <=>  wrapping_sub gives no borrow
    let is_zero = diff.wrapping_sub(1) >> 63;
    Choice::from(is_zero as u8)
}

// ============================================================================
// Branch-free LWE verification
// ============================================================================

/// Verifies in constant time whether a claimed solution matches the LWE instance.
///
/// # Constant-time guarantee
///
/// * No branches on `claimed_s` values.
/// * The loop always runs exactly `n` iterations.
/// * The final result is accumulated via bitwise AND (`&`), not short-circuit.
pub fn verify_lwe_match(
    instance: &LweInstance,
    claimed_s: &[u64],
    allowed_noise_bound: u64,
    modulus_q: u64,
) -> Choice {
    if claimed_s.len() != instance.b.len() {
        return Choice::from(0);
    }

    let n = claimed_s.len();
    let mut all_match = Choice::from(1);

    for i in 0..n {
        let mut computed_as = 0u64;
        for j in 0..n {
            let product = (instance.public_matrix_a[i][j] as u128 * claimed_s[j] as u128) % modulus_q as u128;
            computed_as = (computed_as + product as u64) % modulus_q;
        }

        // diff = |b[i] - computed_as| mod q (branch-free absolute difference)
        let b_i = instance.b[i];
        let raw_diff = b_i.wrapping_sub(computed_as);
        let alt_diff = computed_as.wrapping_sub(b_i);
        let b_ge = ct_le_u64(computed_as, b_i);
        let diff = u64::conditional_select(&alt_diff, &raw_diff, b_ge);

        // Check diff <= allowed_noise_bound (constant time)
        let within_bound = ct_le_u64(diff, allowed_noise_bound);
        all_match &= within_bound;
    }

    all_match
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lwe_round_trip_u64() {
        let secret = vec![U64::from(42u64), U64::from(99u64)];
        let noise = vec![5u64, 3u64];
        let q = 1009u64;

        let instance = isolate_chain_parameter(&secret, &noise, q).unwrap();
        let claimed = vec![42u64, 99u64];
        assert!(bool::from(verify_lwe_match(&instance, &claimed, 10, q)));
    }

    #[test]
    fn lwe_round_trip_u256() {
        let secret = vec![
            U256::from_be_hex("000000000000000000000000000000000000000000000000000000000000002A"),
            U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000063"),
        ];
        let noise = vec![5u64, 3u64];
        let q = 1009u64;

        let instance = isolate_chain_parameter(&secret, &noise, q).unwrap();
        let claimed = vec![42u64, 99u64];
        assert!(bool::from(verify_lwe_match(&instance, &claimed, 10, q)));
    }

    #[test]
    fn lwe_invalid_length() {
        let secret = vec![U64::from(1u64)];
        let noise = vec![1u64, 2u64];
        assert!(isolate_chain_parameter::<U64>(&secret, &noise, 100).is_none());
    }

    #[test]
    fn ct_le_u64_correctness() {
        assert!(bool::from(ct_le_u64(5, 10)));
        assert!(bool::from(ct_le_u64(5, 5)));
        assert!(!bool::from(ct_le_u64(10, 5)));
    }

    #[test]
    fn ct_eq_u64_correctness() {
        assert!(bool::from(ct_eq_u64(42, 42)));
        assert!(!bool::from(ct_eq_u64(42, 43)));
    }
}
```
