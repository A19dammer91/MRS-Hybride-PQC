//! Shamir Secret Sharing over GF(2^8) with AES irreducible polynomial 0x11B.
//!
//! Each byte of a secret is treated as an independent element in GF(256).
//! A (threshold-1)-degree polynomial is constructed per byte, and shares
//! are evaluations at distinct non-zero points x = 1, 2, ..., n.
//!
//! Recovery uses Lagrange interpolation at x = 0.
//!
//! # Constant-time properties
//! `gf_mul` and `gf_inv` are implemented without secret-dependent memory
//! lookups or branches. All operations are bitwise and arithmetic on
//! `u8` values with fixed iteration counts. This eliminates the
//! cache-timing side channel present in classic T-table GF(256)
//! implementations.
//!
//! Note: this is "constant-time" in the practical software sense (no
//! secret-dependent branches or memory accesses), not formally verified
//! against timing leakage at the gate or micro-architecture level.

use zeroize::Zeroize;

/// Errors that can occur during share splitting or recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShamirError {
    /// `threshold` must be at least 2 (threshold 1 is not meaningful
    /// secret *sharing* and 0 is nonsensical).
    ThresholdTooSmall,
    /// `shares` must be at least `threshold`.
    NotEnoughShares,
    /// `shares` must fit in a non-zero `u8` index (max 255).
    TooManyShares,
    /// `recover_secret` was called with zero shares.
    NoSharesProvided,
    /// Two shares share the same x-coordinate (index).
    DuplicateShareIndex,
    /// A share index of 0 was supplied. Index 0 is reserved for the
    /// secret itself (the point the polynomial is evaluated at during
    /// recovery) and must never be used as a share's x-coordinate.
    InvalidShareIndex,
}

/// AES irreducible polynomial without the x^8 term: x^4 + x^3 + x + 1.
const AES_POLY: u8 = 0x1B;

/// Addition in GF(256) is XOR.
#[inline]
pub fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Branch-free GF(256) multiplication under the AES polynomial 0x11B.
///
/// Uses the "Russian peasant" / shift-and-add algorithm with a fixed
/// 8-iteration loop. No branches, no table lookups, and no memory
/// accesses depend on `a` or `b`.
#[inline]
pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        // If b's LSB is set, XOR result with a. Branch-free via mask.
        let mask = 0u8.wrapping_sub(b & 1);
        result ^= a & mask;

        // If a's MSB is set, the next left-shift overflows into x^8;
        // reduce by XOR-ing with the polynomial (without x^8 term).
        let high = a >> 7;
        a <<= 1;
        let reduce_mask = 0u8.wrapping_sub(high);
        a ^= AES_POLY & reduce_mask;

        b >>= 1;
    }
    result
}

/// Branch-free GF(256) multiplicative inverse.
///
/// In GF(256), a^255 = 1 for all a != 0, so a^-1 = a^254.
/// 254 = 0b11111110 = 2 + 4 + 8 + 16 + 32 + 64 + 128.
/// We compute a^254 with a fixed sequence of 7 squarings and 6
/// multiplications — no branches, no lookups.
///
/// Returns 0 for a = 0 (mathematically undefined, but handled
/// branch-free so the function never panics).
#[inline]
pub fn gf_inv(a: u8) -> u8 {
    // is_nonzero = 0 if a == 0, else 1. Branch-free idiom.
    let is_nonzero = (a | a.wrapping_neg()) >> 7;
    let mask = 0u8.wrapping_sub(is_nonzero); // 0x00 if a==0, 0xFF if a>0

    // s1 = a^2
    let s1 = gf_mul(a, a);
    // s2 = a^4
    let s2 = gf_mul(s1, s1);
    // s3 = a^8
    let s3 = gf_mul(s2, s2);
    // s4 = a^16
    let s4 = gf_mul(s3, s3);
    // s5 = a^32
    let s5 = gf_mul(s4, s4);
    // s6 = a^64
    let s6 = gf_mul(s5, s5);
    // s7 = a^128
    let s7 = gf_mul(s6, s6);

    // a^254 = a^128 * a^64 * a^32 * a^16 * a^8 * a^4 * a^2
    let mut r = gf_mul(s7, s6);
    r = gf_mul(r, s5);
    r = gf_mul(r, s4);
    r = gf_mul(r, s3);
    r = gf_mul(r, s2);
    r = gf_mul(r, s1);

    r & mask
}

/// Evaluate a polynomial at point x using Horner's method.
/// coeffs[0] is the constant term (the secret).
pub fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for i in (0..coeffs.len()).rev() {
        result = gf_add(gf_mul(result, x), coeffs[i]);
    }
    result
}

/// Lagrange interpolation at x = 0.
/// Given points (x_i, y_i), returns f(0) where f is the unique polynomial
/// of degree < points.len() passing through all points.
///
/// Callers are responsible for ensuring `points` contains at least
/// `threshold` entries with distinct, non-zero x-coordinates; this
/// function has no way to detect an under-supplied or malformed point
/// set and will silently return an incorrect value rather than an error
/// if given fewer or the wrong points; use [`recover_secret`] for the
/// validated, higher-level entry point.
pub fn lagrange_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut secret = 0u8;
    for (i, &(x_i, y_i)) in points.iter().enumerate() {
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (j, &(x_j, _)) in points.iter().enumerate() {
            if i != j {
                numerator = gf_mul(numerator, x_j);
                // In GF(2^8), subtraction = addition = XOR
                denominator = gf_mul(denominator, gf_add(x_j, x_i));
            }
        }
        let lagrange_coeff = gf_mul(numerator, gf_inv(denominator));
        secret = gf_add(secret, gf_mul(y_i, lagrange_coeff));
    }
    secret
}

/// Validate a (threshold, shares) configuration before splitting.
fn validate_split_params(threshold: usize, shares: usize) -> Result<(), ShamirError> {
    if threshold < 2 {
        return Err(ShamirError::ThresholdTooSmall);
    }
    if shares < threshold {
        return Err(ShamirError::NotEnoughShares);
    }
    if shares > 255 {
        return Err(ShamirError::TooManyShares);
    }
    Ok(())
}

/// Split a 32-byte secret into `shares` shares with `threshold` required.
/// Returns a Vec of (index, [u8; 32]) tuples. Indices are 1-based
/// (never 0 — index 0 is reserved for the secret's own evaluation point).
///
/// # Errors
/// - [`ShamirError::ThresholdTooSmall`] if `threshold < 2`.
/// - [`ShamirError::NotEnoughShares`] if `shares < threshold`.
/// - [`ShamirError::TooManyShares`] if `shares > 255`.
///
/// # Requirements
/// - `rng` must be cryptographically secure. The security of the sharing
///   scheme depends entirely on the coefficients drawn from it being
///   unpredictable.
pub fn split_secret(
    secret: &[u8; 32],
    threshold: usize,
    shares: usize,
    rng: &mut impl rand::RngCore,
) -> Result<Vec<(u8, [u8; 32])>, ShamirError> {
    validate_split_params(threshold, shares)?;

    let mut share_values = vec![[0u8; 32]; shares];

    for byte_idx in 0..32 {
        let mut coeffs = vec![0u8; threshold];
        coeffs[0] = secret[byte_idx];
        for coeff in coeffs.iter_mut().skip(1) {
            *coeff = rng.next_u32() as u8;
        }

        for (share_idx, share_val) in share_values.iter_mut().enumerate().take(shares) {
            // 1-based: x = 1, 2, ..., shares. x = 0 is never used as a
            // share point since that is the secret's own evaluation point.
            let x = (share_idx + 1) as u8;
            share_val[byte_idx] = eval_poly(&coeffs, x);
        }

        coeffs.zeroize();
    }

    let mut result = Vec::with_capacity(shares);
    for (idx, mut value) in share_values.into_iter().enumerate() {
        result.push(((idx + 1) as u8, value));
        // The Vec retains its own copy via push (Copy type), so the
        // loop-local binding can be cleared without affecting `result`.
        value.zeroize();
    }
    Ok(result)
}

/// Recover a 32-byte secret from shares using Lagrange interpolation.
///
/// # Errors
/// - [`ShamirError::NoSharesProvided`] if `shares` is empty.
/// - [`ShamirError::InvalidShareIndex`] if any share has index 0.
/// - [`ShamirError::DuplicateShareIndex`] if two shares share an index.
///
/// # Important
/// This function cannot verify that the supplied shares meet the
/// *original* `threshold` used at split time — that information is not
/// encoded in the shares themselves. Supplying fewer than the original
/// threshold will not produce an error; it will silently produce an
/// incorrect secret. Callers must track and enforce the intended
/// threshold themselves (e.g. via `MasterSecret`'s own bookkeeping).
pub fn recover_secret(shares: &[(u8, [u8; 32])]) -> Result<[u8; 32], ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::NoSharesProvided);
    }

    for (idx, _) in shares {
        if *idx == 0 {
            return Err(ShamirError::InvalidShareIndex);
        }
    }

    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].0 == shares[j].0 {
                return Err(ShamirError::DuplicateShareIndex);
            }
        }
    }

    let mut secret = [0u8; 32];
    for byte_idx in 0..32 {
        let points: Vec<(u8, u8)> = shares
            .iter()
            .map(|(idx, val)| (*idx, val[byte_idx]))
            .collect();
        secret[byte_idx] = lagrange_at_zero(&points);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn gf_mul_identity() {
        assert_eq!(gf_mul(1, 42), 42);
        assert_eq!(gf_mul(42, 1), 42);
        assert_eq!(gf_mul(0, 42), 0);
        assert_eq!(gf_mul(42, 0), 0);
    }

    #[test]
    fn gf_mul_associative() {
        // (a * b) * c == a * (b * c)
        assert_eq!(gf_mul(gf_mul(7, 9), 13), gf_mul(7, gf_mul(9, 13)));
    }

    #[test]
    fn gf_mul_commutative() {
        assert_eq!(gf_mul(7, 9), gf_mul(9, 7));
        assert_eq!(gf_mul(0x53, 0xCA), gf_mul(0xCA, 0x53));
    }

    #[test]
    fn gf_mul_known_vectors() {
        // Known AES GF(2^8) multiplication test vectors
        assert_eq!(gf_mul(0x57, 0x13), 0xFE);
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
    }

    #[test]
    fn gf_inv_roundtrip() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse failed for {}", a);
        }
    }

    #[test]
    fn gf_inv_of_zero_is_zero() {
        assert_eq!(gf_inv(0), 0);
    }

    #[test]
    fn eval_poly_at_zero_is_secret() {
        let coeffs = [42u8, 1, 2, 3];
        assert_eq!(eval_poly(&coeffs, 0), 42);
    }

    #[test]
    fn lagrange_recover_single_point() {
        // f(x) = 7 + 3x, recover f(0) from (1, 10), (2, 13)
        let points = [(1u8, 10u8), (2u8, 13u8)];
        assert_eq!(lagrange_at_zero(&points), 7);
    }

    #[test]
    fn shamir_roundtrip_3_of_5() {
        let secret = [0xABu8; 32];
        let mut rng = OsRng;
        let shares = split_secret(&secret, 3, 5, &mut rng).expect("split failed");

        // Recover with shares 0, 2, 4
        let subset = vec![shares[0], shares[2], shares[4]];
        let recovered = recover_secret(&subset).expect("recover failed");
        assert_eq!(recovered, secret);
    }

    // GECORRIGEERDE TEST: nu met een echte 32-byte array
    #[test]
    fn shamir_roundtrip_2_of_4() {
        // Vaste 32-byte testvector (0x01 t/m 0x20)
        let secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ];
        let mut rng = OsRng;
        let shares = split_secret(&secret, 2, 4, &mut rng).expect("split failed");

        let recovered = recover_secret(&shares).expect("recover failed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn shamir_different_subsets_equivalent() {
        let secret = [0xCDu8; 32];
        let mut rng = OsRng;
        let shares = split_secret(&secret, 3, 5, &mut rng).expect("split failed");

        let subsets = vec![
            vec![shares[0], shares[1], shares[2]],
            vec![shares[1], shares[3], shares[4]],
            vec![shares[0], shares[3], shares[4]],
        ];

        for subset in subsets {
            let recovered = recover_secret(&subset).expect("recover failed");
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn split_rejects_threshold_too_small() {
        let secret = [0u8; 32];
        let mut rng = OsRng;
        assert_eq!(
            split_secret(&secret, 1, 5, &mut rng),
            Err(ShamirError::ThresholdTooSmall)
        );
        assert_eq!(
            split_secret(&secret, 0, 5, &mut rng),
            Err(ShamirError::ThresholdTooSmall)
        );
    }

    #[test]
    fn split_rejects_not_enough_shares() {
        let secret = [0u8; 32];
        let mut rng = OsRng;
        assert_eq!(
            split_secret(&secret, 5, 3, &mut rng),
            Err(ShamirError::NotEnoughShares)
        );
    }

    #[test]
    fn split_rejects_too_many_shares() {
        let secret = [0u8; 32];
        let mut rng = OsRng;
        assert_eq!(
            split_secret(&secret, 2, 256, &mut rng),
            Err(ShamirError::TooManyShares)
        );
    }

    #[test]
    fn recover_rejects_empty_shares() {
        let shares: Vec<(u8, [u8; 32])> = vec![];
        assert_eq!(recover_secret(&shares), Err(ShamirError::NoSharesProvided));
    }

    #[test]
    fn recover_rejects_zero_index() {
        let shares = vec![(0u8, [1u8; 32]), (1u8, [2u8; 32])];
        assert_eq!(
            recover_secret(&shares),
            Err(ShamirError::InvalidShareIndex)
        );
    }

    #[test]
    fn recover_rejects_duplicate_index() {
        let shares = vec![(1u8, [1u8; 32]), (1u8, [2u8; 32])];
        assert_eq!(
            recover_secret(&shares),
            Err(ShamirError::DuplicateShareIndex)
        );
    }

    #[test]
    fn recover_with_fewer_than_threshold_gives_wrong_secret_not_error() {
        // Documents the documented limitation: recover_secret cannot know
        // the original threshold, so an under-supplied set of shares
        // succeeds but yields the wrong secret rather than an error.
        let secret = [0x42u8; 32];
        let mut rng = OsRng;
        let shares = split_secret(&secret, 3, 5, &mut rng).expect("split failed");

        // Only 2 of the required 3 shares.
        let insufficient = vec![shares[0], shares[1]];
        let recovered = recover_secret(&insufficient).expect("recover should not error");
        assert_ne!(
            recovered, secret,
            "recovery with too few shares should not coincidentally match"
        );
    }
        }
