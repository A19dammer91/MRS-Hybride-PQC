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
//!
//! # Threshold verification (commitment)
//! Shamir shares carry no information about the original `threshold`.
//! Recovering with fewer shares than were originally required does not
//! fail mathematically — it silently produces an incorrect 32-byte
//! value. [`split_secret`] therefore also returns a public SHA-256
//! **commitment** to the original secret; [`recover_secret_checked`]
//! recomputes that hash after interpolation and rejects the result on
//! mismatch, turning a silent wrong-answer failure mode into an
//! explicit [`ShamirError::CommitmentMismatch`]. The commitment is not
//! secret and may be stored or transmitted alongside (not as part of)
//! the shares.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
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
    /// The recovered secret's commitment does not match the one supplied
    /// at split time. This means either too few shares were supplied,
    /// the wrong shares were supplied, or a share's value was corrupted
    /// or tampered with — [`recover_secret_checked`] cannot distinguish
    /// between these causes, only detect that the result is wrong.
    CommitmentMismatch,
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
        let mask = 0u8.wrapping_sub(b & 1);
        result ^= a & mask;

        let high = a >> 7;
        a <<= 1;
        let reduce_mask = 0u8.wrapping_sub(high);
        a ^= AES_POLY & reduce_mask;

        b >>= 1;
    }
    result
}

/// Branch-free GF(256) multiplicative inverse.
#[inline]
pub fn gf_inv(a: u8) -> u8 {
    let is_nonzero = (a | a.wrapping_neg()) >> 7;
    let mask = 0u8.wrapping_sub(is_nonzero);

    let s1 = gf_mul(a, a);
    let s2 = gf_mul(s1, s1);
    let s3 = gf_mul(s2, s2);
    let s4 = gf_mul(s3, s3);
    let s5 = gf_mul(s4, s4);
    let s6 = gf_mul(s5, s5);
    let s7 = gf_mul(s6, s6);

    let mut r = gf_mul(s7, s6);
    r = gf_mul(r, s5);
    r = gf_mul(r, s4);
    r = gf_mul(r, s3);
    r = gf_mul(r, s2);
    r = gf_mul(r, s1);

    r & mask
}

/// Evaluate a polynomial at point x using Horner's method.
pub fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for i in (0..coeffs.len()).rev() {
        result = gf_add(gf_mul(result, x), coeffs[i]);
    }
    result
}

/// Lagrange interpolation at x = 0.
pub fn lagrange_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut secret = 0u8;
    for (i, &(x_i, y_i)) in points.iter().enumerate() {
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (j, &(x_j, _)) in points.iter().enumerate() {
            if i != j {
                numerator = gf_mul(numerator, x_j);
                denominator = gf_mul(denominator, gf_add(x_j, x_i));
            }
        }
        let lagrange_coeff = gf_mul(numerator, gf_inv(denominator));
        secret = gf_add(secret, gf_mul(y_i, lagrange_coeff));
    }
    secret
}

/// Validate a (threshold, shares) configuration.
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

/// Compute a public SHA-256 commitment to a 32-byte secret.
///
/// This value is NOT secret and reveals nothing about the secret beyond
/// what a hash normally reveals (i.e. it is safe to store or transmit
/// alongside shares). It exists purely so that [`recover_secret_checked`]
/// can detect a wrong-threshold or corrupted-share recovery instead of
/// silently returning an incorrect secret.
pub fn commit(secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"MRS-AUTH-SHAMIR-COMMIT-v1");
    hasher.update(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Split a 32-byte secret into shares, returning both the shares and a
/// public commitment to the original secret.
///
/// The commitment must be stored or transmitted alongside the shares
/// (it is not secret) so that [`recover_secret_checked`] can later
/// verify that recovery used a sufficient, correct set of shares.
pub fn split_secret(
    secret: &[u8; 32],
    threshold: usize,
    shares: usize,
    rng: &mut impl rand::RngCore,
) -> Result<(Vec<(u8, [u8; 32])>, [u8; 32]), ShamirError> {
    validate_split_params(threshold, shares)?;

    let mut share_values = vec![[0u8; 32]; shares];

    for byte_idx in 0..32 {
        let mut coeffs = vec![0u8; threshold];
        coeffs[0] = secret[byte_idx];
        for coeff in coeffs.iter_mut().skip(1) {
            *coeff = rng.next_u32() as u8;
        }

        for (share_idx, share_val) in share_values.iter_mut().enumerate().take(shares) {
            let x = (share_idx + 1) as u8;
            share_val[byte_idx] = eval_poly(&coeffs, x);
        }

        coeffs.zeroize();
    }

    let mut result = Vec::with_capacity(shares);
    for (idx, mut value) in share_values.into_iter().enumerate() {
        result.push(((idx + 1) as u8, value));
        value.zeroize();
    }

    let commitment = commit(secret);
    Ok((result, commitment))
}

/// Recover a 32-byte secret from shares, with NO check that the correct
/// threshold was met.
///
/// # Warning
/// This function cannot tell whether `shares` meets the original
/// threshold. Supplying too few (or the wrong) shares does not error —
/// it silently returns an incorrect 32-byte value. Prefer
/// [`recover_secret_checked`] wherever a commitment is available, which
/// is the case for any secret split via [`split_secret`] in this crate.
/// This unchecked variant remains available for callers who have their
/// own external verification mechanism.
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

/// Recover a 32-byte secret from shares and verify it against a
/// commitment produced by [`split_secret`].
///
/// This is the recommended recovery entry point: unlike
/// [`recover_secret`], it detects (rather than silently ignores) the
/// case where too few, the wrong, or corrupted shares were supplied.
///
/// # Errors
/// Returns everything [`recover_secret`] can return, plus
/// [`ShamirError::CommitmentMismatch`] if the interpolated secret does
/// not match `expected_commitment`.
pub fn recover_secret_checked(
    shares: &[(u8, [u8; 32])],
    expected_commitment: &[u8; 32],
) -> Result<[u8; 32], ShamirError> {
    let mut secret = recover_secret(shares)?;
    let actual_commitment = commit(&secret);

    // Constant-time comparison: the commitment is public, but comparing
    // it in a way that depends on secret-derived data with early-exit
    // logic is an unnecessary habit to avoid in a crate that is
    // constant-time elsewhere.
    let matches = actual_commitment.ct_eq(expected_commitment);
    if matches.unwrap_u8() == 1 {
        Ok(secret)
    } else {
        secret.zeroize();
        Err(ShamirError::CommitmentMismatch)
    }
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
        assert_eq!(gf_mul(gf_mul(7, 9), 13), gf_mul(7, gf_mul(9, 13)));
    }

    #[test]
    fn gf_mul_commutative() {
        assert_eq!(gf_mul(7, 9), gf_mul(9, 7));
        assert_eq!(gf_mul(0x53, 0xCA), gf_mul(0xCA, 0x53));
    }

    #[test]
    fn gf_mul_known_vectors() {
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
        // f(x) = 5 + 7x in GF(2^8)
        // f(1) = 5 xor 7 = 2
        // f(2) = 5 xor (7*2) = 5 xor 14 = 11
        let points = [(1u8, 2u8), (2u8, 11u8)];
        assert_eq!(lagrange_at_zero(&points), 5);
    }

    #[test]
    fn shamir_roundtrip_3_of_5() {
        let secret = [0xABu8; 32];
        let mut rng = OsRng;
        let (shares, _commitment) = split_secret(&secret, 3, 5, &mut rng).expect("split failed");
        let subset = vec![shares[0], shares[2], shares[4]];
        let recovered = recover_secret(&subset).expect("recover failed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn shamir_roundtrip_2_of_4() {
        let secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let mut rng = OsRng;
        let (shares, _commitment) = split_secret(&secret, 2, 4, &mut rng).expect("split failed");
        let recovered = recover_secret(&shares).expect("recover failed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn shamir_different_subsets_equivalent() {
        let secret = [0xCDu8; 32];
        let mut rng = OsRng;
        let (shares, _commitment) = split_secret(&secret, 3, 5, &mut rng).expect("split failed");
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
        assert_eq!(recover_secret(&shares), Err(ShamirError::InvalidShareIndex));
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
        let secret = [0x42u8; 32];
        let mut rng = OsRng;
        let (shares, _commitment) = split_secret(&secret, 3, 5, &mut rng).expect("split failed");
        let insufficient = vec![shares[0], shares[1]];
        let recovered = recover_secret(&insufficient).expect("recover should not error");
        assert_ne!(
            recovered, secret,
            "recovery with too few shares should not coincidentally match"
        );
    }

    // --- Commitment-checked recovery ---

    #[test]
    fn commit_is_deterministic() {
        let secret = [0x77u8; 32];
        assert_eq!(commit(&secret), commit(&secret));
    }

    #[test]
    fn commit_differs_for_different_secrets() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert_ne!(commit(&a), commit(&b));
    }

    #[test]
    fn checked_roundtrip_succeeds_with_enough_shares() {
        let secret = [0x99u8; 32];
        let mut rng = OsRng;
        let (shares, commitment) = split_secret(&secret, 3, 5, &mut rng).expect("split failed");
        let subset = vec![shares[0], shares[2], shares[4]];
        let recovered =
            recover_secret_checked(&subset, &commitment).expect("checked recover failed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn checked_recovery_rejects_insufficient_shares() {
        let secret = [0x42u8; 32];
        let mut rng = OsRng;
        let (shares, commitment) = split_secret(&secret, 3, 5, &mut rng).expect("split failed");
        let insufficient = vec![shares[0], shares[1]];
        assert_eq!(
            recover_secret_checked(&insufficient, &commitment),
            Err(ShamirError::CommitmentMismatch)
        );
    }

    #[test]
    fn checked_recovery_rejects_wrong_commitment() {
        let secret = [0x11u8; 32];
        let other_secret = [0x22u8; 32];
        let mut rng = OsRng;
        let (shares, _own_commitment) =
            split_secret(&secret, 3, 5, &mut rng).expect("split failed");
        let wrong_commitment = commit(&other_secret);
        let subset = vec![shares[0], shares[1], shares[2]];
        assert_eq!(
            recover_secret_checked(&subset, &wrong_commitment),
            Err(ShamirError::CommitmentMismatch)
        );
    }

    #[test]
    fn checked_recovery_propagates_lower_level_errors() {
        let commitment = [0u8; 32];
        let shares: Vec<(u8, [u8; 32])> = vec![];
        assert_eq!(
            recover_secret_checked(&shares, &commitment),
            Err(ShamirError::NoSharesProvided)
        );
    }
}
