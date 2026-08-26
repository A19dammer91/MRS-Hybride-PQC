//! Diophantine core, generic over any `crypto_bigint` unsigned integer type
//! (e.g. `U64`, `U128`, `U256`, ...) via the small [`MrsInt`] trait defined
//! below — not via `crypto_bigint::Integer`.
//!
//! # Why not `crypto_bigint::Integer`
//!
//! `Integer` is `crypto_bigint`'s all-encompassing trait for its own `Uint`
//! family. It carries `DivRemLimb` as a supertrait — a limb-level division
//! primitive that is an internal implementation detail of the crate's own
//! `Uint`, not something meant to be reimplemented from outside it (whether
//! or not it is formally sealed, hand-rolling a correct limb-level division
//! algorithm is not something to attempt here). Trying to `impl Integer for
//! MyOwnType` is therefore fragile at best.
//!
//! Instead, [`MrsInt`] is a small trait bundling only the standalone,
//! independently-usable operations this module actually needs:
//! `CheckedAdd` / `CheckedSub` / `CheckedMul` (separate, simple traits that
//! `crypto_bigint` exports on its own), the `Div`/`Rem` operators against a
//! `NonZero<Self>` divisor, and the `subtle` constant-time comparison and
//! selection traits. `U64` and `U256` implement all of these natively —
//! no wrapper types are needed.
//!
//! # Zeroize
//!
//! Rather than hand-writing `Zeroize` for a newtype, enable it directly on
//! `crypto_bigint`'s own types via the crate's `zeroize` Cargo feature:
//! ```toml
//! crypto-bigint = { version = "0.6", features = ["zeroize"] }
//! ```
//! That gives a real, crate-maintained `Zeroize` impl on `U64`/`U256`
//! themselves, with no risk of a hand-rolled impl missing internal state.
//!
//! # A note on constant time
//!
//! `N` (the public Diophantine parameter) and its derived quantities are
//! *public* values in this protocol — the secret is which chain gets
//! sampled from the resulting forest, not `N` itself. Ordinary
//! (non-secret-dependent) branching on `N` is therefore fine and used
//! below where it is simpler; the [`select_branch_free`] helpers exist for
//! the places where a choice genuinely does depend on secret-adjacent data
//! (e.g. selecting among candidate chains) and must not branch.

use crypto_bigint::{CheckedAdd, CheckedMul, CheckedSub, NonZero};
use core::ops::{Div, Rem};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};
use zeroize::Zeroize;

// ============================================================================
// The MrsInt trait
// ============================================================================

/// Everything the MRS(19,9) algebra needs from an integer type, and nothing
/// more. Implemented below for `crypto_bigint::{U64, U256}`; implement it
/// for any other `crypto_bigint` width the same way.
pub trait MrsInt:
    Clone
    + Copy
    + Sized
    + From<u64>
    + CheckedAdd
    + CheckedSub
    + CheckedMul
    + Div<NonZero<Self>, Output = Self>
    + Rem<NonZero<Self>, Output = Self>
    + ConstantTimeEq
    + ConstantTimeGreater
    + ConstantTimeLess
    + ConditionallySelectable
    + Zeroize
{
    /// The additive identity. A plain associated const (not part of any
    /// shared crypto_bigint trait) so this module does not depend on
    /// `Integer`/`Zero` at all.
    const ZERO: Self;
}

impl MrsInt for crypto_bigint::U64 {
    const ZERO: Self = crypto_bigint::U64::ZERO;
}

impl MrsInt for crypto_bigint::U256 {
    const ZERO: Self = crypto_bigint::U256::ZERO;
}

/// Builds a `NonZero<T>` from a small compile-time-known constant.
/// Panics only if the constant itself is zero, which never happens for the
/// literals used in this module (9, 19, 171).
#[inline]
fn nz<T: MrsInt>(val: u64) -> NonZero<T> {
    Option::from(NonZero::new(T::from(val)))
        .unwrap_or_else(|| panic!("constant {val} must be non-zero"))
}

/// Unwraps a `CheckedAdd`/`CheckedSub`/`CheckedMul` result (a `CtOption`),
/// panicking with a descriptive message on overflow. All call sites below
/// operate on the public parameter `N` and its bounded derivatives, so a
/// panic here indicates `N` does not fit the chosen width — a configuration
/// error, not a runtime/secret-dependent condition.
#[inline]
fn expect_ct<T>(ct: crypto_bigint::subtle::CtOption<T>, msg: &str) -> T {
    Option::from(ct).unwrap_or_else(|| panic!("{msg}"))
}

// ============================================================================
// DiophantinePair
// ============================================================================

/// A single representation (A, B) at one layer, generic over the integer
/// width `T`.
#[derive(Debug, Clone, Copy)]
pub struct DiophantinePair<T: MrsInt> {
    pub a: T,
    pub b: T,
}

impl<T: MrsInt> Zeroize for DiophantinePair<T> {
    fn zeroize(&mut self) {
        self.a.zeroize();
        self.b.zeroize();
    }
}

impl<T: MrsInt> Drop for DiophantinePair<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: MrsInt> ConditionallySelectable for DiophantinePair<T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            a: T::conditional_select(&a.a, &b.a, choice),
            b: T::conditional_select(&a.b, &b.b, choice),
        }
    }
}

impl<T: MrsInt> ConstantTimeEq for DiophantinePair<T> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.a.ct_eq(&other.a) & self.b.ct_eq(&other.b)
    }
}

/// Converts a value to big-endian bytes, for HKDF input / hashing.
/// Implemented directly on the concrete `crypto_bigint` types since byte
/// encoding is width-specific.
pub trait ToBytes {
    fn to_be_bytes_vec(&self) -> Vec<u8>;
}

impl ToBytes for crypto_bigint::U64 {
    fn to_be_bytes_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl ToBytes for crypto_bigint::U256 {
    fn to_be_bytes_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

// ============================================================================
// Core algebra
// ============================================================================

/// Checks whether the main number N satisfies the Frobenius bound
/// (N >= 144). N is a public parameter (see the module-level note on
/// constant time), so an ordinary boolean return is used.
#[inline]
pub fn check_frobenius_bound<T: MrsInt>(n: &T) -> bool {
    let frobenius = T::from(143u64);
    bool::from(n.ct_gt(&frobenius))
}

/// Computes the mathematically pure anchor value A_0 = N mod 9.
#[inline]
pub fn calculate_anchor<T: MrsInt>(n: &T) -> T {
    (*n).rem(nz::<T>(9))
}

/// Computes the exact number of valid representations at a layer via
/// Popoviciu's formula: R(N) = floor((N - 19*A_0) / 171) + 1
pub fn calculate_popoviciu_cardinality<T: MrsInt>(n: &T) -> T {
    let a0 = calculate_anchor(n);
    let nineteen = T::from(19u64);

    let subtrahend = expect_ct(nineteen.checked_mul(&a0), "19 * A0 overflow");

    if bool::from(n.ct_lt(&subtrahend)) {
        return T::ZERO;
    }

    let diff = expect_ct(n.checked_sub(&subtrahend), "checked above: n >= subtrahend");

    let quotient = diff.div(nz::<T>(171));
    expect_ct(quotient.checked_add(&T::from(1u64)), "R(N) + 1 overflow")
}

/// Generates the linear family of solutions based on the step vector
/// (A + 9k, B - 19k).
pub fn generate_representation_family<T: MrsInt>(n: &T) -> Vec<DiophantinePair<T>> {
    let a0 = calculate_anchor(n);
    let r_n = calculate_popoviciu_cardinality(n);
    let mut family = Vec::new();

    let nine = T::from(9u64);
    let nineteen = T::from(19u64);
    let nine_nz = nz::<T>(9);

    let mut k = T::ZERO;
    while bool::from(k.ct_lt(&r_n)) {
        let step = expect_ct(nine.checked_mul(&k), "9k overflow");
        let a = expect_ct(a0.checked_add(&step), "A0 + 9k overflow");

        let nineteen_a = expect_ct(nineteen.checked_mul(&a), "19A overflow");
        let remainder = expect_ct(n.checked_sub(&nineteen_a), "N - 19A underflow");
        let b = remainder.div(nine_nz);

        family.push(DiophantinePair { a, b });

        k = expect_ct(k.checked_add(&T::from(1u64)), "k overflow — R(N) exceeds this width");
    }

    family
}

// ============================================================================
// Branch-free selection helpers
// ============================================================================

/// The result of a branch-free scan: the selected pair (meaningful only if
/// `valid` is true) and a `Choice` recording whether any item matched.
#[derive(Debug, Clone, Copy)]
pub struct BranchFreeResult<T: MrsInt> {
    pub pair: DiophantinePair<T>,
    pub valid: Choice,
}

impl<T: MrsInt> Zeroize for BranchFreeResult<T> {
    fn zeroize(&mut self) {
        self.pair.zeroize();
    }
}

impl<T: MrsInt> Drop for BranchFreeResult<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Scans the entire slice in O(n) with no early exit, accumulating the
/// first matching element via `ConditionallySelectable`. Use this instead
/// of `.iter().find(...)` whenever which element matches must not be
/// observable via timing.
pub fn select_branch_free<T: MrsInt, F>(
    items: &[DiophantinePair<T>],
    mut predicate: F,
) -> BranchFreeResult<T>
where
    F: FnMut(&DiophantinePair<T>, usize) -> Choice,
{
    if items.is_empty() {
        return BranchFreeResult {
            pair: DiophantinePair { a: T::ZERO, b: T::ZERO },
            valid: Choice::from(0u8),
        };
    }
    let mut result = items[0];
    let mut found = Choice::from(0u8);
    for (idx, item) in items.iter().enumerate() {
        let cond = predicate(item, idx);
        let should_take = cond & !found;
        result = DiophantinePair::conditional_select(&result, item, should_take);
        found |= cond;
    }
    BranchFreeResult { pair: result, valid: found }
}

/// As [`select_branch_free`], but also returns the selected index (also
/// chosen branch-free, via `usize`'s `ConditionallySelectable` impl from
/// `subtle`).
pub fn select_branch_free_with_index<T: MrsInt, F>(
    items: &[DiophantinePair<T>],
    mut predicate: F,
) -> (BranchFreeResult<T>, usize)
where
    F: FnMut(&DiophantinePair<T>, usize) -> Choice,
{
    if items.is_empty() {
        return (
            BranchFreeResult {
                pair: DiophantinePair { a: T::ZERO, b: T::ZERO },
                valid: Choice::from(0u8),
            },
            0,
        );
    }
    let mut result = items[0];
    let mut found = Choice::from(0u8);
    let mut selected_idx = 0usize;
    for (idx, item) in items.iter().enumerate() {
        let cond = predicate(item, idx);
        let should_take = cond & !found;
        result = DiophantinePair::conditional_select(&result, item, should_take);
        selected_idx = usize::conditional_select(&selected_idx, &idx, should_take);
        found |= cond;
    }
    (BranchFreeResult { pair: result, valid: found }, selected_idx)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::{U256, U64};

    #[test]
    fn anchor_matches_plain_mod_u64() {
        let n = U64::from(5_000_003u64);
        assert_eq!(calculate_anchor(&n), U64::from(5_000_003u64 % 9));
    }

    #[test]
    fn frobenius_bound_u64() {
        assert!(check_frobenius_bound(&U64::from(200u64)));
        assert!(!check_frobenius_bound(&U64::from(100u64)));
    }

    #[test]
    fn popoviciu_monotonic() {
        let r1 = calculate_popoviciu_cardinality(&U64::from(200u64));
        let r2 = calculate_popoviciu_cardinality(&U64::from(500u64));
        assert!(bool::from(r1.ct_lt(&r2)));
    }

    #[test]
    fn family_reconstructs_n_u64() {
        let n = U64::from(5_000_003u64);
        for pair in generate_representation_family(&n) {
            let lhs = U64::from(19u64)
                .checked_mul(&pair.a)
                .unwrap()
                .checked_add(&U64::from(9u64).checked_mul(&pair.b).unwrap())
                .unwrap();
            assert_eq!(lhs, n);
        }
    }

    #[test]
    fn family_reconstructs_n_u256() {
        let n = U256::from_be_hex(
            "0000000000000000000000000000000000000000000000000000E8D4A51000",
        );
        for pair in generate_representation_family(&n) {
            let lhs = U256::from(19u64)
                .checked_mul(&pair.a)
                .unwrap()
                .checked_add(&U256::from(9u64).checked_mul(&pair.b).unwrap())
                .unwrap();
            assert_eq!(lhs, n);
        }
    }

    #[test]
    fn branch_free_select_basic() {
        let n = U64::from(500u64);
        let family = generate_representation_family(&n);
        let res = select_branch_free(&family, |pair, _| pair.a.rem(nz::<U64>(2)).ct_eq(&U64::ZERO));
        assert!(bool::from(res.valid));
        assert!(bool::from(res.pair.a.rem(nz::<U64>(2)).ct_eq(&U64::ZERO)));
    }

    #[test]
    fn zeroize_pair() {
        let mut p = DiophantinePair { a: U64::from(0xDEADBEEFu64), b: U64::from(0xCAFEBABEu64) };
        p.zeroize();
        assert_eq!(p.a, U64::ZERO);
        assert_eq!(p.b, U64::ZERO);
    }

    #[test]
    fn ct_eq_pair() {
        let p1 = DiophantinePair { a: U64::from(42u64), b: U64::from(99u64) };
        let p2 = DiophantinePair { a: U64::from(42u64), b: U64::from(99u64) };
        let p3 = DiophantinePair { a: U64::from(42u64), b: U64::from(100u64) };
        assert!(bool::from(p1.ct_eq(&p2)));
        assert!(!bool::from(p1.ct_eq(&p3)));
    }
}
