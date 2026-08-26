//! Diophantine core, generic over any `crypto_bigint` unsigned integer type
//! (e.g. `U64`, `U128`, `U256`, ...) via the small [`MrsInt`] trait defined
//! below — not via `crypto_bigint::Integer`.

use crypto_bigint::{CheckedAdd, CheckedMul, CheckedSub, ConstZero, NonZero};
use core::ops::{Div, Rem};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};
use zeroize::Zeroize;

// ============================================================================
// The MrsInt trait
// ============================================================================

/// Everything the MRS(19,9) algebra needs from an integer type, and nothing
/// more. Implemented below for `crypto_bigint::{U64, U256}`.
///
/// `ZERO` komt van het supertrait `ConstZero`; we definieren het hier NIET
/// opnieuw om ambiguiteit (E0034) te voorkomen.
pub trait MrsInt:
    Clone
    + Copy
    + Sized
    + From<u64>
    + ConstZero
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
}

impl MrsInt for crypto_bigint::U64 {}

impl MrsInt for crypto_bigint::U256 {}

/// Builds a `NonZero<T>` from a small compile-time-known constant.
#[inline]
fn nz<T: MrsInt>(val: u64) -> NonZero<T> {
    let ct = NonZero::new(T::from(val));
    Option::from(ct).unwrap_or_else(|| panic!("constant {val} must be non-zero"))
}

/// Unwraps a `CheckedAdd`/`CheckedSub`/`CheckedMul` result.
#[inline]
fn expect_ct<T>(ct: crypto_bigint::subtle::CtOption<T>, msg: &str) -> T {
    Option::from(ct).unwrap_or_else(|| panic!("{msg}"))
}

// ============================================================================
// DiophantinePair — Copy + Zeroize (geen Drop; Copy is vereist voor
// ConditionallySelectable en maakt branch-free selectie mogelijk)
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

#[inline]
pub fn check_frobenius_bound<T: MrsInt>(n: &T) -> bool {
    let frobenius = T::from(143u64);
    bool::from(n.ct_gt(&frobenius))
}

#[inline]
pub fn calculate_anchor<T: MrsInt>(n: &T) -> T {
    (*n).rem(nz::<T>(9))
}

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
// Branch-free selection helpers — Copy + Zeroize (geen Drop)
// ============================================================================

/// The result of a branch-free scan.
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

/// Scans the entire slice in O(n) with no early exit.
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

/// As [`select_branch_free`], but also returns the selected index.
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
        selected_idx = if bool::from(should_take) { idx } else { selected_idx };
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
                .checked_mul(&pair.a).unwrap()
                .checked_add(&U64::from(9u64).checked_mul(&pair.b).unwrap()).unwrap();
            assert_eq!(lhs, n);
        }
    }

    #[test]
    fn family_reconstructs_n_u256() {
        let n = U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000004C4B3B");
        for pair in generate_representation_family(&n) {
            let lhs = U256::from(19u64)
                .checked_mul(&pair.a).unwrap()
                .checked_add(&U256::from(9u64).checked_mul(&pair.b).unwrap()).unwrap();
            assert_eq!(lhs, n);
        }
    }

    #[test]
    fn branch_free_select_finds_match() {
        let family = generate_representation_family(&U64::from(500u64));
        let target = U64::from(5u64);
        let res = select_branch_free(&family, |pair, _idx| pair.a.ct_eq(&target));
        assert!(bool::from(res.valid));
        assert_eq!(res.pair.a, target);
    }
            }
