//! Diophantine core, generic over any integer type from the `crypto_bigint`
//! crate (e.g. `U64`, `U128`, `U256`, ...).

use crypto_bigint::{CheckedMul, Integer, NonZero, U64, U256};
use core::ops::{Div, Rem};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

// Zeroize implementatie voor U64 en U256
impl Zeroize for U64 {
    fn zeroize(&mut self) {
        *self = U64::from(0u64);
    }
}

impl Zeroize for U256 {
    fn zeroize(&mut self) {
        *self = U256::from(0u64);
    }
}

#[inline]
fn nz<T: MrsInt>(val: u64) -> NonZero<T> {
    let opt = NonZero::new(T::from(val));
    assert!(bool::from(opt.is_some()), "constant {} must be non-zero", val);
    opt.unwrap()
}

/// Supertrait alias for everything the MRS(19,9) algebra needs.
pub trait MrsInt:
    Integer
    + Div<NonZero<Self>, Output = Self>
    + Rem<NonZero<Self>, Output = Self>
    + Clone
    + Copy  // Copy toegevoegd
    + Zeroize
    + ConditionallySelectable
    + ConstantTimeEq
{
}

impl<T> MrsInt for T where
    T: Integer
        + Div<NonZero<T>, Output = T>
        + Rem<NonZero<T>, Output = T>
        + Clone
        + Copy
        + Zeroize
        + ConditionallySelectable
        + ConstantTimeEq
{
}

/// Convert a big integer to a byte vector for HKDF / hashing.
pub trait ToBytes: MrsInt {
    fn to_be_bytes_vec(&self) -> Vec<u8>;
}

impl ToBytes for U64 {
    fn to_be_bytes_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl ToBytes for U256 {
    fn to_be_bytes_vec(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

// ============================================================================
// DiophantinePair - Copy toegevoegd
// ============================================================================

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

// ============================================================================
// Branch-free result type
// ============================================================================

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

// ============================================================================
// Core algebra (blijft hetzelfde)
// ============================================================================

#[inline]
pub fn check_frobenius_bound<T: MrsInt>(n: &T) -> bool {
    let frobenius = T::from(143u64);
    n.ct_gt(&frobenius).into()
}

#[inline]
pub fn calculate_anchor<T: MrsInt>(n: &T) -> T {
    n.clone().rem(nz::<T>(9))
}

pub fn calculate_popoviciu_cardinality<T: MrsInt>(n: &T) -> T {
    let a0 = calculate_anchor(n);
    let nineteen = T::from(19u64);
    let one_seventy_one = nz::<T>(171);

    let subtrahend = nineteen
        .checked_mul(&a0)
        .expect("19 * A0 overflow");

    if bool::from(n.ct_lt(&subtrahend)) {
        return T::from(0u64);
    }

    let diff = n
        .checked_sub(&subtrahend)
        .expect("n >= subtrahend");

    diff.div(one_seventy_one)
        .checked_add(&T::from(1u64))
        .expect("R(N) + 1 overflow")
}

pub fn generate_representation_family<T: MrsInt>(n: &T) -> Vec<DiophantinePair<T>> {
    let a0 = calculate_anchor(n);
    let r_n = calculate_popoviciu_cardinality(n);
    let mut family = Vec::new();

    let nine = T::from(9u64);
    let nineteen = nz::<T>(19);
    let nine_nz = nz::<T>(9);

    let mut k = T::from(0u64);
    while bool::from(k.ct_lt(&r_n)) {
        let a = a0
            .checked_add(&nine.checked_mul(&k).expect("9k overflow"))
            .expect("A0 + 9k overflow");
        let nineteen_a = nineteen.as_ref().checked_mul(&a).expect("19A overflow");
        let b = n
            .checked_sub(&nineteen_a)
            .expect("N - 19A underflow")
            .div(nine_nz.clone());

        debug_assert!(
            bool::from(n.ct_eq(
                &nineteen.as_ref().checked_mul(&a).unwrap()
                    .checked_add(&nine.checked_mul(&b).unwrap()).unwrap()
            )),
            "19A + 9B must equal N"
        );

        family.push(DiophantinePair { a, b });
        k = k.checked_add(&T::from(1u64)).expect("k overflow");
    }
    family
}

// ============================================================================
// Branch-free selection helpers
// ============================================================================

pub fn select_branch_free<T: MrsInt, F>(
    items: &[DiophantinePair<T>],
    mut predicate: F,
) -> BranchFreeResult<T>
where
    F: FnMut(&DiophantinePair<T>, usize) -> Choice,
{
    if items.is_empty() {
        return BranchFreeResult {
            pair: DiophantinePair { a: T::from(0u64), b: T::from(0u64) },
            valid: Choice::from(0u8),
        };
    }
    let mut result = items[0];
    let mut found = Choice::from(0u8);
    for (idx, item) in items.iter().enumerate() {
        let cond = predicate(item, idx);
        let should_take = cond & (!found);
        result = DiophantinePair::conditional_select(&result, item, should_take);
        found |= cond;
    }
    BranchFreeResult { pair: result, valid: found }
}

pub fn select_branch_free_with_index<T: MrsInt, F>(
    items: &[DiophantinePair<T>],
    mut predicate: F,
) -> (BranchFreeResult<T>, usize)
where
    F: FnMut(&DiophantinePair<T>, usize) -> Choice,
{
    if items.is_empty() {
        return (BranchFreeResult {
            pair: DiophantinePair { a: T::from(0u64), b: T::from(0u64) },
            valid: Choice::from(0u8),
        }, 0);
    }
    let mut result = items[0];
    let mut found = Choice::from(0u8);
    let mut selected_idx = 0usize;
    for (idx, item) in items.iter().enumerate() {
        let cond = predicate(item, idx);
        let should_take = cond & (!found);
        result = DiophantinePair::conditional_select(&result, item, should_take);
        selected_idx = usize::conditional_select(&selected_idx, &idx, should_take);
        found |= cond;
    }
    (BranchFreeResult { pair: result, valid: found }, selected_idx)
}

// ============================================================================
// Tests (blijven hetzelfde)
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
            let lhs = U64::from(19u64).checked_mul(&pair.a).unwrap()
                .checked_add(&U64::from(9u64).checked_mul(&pair.b).unwrap()).unwrap();
            assert_eq!(lhs, n);
        }
    }

    #[test]
    fn family_reconstructs_n_u256() {
        let n = U256::from_be_hex("0000000000000000000000000000000000000000000000000000E8D4A51000");
        for pair in generate_representation_family(&n) {
            let lhs = U256::from(19u64).checked_mul(&pair.a).unwrap()
                .checked_add(&U256::from(9u64).checked_mul(&pair.b).unwrap()).unwrap();
            assert_eq!(lhs, n);
        }
    }

    #[test]
    fn branch_free_select_basic() {
        let n = U64::from(500u64);
        let family = generate_representation_family(&n);
        let res = select_branch_free(&family, |pair, _| {
            pair.a.clone().rem(nz::<U64>(2)).ct_eq(&U64::from(0u64))
        });
        assert!(bool::from(res.valid));
        assert!(bool::from(res.pair.a.clone().rem(nz::<U64>(2)).ct_eq(&U64::from(0u64))));
    }

    #[test]
    fn zeroize_pair() {
        let mut p = DiophantinePair { a: U64::from(0xDEADBEEFu64), b: U64::from(0xCAFEBABEu64) };
        p.zeroize();
        assert!(bool::from(p.a.ct_eq(&U64::from(0u64))));
        assert!(bool::from(p.b.ct_eq(&U64::from(0u64))));
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
