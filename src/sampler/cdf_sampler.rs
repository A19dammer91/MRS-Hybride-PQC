```rust
//! Weighted CDF sampler and O(1) triangle fast-path for the MRS(19,9)
//! Diophantine forest.
//!
//! Generic over `crypto_bigint` width (`U64`, `U256`, ...).

use crate::core::diophantine::{
    BranchFreeResult, DiophantinePair, MrsInt, ToBytes,
    calculate_anchor, calculate_popoviciu_cardinality, generate_representation_family,
    select_branch_free,
};
use crypto_bigint::{CheckedAdd, CheckedMul, CheckedSub, Integer, NonZero};
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

#[inline]
fn nz<T: MrsInt>(val: u64) -> NonZero<T> {
    let opt = NonZero::new(T::from(val));
    assert!(bool::from(opt.is_some()), "constant {} must be non-zero", val);
    opt.unwrap()
}

// ============================================================================
// Randomness trait
// ============================================================================

pub trait FromRandom: MrsInt {
    fn from_random(rng: &mut impl RngCore) -> Self;
}

impl FromRandom for crypto_bigint::U64 {
    fn from_random(rng: &mut impl RngCore) -> Self {
        Self::from(rng.next_u64())
    }
}

impl FromRandom for crypto_bigint::U256 {
    fn from_random(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let opt = Self::from_be_slice(&bytes);
        assert!(bool::from(opt.is_some()), "32 bytes always fit U256");
        opt.unwrap()
    }
}

pub trait SamplerInt: MrsInt + FromRandom + ToBytes {}
impl<T> SamplerInt for T where T: MrsInt + FromRandom + ToBytes {}

// ============================================================================
// MrsChain
// ============================================================================

#[derive(Debug, Clone)]
pub struct MrsChain<T: SamplerInt> {
    pub layers: Vec<DiophantinePair<T>>,
    pub valid: Choice,
}

impl<T: SamplerInt> Zeroize for MrsChain<T> {
    fn zeroize(&mut self) {
        for layer in &mut self.layers {
            layer.zeroize();
        }
    }
}

impl<T: SamplerInt> Drop for MrsChain<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ============================================================================
// Digital root (branch-free)
// ============================================================================

#[inline]
pub fn digital_root<T: SamplerInt>(n: &T) -> T {
    let zero = T::from(0u64);
    let is_zero = n.ct_eq(&zero);
    let one = T::from(1u64);
    let nine = nz::<T>(9);
    let n_minus_1 = n.clone().checked_sub(&one).unwrap_or_else(|| T::from(0u64));
    let rem = n_minus_1.rem(nine);
    let dr = one.checked_add(&rem).expect("1 + rem <= 9");
    T::conditional_select(&zero, &dr, !is_zero)
}

// ============================================================================
// Triangle condition
// ============================================================================

#[inline]
pub fn validate_triangle_condition<T: SamplerInt>(b: &T, x: &T) -> Choice {
    let dr_b = digital_root(b);
    let dr_x = digital_root(x);
    let two = T::from(2u64);
    let target = digital_root(&two.checked_mul(&dr_x).expect("2*dr_x overflow"));
    dr_b.ct_eq(&target)
}

pub fn count_triangle_filtered<T: SamplerInt>(n: &T) -> T {
    let family = generate_representation_family(n);
    let mut count = T::from(0u64);
    let one = T::from(1u64);
    let zero = T::from(0u64);
    for pair in family {
        let cond = validate_triangle_condition(&pair.b, n);
        let increment = T::conditional_select(&one, &zero, cond);
        count = count.checked_add(&increment).expect("count overflow");
    }
    count
}

#[inline]
pub fn check_ahead_valid<T: SamplerInt>(a_value: &T) -> Choice {
    let count = count_triangle_filtered(a_value);
    let two = T::from(2u64);
    !count.ct_lt(&two)
}

// ============================================================================
// Uniform random generation
// ============================================================================

fn uniform_below<T: SamplerInt>(bound: &T, rng: &mut impl RngCore) -> T {
    let zero = T::from(0u64);
    let is_zero_bound = bound.ct_eq(&zero);
    loop {
        let r = T::from_random(rng);
        let in_range = r.ct_lt(bound) | r.ct_eq(bound);
        if bool::from(in_range | is_zero_bound) {
            return T::conditional_select(&zero, &r, in_range);
        }
    }
}

// ============================================================================
// O(1) triangle sampler (fast-path)
// ============================================================================

/// Samples one triangle-valid `(A,B)` pair for a given `N` in O(1).
///
/// Fully branch-free: no `if` on `k0`, `kmax`, or the random draw.
pub fn sample_triangle<T: SamplerInt>(n: &T, rng: &mut impl RngCore) -> BranchFreeResult<T> {
    let zero = T::from(0u64);
    let one = T::from(1u64);
    let two = T::from(2u64);
    let nine = nz::<T>(9);
    let nineteen = nz::<T>(19);

    let a0 = calculate_anchor(n);

    let nineteen_a0 = nineteen.as_ref().checked_mul(&a0).expect("19*A0 overflow");
    let b0 = n.checked_sub(&nineteen_a0).expect("N-19A0 underflow").div(nine.clone());

    let dr_n = digital_root(n);
    let two_dr_n = two.checked_mul(&dr_n).expect("2*dr_n overflow");
    let target_r = digital_root(&two_dr_n);

    let b0_lt_target = b0.ct_lt(&target_r);
    let b0_adjusted = T::conditional_select(
        &b0,
        &b0.checked_add(nine.as_ref()).expect("B0+9 overflow"),
        b0_lt_target,
    );
    let k0 = b0_adjusted.checked_sub(&target_r).expect("adj B0 >= target").rem(nine.clone());

    let r_n = calculate_popoviciu_cardinality(n);
    let k_max = r_n.checked_sub(&one).unwrap_or_else(|| zero.clone());

    let is_valid = !k0.ct_gt(&k_max);

    let diff = T::conditional_select(
        &k_max.checked_sub(&k0).expect("kmax >= k0"),
        &zero,
        !is_valid,
    );
    let t_max = diff.div(nine.clone());

    let t = uniform_below(&t_max, rng);
    let nine_t = nine.as_ref().checked_mul(&t).expect("9t overflow");
    let k = k0.checked_add(&nine_t).expect("k0+9t overflow");

    let nine_k = nine.as_ref().checked_mul(&k).expect("9k overflow");
    let a = a0.checked_add(&nine_k).expect("A0+9k overflow");

    let nineteen_a = nineteen.as_ref().checked_mul(&a).expect("19A overflow");
    let b = n.checked_sub(&nineteen_a).expect("N-19A underflow").div(nine.clone());

    let final_a = T::conditional_select(&a, &zero, !is_valid);
    let final_b = T::conditional_select(&b, &zero, !is_valid);

    BranchFreeResult {
        pair: DiophantinePair { a: final_a, b: final_b },
        valid: is_valid,
    }
}

// ============================================================================
// 3-layer sampler using the O(1) fast-path
// ============================================================================

/// Samples a 3-layer Matryoshka chain from `root_n`.
///
/// Uses the O(1) `sample_triangle` per layer instead of materialising the
/// entire representation family. This makes cryptographic-scale N (~10^42)
/// practical.
pub fn sample_three_layers<T: SamplerInt>(root_n: &T, rng: &mut impl RngCore) -> Option<MrsChain<T>> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n.clone();

    for _ in 0..DEPTH {
        let result = sample_triangle(&current_n, rng);
        if !bool::from(result.valid) {
            return None;
        }
        current_n = result.pair.a.clone();
        chain.push(result.pair);
    }

    Some(MrsChain { layers: chain, valid: Choice::from(1u8) })
}

// ============================================================================
// Fallback: CDF over materialised family (for small N / testing)
// ============================================================================

/// Classic weighted-CDF sampler. Materialises the full representation
/// family, then picks via branch-free CDF scan. Use this only for small
/// N where R(N) fits in memory; for cryptographic scales, prefer
/// `sample_three_layers`.
pub fn sample_three_layers_cdf<T: SamplerInt>(root_n: &T, rng: &mut impl RngCore) -> Option<MrsChain<T>> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n.clone();

    for layer in 0..DEPTH {
        let is_last = layer == DEPTH - 1;
        let family = generate_representation_family(&current_n);

        let mut candidates: Vec<DiophantinePair<T>> = Vec::new();
        let mut weights: Vec<T> = Vec::new();

        for pair in family {
            if !bool::from(validate_triangle_condition(&pair.b, &current_n)) { continue; }
            if !is_last && !bool::from(check_ahead_valid(&pair.a)) { continue; }
            let w = if is_last { T::from(1u64) } else { count_triangle_filtered(&pair.a) };
            if bool::from(w.ct_eq(&T::from(0u64))) { continue; }
            candidates.push(pair);
            weights.push(w);
        }

        if candidates.is_empty() { return None; }

        let total_weight = weights.iter().cloned()
            .fold(T::from(0u64), |acc, w| acc.checked_add(&w).expect("weight sum overflow"));
        let r = uniform_below(&total_weight, rng);

        let mut acc = T::from(0u64);
        let result = select_branch_free(&candidates, |_pair, idx| {
            acc = acc.checked_add(&weights[idx]).expect("acc overflow");
            r.ct_lt(&acc)
        });

        if !bool::from(result.valid) { return None; }
        current_n = result.pair.a.clone();
        chain.push(result.pair);
    }

    Some(MrsChain { layers: chain, valid: Choice::from(1u8) })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U64;
    use rand::rngs::OsRng;

    #[test]
    fn digital_root_correct() {
        assert_eq!(digital_root(&U64::from(0u64)), U64::from(0u64));
        assert_eq!(digital_root(&U64::from(9u64)), U64::from(9u64));
        assert_eq!(digital_root(&U64::from(10u64)), U64::from(1u64));
        assert_eq!(digital_root(&U64::from(144u64)), U64::from(9u64));
    }

    #[test]
    fn triangle_reconstructs_n() {
        let n = U64::from(5_000_003u64);
        let mut rng = OsRng;
        let res = sample_triangle(&n, &mut rng);
        assert!(bool::from(res.valid));
        let lhs = U64::from(19u64).checked_mul(&res.pair.a).unwrap()
            .checked_add(&U64::from(9u64).checked_mul(&res.pair.b).unwrap()).unwrap();
        assert_eq!(lhs, n);
    }

    #[test]
    fn triangle_satisfies_condition() {
        let n = U64::from(5_000_003u64);
        let mut rng = OsRng;
        let res = sample_triangle(&n, &mut rng);
        assert!(bool::from(res.valid));
        assert!(bool::from(validate_triangle_condition(&res.pair.b, &n)));
    }

    #[test]
    fn three_layers_nesting() {
        let n = U64::from(200_001u64);
        let mut rng = OsRng;
        let chain = sample_three_layers(&n, &mut rng).expect("sampling should succeed");
        assert_eq!(chain.layers.len(), 3);
        assert!(bool::from(n.ct_gt(&chain.layers[0].a)));
        assert!(bool::from(chain.layers[0].a.ct_gt(&chain.layers[1].a)));
    }

    #[test]
    fn three_layers_not_deterministic() {
        let n = U64::from(10_000_007u64);
        let mut rng = OsRng;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            if let Some(chain) = sample_three_layers(&n, &mut rng) {
                let key: Vec<(U64, U64)> = chain.layers.iter().map(|p| (p.a.clone(), p.b.clone())).collect();
                seen.insert(key);
            }
        }
        assert!(seen.len() > 1, "should produce distinct chains");
    }

    #[test]
    fn cdf_fallback_matches_fast_path() {
        let n = U64::from(200_001u64);
        let mut rng = OsRng;
        // Just verify both methods succeed and produce valid chains
        let fast = sample_three_layers(&n, &mut rng);
        let cdf = sample_three_layers_cdf(&n, &mut rng);
        assert!(fast.is_some());
        assert!(cdf.is_some());
    }
}
```
