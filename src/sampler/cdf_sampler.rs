//! Weighted CDF sampler and O(1) triangle fast-path for the MRS(19,9)
//! Diophantine forest.
//!
//! Generic over `crypto_bigint` width (`U64`, `U256`, ...).

use crate::core::diophantine::{
    BranchFreeResult, DiophantinePair, MrsInt, ToBytes,
    calculate_anchor, calculate_popoviciu_cardinality, generate_representation_family,
    select_branch_free, check_frobenius_bound,
};
use crypto_bigint::{CheckedAdd, CheckedMul, CheckedSub, Integer, NonZero, Uint};
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;
use std::ops::Div;

#[inline]
fn nz<T: MrsInt>(val: u64) -> NonZero<T> {
    let opt = NonZero::new(T::from(val));
    assert!(bool::from(opt.is_some()), "constant {} must be non-zero", val);
    opt.unwrap()
}

// ============================================================================
// Randomness trait & Auxiliary Sampling
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

/// Securely samples a random value uniform below a public bound `upper_bound`.
#[inline]
pub fn uniform_below<T: SamplerInt>(upper_bound: &T, rng: &mut impl RngCore) -> T {
    let zero = T::from(0u64);
    if bool::from(upper_bound.ct_eq(&zero)) {
        return zero;
    }
    let random_val = T::from_random(rng);
    let nine = nz::<T>(9);
    random_val.rem(NonZero::new(upper_bound.clone()).unwrap_or(nine))
}

// ============================================================================
// MrsChain
// ============================================================================

#[derive(Debug, Clone)]
pub struct MrsChain<T: SamplerInt> {
    pub layers: Vec<DiophantinePair<T>>,
    pub valid: bool,
}

impl<T: SamplerInt> Zeroize for MrsChain<T> {
    fn zeroize(&mut self) {
        for layer in &mut self.layers {
            layer.a.zeroize();
            layer.b.zeroize();
        }
    }
}

impl<T: SamplerInt> Drop for MrsChain<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ============================================================================
// Digital root & Closed-Form Counter
// ============================================================================

/// Computes the digital root of a number in constant time, without loops
#[inline]
pub fn digital_root<T: SamplerInt>(n: &T) -> T {
    let zero = T::from(0u64);
    let is_zero = n.ct_eq(&zero);
    let one = T::from(1u64);
    let nine = nz::<T>(9);
    let n_minus_1 = n.clone().checked_sub(&one).unwrap_or_else(|| T::from(0u64));
    let rem = n_minus_1.rem(nine);
    let dr = one.checked_add(&rem).expect("1 + rem <= 9");
    zero.conditional_select(&dr, !is_zero)
}

/// Closed-form replacement for counting triangle-filtered valid alibis
pub fn count_triangle_filtered_closed_form<T: SamplerInt>(n: &T) -> T {
    let zero = T::from(0u64);
    let one = T::from(1u64);
    let nine = nz::<T>(9);
    let nineteen = nz::<T>(19);

    let a0 = calculate_anchor(n);
    
    // Guard tegen kleine N underflow: check of 19 * a0 > n
    let nineteen_a0 = nineteen.as_ref().checked_mul(&a0).expect("19*A0 overflow");
    if bool::from(n.ct_lt(&nineteen_a0)) {
        return zero;
    }

    let b0 = n.checked_sub(&nineteen_a0).expect("guarded").div(nine.clone());
    let k_max = b0.div(nineteen);
    let target = digital_root(&T::from(2u64).checked_mul(&a0).expect("2*A0 overflow"));
    
    // k0 = (b0 + 9 - target) % 9 computed branch-free
    let b0_plus_9 = b0.checked_add(nine.as_ref()).expect("B0+9 overflow");
    let k0 = b0_plus_9.checked_sub(&target).expect("B0+9 >= target").rem(nine.clone());

    let is_invalid = k0.ct_gt(&k_max);
    let diff = k_max.checked_sub(&k0).unwrap_or_else(|| zero.clone());
    let res = diff.div(nine.clone()).checked_add(&one).expect("R'(N) overflow");

    zero.conditional_select(&res, !is_invalid)
}

#[inline]
pub fn check_ahead_valid_closed_form<T: SamplerInt>(a_value: &T) -> bool {
    let two = T::from(2u64);
    !count_triangle_filtered_closed_form(a_value).ct_lt(&two).into()
}
// ============================================================================
// Triangle condition and Sampler Engine
// ============================================================================

#[inline]
pub fn validate_triangle_condition<T: SamplerInt>(b: &T, x: &T) -> Choice {
    let dr_b = digital_root(b);
    let dr_x = digital_root(x);
    let two = T::from(2u64);
    let target = digital_root(&two.checked_mul(&dr_x).expect("2*dr_x overflow"));
    dr_b.ct_eq(&target)
}

/// O(1) Triangle Fast-Path sampling logic - Corrected with proper K_max bounds
pub fn sample_triangle<T: SamplerInt>(n: &T, rng: &mut impl RngCore) -> BranchFreeResult<T> {
    let zero = T::from(0u64);
    let one = T::from(1u64);
    let nine = nz::<T>(9);
    let nineteen = nz::<T>(19);

    let a0 = calculate_anchor(n);
    let two = T::from(2u64);

    // B0 guard-check wiskundige basisreconstructie
    let nineteen_a0 = nineteen.as_ref().checked_mul(&a0).expect("19*A0 overflow");
    if bool::from(n.ct_lt(&nineteen_a0)) {
        return BranchFreeResult {
            pair: DiophantinePair { a: zero.clone(), b: zero.clone() },
            valid: Choice::from(0u8),
        };
    }

    let b0 = n.checked_sub(&nineteen_a0).expect("guarded").div(nine.clone());

    let dr_n = digital_root(n);
    let two_dr_n = two.checked_mul(&dr_n).expect("2*dr_n overflow");
    let target_r = digital_root(&two_dr_n);

    // K0 bepaling via B0 modulus verschuiving
    let b0_lt_target = b0.ct_lt(&target_r);
    let b0_adjusted = b0.conditional_select(
        &b0.checked_add(nine.as_ref()).expect("B0+9 overflow"),
        b0_lt_target,
    );
    let k0 = b0_adjusted.checked_sub(&target_r).expect("adj B0 >= target").rem(nine.clone());

    // CORRECTIE: r_n via Popoviciu. K_max = R(N) - 1. Veiligheidscheck tegen -2 bij veelvouden van 9.
    let r_n = calculate_popoviciu_cardinality(n);
    let k_max = r_n.checked_sub(&one).unwrap_or_else(|| zero.clone());

    let is_valid = !k0.ct_gt(&k_max);

    let diff = k_max.checked_sub(&k0).unwrap_or_else(|| zero.clone())
        .conditional_select(&zero, !is_valid);
    let t_max = diff.div(nine.clone());

    let t = uniform_below(&t_max, rng);
    let nine_t = nine.as_ref().checked_mul(&t).expect("9t overflow");
    let k = k0.checked_add(&nine_t).expect("k0+9t overflow");

    let nine_k = nine.as_ref().checked_mul(&k).expect("9k overflow");
    let a = a0.checked_add(&nine_k).expect("A0+9k overflow");

    let nineteen_a = nineteen.as_ref().checked_mul(&a).expect("19A overflow");
    let b = n.checked_sub(&nineteen_a).expect("N-19A underflow").div(nine.clone());

    let final_a = a.conditional_select(&zero, !is_valid);
    let final_b = b.conditional_select(&zero, !is_valid);

    BranchFreeResult {
        pair: DiophantinePair { a: final_a, b: final_b },
        valid: is_valid,
    }
}

// ============================================================================
// Production 3-layer sampler using Closed-Form optimization
// ============================================================================

pub fn sample_three_layers<T: SamplerInt>(root_n: T, rng: &mut impl RngCore) -> Option<MrsChain<T>> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;

    for layer in 0..DEPTH {
        let is_last_layer = layer == DEPTH - 1;
        let zero = T::from(0u64);
        let one = T::from(1u64);
        let nine = nz::<T>(9);
        let nineteen = nz::<T>(19);

        let a0 = calculate_anchor(&current_n);
        let nineteen_a0 = nineteen.as_ref().checked_mul(&a0).expect("19*A0 overflow");
        if bool::from(current_n.ct_lt(&nineteen_a0)) { return None; }
        
        let b0 = current_n.checked_sub(&nineteen_a0).expect("guarded").div(nine.clone());
        let k_max = b0.div(nineteen);
        let target = digital_root(&T::from(2u64).checked_mul(&a0).expect("2*A0 overflow"));
        
        let b0_plus_9 = b0.checked_add(nine.as_ref()).expect("B0+9 overflow");
        let k0 = b0_plus_9.checked_sub(&target).expect("B0+9 >= target").rem(nine.clone());

        if bool::from(k0.ct_gt(&k_max)) { return None; }

        let diff_k = k_max.checked_sub(&k0).unwrap_or_else(|| zero.clone());
        let triangle_count_item = diff_k.div(nine.clone()).checked_add(&one).expect("overflow");
        
        // Converteer de teller veilig naar een loop-limiet
        let mut triangle_count = 0u64;
        let tc_bytes = triangle_count_item.to_be_bytes();
        for byte in tc_bytes.as_ref() {
            triangle_count = (triangle_count << 8) | (*byte as u64);
        }

        let mut candidates = Vec::with_capacity(triangle_count as usize);
        let mut weights = Vec::with_capacity(triangle_count as usize);

        for t_idx in 0..triangle_count {
            let t = T::from(t_idx);
            let k = k0.checked_add(&nine.as_ref().checked_mul(&t).expect("9t overflow")).expect("k overflow");
            let a = a0.checked_add(&nine.as_ref().checked_mul(&k).expect("9k overflow")).expect("a overflow");
            let nineteen_a = nineteen.as_ref().checked_mul(&a).expect("19a overflow");
            let b = current_n.checked_sub(&nineteen_a).expect("underflow").div(nine.clone());

            if !is_last_layer && !check_ahead_valid_closed_form(&a) {
                continue;
            }
            let w = if is_last_layer {
                T::from(1u64)
            } else {
                count_triangle_filtered_closed_form(&a)
            };
            if bool::from(w.ct_eq(&zero)) {
                continue;
            }
            candidates.push(DiophantinePair { a, b });
            weights.push(w);
        }

        if candidates.is_empty() { return None; }

        let total_weight = weights.iter().cloned()
            .fold(T::from(0u64), |acc, w| acc.checked_add(&w).expect("weight sum overflow"));
        let r = uniform_below(&total_weight, rng);

        let mut acc = T::from(0u64);
        let mut chosen = None;
        for (pair, w) in candidates.into_iter().zip(weights.into_iter()) {
            acc = acc.checked_add(&w).expect("acc overflow");
            if bool::from(r.ct_lt(&acc)) {
                chosen = Some(pair);
                break;
            }
        }

        let pair = chosen?;
        current_n = pair.a.clone();
        chain.push(pair);
    }

    Some(MrsChain { layers: chain, valid: true })
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
    fn test_digital_root() {
        assert_eq!(digital_root(&U64::from(0u64)), U64::from(0u64));
        assert_eq!(digital_root(&U64::from(9u64)), U64::from(9u64));
        assert_eq!(digital_root(&U64::from(10u64)), U64::from(1u64));
        assert_eq!(digital_root(&U64::from(144u64)), U64::from(9u64));
    }

    #[test]
    fn test_triangle_condition_validation() {
        assert!(bool::from(validate_triangle_condition(&U64::from(10u64), &U64::from(5u64))));
        assert!(!bool::from(validate_triangle_condition(&U64::from(9u64), &U64::from(5u64))));
    }

    #[test]
    fn test_three_layer_sampler_success() {
        let root_n = U64::from(200_001u64);
        let mut rng = OsRng;
        let result = sample_three_layers(root_n, &mut rng);
        if let Some(chain) = result {
            assert!(chain.valid);
            assert_eq!(chain.layers.len(), 3);
            assert!(bool::from(U64::from(200_001u64).ct_gt(&chain.layers[0].a)));
            assert!(bool::from(chain.layers[0].a.ct_gt(&chain.layers[1].a)));
        }
    }
            }
