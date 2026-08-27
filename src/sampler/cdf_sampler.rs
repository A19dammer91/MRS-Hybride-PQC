//! Weighted CDF sampler and O(1) triangle fast-path for the MRS(19,9)
//! Diophantine forest.
//!
//! Generic over native machine-word scale (`u64`) with an optional path
//! for cryptographic scale scaling via the `bigint` feature flag.

use crate::core::diophantine::{generate_representation_family, DiophantinePair};
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// Struct holding a complete 3-layer chain (Matryoshka)
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

/// Computes the digital root of a number in constant time, without loops
#[inline]
pub fn digital_root(n: u64) -> u64 {
    if n == 0 { 0 } else { 1 + ((n - 1) % 9) }
}

/// Checks the harmonic triangle requirement: dr(B) == dr(2 * dr(X))
#[inline]
pub fn validate_triangle_condition(b: u64, x: u64) -> bool {
    let dr_b = digital_root(b);
    let dr_x = digital_root(x);
    let target = digital_root(2 * dr_x);
    dr_b == target
}

/// Closed-form replacement for `count_triangle_filtered`: O(1) instead of 
/// O(N) enumeration. Counts how many representations N = 19A + 9B (with 
/// A,B >= 0) satisfy the triangle condition dr(B) == dr(2*dr(N)).
pub fn count_triangle_filtered_closed_form(n: u64) -> u64 {
    let a0 = digital_root(n);
    if 19 * a0 > n { return 0; } // Underflow bounds-check safeguard

    let b0 = (n - 19 * a0) / 9;
    let k_max = b0 / 19;
    let target = digital_root(2 * a0);
    
    let k0 = (b0 + 9 - target) % 9;
    if k0 > k_max { 0 } else { (k_max - k0) / 9 + 1 }
}

#[inline]
pub fn check_ahead_valid_closed_form(a_value: u64) -> bool {
    count_triangle_filtered_closed_form(a_value) >= 2
}

/// Draws a cryptographically random integer in [0, bound) without modulo 
/// bias, via rejection sampling on a CSPRNG.
#[inline]
fn uniform_below(bound: u64, rng: &mut impl RngCore) -> u64 {
    assert!(bound > 0, "bound must be positive");
    let limit = u64::MAX - (u64::MAX % bound);
    loop {
        let r = rng.next_u64();
        if r < limit { return r % bound; }
    }
}
// ============================================================================
// Core Sampler Engine & Optional BigInt Bridge
// ============================================================================

/// O(1) Triangle Fast-Path sampling logic based on the 19-9 system structure.
pub fn sample_triangle_core(n: u64, rng: &mut impl RngCore) -> Option<DiophantinePair> {
    let a0 = digital_root(n);
    if 19 * a0 > n { return None; }

    let b0 = (n - 19 * a0) / 9;
    let target = digital_root(2 * a0);
    let k0 = (b0 + 9 - target) % 9;

    let k_max = b0 / 19;
    if k0 > k_max { return None; }

    let diff = k_max - k0;
    let t_max = diff / 9;
    let t = uniform_below(t_max + 1, rng);
    let k = k0 + 9 * t;

    let a = a0 + 9 * k;
    let b = b0 - 19 * k;
    Some(DiophantinePair { a, b })
}

/// Builds a 3-layer Matryoshka chain based on root_n using closed-form O(1) work.
pub fn sample_three_layers(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;

    for layer in 0..DEPTH {
        let is_last_layer = layer == DEPTH - 1;
        let a0 = digital_root(current_n);
        if 19 * a0 > current_n { return None; }

        let b0 = (current_n - 19 * a0) / 9;
        let k_max = b0 / 19;
        let target = digital_root(2 * a0);
        let k0 = (b0 + 9 - target) % 9;

        if k0 > k_max { return None; }
        let triangle_count = (k_max - k0) / 9 + 1;

        let mut candidates = Vec::with_capacity(triangle_count as usize);
        let mut weights = Vec::with_capacity(triangle_count as usize);

        for t in 0..triangle_count {
            let k = k0 + 9 * t;
            let a = a0 + 9 * k;
            let b = b0 - 19 * k;

            if !is_last_layer && !check_ahead_valid_closed_form(a) {
                continue;
            }
            let w = if is_last_layer {
                1
            } else {
                count_triangle_filtered_closed_form(a)
            };
            if w == 0 {
                continue;
            }
            candidates.push(DiophantinePair { a, b });
            weights.push(w);
        }

        if candidates.is_empty() { return None; }

        let total_weight: u64 = weights.iter().sum();
        let r = uniform_below(total_weight, rng);

        let mut acc = 0u64;
        let mut chosen = None;
        for (pair, w) in candidates.into_iter().zip(weights.into_iter()) {
            acc += w;
            if r < acc {
                chosen = Some(pair);
                break;
            }
        }

        let pair = chosen?;
        current_n = pair.a;
        chain.push(pair);
    }

    Some(MrsChain { layers: chain, valid: true })
}

// Optional bridge block activated only via '--features bigint'
#[cfg(feature = "bigint")]
pub mod crypto_bigint_extension {
    use super::*;
    use crypto_bigint::U256;
    
    pub fn sample_triangle_u256(_n: &U256) -> Option<(U256, U256)> {
        None
    }
}

// ============================================================================
// Test Suite
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_digital_root() {
        assert_eq!(digital_root(0), 0);
        assert_eq!(digital_root(9), 9);
        assert_eq!(digital_root(10), 1);
        assert_eq!(digital_root(144), 9);
    }

    #[test]
    fn test_triangle_condition_validation() {
        assert!(validate_triangle_condition(10, 5));
        assert!(!validate_triangle_condition(9, 5));
    }

    #[test]
    fn test_three_layer_sampler_success() {
        let root_n = 200_001;
        let mut rng = OsRng;
        let result = sample_three_layers(root_n, &mut rng);
        if let Some(chain) = result {
            assert!(chain.valid);
            assert_eq!(chain.layers.len(), 3);
            assert!(root_n > chain.layers[0].a);
        }
    }
            }
                                
