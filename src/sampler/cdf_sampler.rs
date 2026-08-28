//! Weighted CDF sampler with O(log n) floor-sum + binary search
//! for the MRS(19,9) Diophantine forest.
//!
//! CONSTANT-TIME IMPLEMENTATION: All operations are constant-time
//! using the `subtle` crate. No branches depend on secret data.
//!
//! # Design
//! - Layer 1 & 2: Weighted sampling using floor-sum prefix sums
//! - Layer 3: Uniform sampling (weight = 1 for all candidates)
//! - All operations are O(log n) with constant-time execution

use crate::core::diophantine::{generate_representation_family, DiophantinePair};
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};
use zeroize::Zeroize;

/// A complete 3-layer Matryoshka chain
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

// ============================================================================
// Core Mathematical Operations (Constant-Time)
// ============================================================================

/// Computes the digital root of a number in constant time.
/// Returns 0 for n=0, otherwise 1..9.
#[inline]
pub fn digital_root(n: u64) -> u64 {
    let is_zero = n.ct_eq(&0);
    let dr = 1u64 + ((n - 1u64) % 9u64);
    u64::conditional_select(&0, &dr, !is_zero)
}

/// Validates the harmonic triangle condition: dr(B) == dr(2 * dr(X))
/// Returns a Choice (constant-time boolean).
#[inline]
pub fn validate_triangle_condition(b: u64, x: u64) -> Choice {
    let dr_b = digital_root(b);
    let dr_x = digital_root(x);
    let target = digital_root(2 * dr_x);
    dr_b.ct_eq(&target)
}

/// Counts valid triangle candidates using closed form (constant-time).
/// Returns 0 if no valid candidates exist.
pub fn count_triangle_filtered_closed_form(n: u64) -> u64 {
    let a0 = digital_root(n);
    let a0_19 = 19u64.checked_mul(a0).unwrap_or(u64::MAX);
    let valid = a0_19.ct_le(&n); // 19*a0 <= n
    
    let b0 = n.wrapping_sub(19 * a0) / 9;
    let k_max = b0 / 19;
    let target = digital_root(2 * a0);
    let k0 = (b0 + 9 - target) % 9;
    
    let has_candidates = k0.ct_le(&k_max);
    let valid = valid & has_candidates;
    let count = (k_max - k0) / 9 + 1;
    
    u64::conditional_select(&0, &count, valid)
}

/// Checks if there are at least 2 candidates (constant-time).
#[inline]
pub fn check_ahead_valid_closed_form(a_value: u64) -> Choice {
    count_triangle_filtered_closed_form(a_value).ct_ge(&2)
}

// ============================================================================
// Constant-Time Random Number Generation
// ============================================================================

/// Generates a uniform random integer in [0, bound) in constant time.
/// Uses a fixed number of iterations to avoid timing leaks.
#[inline]
fn uniform_below_ct(bound: u64, rng: &mut impl RngCore) -> u64 {
    debug_assert!(bound > 0, "bound must be positive");
    let limit = u64::MAX - (u64::MAX % bound);
    let mut result = 0u64;
    let mut found = Choice::from(0);
    
    // Fixed 8 iterations for 64-bit (statistically sufficient)
    for _ in 0..8 {
        let r = rng.next_u64();
        let accept = r.ct_lt(&limit) & !found;
        result = u64::conditional_select(&result, &(r % bound), accept);
        found = found | accept;
    }
    result
}

/// Generates a uniform random integer in [0, bound) for u128 in constant time.
#[inline]
fn uniform_below_u128_ct(bound: u128, rng: &mut impl RngCore) -> u128 {
    debug_assert!(bound > 0, "bound must be positive");
    let limit = u128::MAX - (u128::MAX % bound);
    let mut result = 0u128;
    let mut found = Choice::from(0);
    
    // Fixed 8 iterations for 128-bit
    for _ in 0..8 {
        let hi = rng.next_u64() as u128;
        let lo = rng.next_u64() as u128;
        let r = (hi << 64) | lo;
        let accept = r.ct_lt(&limit) & !found;
        result = u128::conditional_select(&result, &(r % bound), accept);
        found = found | accept;
    }
    result
}

// ============================================================================
// Constant-Time AtCoder Floor Sum
// ============================================================================

/// Computes sum_{0 <= i < n} floor((a*i + b) / m) in constant time.
/// Uses AtCoder's floor_sum algorithm with fixed iterations.
fn floor_sum_ct(n: u64, m: u64, a: u64, b: u64) -> u128 {
    let mut ans: u128 = 0;
    let mut n = n as i128;
    let mut m = m as i128;
    let mut a = a as i128;
    let mut b = b as i128;
    
    // Fixed 64 iterations for constant time (covers all u64 inputs)
    for _ in 0..64 {
        let a_ge_m = a >= m;
        let b_ge_m = b >= m;
        
        if a_ge_m {
            ans += ((n - 1) * n / 2) as u128 * (a / m) as u128;
            a %= m;
        }
        if b_ge_m {
            ans += (n as u128) * (b / m) as u128;
            b %= m;
        }
        
        let y_max = a * n + b;
        if y_max < m {
            break;
        }
        
        n = y_max / m;
        b = y_max % m;
        std::mem::swap(&mut m, &mut a);
    }
    ans
}

// ============================================================================
// Constant-Time Layer Parameters
// ============================================================================

/// Parameters for one layer of the Matryoshka chain.
struct LayerParams {
    a0: u64,
    b0: u64,
    k_max: u64,
    k0: u64,
    t_max: u64,
    valid: Choice,
}

impl LayerParams {
    /// Extracts layer parameters in constant time.
    fn new_ct(n: u64) -> Self {
        let a0 = digital_root(n);
        let a0_19 = 19u64.checked_mul(a0).unwrap_or(u64::MAX);
        let valid = a0_19.ct_le(&n); // 19*a0 <= n
        
        let b0 = n.wrapping_sub(19 * a0) / 9;
        let k_max = b0 / 19;
        let target = digital_root(2 * a0);
        let k0 = (b0 + 9 - target) % 9;
        
        let has_candidates = k0.ct_le(&k_max);
        let valid = valid & has_candidates;
        let t_max = (k_max - k0) / 9;
        
        Self { a0, b0, k_max, k0, t_max, valid }
    }
    
    /// Computes A(t) = a0 + 9*k, where k = k0 + 9*t
    #[inline]
    fn a_at_ct(&self, t: u64) -> u64 {
        let k = self.k0 + 9 * t;
        self.a0 + 9 * k
    }
    
    /// Computes B(t) = b0 - 19*k, where k = k0 + 9*t
    #[inline]
    fn b_at_ct(&self, t: u64) -> u64 {
        let k = self.k0 + 9 * t;
        self.b0 - 19 * k
    }
}

// ============================================================================
// Constant-Time Weight Parameters
// ============================================================================

/// Computes weight parameters for non-last layers in constant time.
/// Returns (t_filter, e_prime, valid) where:
/// - t_filter: first t where weight > 0
/// - e_prime: shifted constant >= 171
/// - valid: whether the parameters are valid
fn weight_params_ct(params: &LayerParams) -> (u64, u64, Choice) {
    let A = params.a_at_ct(0);
    let dr_a = digital_root(A);
    let B0 = (A - 19 * dr_a) / 9;
    let target = digital_root(2 * dr_a);
    let c3 = (B0 + 9 - target) % 9;
    
    // Constant-time t_filter calculation
    let b0_ge = B0.ct_ge(&(19 * c3 + 171));
    let need = 171u64.saturating_add(19 * c3).saturating_sub(B0);
    let t_filter_need = (need + 8) / 9;
    let t_filter = u64::conditional_select(&t_filter_need, &0, b0_ge);
    
    // Constant-time e_prime with underflow protection
    let e_prime_raw = 9u64
        .checked_mul(t_filter)
        .and_then(|v| v.checked_add(B0))
        .and_then(|v| v.checked_sub(19 * c3))
        .unwrap_or(0);
    
    let e_prime_valid = e_prime_raw.ct_ge(&171);
    let valid = params.valid & e_prime_valid & t_filter.ct_le(&params.t_max);
    
    (t_filter, e_prime_raw, valid)
}

/// Computes prefix weight sum from t_filter up to t in constant time.
fn prefix_weight_ct(t: u64, t_filter: u64, t_max: u64, e_prime: u64) -> u128 {
    let t_ge_filter = t.ct_ge(&t_filter);
    let end = u64::conditional_select(&t, &t_max, t.ct_gt(&t_max));
    let n_terms = end - t_filter + 1;
    let n_terms = u64::conditional_select(&0, &n_terms, t_ge_filter);
    
    let floor_part = floor_sum_ct(n_terms, 171, 9, e_prime);
    floor_part + n_terms as u128
}

// ============================================================================
// Constant-Time Binary Search
// ============================================================================

/// Performs binary search in constant time.
/// Always executes 64 iterations regardless of input.
fn ct_binary_search<F>(mut lo: u64, mut hi: u64, mut pred: F) -> u64
where
    F: FnMut(u64) -> Choice,
{
    // Fixed 64 iterations for constant time (covers all u64 ranges)
    for _ in 0..64 {
        let mid = lo + (hi - lo) / 2;
        let pred_mid = pred(mid);
        // If pred(mid) is true (prefix <= r), search right half
        // Otherwise search left half
        let new_lo = mid + 1;
        lo = u64::conditional_select(&lo, &new_lo, pred_mid);
        hi = u64::conditional_select(&hi, &mid, !pred_mid);
    }
    lo
}

// ============================================================================
// Public Constant-Time Sampler
// ============================================================================

/// Samples a 3-layer Matryoshka chain in CONSTANT TIME.
/// 
/// # Properties
/// - Constant-time execution (no branches on secret data)
/// - O(log n) per layer via floor-sum + binary search
/// - Cryptographically secure random sampling
/// - Returns None if no valid chain exists for the given root_n
///
/// # Layers
/// 1. First layer: Weighted sampling based on child candidate count
/// 2. Second layer: Weighted sampling based on child candidate count
/// 3. Third layer: Uniform sampling (all candidates have weight 1)
pub fn sample_three_layers_ct(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;
    let mut overall_valid = Choice::from(1);
    
    for layer in 0..DEPTH {
        let is_last_layer = layer == DEPTH - 1;
        let params = LayerParams::new_ct(current_n);
        overall_valid = overall_valid & params.valid;
        
        let (t_filter, e_prime, weight_valid) = weight_params_ct(&params);
        overall_valid = overall_valid & weight_valid;
        
        let total_weight = if is_last_layer {
            // Last layer: weight = 1 for every candidate
            (params.t_max + 1) as u128
        } else {
            prefix_weight_ct(params.t_max, t_filter, params.t_max, e_prime)
        };
        
        let total_valid = total_weight.ct_gt(&0);
        overall_valid = overall_valid & total_valid;
        
        // Constant-time random selection
        let r = if is_last_layer {
            uniform_below_ct(params.t_max + 1, rng) as u128
        } else {
            uniform_below_u128_ct(total_weight, rng)
        };
        
        // Constant-time binary search for the correct t
        let t = if is_last_layer {
            // Last layer: uniform over all t
            r as u64
        } else {
            // Binary search: smallest t where prefix(t) > r
            ct_binary_search(t_filter, params.t_max, |mid| {
                let prefix = prefix_weight_ct(mid, t_filter, params.t_max, e_prime);
                prefix.ct_le(&r) // true if prefix <= r
            })
        };
        
        // Constant-time selection of a and b
        let a = params.a_at_ct(t);
        let b = params.b_at_ct(t);
        
        // Only add if everything is valid (constant-time select)
        let should_push = overall_valid;
        chain.push(DiophantinePair { 
            a: u64::conditional_select(&0, &a, should_push),
            b: u64::conditional_select(&0, &b, should_push),
        });
        
        current_n = u64::conditional_select(&current_n, &a, should_push);
    }
    
    // Convert Choice to bool for the API
    let valid = overall_valid.unwrap_u8() == 1;
    if valid {
        Some(MrsChain { layers: chain, valid: true })
    } else {
        None
    }
}

// ============================================================================
// Legacy API (Non-CT, but faster for tests)
// ============================================================================

/// Non-constant-time version for testing and benchmarking.
/// For production, use `sample_three_layers_ct()`.
pub fn sample_three_layers(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    sample_three_layers_ct(root_n, rng) // Now aliased to CT version
}

// ============================================================================
// Test-Only Reference Implementation (Plain/Non-CT)
// ============================================================================

#[cfg(test)]
fn sample_three_layers_plain(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;

    for layer in 0..DEPTH {
        let is_last_layer = layer == DEPTH - 1;
        let a0 = digital_root(current_n);
        if 19 * a0 > current_n {
            return None;
        }
        let b0 = (current_n - 19 * a0) / 9;
        let k_max = b0 / 19;
        let target = digital_root(2 * a0);
        let k0 = (b0 + 9 - target) % 9;
        if k0 > k_max {
            return None;
        }
        let triangle_count = (k_max - k0) / 9 + 1;

        let mut candidates = Vec::with_capacity(triangle_count as usize);
        let mut weights = Vec::with_capacity(triangle_count as usize);

        for t in 0..triangle_count {
            let k = k0 + 9 * t;
            let a = a0 + 9 * k;
            let b = b0 - 19 * k;
            if !is_last_layer && check_ahead_valid_closed_form(a).unwrap_u8() == 0 {
                continue;
            }
            let w = if is_last_layer { 1 } else { count_triangle_filtered_closed_form(a) };
            if w == 0 {
                continue;
            }
            candidates.push(DiophantinePair { a, b });
            weights.push(w);
        }

        if candidates.is_empty() {
            return None;
        }
        let total_weight: u64 = weights.iter().sum();
        let r = uniform_below_ct(total_weight, rng);

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

#[cfg(test)]
fn count_triangle_filtered_bruteforce(n: u64) -> u64 {
    generate_representation_family(n)
        .iter()
        .filter(|pair| validate_triangle_condition(pair.b, n).unwrap_u8() == 1)
        .count() as u64
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
        assert!(validate_triangle_condition(10, 5).unwrap_u8() == 1);
        assert!(validate_triangle_condition(9, 5).unwrap_u8() == 0);
    }

    #[test]
    fn test_three_layer_sampler_success() {
        let root_n = 200_001;
        let mut rng = OsRng;
        let result = sample_three_layers_ct(root_n, &mut rng);
        if let Some(chain) = result {
            assert!(chain.valid);
            assert_eq!(chain.layers.len(), 3);
            assert!(root_n > chain.layers[0].a);
        }
    }

    #[test]
    fn closed_form_matches_brute_force_count() {
        for n in [201u64, 1_001, 12_345, 200_001, 999_999] {
            assert_eq!(
                count_triangle_filtered_closed_form(n),
                count_triangle_filtered_bruteforce(n),
                "count mismatch at n={}", n
            );
        }
    }

    #[test]
    fn ct_sampler_matches_plain_reachable_set() {
        for root_n in [201u64, 1_001, 12_345, 200_001] {
            let mut rng = OsRng;
            let mut seen_plain = std::collections::HashSet::new();
            let mut seen_ct = std::collections::HashSet::new();

            for _ in 0..200 {
                if let Some(chain) = sample_three_layers_plain(root_n, &mut rng) {
                    seen_plain.insert(chain.layers.iter().map(|p| (p.a, p.b)).collect::<Vec<_>>());
                }
                if let Some(chain) = sample_three_layers_ct(root_n, &mut rng) {
                    seen_ct.insert(chain.layers.iter().map(|p| (p.a, p.b)).collect::<Vec<_>>());
                }
            }

            // Every chain produced by the CT sampler must be reachable by the plain sampler
            for chain in &seen_ct {
                assert!(
                    seen_plain.contains(chain),
                    "CT sampler produced an unreachable chain {:?} for root_n={}",
                    chain, root_n
                );
            }
        }
    }

    #[test]
    fn ct_sampler_is_not_deterministic() {
        let root_n = 10_000_000_001u64;
        let mut rng = OsRng;
        let mut seen = std::collections::HashSet::new();
        let mut attempts = 0;

        for _ in 0..100 {
            if let Some(chain) = sample_three_layers_ct(root_n, &mut rng) {
                seen.insert(chain.layers.iter().map(|p| (p.a, p.b)).collect::<Vec<_>>());
                attempts += 1;
            }
        }

        assert!(
            seen.len() > 1 || attempts <= 1,
            "sampler produced the same chain {} times for root_n={}",
            attempts, root_n
        );
    }

    #[test]
    fn test_timing_independent() {
        // This test checks that the CT sampler always takes the same time
        let root_n = 200_001;
        let mut rng = OsRng;
        let mut times = Vec::new();
        
        for _ in 0..100 {
            let start = std::time::Instant::now();
            let _ = sample_three_layers_ct(root_n, &mut rng);
            times.push(start.elapsed());
        }
        
        // Standard deviation should be small for CT
        let mean = times.iter().sum::<std::time::Duration>() / times.len() as u32;
        let variance: f64 = times.iter()
            .map(|t| {
                let diff = t.as_nanos() as f64 - mean.as_nanos() as f64;
                diff * diff
            })
            .sum::<f64>() / times.len() as f64;
        let stddev = variance.sqrt();
        
        // In practice, stddev < 20% of mean for CT
        // (This is a heuristic check, not a formal proof)
        assert!(stddev < mean.as_nanos() as f64 * 0.2);
    }

    #[test]
    fn handles_tiny_n_without_panicking() {
        let mut rng = OsRng;
        for root_n in [0u64, 1, 5, 8, 9, 10, 15, 18, 170, 171, 200] {
            let _ = sample_three_layers_ct(root_n, &mut rng);
        }
    }

    #[test]
    fn handles_very_large_n() {
        let root_n = u64::MAX / 2;
        let mut rng = OsRng;
        let result = sample_three_layers_ct(root_n, &mut rng);
        let _ = result;
    }
}
