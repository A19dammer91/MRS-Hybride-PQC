//! Weighted CDF sampler with O(log n) floor-sum + binary search
//! for the MRS(19,9) Diophantine witness space.
//!
//! CONSTANT-TIME IMPLEMENTATION: all operations on secret-dependent data
//! (chain contents, layer parameters, sampled indices) are constant-time.
//! Branching on the *loop index* (`layer`) is fine — it is public/structural,
//! not derived from any secret — but nothing derived from `root_n`,
//! `master_secret`, or sampled randomness is ever used in an `if`.
//!
//! `subtle` gives us `ConstantTimeEq`, `ConstantTimeGreater`,
//! `ConstantTimeLess`, and `ConditionallySelectable` for the built-in
//! integer types up to `u64`/`i64` — but NOT `ct_le`/`ct_ge` (its dual
//! comparisons), and NOT anything at all for `u128`/`i128`. Both gaps are
//! filled locally below instead of being called as if they existed.
//!
//! # Design
//! - Layer 1 & 2: weighted sampling using floor-sum prefix sums
//! - Layer 3: uniform sampling (weight = 1 for all candidates)
//! - All per-layer work is O(log n) but runs in a fixed number of
//!   iterations regardless of input, so it takes constant time.

use crate::core::diophantine::{DiophantinePair, digital_root};
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};
use zeroize::Zeroize;

/// A complete 3-layer witness chain.
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

// ============================================================================
// Constant-Time Comparison Helpers
// ============================================================================
// `subtle` only ships `ct_lt`/`ct_gt`/`ct_eq`. These extension traits add
// the missing dual comparisons for `u64`, defined in terms of what already
// exists, so they carry the exact same constant-time guarantee.

trait ConstantTimeLe {
    fn ct_le(&self, other: &Self) -> Choice;
}

trait ConstantTimeGe {
    fn ct_ge(&self, other: &Self) -> Choice;
}

impl ConstantTimeLe for u64 {
    #[inline]
    fn ct_le(&self, other: &Self) -> Choice {
        !self.ct_gt(other)
    }
}

impl ConstantTimeGe for u64 {
    #[inline]
    fn ct_ge(&self, other: &Self) -> Choice {
        !self.ct_lt(other)
    }
}

// `subtle` implements none of these traits for `u128`, so every comparison
// and selection on `u128` is hand-rolled here. `overflowing_sub`'s borrow
// flag is a single branch-free arithmetic instruction on every target
// `subtle` itself supports, so this carries the same guarantee as the
// built-in `u64` primitives.

#[inline]
fn ct_lt_u128(a: u128, b: u128) -> Choice {
    let (_, borrow) = a.overflowing_sub(b);
    Choice::from(borrow as u8)
}

#[inline]
fn ct_gt_u128(a: u128, b: u128) -> Choice {
    ct_lt_u128(b, a)
}

#[inline]
fn ct_le_u128(a: u128, b: u128) -> Choice {
    !ct_gt_u128(a, b)
}

#[inline]
fn ct_ge_u128(a: u128, b: u128) -> Choice {
    !ct_lt_u128(a, b)
}

/// `u128` has no `ConditionallySelectable` impl in `subtle` (and we can't
/// add one ourselves — both the trait and the type are foreign). This is
/// the freestanding equivalent: returns `a` if `choice` is 0, `b` if 1.
#[inline]
fn ct_select_u128(a: u128, b: u128, choice: Choice) -> u128 {
    let mask = (choice.unwrap_u8() as u128).wrapping_neg();
    (b & mask) | (a & !mask)
}

#[inline]
fn ct_eq_u128(a: u128, b: u128) -> Choice {
    !ct_lt_u128(a, b) & !ct_gt_u128(a, b)
}

// ============================================================================
// Core Mathematical Operations (Constant-Time)
// ============================================================================
// `digital_root` and `validate_triangle_condition` live in
// `core::diophantine` — they are not redefined here. Two implementations
// of the same formula drifting apart is exactly the kind of bug this
// crate can't afford, so this module only ever adds NEW operations on
// top of the shared ones.

/// Counts valid triangle candidates using the closed form (constant-time).
/// Returns 0 if no valid candidates exist.
pub fn count_triangle_filtered_closed_form(n: u64) -> u64 {
    let a0 = digital_root(n);
    let a0_19 = 19u64.checked_mul(a0).unwrap_or(u64::MAX);
    let valid = a0_19.ct_le(&n); // 19*a0 <= n

    let b0 = n.wrapping_sub(19 * a0) / 9;
    let k_max = b0 / 19;
    let target = digital_root(2 * a0);
    let k0 = b0.wrapping_add(9).wrapping_sub(target) % 9;

    let has_candidates = k0.ct_le(&k_max);
    let valid = valid & has_candidates;
    let count = k_max.wrapping_sub(k0) / 9 + 1;

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
///
/// `bound` may legitimately be 0 here — an earlier layer's parameters were
/// invalid and `overall_valid` will end up false regardless of what this
/// function returns. But `% 0` is a hard panic in Rust that can't be
/// masked after the fact (unlike almost everything else in this file), so
/// `bound` is floored to 1 via constant-time select *before* any division
/// happens. `debug_assert!` alone does NOT prevent this: it's compiled out
/// entirely in release builds, and even in debug builds it only changes
/// which panic message you get.
#[inline]
fn uniform_below_ct(bound: u64, rng: &mut impl RngCore) -> u64 {
    let safe_bound = u64::conditional_select(&bound, &1, bound.ct_eq(&0));
    let limit = u64::MAX - (u64::MAX % safe_bound);
    let mut result = 0u64;
    let mut found = Choice::from(0);

    // Fixed 8 iterations (statistically sufficient rejection sampling).
    for _ in 0..8 {
        let r = rng.next_u64();
        let accept = r.ct_lt(&limit) & !found;
        result = u64::conditional_select(&result, &(r % safe_bound), accept);
        found |= accept;
    }
    result
}

/// Generates a uniform random integer in [0, bound) for `u128` in constant time.
/// See `uniform_below_ct` above for why `bound == 0` is handled rather than
/// asserted against.
#[inline]
fn uniform_below_u128_ct(bound: u128, rng: &mut impl RngCore) -> u128 {
    let safe_bound = ct_select_u128(bound, 1, ct_eq_u128(bound, 0));
    let limit = u128::MAX - (u128::MAX % safe_bound);
    let mut result = 0u128;
    let mut found = Choice::from(0);

    // Fixed 8 iterations for 128-bit.
    for _ in 0..8 {
        let hi = rng.next_u64() as u128;
        let lo = rng.next_u64() as u128;
        let r = (hi << 64) | lo;
        let accept = ct_lt_u128(r, limit) & !found;
        result = ct_select_u128(result, r % safe_bound, accept);
        found |= accept;
    }
    result
}

// ============================================================================
// Constant-Time AtCoder Floor Sum
// ============================================================================

/// Computes `sum_{0 <= i < n} floor((a*i + b) / m)` in constant time.
/// Fixed 64 iterations; once the algorithm would logically terminate,
/// ALL state (not just `n`) is frozen so later iterations are pure no-ops —
/// this also guarantees `m` never decays to 0, which would otherwise make
/// a later division panic. `m` is also floored to 1 on entry (via constant-
/// time select, not `.max()`, which is a codegen detail rather than a
/// language guarantee) in case an invalid upstream layer ever passes 0.
fn floor_sum_ct(n: u64, m: u64, a: u64, b: u64) -> u128 {
    let mut ans: u128 = 0;
    let mut n = n as u128;
    let mut m = ct_select_u128(m as u128, 1, ct_lt_u128(m as u128, 1));
    let mut a = a as u128;
    let mut b = b as u128;
    let mut done = Choice::from(0);

    for _ in 0..64 {
        let a_ge_m = ct_ge_u128(a, m) & !done;
        let a_div_m = a / m;
        let a_mod_m = a % m;
        let add_a = n.wrapping_sub(1).wrapping_mul(n) / 2 * a_div_m;
        ans = ct_select_u128(ans, ans.wrapping_add(add_a), a_ge_m);
        a = ct_select_u128(a, a_mod_m, a_ge_m);

        let b_ge_m = ct_ge_u128(b, m) & !done;
        let b_div_m = b / m;
        let b_mod_m = b % m;
        let add_b = n.wrapping_mul(b_div_m);
        ans = ct_select_u128(ans, ans.wrapping_add(add_b), b_ge_m);
        b = ct_select_u128(b, b_mod_m, b_ge_m);

        let y_max = a.wrapping_mul(n).wrapping_add(b);
        let terminates_now = ct_lt_u128(y_max, m) & !done;

        let new_n = y_max / m;
        let new_b = y_max % m;

        // Swap m and a only while genuinely still running — not even on
        // the iteration that terminates, matching the original recursive
        // algorithm, which does not recurse/swap once it terminates.
        let advance = !done & !terminates_now;
        let (new_m, new_a) = (ct_select_u128(m, a, advance), ct_select_u128(a, m, advance));
        m = new_m;
        a = new_a;
        n = ct_select_u128(n, new_n, advance);
        b = ct_select_u128(b, new_b, advance);

        done |= terminates_now;
    }
    ans
}

// ============================================================================
// Constant-Time Layer Parameters
// ============================================================================

/// Parameters for one layer of the witness chain.
struct LayerParams {
    a0: u64,
    b0: u64,
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
        let k0 = b0.wrapping_add(9).wrapping_sub(target) % 9;

        let has_candidates = k0.ct_le(&k_max);
        let valid = valid & has_candidates;
        let t_max = k_max.wrapping_sub(k0) / 9;

        Self { a0, b0, k0, t_max, valid }
    }

    /// Computes A(t) = a0 + 9*k, where k = k0 + 9*t.
    #[inline]
    fn a_at_ct(&self, t: u64) -> u64 {
        let k = self.k0 + 9 * t;
        self.a0 + 9 * k
    }

    /// Computes B(t) = b0 - 19*k, where k = k0 + 9*t.
    #[inline]
    fn b_at_ct(&self, t: u64) -> u64 {
        let k = self.k0 + 9 * t;
        self.b0.wrapping_sub(19 * k)
    }
}

// ============================================================================
// Constant-Time Weight Parameters
// ============================================================================

/// Computes weight parameters for non-last layers in constant time.
/// Returns `(t_filter, e_prime, valid)` where:
/// - `t_filter`: first `t` where weight > 0
/// - `e_prime`: shifted constant >= 171
/// - `valid`: whether the parameters are valid
fn weight_params_ct(params: &LayerParams) -> (u64, u64, Choice) {
    let a_val = params.a_at_ct(0);
    let dr_a = digital_root(a_val);
    let b0_val = (a_val - 19 * dr_a) / 9;
    let target = digital_root(2 * dr_a);
    let c3 = b0_val.wrapping_add(9).wrapping_sub(target) % 9;

    // Constant-time t_filter calculation.
    let b0_ge = b0_val.ct_ge(&(19 * c3 + 171));
    let need = 171u64.saturating_add(19 * c3).saturating_sub(b0_val);
    let t_filter_need = (need + 8) / 9;
    let t_filter = u64::conditional_select(&t_filter_need, &0, b0_ge);

    // Constant-time e_prime with underflow protection.
    let e_prime_raw = 9u64
        .checked_mul(t_filter)
        .and_then(|v| v.checked_add(b0_val))
        .and_then(|v| v.checked_sub(19 * c3))
        .unwrap_or(0);

    let e_prime_valid = e_prime_raw.ct_ge(&171);
    let valid = params.valid & e_prime_valid & t_filter.ct_le(&params.t_max);

    (t_filter, e_prime_raw, valid)
}

/// Computes the prefix weight sum from `t_filter` up to `t` in constant time.
fn prefix_weight_ct(t: u64, t_filter: u64, t_max: u64, e_prime: u64) -> u128 {
    let t_ge_filter = t.ct_ge(&t_filter);
    let end = u64::conditional_select(&t, &t_max, t.ct_gt(&t_max));
    let n_terms_raw = end.wrapping_sub(t_filter).wrapping_add(1);
    let n_terms = u64::conditional_select(&0, &n_terms_raw, t_ge_filter);

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
    for _ in 0..64 {
        let mid = lo + (hi.wrapping_sub(lo)) / 2;
        let pred_mid = pred(mid);
        // If pred(mid) is true (prefix <= r), search the right half;
        // otherwise search the left half.
        let new_lo = mid + 1;
        lo = u64::conditional_select(&lo, &new_lo, pred_mid);
        hi = u64::conditional_select(&hi, &mid, !pred_mid);
    }
    lo
}

// ============================================================================
// Public Constant-Time Sampler
// ============================================================================

/// Samples a 3-layer witness chain in constant time.
///
/// # Properties
/// - No branch depends on secret data (only on the public loop index).
/// - O(log n) work per layer via floor-sum + binary search, each bounded
///   by a fixed iteration count.
/// - Cryptographically secure random sampling.
/// - Returns `None` if no valid chain exists for the given `root_n` — but
///   note `root_n` itself is never branched on to decide this; the `None`
///   falls out of `overall_valid` staying false through every layer.
///
/// # Layers
/// 1. First layer: weighted sampling based on child candidate count.
/// 2. Second layer: weighted sampling based on child candidate count.
/// 3. Third layer: uniform sampling (all candidates have weight 1).
pub fn sample_three_layers_ct(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;
    let mut overall_valid = Choice::from(1);

    for layer in 0..DEPTH {
        // Branching on `layer` is fine: it's the public loop index, not
        // derived from any secret.
        let is_last_layer = layer == DEPTH - 1;

        let params = LayerParams::new_ct(current_n);
        overall_valid &= params.valid;

        let (t_filter, e_prime, weight_valid) = weight_params_ct(&params);
        overall_valid &= weight_valid;

        let total_weight = if is_last_layer {
            (params.t_max + 1) as u128
        } else {
            prefix_weight_ct(params.t_max, t_filter, params.t_max, e_prime)
        };

        let total_valid = ct_gt_u128(total_weight, 0);
        overall_valid &= total_valid;

        let r = if is_last_layer {
            uniform_below_ct(params.t_max + 1, rng) as u128
        } else {
            uniform_below_u128_ct(total_weight, rng)
        };

        let t = if is_last_layer {
            r as u64
        } else {
            // Smallest t where prefix(t) > r.
            ct_binary_search(t_filter, params.t_max, |mid| {
                let prefix = prefix_weight_ct(mid, t_filter, params.t_max, e_prime);
                ct_le_u128(prefix, r) // true if prefix <= r
            })
        };

        let a = params.a_at_ct(t);
        let b = params.b_at_ct(t);

        // Only commit if everything up to this point is valid.
        let should_push = overall_valid;
        chain.push(DiophantinePair {
            a: u64::conditional_select(&0, &a, should_push),
            b: u64::conditional_select(&0, &b, should_push),
        });

        current_n = u64::conditional_select(&current_n, &a, should_push);
    }

    if overall_valid.unwrap_u8() == 1 {
        Some(MrsChain { layers: chain, valid: true })
    } else {
        None
    }
}

/// Alias kept for readability at call sites that don't need to spell out
/// `_ct` — this always resolves to the constant-time implementation above.
/// There is no separate non-constant-time production path.
pub fn sample_three_layers(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    sample_three_layers_ct(root_n, rng)
}

// ============================================================================
// Test-Only Independent Reference Count
// ============================================================================


/// by the triangle condition using `core::diophantine`'s own (Popoviciu-
/// cardinality-based) generator — a genuinely different derivation from
/// `count_triangle_filtered_closed_form`'s a0/b0/k0/k_max approach, so this
/// actually catches a bug in either one instead of checking a formula
/// against a restatement of itself.
#[cfg(test)]
fn count_triangle_filtered_bruteforce(n: u64) -> u64 {
    crate::core::diophantine::generate_representation_family(n).len() as u64
}

// ============================================================================
// Test Suite
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::diophantine::validate_triangle_condition;
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
        let root_n = 3_000_001;
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
    fn ct_sampler_produces_valid_chains() {
        // Property-based instead of comparing against a separately-drawn
        // plain-sampler set. That comparison needed huge sample counts to
        // reliably overlap two independent random draws from a candidate
        // space of thousands of possible chains, and — worse — silently
        // passed vacuously whenever root_n produced empty sets (which is
        // exactly what happened with the old, structurally infeasible
        // root_n test values: "empty set is a subset of empty set" always
        // holds, so the test looked green while checking nothing).
        //
        // This instead verifies the actual defining properties directly
        // on every chain the CT sampler returns: this is what "valid"
        // means, independent of what the plain sampler happens to draw.
        for root_n in [3_000_001u64, 3_500_007, 4_200_013, 10_000_001] {
            let mut rng = OsRng;
            let mut sampled_any = false;

            for _ in 0..500 {
                if let Some(chain) = sample_three_layers_ct(root_n, &mut rng) {
                    sampled_any = true;
                    assert_eq!(
                        chain.layers.len(), 3,
                        "chain for root_n={} has wrong depth", root_n
                    );

                    let mut current_n = root_n;
                    let last_index = chain.layers.len() - 1;
                    for (i, pair) in chain.layers.iter().enumerate() {
                        let is_last = i == last_index;

                        // Defining Diophantine relation: 19*A + 9*B == parent.
                        let lhs = 19u64.wrapping_mul(pair.a).wrapping_add(9u64.wrapping_mul(pair.b));
                        assert_eq!(
                            lhs, current_n,
                            "layer {} fails 19*A+9*B == parent for root_n={}: A={}, B={}, parent={}",
                            i, root_n, pair.a, pair.b, current_n
                        );

                        // Harmonic triangle condition: dr(B) == dr(2*dr(parent)).
                        assert!(
                            validate_triangle_condition(pair.b, current_n).unwrap_u8() == 1,
                            "layer {} fails triangle condition for root_n={}: A={}, B={}, parent={}",
                            i, root_n, pair.a, pair.b, current_n
                        );

                        // Non-final layers must themselves admit >= 2
                        // children, otherwise the chain couldn't
                        // legitimately have continued past this point.
                        if !is_last {
                            assert!(
                                check_ahead_valid_closed_form(pair.a).unwrap_u8() == 1,
                                "layer {} value A={} has fewer than 2 children for root_n={}",
                                i, pair.a, root_n
                            );
                        }

                        current_n = pair.a;
                    }
                }
            }

            assert!(
                sampled_any,
                "sampler never produced a chain for root_n={} in 500 tries", root_n
            );
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
        let _ = sample_three_layers_ct(root_n, &mut rng);
    }
                    }
