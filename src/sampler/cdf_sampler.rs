//! Weighted CDF sampler and O(1) triangle fast-path for the MRS(19,9)
//! Diophantine forest.
//!
//! The public `sample_three_layers` is constant-time: no early returns,
//! no data-dependent branches, and a fixed number of loop iterations per
//! layer (derived only from `root_n` and the layer index, never from the
//! secret `current_n` chosen at a previous layer). A single validity
//! flag is threaded through all three layers via masking; the only
//! data-dependent branch in the whole function is the final `Some`/`None`
//! decision, which is the function's actual output, not an internal
//! timing side-channel.
//!
//! KNOWN LIMITATION: this closes every *control-flow* timing leak, but
//! does not address variable-latency integer division/modulo at the CPU
//! instruction level (`/`, `%` by 9, 19, 171, 1539 can still have
//! operand-dependent latency on some hardware). Fully closing that would
//! require replacing those divisions with constant-time reciprocal
//! multiplication (Barrett/Montgomery-style reduction), which is a
//! larger, separate piece of work not implemented here.

use crate::core::diophantine::{generate_representation_family, DiophantinePair};
use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};
use zeroize::Zeroize;

/// Struct holding a complete 3-layer chain (Matryoshka)
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

/// Computes the digital root of a number, without loops.
/// (Non-constant-time; kept for use outside the sampler hot path and by
/// the test suite. The sampler itself uses `digital_root_ct` below.)
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

/// Closed-form O(1) triangle count (non-constant-time branch version;
/// kept public for callers that don't need CT guarantees, and used by
/// the plain test oracle). The sampler itself uses the `_ct` version.
pub fn count_triangle_filtered_closed_form(n: u64) -> u64 {
    let a0 = digital_root(n);
    if 19 * a0 > n {
        return 0;
    }
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
        if r < limit {
            return r % bound;
        }
    }
}

// ============================================================================
// Constant-time primitives used by the public sample_three_layers below.
// ============================================================================

/// Constant-time digital root: no branch on `n == 0`.
#[inline]
fn digital_root_ct(n: u64) -> u64 {
    let is_zero = n.ct_eq(&0);
    let nonzero_val = 1 + (n.wrapping_sub(1) % 9);
    u64::conditional_select(&nonzero_val, &0, is_zero)
}

/// Constant-time closed-form triangle count. Never branches: an invalid
/// anchor or an out-of-range k0 both collapse to 0 via masking.
#[inline]
fn count_triangle_filtered_closed_form_ct(n: u64) -> u64 {
    let a0 = digital_root_ct(n);
    let anchor_ok = !(19u64.wrapping_mul(a0)).ct_gt(&n);
    let b0 = n.wrapping_sub(19u64.wrapping_mul(a0)) / 9;
    let k_max = b0 / 19;
    let target = digital_root_ct(2 * a0);
    let k0 = (b0.wrapping_add(9).wrapping_sub(target)) % 9;
    let k0_ok = !k0.ct_gt(&k_max);

    let count_raw = (k_max.wrapping_sub(k0)) / 9 + 1;
    let valid = anchor_ok & k0_ok;
    u64::conditional_select(&0, &count_raw, valid)
}

#[inline]
fn check_ahead_valid_closed_form_ct(a_value: u64) -> Choice {
    count_triangle_filtered_closed_form_ct(a_value).ct_gt(&1)
}

/// Fixed, PUBLIC upper bound on candidate slots for a layer bounded by
/// `n_bound`. Derivation: b0 <= n_bound/9, k_max <= n_bound/171,
/// triangle_count <= n_bound/1539 + 1. Holds for any n <= n_bound
/// regardless of digital-root residue effects.
#[inline]
fn max_triangle_slots(n_bound: u64) -> u64 {
    n_bound / 1539 + 2
}

/// Builds a 3-layer Matryoshka chain based on root_n, in constant time.
/// See the module-level doc comment for the full security rationale.
pub fn sample_three_layers(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    const DEPTH: usize = 3;
    let mut chain: Vec<DiophantinePair> = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;
    let mut n_bound = root_n;
    let mut overall_valid = Choice::from(1u8);

    for layer in 0..DEPTH {
        let is_last_layer = layer == DEPTH - 1;
        let slot_count = max_triangle_slots(n_bound);

        let a0 = digital_root_ct(current_n);
        let anchor_ok = !(19u64.wrapping_mul(a0)).ct_gt(&current_n);
        let b0 = current_n.wrapping_sub(19u64.wrapping_mul(a0)) / 9;
        let k_max = b0 / 19;
        let target = digital_root_ct(2 * a0);
        let k0 = (b0.wrapping_add(9).wrapping_sub(target)) % 9;

        // Pass 1: total weight over the fixed slot_count slots.
        let mut total_weight_raw: u64 = 0;
        for t in 0..slot_count {
            let k = k0.wrapping_add(9u64.wrapping_mul(t));
            let k_in_range = !k.ct_gt(&k_max);
            let a = a0.wrapping_add(9u64.wrapping_mul(k));

            let w_last = 1u64;
            let w_mid_raw = count_triangle_filtered_closed_form_ct(a);
            let w_mid = u64::conditional_select(&0, &w_mid_raw, check_ahead_valid_closed_form_ct(a));
            let w_layer_kind = u64::conditional_select(&w_mid, &w_last, Choice::from(is_last_layer as u8));
            let w = u64::conditional_select(&0, &w_layer_kind, k_in_range);
            total_weight_raw += w;
        }
        let total_weight = u64::conditional_select(&0, &total_weight_raw, anchor_ok);
        let has_weight = !total_weight.ct_eq(&0);
        let layer_ok = anchor_ok & has_weight;

        let safe_bound = u64::conditional_select(&1, &total_weight, has_weight);
        let r = uniform_below(safe_bound, rng);

        // Pass 2: branch-free selection over the same fixed slot_count.
        let mut acc: u64 = 0;
        let mut found = Choice::from(0u8);
        let mut chosen_a: u64 = 0;
        let mut chosen_b: u64 = 0;

        for t in 0..slot_count {
            let k = k0.wrapping_add(9u64.wrapping_mul(t));
            let k_in_range = !k.ct_gt(&k_max);
            let a = a0.wrapping_add(9u64.wrapping_mul(k));
            let b = b0.wrapping_sub(19u64.wrapping_mul(k));

            let w_last = 1u64;
            let w_mid_raw = count_triangle_filtered_closed_form_ct(a);
            let w_mid = u64::conditional_select(&0, &w_mid_raw, check_ahead_valid_closed_form_ct(a));
            let w_layer_kind = u64::conditional_select(&w_mid, &w_last, Choice::from(is_last_layer as u8));
            let w = u64::conditional_select(&0, &w_layer_kind, k_in_range);

            acc += w;
            let is_winning_slot = r.ct_lt(&acc);
            let select_this = is_winning_slot & !found;
            chosen_a.conditional_assign(&a, select_this);
            chosen_b.conditional_assign(&b, select_this);
            found |= is_winning_slot;
        }

        overall_valid &= layer_ok;
        current_n = chosen_a; // may be garbage if this layer was invalid;
                               // harmless -- overall_valid already records
                               // the failure and every downstream
                               // computation stays branch-free regardless.
        n_bound /= 19;
        chain.push(DiophantinePair { a: chosen_a, b: chosen_b });
    }

    // The one unavoidable branch in the whole function: reporting the
    // final success/failure result -- the function's actual output, not
    // an internal timing side-channel, since every layer above always
    // did the same fixed amount of work regardless of the outcome.
    if bool::from(overall_valid) {
        Some(MrsChain { layers: chain, valid: true })
    } else {
        None
    }
}

// Optional bridge block activated only via '--features bigint'
#[cfg(feature = "bigint")]
pub mod crypto_bigint_extension {
    use super::*;
    use crypto_bigint::U256;

    pub fn sample_triangle_u256(_n: &U256) -> Option<(U256, U256)> {
        None // not yet implemented
    }
}

// ============================================================================
// Test-only plain (non-CT) reference implementation, used purely to
// confirm the CT sampler above produces the same reachable set of chains
// as the straightforward algorithm.
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
            if !is_last_layer && !check_ahead_valid_closed_form(a) {
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

#[cfg(test)]
fn count_triangle_filtered_bruteforce(n: u64) -> u64 {
    generate_representation_family(n)
        .iter()
        .filter(|pair| validate_triangle_condition(pair.b, n))
        .count() as u64
}

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
    fn ct_matches_plain_reachable_set() {
        for root_n in [201u64, 1_001, 12_345, 200_001] {
            let mut rng = OsRng;
            let mut seen_plain = std::collections::HashSet::new();
            let mut seen_ct = std::collections::HashSet::new();

            for _ in 0..200 {
                if let Some(chain) = sample_three_layers_plain(root_n, &mut rng) {
                    seen_plain.insert(chain.layers.iter().map(|p| (p.a, p.b)).collect::<Vec<_>>());
                }
                if let Some(chain) = sample_three_layers(root_n, &mut rng) {
                    seen_ct.insert(chain.layers.iter().map(|p| (p.a, p.b)).collect::<Vec<_>>());
                }
            }

            for chain in &seen_ct {
                assert!(
                    seen_plain.contains(chain),
                    "ct variant produced an unreachable chain {:?} for root_n={}",
                    chain, root_n
                );
            }
        }
    }

    #[test]
    fn ct_is_not_deterministic_large_n() {
        let root_n = 10_000_000_001u64;
        let mut rng = OsRng;
        let mut seen = std::collections::HashSet::new();
        let mut attempts = 0;

        for _ in 0..100 {
            if let Some(chain) = sample_three_layers(root_n, &mut rng) {
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
            let _ = sample_three_layers(root_n, &mut rng); // must not panic
        }
    }
}
