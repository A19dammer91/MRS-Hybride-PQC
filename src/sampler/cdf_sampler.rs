use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};

// ============================================================================
// Branch-free primitives
//
// The plain `digital_root`, `count_triangle_filtered_closed_form`, and
// `check_ahead_valid_closed_form` all contain `if`/early-return branches
// on values that can be secret (a candidate's `a`, or a layer's
// `current_n`). The fully constant-time sampler below needs versions of
// each with no data-dependent control flow at all -- only
// `conditional_select`/masking.
// ============================================================================

/// Constant-time digital root: no branch on `n == 0`.
#[inline]
fn digital_root_ct(n: u64) -> u64 {
    let is_zero = n.ct_eq(&0);
    let nonzero_val = 1 + (n.wrapping_sub(1) % 9);
    u64::conditional_select(&nonzero_val, &0, is_zero)
}

/// Constant-time closed-form triangle count. Never branches: an invalid
/// anchor or an out-of-range k0 both collapse to 0 via masking instead of
/// an early `if`/`return`.
#[inline]
fn count_triangle_filtered_closed_form_ct(n: u64) -> u64 {
    let a0 = digital_root_ct(n);
    let anchor_ok = !(19u64.wrapping_mul(a0)).ct_gt(&n); // 19*a0 <= n
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
    let count = count_triangle_filtered_closed_form_ct(a_value);
    count.ct_gt(&1) // count >= 2
}

/// Fixed, public upper bound on candidate slots for a layer bounded by
/// `n_bound`. See the non-CT version's doc comment for the derivation
/// (b0 <= n_bound/9, k_max <= n_bound/171, triangle_count <= n_bound/1539+1).
#[inline]
fn max_triangle_slots(n_bound: u64) -> u64 {
    n_bound / 1539 + 2
}

/// Fully constant-time 3-layer sampler: no early returns anywhere in the
/// per-layer logic. Every layer always executes its full, fixed-size
/// slot computation (`max_triangle_slots(n_bound)` iterations, twice --
/// once for the weight total, once for selection), regardless of whether
/// that layer's anchor is valid or whether earlier layers already failed.
/// A single validity flag (`Choice`) is threaded through all three layers
/// via masking; only the final `Some`/`None` at the very end depends on
/// that flag -- there is exactly one data-dependent branch in the whole
/// function, at the point where the result is actually reported, which
/// is the function's real output and not an internal timing side-channel.
pub fn sample_three_layers_ct2(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    const DEPTH: usize = 3;
    let mut chain: Vec<DiophantinePair> = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;
    let mut n_bound = root_n;
    let mut overall_valid = Choice::from(1u8);

    for layer in 0..DEPTH {
        let is_last_layer = layer == DEPTH - 1;
        let slot_count = max_triangle_slots(n_bound); // public, fixed per layer

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
        // A layer only truly succeeds if its anchor was valid AND it has
        // at least one candidate slot with nonzero weight.
        let total_weight = u64::conditional_select(&0, &total_weight_raw, anchor_ok);
        let has_weight = !total_weight.ct_eq(&0);
        let layer_ok = anchor_ok & has_weight;

        // Never call uniform_below(0, ..) -- substitute a safe dummy
        // bound when this layer has no real weight; the chosen (a,b) for
        // an invalid layer is discarded anyway via overall_valid below.
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
                               // harmless, since overall_valid already
                               // records the failure and every downstream
                               // computation stays branch-free regardless
                               // of input.
        n_bound /= 19;
        chain.push(DiophantinePair { a: chosen_a, b: chosen_b });
    }

    // The ONE unavoidable branch in the whole function: reporting the
    // final success/failure result. This is the function's actual
    // output (equivalent to any authentication check ultimately
    // returning true/false) -- not an internal timing side-channel, since
    // every layer above always did the same fixed amount of work to get
    // here regardless of which path succeeded or failed.
    if bool::from(overall_valid) {
        Some(MrsChain { layers: chain, valid: true })
    } else {
        None
    }
}

// ============================================================================
// KNOWN REMAINING LIMITATION -- read before relying on this for a real
// threat model with a co-located timing adversary.
//
// This closes every *control-flow* leak: no early returns, no data-
// dependent loop bounds, no data-dependent branches. What it does NOT
// close is variable-latency integer division and modulo (`/`, `%`) at
// the CPU instruction level. On many processors, the `div`/`idiv`
// instruction's latency depends on the operand values, not just their
// bit-width -- so `b0 / 19`, `k_max / 9`, `(...) % 9` etc. can still leak
// a small amount of timing information about their operands even though
// there is no branch anywhere in this source file.
//
// Fully closing that requires replacing every division/modulo by a
// small constant (9, 19, 171, 1539) with constant-time reciprocal
// multiplication (Barrett or Montgomery-style reduction), which is a
// meaningfully larger, more error-prone piece of work and is the kind of
// thing worth having independently reviewed before shipping, given this
// is a cryptographic authentication primitive. I have not implemented
// that here -- flagging it explicitly rather than presenting this as a
// complete constant-time guarantee it does not fully provide.
// ============================================================================

#[cfg(test)]
mod constant_time_v2_tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn ct2_matches_plain_reachable_set() {
        for root_n in [201u64, 1_001, 12_345, 200_001] {
            let mut rng = OsRng;
            let mut seen_plain = std::collections::HashSet::new();
            let mut seen_ct2 = std::collections::HashSet::new();

            for _ in 0..200 {
                if let Some(chain) = sample_three_layers(root_n, &mut rng) {
                    seen_plain.insert(chain.layers.iter().map(|p| (p.a, p.b)).collect::<Vec<_>>());
                }
                if let Some(chain) = sample_three_layers_ct2(root_n, &mut rng) {
                    seen_ct2.insert(chain.layers.iter().map(|p| (p.a, p.b)).collect::<Vec<_>>());
                }
            }

            for chain in &seen_ct2 {
                assert!(
                    seen_plain.contains(chain),
                    "ct2 variant produced an unreachable chain {:?} for root_n={}",
                    chain, root_n
                );
            }
        }
    }

    #[test]
    fn ct2_is_not_deterministic_large_n() {
        let root_n = 10_000_000_001u64;
        let mut rng = OsRng;
        let mut seen = std::collections::HashSet::new();
        let mut attempts = 0;

        for _ in 0..100 {
            if let Some(chain) = sample_three_layers_ct2(root_n, &mut rng) {
                seen.insert(chain.layers.iter().map(|p| (p.a, p.b)).collect::<Vec<_>>());
                attempts += 1;
            }
        }

        assert!(
            seen.len() > 1 || attempts <= 1,
            "ct2 sampler produced the same chain {} times for root_n={}",
            attempts, root_n
        );
    }

    #[test]
    fn ct2_handles_tiny_n_without_panicking() {
        // Small N values are exactly where the old code would underflow.
        // ct2 must never panic, regardless of outcome.
        let mut rng = OsRng;
        for root_n in [0u64, 1, 5, 8, 9, 10, 15, 18, 170, 171, 200] {
            let _ = sample_three_layers_ct2(root_n, &mut rng); // must not panic
        }
    }
}
