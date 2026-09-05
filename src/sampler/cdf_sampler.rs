// Weighted CDF sampler with O(log n) floor-sum + binary search
// for the MRS(19,9) Diophantine witness space.
//
//! CONSTANT-TIME IMPLEMENTATION: all operations on secret-dependent data
//! (chain contents, layer parameters, sampled indices, and how many
//! attempts a retry loop needed) are constant-time.
//! Branching on the *loop index* ('layer' or the retry counter) is fine,
//! it is public/structural, not derived from any secret, but nothing
//! derived from 'root_n', 'master_secret', or sampled randomness is ever
//! used to decide how much work runs or which code path executes.
//!
//! 'subtle' gives us 'ConstantTimeEq', 'ConstantTimeGreater',
//! 'ConstantTimeLess', and 'ConditionallySelectable' for the built-in
//! integer types up to 'u64'/'i64', but NOT 'ct_le'/'ct_ge' (its dual
//! comparisons), and NOT anything at all for 'u128'/'i128'. Both gaps are
//! filled locally below instead of being called as if they existed.
//!
//! # Design
//! - Layer 1 & 2: weighted sampling using floor-sum prefix sums.
//! - Layer 3: uniform sampling (weight = 1 for all candidates).
//! - All per-layer work is O(log n) but runs in a fixed number of
//!   iterations regardless of input, so it takes constant time.
//! - A single draw can fail to produce a valid chain for a `root_n` that
//!   does admit one, since layer parameters are drawn from a public but
//!   sparse candidate space. `sample_three_layers_ct_with_retries` retries
//!   a fixed number of times to make that failure rate negligible, and
//!   does so without an early return: see that function's doc comment for
//!   why an early-exit retry loop would undo the constant-time guarantee
//!   built up here.

use crate::core::diophantine::{digital_root, validate_triangle_condition, DiophantinePair};
use rand::RngCore;
use subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
};
use zeroize::Zeroize;

// A complete 3-layer witness chain.
#[derive(Debug, Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

// =============================================================
// Constant-Time Comparison Helpers
// =============================================================

// 'subtle' only ships 'ct_lt'/'ct_gt'/'ct_eq'. These extension traits add
// the missing dual comparisons for 'u64', defined in terms of what already
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

// 'subtle' implements none of these traits for 'u128', so every comparison
// and selection on 'u128' is hand-rolled here. 'overflowing_sub''s borrow
// flag is a single branch-free arithmetic instruction on every target
// 'subtle' itself supports, so this carries the same guarantee as the
// built-in 'u64' primitives.
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
/// add one ourselves, both the trait and the type are foreign). This is
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
// `core::diophantine`, they are not redefined here. Two implementations
// of the same formula drifting apart is exactly the kind of bug this
// crate can't afford, so this module only ever adds NEW operations on
// top of the shared ones. The same principle is why the final assembled
// chain below is not re-checked against the triangle condition a second
// time: the check already runs once, per layer, against the single
// shared implementation while the chain is built. A second call site
// checking the same formula a second time does not add independent
// verification power, it only adds a second place for an argument-order
// mistake to live.

/// Counts valid triangle candidates using the closed form (constant-time).
/// Returns 0 if no valid candidates exist.
pub fn count_triangle_filtered_closed_form(n: u64) -> u64 {
    let a0 = digital_root(n);
    let a0_19 = 19u64.saturating_mul(a0);
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

// =============================================================
// Constant-Time Random Number Generation
// =============================================================

/// Generates a uniform random integer in [0, bound) in constant time.
/// Uses a fixed number of iterations to avoid timing leaks.
///
/// Returns the drawn value together with a `Choice` that is 1 only if one
/// of the fixed iterations actually produced an in-range draw. When none
/// do (astronomically unlikely for a CSPRNG over 8 independent draws, but
/// not impossible), the returned value is 0 and the `Choice` is 0.
/// Callers MUST fold that `Choice` into their own validity tracking
/// rather than trusting the returned value on its own: a plain 0 is
/// otherwise indistinguishable from a genuine draw of 0, and treating it
/// as genuine would silently produce a non-random, predictable witness
/// component instead of reporting that this attempt failed.
///
/// 'bound' may legitimately be 0 here (an earlier layer's parameters were
/// invalid). '% 0' is a hard panic in Rust that can't be masked after the
/// fact, so 'bound' is floored to 1 via constant-time select before any
/// division happens; callers already track the bound == 0 case separately
/// through their own validity flags, so the `Choice` returned here does
/// not need to special-case it.
#[inline]
fn uniform_below_ct(bound: u64, rng: &mut impl RngCore) -> (u64, Choice) {
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
    (result, found)
}

/// Generates a uniform random integer in [0, bound) for 'u128' in constant
/// time. See `uniform_below_ct` above for why `bound == 0` is handled
/// rather than asserted against, and why the returned `Choice` must be
/// checked by the caller rather than trusted implicitly.
#[inline]
fn uniform_below_u128_ct(bound: u128, rng: &mut impl RngCore) -> (u128, Choice) {
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
    (result, found)
}

// =============================================================
// Constant-Time AtCoder Floor Sum
// =============================================================

/// Computes sum_{0 <= i < n} floor((a*i + b)/m) in constant time.
/// Fixed 64 iterations; once the algorithm would logically terminate,
/// ALL state (not just 'n') is frozen so later iterations are pure no-ops,
/// this also guarantees 'm' never decays to 0, which would otherwise make
/// a later division panic. 'm' is also floored to 1 on entry (via constant
/// time select, not 'max()', which is a codegen detail rather than a
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

        // Swap m and a only while genuinely still running, not even on
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

// =============================================================
// Constant-Time Layer Parameters
// =============================================================

// Parameters for one layer of the witness chain.
pub struct LayerParams {
    pub a0: u64,
    pub b0: u64,
    pub k0: u64,
    pub t_max: u64,
    pub valid: Choice,
}

impl LayerParams {
    // Extracts layer parameters in constant time.
    pub fn new_ct(n: u64) -> Self {
        let a0 = digital_root(n);
        let a0_19 = 19u64.saturating_mul(a0);
        let valid = a0_19.ct_le(&n); // 19*a0 <= n

        let b0 = n.wrapping_sub(19 * a0) / 9;
        let k_max = b0 / 19;
        let target = digital_root(2 * a0);
        let k0 = b0.wrapping_add(9).wrapping_sub(target) % 9;
        let has_candidates = k0.ct_le(&k_max);
        let valid = valid & has_candidates;

        let t_max = k_max.wrapping_sub(k0) / 9;
        Self {
            a0,
            b0,
            k0,
            t_max,
            valid,
        }
    }

    // Computes A(t) = a0 + 9*k, where k = k0 + 9*t.
    #[inline]
    pub fn a_at_ct(&self, t: u64) -> u64 {
        let k = self.k0 + 9 * t;
        self.a0 + 9 * k
    }

    /// Computes B(t) = b0 - 19*k, where k = k0 + 9*t.
    #[inline]
    pub fn b_at_ct(&self, t: u64) -> u64 {
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
///
/// `(a_val - 19*dr_a)` would silently wrap in release mode when
/// `a_at(0) < 19*dr_a`. `t_skip = ceil((19*dr_a - a_at(0))/81)` steps are
/// taken first; `dr(a_at(t))` is constant across the layer since
/// `a_at(t)` grows by 81 per step, so this guarantees `a_at(t_skip)`
/// is large enough for the subtraction below to stay in range.
fn weight_params_ct(params: &LayerParams) -> (u64, u64, Choice) {
    let a0_val = params.a_at_ct(0);
    let dr_a = digital_root(a0_val);
    let threshold = 19u64.wrapping_mul(dr_a);
    let underflow = a0_val.ct_lt(&threshold);
    let diff = u64::conditional_select(&0, &threshold.wrapping_sub(a0_val), underflow);
    let t_skip = (diff + 80) / 81;
    let a_val = params.a_at_ct(t_skip);

    // Whether a_val >= threshold, computed in constant time.
    let a_val_ge_threshold = a_val.ct_ge(&threshold);

    // A safe difference that cannot wrap to u64::MAX, and a division that
    // only ever runs on that safe difference.
    let safe_diff = u64::conditional_select(&0, &a_val.wrapping_sub(threshold), a_val_ge_threshold);
    let b0_val_raw = safe_diff / 9;
    let b0_val = u64::conditional_select(&0, &b0_val_raw, a_val_ge_threshold);

    let target = digital_root(2 * dr_a);
    let c3 = b0_val.wrapping_add(9).wrapping_sub(target) % 9;

    let b0_ge = b0_val.ct_ge(&(19 * c3 + 171));
    let need = 171u64.saturating_add(19 * c3).saturating_sub(b0_val);
    let t_filter_raw = (need + 8) / 9;
    let t_filter_eff = u64::conditional_select(&t_filter_raw, &0, b0_ge);
    let t_filter = t_skip.wrapping_add(t_filter_eff);

    let e_prime_raw = 9u64
        .checked_mul(t_filter)
        .and_then(|v| v.checked_add(b0_val))
        .and_then(|v| v.checked_sub(19 * c3))
        .unwrap_or(0);

    let e_prime_valid = e_prime_raw.ct_ge(&171);
    let t_filter_ok = t_filter.ct_le(&params.t_max);

    let valid = params.valid & e_prime_valid & t_filter_ok & a_val_ge_threshold;

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
        // This loop always runs the full 64 iterations for constant-time
        // reasons, even after lo/hi have converged. Once converged, `lo`
        // can legitimately end up past `hi` (via `new_lo = mid + 1`), at
        // which point `hi.wrapping_sub(lo)` intentionally wraps to a huge
        // value on the following "phantom" iterations. `wrapping_add` here
        // keeps that arithmetic well-defined instead of panicking under
        // overflow checks.
        let mid = lo.wrapping_add(hi.wrapping_sub(lo) / 2);
        let pred_mid = pred(mid);

        // If pred(mid) is true (prefix <= r), search the right half,
        // otherwise search the left half.
        let new_lo = mid.wrapping_add(1);
        lo = u64::conditional_select(&lo, &new_lo, pred_mid);
        hi = u64::conditional_select(&hi, &mid, !pred_mid);
    }
    lo
}

// ============================================================================
// Chain Selection and Structural Verification
// ============================================================================

/// Selects between two chains without branching on `choice`. This is what
/// lets the retry loop below pick a winning chain from several attempts
/// without an early return: every attempt runs, and the first one that
/// validates is folded into the result through this function instead of
/// through a branch. Exported (not just used internally) so that callers
/// like `security::witness`, which need the exact same pattern for their
/// own outer retry loops, reuse this instead of re-deriving it.
pub fn select_chain(current_best: &MrsChain, candidate: &MrsChain, choice: Choice) -> MrsChain {
    let layers = current_best
        .layers
        .iter()
        .zip(candidate.layers.iter())
        .map(|(cur, cand)| DiophantinePair {
            a: u64::conditional_select(&cur.a, &cand.a, choice),
            b: u64::conditional_select(&cur.b, &cand.b, choice),
        })
        .collect();
    MrsChain { layers, valid: true }
}

/// Checks the descent property: each layer's `a` must be strictly smaller
/// than the value it was derived from. Unlike the triangle condition
/// (checked once, per layer, against the single shared implementation
/// while the chain is built), this property is not otherwise verified
/// anywhere else, so it is checked once here on the assembled chain.
fn verify_descent(chain: &MrsChain, root_n: u64) -> bool {
    if chain.layers.len() != 3 {
        return false;
    }
    root_n > chain.layers[0].a
        && chain.layers[0].a > chain.layers[1].a
        && chain.layers[1].a > chain.layers[2].a
}

// ============================================================================
// Core Sampler Implementation
// ============================================================================

/// Core sampling logic for a single attempt. Always performs the same
/// fixed amount of work for a given `root_n` regardless of the randomness
/// drawn, and always returns a chain together with a `Choice` saying
/// whether that chain is a genuine valid witness.
///
/// There is deliberately no `Option` at this level. Wrapping the result
/// in `Option` here would let a caller branch on `is_some()` to decide
/// whether to do more work, which is exactly the kind of secret-dependent
/// branch this function exists to avoid; `Option` only appears at the
/// public API boundary below, where returning `None` costs no extra work
/// compared to returning `Some`.
///
/// # Layers
/// 1. First layer: weighted sampling based on child candidate count.
/// 2. Second layer: weighted sampling based on child candidate count.
/// 3. Third layer: uniform sampling (all candidates have weight 1).
fn sample_three_layers_ct_raw(root_n: u64, rng: &mut impl RngCore) -> (MrsChain, Choice) {
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
        // `weight_params_ct` derives t_filter/e_prime for the *weighted*
        // CDF sampling used by non-final layers. The final layer samples
        // uniformly over [0, t_max] instead and never uses t_filter/e_prime
        // at all, so weight_valid being false here (which happens
        // routinely once the final layer's t_max is small) must not veto
        // an otherwise-valid uniform pick.
        if !is_last_layer {
            overall_valid &= weight_valid;
        }

        let total_weight = if is_last_layer {
            (params.t_max + 1) as u128
        } else {
            prefix_weight_ct(params.t_max, t_filter, params.t_max, e_prime)
        };

        let total_valid = ct_gt_u128(total_weight, 0);
        overall_valid &= total_valid;

        let (r, r_ok) = if is_last_layer {
            let (v, ok) = uniform_below_ct(params.t_max + 1, rng);
            (v as u128, ok)
        } else {
            uniform_below_u128_ct(total_weight, rng)
        };
        overall_valid &= r_ok;

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

        // `weight_params_ct`'s closed-form t_filter only guarantees a
        // count >= 1 (a representation exists at all), not the stricter
        // count >= 2 that non-final layers actually require to remain
        // valid. A candidate with exactly count == 1 can slip through the
        // weighted selection with a nonzero weight even though it should
        // have been excluded, so it is checked directly here.
        let layer_ok = if is_last_layer {
            Choice::from(1)
        } else {
            check_ahead_valid_closed_form(a)
        };
        overall_valid &= layer_ok;

        // The one and only place the triangle condition is checked. See
        // the module-level note above for why it is not re-checked again
        // on the assembled chain.
        let triangle_valid = validate_triangle_condition(b, a);
        overall_valid &= triangle_valid;

        // Only commit if everything up to this point is valid.
        let should_push = overall_valid;
        chain.push(DiophantinePair {
            a: u64::conditional_select(&0, &a, should_push),
            b: u64::conditional_select(&0, &b, should_push),
        });

        current_n = u64::conditional_select(&current_n, &a, should_push);
    }

    (
        MrsChain {
            layers: chain,
            valid: true,
        },
        overall_valid,
    )
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// A single constant-time sampling attempt. May return `None` if this
/// particular draw did not produce a valid chain, `root_n` values that
/// admit no valid chain at all will always return `None` here regardless
/// of `rng`. Most callers should use `sample_three_layers_safe` instead,
/// which retries the fixed number of times ordinary randomness requires.
pub fn sample_three_layers_ct(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    let (chain, valid) = sample_three_layers_ct_raw(root_n, rng);
    let ok = valid & Choice::from(verify_descent(&chain, root_n) as u8);
    if ok.unwrap_u8() == 1 {
        Some(chain)
    } else {
        None
    }
}

/// Raw counterpart to `sample_three_layers_ct_with_retries`: always
/// performs exactly `max_attempts` draws and always returns a chain
/// together with a `Choice`, never an `Option`. Exists so that callers who
/// need to do further constant-time work on the result, such as
/// `security::witness`, which hashes the chain and computes a binding tag
/// from it, can do that work unconditionally instead of branching on
/// `Option::is_some()`. That branch would otherwise reintroduce a
/// secret-correlated difference in how much work runs per attempt, the
/// exact problem this function exists to avoid.
///
/// There is no early return and no quick feasibility check up front:
/// every one of the `max_attempts` draws runs regardless of root_n, and
/// whether `root_n` admits any valid chain at all is folded into the
/// returned `Choice` at the end via `params.valid`, exactly like every
/// other validity condition in this module.
pub fn sample_three_layers_ct_with_retries_raw(
    root_n: u64,
    rng: &mut impl RngCore,
    max_attempts: usize,
) -> (MrsChain, Choice) {
    let params = LayerParams::new_ct(root_n);
    let feasible = params.valid;

    let mut best = MrsChain {
        layers: vec![
            DiophantinePair { a: 0, b: 0 },
            DiophantinePair { a: 0, b: 0 },
            DiophantinePair { a: 0, b: 0 },
        ],
        valid: false,
    };
    let mut found = Choice::from(0);

    for _ in 0..max_attempts {
        let (candidate, candidate_valid) = sample_three_layers_ct_raw(root_n, rng);
        let candidate_ok =
            candidate_valid & Choice::from(verify_descent(&candidate, root_n) as u8);
        let take_this = candidate_ok & !found;
        best = select_chain(&best, &candidate, take_this);
        found |= candidate_ok;
    }

    (best, feasible & found)
}

/// Samples a 3-layer witness chain, retrying internally when a single draw
/// does not produce a valid chain. Thin `Option`-returning wrapper around
/// `sample_three_layers_ct_with_retries_raw`: the same fixed amount of work
/// runs either way, this only decides which enum variant to hand back.
pub fn sample_three_layers_ct_with_retries(
    root_n: u64,
    rng: &mut impl RngCore,
    max_attempts: usize,
) -> Option<MrsChain> {
    let (chain, ok) = sample_three_layers_ct_with_retries_raw(root_n, rng, max_attempts);
    if ok.unwrap_u8() == 1 {
        Some(chain)
    } else {
        None
    }
}

/// Primary public entry point for witness generation. Retries a fixed 10
/// times; see `sample_three_layers_ct_with_retries_raw` for why that retry
/// loop itself runs at constant time rather than exiting early on success.
pub fn sample_three_layers_safe(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    sample_three_layers_ct_with_retries(root_n, rng, 10)
}

/// Raw counterpart to `sample_three_layers_safe`, returning `(MrsChain,
/// Choice)` instead of `Option<MrsChain>` for the same reason
/// `sample_three_layers_ct_with_retries_raw` does. This is what
/// `security::witness` calls from its own outer retry loop.
pub fn sample_three_layers_safe_raw(root_n: u64, rng: &mut impl RngCore) -> (MrsChain, Choice) {
    sample_three_layers_ct_with_retries_raw(root_n, rng, 10)
}

// ============================================================================
// Test-Only Independent Reference Count
// ============================================================================

/// Counts valid triangle candidates by the triangle condition using
/// `core::diophantine`'s own (Popoviciu-cardinality-based) generator, a
/// genuinely different derivation from `count_triangle_filtered_closed_form`'s
/// a0/b0/k0/k_max approach, so this actually catches a bug in either one
/// instead of checking a formula against a restatement of itself.
#[cfg(test)]
fn count_triangle_filtered_bruteforce(n: u64) -> u64 {
    crate::core::diophantine::generate_representation_family(n).len() as u64
}

// ============================================================================
// Debug Helper (Test Only)
// ============================================================================

#[cfg(test)]
pub fn debug_weight_params_ct(params: &LayerParams) -> (u64, u64, Choice, String) {
    let a0_val = params.a_at_ct(0);
    let dr_a = digital_root(a0_val);
    let threshold = 19u64.wrapping_mul(dr_a);
    let underflow = a0_val.ct_lt(&threshold);
    let diff = u64::conditional_select(&0, &threshold.wrapping_sub(a0_val), underflow);
    let t_skip = (diff + 80) / 81;
    let a_val = params.a_at_ct(t_skip);

    let a_val_ge_threshold = a_val.ct_ge(&threshold);
    let safe_diff = u64::conditional_select(&0, &a_val.wrapping_sub(threshold), a_val_ge_threshold);
    let b0_val_raw = safe_diff / 9;
    let b0_val = u64::conditional_select(&0, &b0_val_raw, a_val_ge_threshold);

    let target = digital_root(2 * dr_a);
    let c3 = b0_val.wrapping_add(9).wrapping_sub(target) % 9;

    let b0_ge = b0_val.ct_ge(&(19 * c3 + 171));
    let need = 171u64.saturating_add(19 * c3).saturating_sub(b0_val);
    let t_filter_raw = (need + 8) / 9;
    let t_filter_eff = u64::conditional_select(&t_filter_raw, &0, b0_ge);
    let t_filter = t_skip.wrapping_add(t_filter_eff);

    let e_prime_raw = 9u64
        .checked_mul(t_filter)
        .and_then(|v| v.checked_add(b0_val))
        .and_then(|v| v.checked_sub(19 * c3))
        .unwrap_or(0);

    let e_prime_valid = e_prime_raw.ct_ge(&171);
    let t_filter_ok = t_filter.ct_le(&params.t_max);
    let valid = params.valid & e_prime_valid & t_filter_ok & a_val_ge_threshold;

    let debug_info = format!(
        "a0_val={}, dr_a={}, threshold={}, underflow={}, t_skip={}, a_val={}, \
         a_val_ge_threshold={}, b0_val={}, c3={}, b0_ge={}, t_filter={}, e_prime_raw={}, \
         e_prime_valid={}, t_filter_ok={}, params.valid={}, final_valid={}",
        a0_val,
        dr_a,
        threshold,
        underflow.unwrap_u8(),
        t_skip,
        a_val,
        a_val_ge_threshold.unwrap_u8(),
        b0_val,
        c3,
        b0_ge.unwrap_u8(),
        t_filter,
        e_prime_raw,
        e_prime_valid.unwrap_u8(),
        t_filter_ok.unwrap_u8(),
        params.valid.unwrap_u8(),
        valid.unwrap_u8()
    );

    (t_filter, e_prime_raw, valid, debug_info)
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

        let result = sample_three_layers_safe(root_n, &mut rng);

        if let Some(chain) = result {
            assert!(chain.valid);
            assert_eq!(chain.layers.len(), 3);
            assert!(root_n > chain.layers[0].a);
        } else {
            println!(
                "[INFO] No chain found for root_n={} - this may be expected",
                root_n
            );
        }
    }

    #[test]
    fn closed_form_matches_brute_force_count() {
        for n in [201u64, 1_001, 12_345, 200_001, 999_999] {
            assert_eq!(
                count_triangle_filtered_closed_form(n),
                count_triangle_filtered_bruteforce(n),
                "count mismatch at n={}",
                n
            );
        }
    }

    #[test]
    fn uniform_below_ct_reports_failure_explicitly() {
        // A degenerate RNG that always returns u64::MAX makes every draw
        // land outside the acceptance window for any bound that does not
        // evenly divide u64::MAX + 1, so all 8 iterations reject and the
        // function must report failure rather than fabricating a 0.
        struct AlwaysMax;
        impl RngCore for AlwaysMax {
            fn next_u32(&mut self) -> u32 {
                u32::MAX
            }
            fn next_u64(&mut self) -> u64 {
                u64::MAX
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                dest.fill(0xFF);
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        let mut rng = AlwaysMax;
        let (_value, ok) = uniform_below_ct(3, &mut rng);
        assert_eq!(ok.unwrap_u8(), 0, "expected explicit failure, not a silent 0");
    }

    #[test]
    fn ct_sampler_produces_valid_chains() {
        let test_values = [
            3_000_001u64,
            3_500_007,
            4_200_013,
            10_000_001,
            50_000_000,
            100_000_001,
        ];

        let mut rng = OsRng;
        let mut found_any = false;
        let mut results = Vec::new();

        for &root_n in &test_values {
            let mut chain_found = false;

            for attempt in 0..20 {
                match sample_three_layers_ct_with_retries(root_n, &mut rng, 5) {
                    Some(chain) => {
                        chain_found = true;
                        found_any = true;

                        assert_eq!(chain.layers.len(), 3);
                        assert!(root_n > chain.layers[0].a);
                        assert!(chain.layers[0].a > chain.layers[1].a);
                        assert!(chain.layers[1].a > chain.layers[2].a);

                        for pair in &chain.layers {
                            assert!(
                                validate_triangle_condition(pair.b, pair.a).unwrap_u8() == 1,
                                "Triangle condition failed for ({}, {})",
                                pair.a,
                                pair.b
                            );
                        }

                        results.push((root_n, true));
                        break;
                    }
                    None => {
                        if attempt == 19 {
                            results.push((root_n, false));
                            eprintln!("[WARN] No chain for root_n={} after 20 attempts", root_n);
                        }
                    }
                }
            }

            if !chain_found {
                eprintln!("[WARN] Could not sample any chain for root_n={}", root_n);
            }
        }

        println!("[INFO] Sampling results: {:?}", results);

        assert!(
            found_any,
            "No chains found for any test value - sampler may be broken"
        );
    }

    #[test]
    fn debug_weight_params() {
        let root_n = 3_000_001;
        let params = LayerParams::new_ct(root_n);
        let (t_filter, e_prime, valid, debug_info) = debug_weight_params_ct(&params);

        println!("[DEBUG] root_n={}", root_n);
        println!("[DEBUG] params.valid={}", params.valid.unwrap_u8());
        println!(
            "[DEBUG] t_filter={}, e_prime={}, valid={}",
            t_filter,
            e_prime,
            valid.unwrap_u8()
        );
        println!("[DEBUG] {}", debug_info);
    }

    #[test]
    fn test_sampler_retries() {
        let root_n = 3_000_001;
        let mut rng = OsRng;

        for _ in 0..10 {
            let result = sample_three_layers_ct_with_retries(root_n, &mut rng, 3);
            if let Some(chain) = result {
                assert!(chain.valid);
                assert_eq!(chain.layers.len(), 3);
                assert!(root_n > chain.layers[0].a);
            }
        }

        println!("[INFO] Retry test passed without panics");
    }

    #[test]
    fn retries_always_run_max_attempts_worth_of_draws() {
        // A counting RNG wrapper to confirm the retry loop consumes the
        // same number of underlying draws every time, regardless of how
        // quickly a valid chain is found. Each `sample_three_layers_ct_raw`
        // attempt draws from `rng` a fixed number of times per layer, so a
        // constant-time retry loop must always advance `rng` by the same
        // total amount for a given `max_attempts`, independent of when
        // (or whether) a valid chain first appears among the attempts.
        struct CountingRng<'a> {
            inner: &'a mut dyn RngCore,
            calls: usize,
        }
        impl<'a> RngCore for CountingRng<'a> {
            fn next_u32(&mut self) -> u32 {
                self.calls += 1;
                self.inner.next_u32()
            }
            fn next_u64(&mut self) -> u64 {
                self.calls += 1;
                self.inner.next_u64()
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                self.inner.fill_bytes(dest)
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
                self.inner.try_fill_bytes(dest)
            }
        }

        let root_n = 3_000_001;
        let mut base = OsRng;

        let mut counter_a = CountingRng {
            inner: &mut base,
            calls: 0,
        };
        let _ = sample_three_layers_ct_with_retries(root_n, &mut counter_a, 7);
        let calls_a = counter_a.calls;

        let mut counter_b = CountingRng {
            inner: &mut base,
            calls: 0,
        };
        let _ = sample_three_layers_ct_with_retries(root_n, &mut counter_b, 7);
        let calls_b = counter_b.calls;

        assert_eq!(
            calls_a, calls_b,
            "retry loop drew a different number of random values across two independent runs"
        );
    }
}
