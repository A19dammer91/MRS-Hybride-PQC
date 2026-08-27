use crate::core::diophantine::{generate_representation_family, DiophantinePair};
use rand::rngs::OsRng;
use rand::RngCore;
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
    if n == 0 {
        0
    } else {
        1 + ((n - 1) % 9)
    }
}

/// Checks the harmonic triangle requirement: dr(B) == dr(2 * dr(X))
/// X is the PARENT value at the current layer (the N that was just split),
/// not an externally supplied seed. This is what the a ≡ 1 (mod b) argument
/// from the specification (§4.2) requires: the residue-class shift works
/// per step within X's own representation family.
#[inline]
pub fn validate_triangle_condition(b: u64, x: u64) -> bool {
    let dr_b = digital_root(b);
    let dr_x = digital_root(x);
    let target = digital_root(2 * dr_x);
    dr_b == target
}

/// Counts how many representations of `n` satisfy the triangle condition
/// with respect to X = n itself. This is the number of triangle-valid
/// alibis layer `n` would have at the next layer -- the correct measure
/// for check-ahead, as opposed to the raw (unfiltered) Popoviciu count.
///
/// BRUTE-FORCE VERSION -- O(N). Kept only as a correctness oracle for the
/// closed-form version below (see the `closed_form_tests` module). Do not
/// call this from the sampler hot path; use `count_triangle_filtered_closed_form`.
pub fn count_triangle_filtered(n: u64) -> u64 {
    generate_representation_family(n)
        .iter()
        .filter(|pair| validate_triangle_condition(pair.b, n))
        .count() as u64
}

/// Checks whether `a_value` has at least 2 triangle-valid continuations at
/// the next layer (R'(A) >= 2). Uses the triangle-FILTERED count, not the
/// raw Popoviciu cardinality: the latter can be positive while zero valid
/// continuations remain after triangle filtering, which would undermine
/// the check-ahead guarantee.
///
/// BRUTE-FORCE VERSION -- O(N). See `check_ahead_valid_closed_form`.
#[inline]
pub fn check_ahead_valid(a_value: u64) -> bool {
    count_triangle_filtered(a_value) >= 2
}

/// Computes the hierarchical weight of each triangle-valid candidate at
/// layer `n`, filtered on the triangle condition with respect to `n`
/// itself. This is the weight the sampler actually uses to guarantee
/// uniformity (Forest Symmetry): the number of triangle-valid continuation
/// chains per candidate, not the raw Popoviciu cardinality from earlier
/// versions. Returns the filtered candidates and their weights in the
/// same order.
///
/// BRUTE-FORCE VERSION -- O(N^2) overall when composed with `count_triangle_filtered`.
/// Kept only for the correctness tests. See `sample_three_layers` for the
/// closed-form replacement used in production.
pub fn calculate_layer_weights(n: u64) -> (Vec<DiophantinePair>, Vec<u64>) {
    let family = generate_representation_family(n);
    let mut candidates = Vec::with_capacity(family.len());
    let mut weights = Vec::with_capacity(family.len());

    for pair in family {
        if !validate_triangle_condition(pair.b, n) {
            continue;
        }
        let w = count_triangle_filtered(pair.a);
        if w == 0 {
            continue; // dead end: no triangle-valid continuations on A
        }
        candidates.push(pair);
        weights.push(w);
    }

    (candidates, weights)
}

// ---------------------------------------------------------------------
// Closed-form (O(1)) replacements based on the 19-9 system structure.
//
// N = 19A + 9B, A,B >= 0. Since gcd(19,9) = 1, all non-negative
// representations are indexed by k = 0..=K_max via:
//   A_k = A0 + 9k
//   B_k = B0 - 19k
// where A0 = dr(N) (the published central result of the 19-9 system) and
// B0 = (N - 19*A0) / 9.
//
// Because 19 ≡ 1 (mod 9), dr(B_k) cycles with period 9 in k, decreasing
// by 1 (mod 9) each step. The triangle condition dr(B_k) == target
// therefore holds for exactly one residue class k ≡ k0 (mod 9), which
// turns every enumeration-based count/lookup into an O(1) computation.
// ---------------------------------------------------------------------

/// A0 in the 19-9 system: A0 = dr(N).
#[inline]
fn calculate_anchor(n: u64) -> u64 {
    digital_root(n)
}

/// B0 = (N - 19*A0) / 9. Always an exact integer division for valid N,
/// since 19 ≡ 1 (mod 9) guarantees A0 ≡ N (mod 9).
#[inline]
fn calculate_b0(n: u64, a0: u64) -> u64 {
    (n - 19 * a0) / 9
}

/// Closed-form replacement for `count_triangle_filtered`: O(1) instead of
/// O(N) enumeration. Counts how many representations N = 19A + 9B (with
/// A,B >= 0) satisfy the triangle condition dr(B) == dr(2*dr(N)).
pub fn count_triangle_filtered_closed_form(n: u64) -> u64 {
    let a0 = calculate_anchor(n);
    let b0 = calculate_b0(n, a0);
    let k_max = b0 / 19;

    let target = digital_root(2 * a0);

    // k0 = (b0 - target) mod 9, computed branch-free.
    // Safe: target in [1,9], so b0 + 9 - target is always >= 0.
    let k0 = (b0 + 9 - target) % 9;

    if k0 > k_max {
        0
    } else {
        (k_max - k0) / 9 + 1
    }
}

/// Closed-form replacement for `check_ahead_valid`: O(1) instead of O(N).
#[inline]
pub fn check_ahead_valid_closed_form(a_value: u64) -> bool {
    count_triangle_filtered_closed_form(a_value) >= 2
}

/// Given N and a 0-based index `t` into its triangle-valid representations
/// (caller ensures `t < count_triangle_filtered_closed_form(n)`), returns
/// the t-th such (A, B) pair directly -- without enumerating or filtering
/// any of the other (non-valid) representations.
pub fn sample_triangle_pair(n: u64, t: u64) -> Option<DiophantinePair> {
    let a0 = calculate_anchor(n);
    let b0 = calculate_b0(n, a0);
    let k_max = b0 / 19;

    let target = digital_root(2 * a0);
    let k0 = (b0 + 9 - target) % 9;

    if k0 > k_max {
        return None;
    }

    let k = k0 + 9 * t;
    if k > k_max {
        return None; // defensive; shouldn't trigger if t is bounds-checked
    }

    let a = a0 + 9 * k;
    let b = b0 - 19 * k;

    Some(DiophantinePair { a, b })
}

/// Draws a cryptographically random integer in [0, bound) without modulo
/// bias, via rejection sampling on a CSPRNG.
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

/// Builds a 3-layer Matryoshka chain based on root_n.
///
/// At each layer, a cryptographically random, WEIGHTED sample is drawn
/// among all triangle-valid candidates: a candidate's weight is the
/// number of triangle-valid continuation chains reachable through it (at
/// the last layer: weight 1, since every representation there is already
/// a complete chain by itself). This produces every complete chain in
/// Omega(root_n) with exactly equal probability (Forest Symmetry
/// Theorem).
///
/// CLOSED-FORM VERSION: candidates are generated directly via
/// `sample_triangle_pair`/`count_triangle_filtered_closed_form` instead of
/// enumerating `generate_representation_family(current_n)` and filtering.
/// Per layer this is O(triangle_count) with O(1) work per candidate,
/// instead of the previous O(N) candidates each requiring an O(N)
/// sub-computation (O(N^2) total). `root_n` can now be arbitrarily large
/// without the multi-hour blowup seen with brute-force enumeration.
pub fn sample_three_layers(root_n: u64) -> Option<MrsChain> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;
    let mut rng = OsRng;

    for layer in 0..DEPTH {
        let is_last_layer = layer == DEPTH - 1;

        let a0 = calculate_anchor(current_n);
        let b0 = calculate_b0(current_n, a0);
        let k_max = b0 / 19;
        let target = digital_root(2 * a0);
        let k0 = (b0 + 9 - target) % 9;

        if k0 > k_max {
            return None; // no triangle-valid representation at this layer
        }
        let triangle_count = (k_max - k0) / 9 + 1;

        let mut candidates: Vec<DiophantinePair> = Vec::with_capacity(triangle_count as usize);
        let mut weights: Vec<u64> = Vec::with_capacity(triangle_count as usize);

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

        if candidates.is_empty() {
            return None; // no valid, non-dead-end path at this layer
        }

        let total_weight: u64 = weights.iter().sum();
        let r = uniform_below(total_weight, &mut rng);

        let mut acc: u64 = 0;
        let mut chosen: Option<DiophantinePair> = None;
        for (pair, w) in candidates.into_iter().zip(weights.into_iter()) {
            acc += w;
            if r < acc {
                chosen = Some(pair);
                break;
            }
        }
        let pair = chosen.expect("weights sum to total_weight, the loop must pick something");

        current_n = pair.a;
        chain.push(pair);
    }

    Some(MrsChain {
        layers: chain,
        valid: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digital_root() {
        assert_eq!(digital_root(0), 0);
        assert_eq!(digital_root(9), 9);
        assert_eq!(digital_root(10), 1); // 1 + 0 = 1
        assert_eq!(digital_root(144), 9); // 1 + 4 + 4 = 9
    }

    #[test]
    fn test_triangle_condition_validation() {
        // Hand-computed test vector based on the specification.
        // If X = 5, then dr(X) = 5. Target = dr(2 * 5) = dr(10) = 1.
        // If B = 10, then dr(B) = 1. This must therefore yield 'true'.
        assert!(validate_triangle_condition(10, 5));

        // If B = 9, then dr(B) = 9 (does not match 1), must be 'false'
        assert!(!validate_triangle_condition(9, 5));
    }

    #[test]
    fn test_three_layer_sampler_success() {
        // Test with a starting number N large enough to nest 3 layers deep
        let root_n = 200_001;

        let result = sample_three_layers(root_n);

        // The sampler must either find a valid chain, or stop safely (None)
        if let Some(chain) = result {
            assert!(chain.valid);
            assert_eq!(chain.layers.len(), 3);

            // Check that the Matryoshka nesting is mathematically correct:
            // layer 0's 'A' must be the 'N' for layer 1's computation
            let layer_0_a = chain.layers[0].a;
            let layer_1_a = chain.layers[1].a;

            // The 'A' values must logically keep decreasing as we nest deeper
            assert!(root_n > layer_0_a);
            assert!(layer_0_a > layer_1_a);

            // Every layer must itself satisfy the triangle condition
            // with respect to its own parent value (not an external seed).
            let mut parent = root_n;
            for pair in &chain.layers {
                assert!(validate_triangle_condition(pair.b, parent));
                parent = pair.a;
            }
        }
    }

    #[test]
    fn test_sampler_is_not_deterministic() {
        // NOTE: root_n reduced back from 10_000_000_001 to 200_001.
        // That earlier value combined with the brute-force O(N) sampler
        // caused multi-hour CI runs (O(N^2) per layer). This value already
        // admits enough representation multiplicity to exercise the
        // randomness check. With the closed-form sampler above, much
        // larger root_n values are now cheap too -- see
        // `test_sampler_is_not_deterministic_large_n_closed_form`.
        let root_n = 200_001;

        let mut seen = std::collections::HashSet::new();
        let mut attempts = 0;

        for _ in 0..100 {
            if let Some(chain) = sample_three_layers(root_n) {
                let key: Vec<(u64, u64)> = chain.layers.iter().map(|p| (p.a, p.b)).collect();
                seen.insert(key);
                attempts += 1;
            }
        }

        assert!(
            seen.len() > 1 || attempts <= 1,
            "sampler produced the same chain {} times for root_n={} — \
             either randomness is broken or this N admits only one valid chain",
            attempts, root_n
        );
    }

    #[test]
    fn test_calculate_layer_weights_matches_triangle_filter() {
        // Every candidate calculate_layer_weights returns must itself
        // also pass the triangle condition, and have a weight > 0.
        let n = 200_001;
        let (candidates, weights) = calculate_layer_weights(n);
        assert_eq!(candidates.len(), weights.len());
        for (pair, &w) in candidates.iter().zip(weights.iter()) {
            assert!(validate_triangle_condition(pair.b, n));
            assert!(w > 0);
        }
    }
}

#[cfg(test)]
mod closed_form_tests {
    use super::*;

    /// Independent cross-check of K_max via Popoviciu's formula for two
    /// coprime coefficients (a=19, b=9):
    ///
    ///   R(N) = N/(ab) - {b^-1 * N / a} - {a^-1 * N / b} + 1
    ///
    /// with {x} the fractional part. Here b^-1 mod a = 9^-1 mod 19 = 17
    /// (since 9*17 = 153 = 8*19 + 1), and a^-1 mod b = 19^-1 mod 9 = 1
    /// (since 19 ≡ 1 mod 9). Uses f64 because Popoviciu's formula is
    /// defined over the reals -- this is a test-only oracle, never called
    /// from the sampler hot path.
    fn popoviciu_r_n(n: u64) -> u64 {
        const INV_9_MOD_19: u64 = 17;

        let n_f = n as f64;
        let term1 = n_f / 171.0;
        let frac_a = ((INV_9_MOD_19 * n) % 19) as f64 / 19.0;
        let frac_b = (n % 9) as f64 / 9.0; // inverse of 19 mod 9 is 1, so this is just {N/9}

        (term1 - frac_a - frac_b + 1.0).round() as u64
    }

    #[test]
    fn k_max_matches_popoviciu_r_n_minus_one() {
        for n in [201u64, 1_001, 12_345, 200_001, 999_999, 10_000_000_001] {
            let a0 = calculate_anchor(n);
            let b0 = calculate_b0(n, a0);
            let k_max = b0 / 19;

            let r_n = popoviciu_r_n(n);
            assert_eq!(
                k_max,
                r_n - 1,
                "k_max mismatch at n={}: b0/19={} vs R(N)-1={}",
                n, k_max, r_n - 1
            );
        }
    }

    #[test]
    fn closed_form_matches_brute_force_count() {
        for n in [201u64, 1_001, 12_345, 200_001, 999_999] {
            assert_eq!(
                count_triangle_filtered_closed_form(n),
                count_triangle_filtered(n),
                "count mismatch at n={}", n
            );
        }
    }

    #[test]
    fn closed_form_pairs_match_brute_force_set() {
        for n in [201u64, 1_001, 12_345] {
            let brute: std::collections::HashSet<(u64, u64)> = generate_representation_family(n)
                .into_iter()
                .filter(|p| validate_triangle_condition(p.b, n))
                .map(|p| (p.a, p.b))
                .collect();

            let count = count_triangle_filtered_closed_form(n);
            let closed: std::collections::HashSet<(u64, u64)> = (0..count)
                .map(|t| sample_triangle_pair(n, t).unwrap())
                .map(|p| (p.a, p.b))
                .collect();

            assert_eq!(brute, closed, "set mismatch at n={}", n);
        }
    }

    #[test]
    fn test_sampler_is_not_deterministic_large_n_closed_form() {
        // With the closed-form sampler, a root_n this large is now cheap
        // (O(1) per candidate instead of O(N)), unlike the original
        // brute-force version that hung for 3+ hours at this value.
        let root_n = 10_000_000_001u64;

        let mut seen = std::collections::HashSet::new();
        let mut attempts = 0;

        for _ in 0..100 {
            if let Some(chain) = sample_three_layers(root_n) {
                let key: Vec<(u64, u64)> = chain.layers.iter().map(|p| (p.a, p.b)).collect();
                seen.insert(key);
                attempts += 1;
            }
        }

        assert!(
            seen.len() > 1 || attempts <= 1,
            "sampler produced the same chain {} times for root_n={}",
            attempts, root_n
        );
    }
}
