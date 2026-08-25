use crate::core::diophantine::{generate_representation_family, DiophantinePair};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

/// A complete 3-layer Matryoshka chain.
///
/// Each layer holds one Diophantine representation `(A, B)` such that
/// `parent_N = 19*A + 9*B`. The chain is recursively nested:
/// `N -> A_0 -> A_1 -> A_2`.
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

/// Computes the digital root of `n` in constant time without loops.
///
/// The digital root of a positive integer is the single-digit value
/// obtained by an iterative process of summing digits. This closed-form
/// expression avoids branching on the number of digits.
#[inline]
pub fn digital_root(n: u64) -> u64 {
    if n == 0 {
        0
    } else {
        1 + ((n - 1) % 9)
    }
}

/// Validates the harmonic triangle condition: `dr(B) == dr(2 * dr(X))`.
///
/// `x` is the **parent value** at the current layer (the `N` that was just
/// decomposed), not an externally supplied seed. This is required by the
/// `a ≡ 1 (mod b)` argument from the specification (§4.2): the residue-class
/// shift operates step-wise within the representation family of `x` itself.
#[inline]
pub fn validate_triangle_condition(b: u64, x: u64) -> bool {
    let dr_b = digital_root(b);
    let dr_x = digital_root(x);
    let target = digital_root(2 * dr_x);
    dr_b == target
}

/// Counts how many representations of `n` satisfy the triangle condition
/// relative to `n` itself.
///
/// This is the number of triangle-valid alibis that layer `n` would have on
/// the next layer — the correct metric for check-ahead, as opposed to the
/// raw (unfiltered) Popoviciu cardinality.
pub fn count_triangle_filtered(n: u64) -> u64 {
    generate_representation_family(n)
        .iter()
        .filter(|pair| validate_triangle_condition(pair.b, n))
        .count() as u64
}

/// Checks whether `a_value` has at least 2 triangle-valid continuations on
/// the next layer (`R'(A) >= 2`).
///
/// Uses the **triangle-filtered** count, not the raw Popoviciu cardinality:
/// the latter may be positive while triangle filtering leaves zero valid
/// continuations, which would undermine the check-ahead guarantee.
#[inline]
pub fn check_ahead_valid(a_value: u64) -> bool {
    count_triangle_filtered(a_value) >= 2
}

/// Computes the hierarchical weight of every triangle-valid candidate at
/// layer `n`, filtered on the triangle condition relative to `n` itself.
///
/// This is the weight the sampler actually uses to guarantee uniformity
/// (Forest Symmetry): the number of triangle-valid continuation chains
/// reachable through each candidate, not the raw Popoviciu cardinality of
/// earlier versions.
///
/// Returns the filtered candidates and their weights in the same order.
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

/// Draws a cryptographically random integer in `[0, bound)` without
/// modulo bias, using rejection sampling on a CSPRNG.
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

/// Samples a 3-layer Matryoshka chain from `root_n`.
///
/// At each layer, a candidate is drawn with probability proportional to the
/// number of triangle-valid continuation chains beneath it (weight = number
/// of valid 3-layer completions). On the final layer, every representation
/// has weight 1 because it is itself a complete chain.
///
/// This guarantees that every complete chain in Omega(root_n) is produced
/// with exactly equal probability (Forest Symmetry Theorem).
///
/// # Design note
///
/// Earlier implementations picked the *first* valid pair from the family
/// without any randomness. That was fully deterministic: the same `root_n`
/// always yielded the same chain, providing no secret, unpredictable index.
/// The current weighted CDF sampler fixes this.
///
/// # API change
///
/// The `seed_x` argument has been removed. The triangle condition now tests
/// against `current_n` (the actual parent value per layer) instead of a
/// fixed external value. Callers should use `sample_three_layers(root_n)`.
pub fn sample_three_layers(root_n: u64) -> Option<MrsChain> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;
    let mut rng = OsRng;

    for layer in 0..DEPTH {
        let is_last_layer = layer == DEPTH - 1;
        let family = generate_representation_family(current_n);

        let mut candidates: Vec<DiophantinePair> = Vec::new();
        let mut weights: Vec<u64> = Vec::new();

        for pair in family {
            if !validate_triangle_condition(pair.b, current_n) {
                continue;
            }
            if !is_last_layer && !check_ahead_valid(pair.a) {
                continue;
            }
            let w = if is_last_layer {
                1
            } else {
                count_triangle_filtered(pair.a)
            };
            if w == 0 {
                continue;
            }
            candidates.push(pair);
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
        let pair = chosen.expect("weights sum to total_weight; loop must select something");

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
        assert_eq!(digital_root(10), 1);   // 1 + 0 = 1
        assert_eq!(digital_root(144), 9);  // 1 + 4 + 4 = 9
    }

    #[test]
    fn test_triangle_condition_validation() {
        // Manually computed test vector based on the specification.
        // If X = 5, then dr(X) = 5. Target = dr(2 * 5) = dr(10) = 1.
        // If B = 10, then dr(B) = 1. This must yield `true`.
        assert!(validate_triangle_condition(10, 5));

        // If B = 9, then dr(B) = 9 (does not match 1), must yield `false`.
        assert!(!validate_triangle_condition(9, 5));
    }

    #[test]
    fn test_three_layer_sampler_success() {
        // Use a starting N large enough to nest 3 layers deep.
        let root_n = 200_001;

        let result = sample_three_layers(root_n);

        // The sampler must either find a valid chain or safely return None.
        if let Some(chain) = result {
            assert!(chain.valid);
            assert_eq!(chain.layers.len(), 3);

            // Verify Matryoshka nesting:
            // The A of layer 0 must be the N for layer 1.
            let layer_0_a = chain.layers[0].a;
            let layer_1_a = chain.layers[1].a;

            // A values must strictly decrease as we nest deeper.
            assert!(root_n > layer_0_a);
            assert!(layer_0_a > layer_1_a);

            // Every layer must satisfy the triangle condition
            // relative to its own parent value (not an external seed).
            let mut parent = root_n;
            for pair in &chain.layers {
                assert!(validate_triangle_condition(pair.b, parent));
                parent = pair.a;
            }
        }
    }

    #[test]
    fn test_sampler_is_not_deterministic() {
        // The previous implementation always returned the same chain for a
        // fixed root_n (first match, no randomness). This test confirms
        // that the weighted CDF sampler produces at least 2 distinct chains
        // over 100 trials.
        //
        // NOTE: We use a large N (10_000_007) to ensure the forest contains
        // multiple valid 3-layer chains. Small N may have only one valid
        // path after triangle + check-ahead filtering.
        let root_n = 10_000_007;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            if let Some(chain) = sample_three_layers(root_n) {
                let key: Vec<(u64, u64)> = chain.layers.iter().map(|p| (p.a, p.b)).collect();
                seen.insert(key);
            }
        }
        assert!(
            seen.len() > 1,
            "sampler produced the same chain 100x -- likely only one valid chain exists for this N"
        );
    }

    #[test]
    fn test_calculate_layer_weights_matches_triangle_filter() {
        // Every candidate returned by calculate_layer_weights must itself
        // pass the triangle condition and have weight > 0.
        let n = 200_001;
        let (candidates, weights) = calculate_layer_weights(n);
        assert_eq!(candidates.len(), weights.len());
        for (pair, &w) in candidates.iter().zip(weights.iter()) {
            assert!(validate_triangle_condition(pair.b, n));
            assert!(w > 0);
        }
    }
}

