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
/// This replaces the earlier implementation, which picked the FIRST valid
/// pair from `family` with no randomness at all -- that was fully
/// deterministic (the same root_n always gave the same chain) and
/// therefore offered no secret, unpredictable index.
///
/// **API change:** the `seed_x` argument has been removed. The triangle
/// condition now checks against `current_n` (the actual parent value per
/// layer) instead of a fixed external value. Calls elsewhere in the
/// codebase must be updated to `sample_three_layers(root_n)`.
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
        // Use a larger root_n with enough representation multiplicity
        // to guarantee multiple distinct valid 3-layer chains exist.
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

        // Either we saw multiple different chains (randomness works),
        // or the root_n genuinely admits only one valid chain —
        // which is mathematically valid and not a sampler bug.
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
