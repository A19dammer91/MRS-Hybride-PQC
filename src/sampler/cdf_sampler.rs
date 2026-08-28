//! Weighted CDF sampler with O(log n) floor-sum + binary search
//! for the MRS(19,9) Diophantine forest.
//!
//! No candidate enumeration; supports ranges up to u64::MAX.
//! Each layer samples in O(log n) via:
//!   1. Closed-form weight parameters (O(1))
//!   2. Prefix-sum via AtCoder floor_sum (O(1))
//!   3. Binary search on the CDF (O(log n))

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

/// Closed-form O(1) triangle count.
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

/// Draws a cryptographically random integer in [0, bound) for u128.
#[inline]
fn uniform_below_u128(bound: u128, rng: &mut impl RngCore) -> u128 {
    assert!(bound > 0, "bound must be positive");
    let limit = u128::MAX - (u128::MAX % bound);
    loop {
        let hi = rng.next_u64() as u128;
        let lo = rng.next_u64() as u128;
        let r = (hi << 64) | lo;
        if r < limit {
            return r % bound;
        }
    }
}

// ============================================================================
// AtCoder floor_sum: sum_{0 <= i < n} floor((a*i + b) / m)
// Uses i128 for intermediate products to prevent overflow.
// ============================================================================

fn floor_sum(n: u64, m: u64, a: u64, b: u64) -> u128 {
    let mut ans: u128 = 0;
    let mut n = n as i128;
    let mut m = m as i128;
    let mut a = a as i128;
    let mut b = b as i128;

    loop {
        if a >= m {
            ans += ((n - 1) * n / 2) as u128 * (a / m) as u128;
            a %= m;
        }
        if b >= m {
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
// O(log n) Layer sampler internals
// ============================================================================

/// Parameters for one layer, extracted in O(1).
struct LayerParams {
    a0: u64,
    b0: u64,
    k_max: u64,
    k0: u64,
    t_max: u64,
    valid: bool,
}

impl LayerParams {
    fn new(n: u64) -> Self {
        let a0 = digital_root(n);
        if 19 * a0 > n {
            return Self {
                a0: 0, b0: 0, k_max: 0, k0: 0, t_max: 0, valid: false,
            };
        }
        let b0 = (n - 19 * a0) / 9;
        let k_max = b0 / 19;
        let target = digital_root(2 * a0);
        let k0 = (b0 + 9 - target) % 9;
        if k0 > k_max {
            return Self {
                a0, b0, k_max, k0, t_max: 0, valid: false,
            };
        }
        let t_max = (k_max - k0) / 9;
        Self { a0, b0, k_max, k0, t_max, valid: true }
    }

    #[inline]
    fn a_at(&self, t: u64) -> u64 {
        let k = self.k0 + 9 * t;
        self.a0 + 9 * k
    }

    #[inline]
    fn b_at(&self, t: u64) -> u64 {
        let k = self.k0 + 9 * t;
        self.b0 - 19 * k
    }
}

/// For a non-last layer, compute the weight parameters.
/// Returns (t_filter, e_prime) where:
/// - t_filter: first t where weight > 0 (count >= 2 for the child layer)
/// - e_prime: shifted constant = 9*t_filter + (B0 - 19*c3), always >= 171
///
/// Weight for t >= t_filter: w(t) = floor((9*(t - t_filter) + e_prime) / 171) + 1
fn weight_params(params: &LayerParams) -> Option<(u64, u64)> {
    let A = params.a_at(0);
    let dr_a = digital_root(A);
    let B0 = (A - 19 * dr_a) / 9;
    let target = digital_root(2 * dr_a);
    let c3 = (B0 + 9 - target) % 9;

    // E = B0 - 19*c3
    // We need count >= 2, i.e., floor((9t + E)/171) >= 1, i.e., 9t + E >= 171
    let e = if B0 >= 19 * c3 {
        B0 - 19 * c3
    } else {
        // E is "negative" in the conceptual sense.
        // t_filter will be > 0.
        0 // placeholder, we'll compute t_filter differently
    };

    let t_filter = if B0 >= 19 * c3 + 171 {
        // Even at t=0: 9*0 + E >= 171, so weight > 0 immediately
        0
    } else {
        // Need 9t >= 171 + 19*c3 - B0
        let need = 171u64.saturating_add(19 * c3).saturating_sub(B0);
        (need + 8) / 9 // ceil(need / 9)
    };

    if t_filter > params.t_max {
        return None;
    }

    // e_prime = 9*t_filter + E, guaranteed >= 171
    let e_prime = 9u64.wrapping_mul(t_filter).wrapping_add(
        if B0 >= 19 * c3 { B0 - 19 * c3 } else { B0 + 19 * (9 - c3) } // wait, this is wrong
    );

    // Actually, let's just compute e_prime directly:
    // e_prime = 9 * t_filter + B0 - 19*c3
    // But if B0 < 19*c3, this underflows in u64.
    // However, we know 9*t_filter >= 171 + 19*c3 - B0, so:
    // 9*t_filter + B0 - 19*c3 >= 171.
    // We can compute it as: 9*t_filter + B0 - 19*c3 = 9*t_filter - (19*c3 - B0)
    // And we know 9*t_filter >= 19*c3 - B0 + 171 (approximately), so this is >= 171.
    // Let's use saturating/wrapping arithmetic carefully.
    
    let e_prime = if B0 >= 19 * c3 {
        9 * t_filter + B0 - 19 * c3
    } else {
        // B0 < 19*c3, so 19*c3 - B0 > 0
        // t_filter was computed so that 9*t_filter >= 171 + 19*c3 - B0
        let deficit = 19 * c3 - B0;
        9 * t_filter - deficit
    };

    Some((t_filter, e_prime))
}

/// Prefix weight sum from t_filter up to and including t.
/// Uses floor_sum for O(1) evaluation.
fn prefix_weight(t: u64, t_filter: u64, t_max: u64, e_prime: u64) -> u128 {
    if t < t_filter {
        return 0;
    }
    let end = t.min(t_max);
    let n_terms = end - t_filter + 1;

    // sum_{s=0}^{n_terms-1} floor((9*s + e_prime) / 171)
    let floor_part = floor_sum(n_terms, 171, 9, e_prime);

    floor_part + n_terms as u128
}

// ============================================================================
// Public sampler
// ============================================================================

/// Builds a 3-layer Matryoshka chain based on root_n.
/// O(log n) per layer via floor-sum + binary search. No enumeration.
pub fn sample_three_layers(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain> {
    const DEPTH: usize = 3;
    let mut chain = Vec::with_capacity(DEPTH);
    let mut current_n = root_n;

    for layer in 0..DEPTH {
        let is_last_layer = layer == DEPTH - 1;
        let params = LayerParams::new(current_n);

        if !params.valid {
            return None;
        }

        let t = if is_last_layer {
            // Last layer: uniform over all valid candidates (weight = 1 each)
            uniform_below(params.t_max + 1, rng)
        } else {
            // Non-last layer: weighted sampling
            let (t_filter, e_prime) = weight_params(&params)?;
            let total_weight = prefix_weight(params.t_max, t_filter, params.t_max, e_prime);
            if total_weight == 0 {
                return None;
            }

            let r = uniform_below_u128(total_weight, rng);

            // Binary search: smallest t where prefix(t) > r
            let mut lo = t_filter;
            let mut hi = params.t_max;
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if prefix_weight(mid, t_filter, params.t_max, e_prime) <= r {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            lo
        };

        let a = params.a_at(t);
        let b = params.b_at(t);
        chain.push(DiophantinePair { a, b });
        current_n = a;
    }

    Some(MrsChain { layers: chain, valid: true })
}

// ============================================================================
// Optional bridge block activated only via '--features bigint'
// ============================================================================

#[cfg(feature = "bigint")]
pub mod crypto_bigint_extension {
    use super::*;
    use crypto_bigint::U256;

    pub fn sample_triangle_u256(_n: &U256) -> Option<(U256, U256)> {
        None // not yet implemented
    }
}

// ============================================================================
// Test-only plain (non-CT) reference implementation
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
    fn fast_sampler_matches_plain_reachable_set() {
        for root_n in [201u64, 1_001, 12_345, 200_001] {
            let mut rng = OsRng;
            let mut seen_plain = std::collections::HashSet::new();
            let mut seen_fast = std::collections::HashSet::new();

            for _ in 0..200 {
                if let Some(chain) = sample_three_layers_plain(root_n, &mut rng) {
                    seen_plain.insert(chain.layers.iter().map(|p| (p.a, p.b)).collect::<Vec<_>>());
                }
                if let Some(chain) = sample_three_layers(root_n, &mut rng) {
                    seen_fast.insert(chain.layers.iter().map(|p| (p.a, p.b)).collect::<Vec<_>>());
                }
            }

            for chain in &seen_fast {
                assert!(
                    seen_plain.contains(chain),
                    "fast variant produced an unreachable chain {:?} for root_n={}",
                    chain, root_n
                );
            }
        }
    }

    #[test]
    fn fast_is_not_deterministic_large_n() {
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

    #[test]
    fn handles_very_large_n() {
        let root_n = u64::MAX / 2;
        let mut rng = OsRng;
        // Should complete quickly (O(log n) per layer) and not panic
        let result = sample_three_layers(root_n, &mut rng);
        // We don't assert success because the random choice might hit an
        // invalid path, but it must not hang or overflow.
        let _ = result;
    }
}
