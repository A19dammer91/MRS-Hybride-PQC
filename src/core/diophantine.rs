use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// Struct representing a single representation (A, B) at one layer
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct DiophantinePair {
    pub a: u64,
    pub b: u64,
}

/// Checks whether the main number N satisfies the Frobenius bound (N >= 144)
#[inline]
pub fn check_frobenius_bound(n: u64) -> Choice {
    Choice::from((n > 143) as u8)
}

/// Digital root (1-9, 0 for n=0)
#[inline]
pub fn digital_root(n: u64) -> u64 {
    let is_zero = n.ct_eq(&0);
    let dr = 1u64 + (n.wrapping_sub(1) % 9u64);
    u64::conditional_select(&dr, &0, is_zero)
}

/// Computes the MRS anchor A_0, per the Positive Anchor Convention:
///
///     A_0 = min { a in Z_{>0} : a === N (mod 9) }
///
/// which is equivalent to A_0 = dr(N) — including A_0 = 9 (not 0) when
/// N === 0 (mod 9). This is a thin alias over `digital_root` so the two
/// stay defined in exactly one place.
#[inline]
pub fn calculate_anchor(n: u64) -> u64 {
    digital_root(n)
}

/// Computes the exact number of valid representations at a layer via Popoviciu
pub fn calculate_popoviciu_cardinality(n: u64) -> u64 {
    let a_0 = calculate_anchor(n);
    let subtrahend = 19 * a_0;

    if n < subtrahend {
        return 0;
    }

    ((n - subtrahend) / 171) + 1
}

/// Triangle condition: dr(B) == dr(2 * dr(X))
#[inline]
pub fn validate_triangle_condition(b: u64, x: u64) -> Choice {
    let dr_b = digital_root(b);
    let dr_x = digital_root(x);
    let target = digital_root(2 * dr_x);
    dr_b.ct_eq(&target)
}

/// Generates ALL representations (unfiltered) — for internal/reference use
pub fn generate_representation_family_unfiltered(n: u64) -> Vec<DiophantinePair> {
    let mut family = Vec::new();
    let a_0 = calculate_anchor(n);
    let r_n = calculate_popoviciu_cardinality(n);

    for k in 0..r_n {
        let a = a_0 + (9 * k);
        let b = (n - (19 * a)) / 9;
        family.push(DiophantinePair { a, b });
    }

    family
}

/// Generates ONLY representations that satisfy the triangle condition
pub fn generate_representation_family(n: u64) -> Vec<DiophantinePair> {
    let mut family = Vec::new();
    let a_0 = calculate_anchor(n);
    let r_n = calculate_popoviciu_cardinality(n);

    for k in 0..r_n {
        let a = a_0 + (9 * k);
        let b = (n - (19 * a)) / 9;

        if validate_triangle_condition(b, n).unwrap_u8() == 1 {
            family.push(DiophantinePair { a, b });
        }
    }

    family
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive Anchor Convention: A_0 must never be 0 for any N > 0 —
    /// in particular, not for N divisible by 9 (the exact case the old
    /// `n % 9` implementation got wrong).
    #[test]
    fn calculate_anchor_is_never_zero_for_positive_n() {
        for n in 1..=100_000u64 {
            assert_ne!(
                calculate_anchor(n),
                0,
                "calculate_anchor({}) returned 0, violating the Positive Anchor Convention",
                n
            );
        }
    }

    /// calculate_anchor and digital_root must agree everywhere — they are
    /// the same quantity by definition and must not be allowed to drift
    /// into two independent implementations again.
    #[test]
    fn calculate_anchor_matches_digital_root() {
        for n in 1..=100_000u64 {
            assert_eq!(calculate_anchor(n), digital_root(n));
        }
    }

    /// Regression test: for small multiples of 9 where 19 * dr(N) > N, no
    /// valid representation exists, so the family must be empty.
    #[test]
    fn small_multiples_of_nine_yield_no_spurious_representations() {
        for n in [9u64, 18, 27, 36, 45, 54, 63, 72, 81, 90, 99, 108, 117, 126, 135, 144, 153, 162, 171] {
            let a0 = calculate_anchor(n);
            assert_eq!(a0, 9, "calculate_anchor({}) should be 9, got {}", n, a0);

            if 19 * a0 > n {
                assert_eq!(
                    calculate_popoviciu_cardinality(n),
                    0,
                    "N={} should have zero valid representations (19*9={} > N)",
                    n,
                    19 * a0
                );
                assert!(
                    generate_representation_family(n).is_empty(),
                    "N={} should yield an empty representation family, found: {:?}",
                    n,
                    generate_representation_family(n)
                );
                assert!(
                    generate_representation_family_unfiltered(n).is_empty(),
                    "N={} should yield an empty unfiltered family too",
                    n
                );
            }
        }
    }

    /// General property, checked exhaustively over a wide range: whenever
    /// 19 * dr(N) > N, the representation family must be empty.
    #[test]
    fn no_representations_exist_below_the_anchor_threshold() {
        for n in 1..=50_000u64 {
            let a0 = calculate_anchor(n);
            if 19 * a0 > n {
                assert_eq!(
                    calculate_popoviciu_cardinality(n),
                    0,
                    "N={}: expected 0 representations below threshold",
                    n
                );
                assert!(
                    generate_representation_family_unfiltered(n).is_empty(),
                    "N={}: expected empty family below threshold",
                    n
                );
            }
        }
    }
}
