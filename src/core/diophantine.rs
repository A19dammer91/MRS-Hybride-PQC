use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};
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
    // 143 is the largest number that cannot be represented; everything above it is valid
    Choice::from((n > 143) as u8)
}

/// Computes the mathematically pure anchor value A_0 = N mod 9
/// Avoids the digital-root error at multiples of 9
#[inline]
pub fn calculate_anchor(n: u64) -> u64 {
    n % 9
}

/// Computes the exact number of valid representations at a layer via Popoviciu
/// Formula: R(N) = floor((N - 19*A_0) / 171) + 1
pub fn calculate_popoviciu_cardinality(n: u64) -> u64 {
    let a_0 = calculate_anchor(n);
    let subtrahend = 19 * a_0;

    if n < subtrahend {
        return 0;
    }

    ((n - subtrahend) / 171) + 1
}

/// Generates the linear family of solutions based on the step vector (A + 9k, B - 19k)
pub fn generate_representation_family(n: u64) -> Vec<DiophantinePair> {
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
