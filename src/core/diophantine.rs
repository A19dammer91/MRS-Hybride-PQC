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

/// Digital root of a number (1-9, with 0 for n=0)
#[inline]
pub fn digital_root(n: u64) -> u64 {
    let is_zero = n.ct_eq(&0);
    let dr = 1u64 + (n.wrapping_sub(1) % 9u64);
    u64::conditional_select(&dr, &0, is_zero)
}

/// Validates the harmonic triangle condition: dr(B) == dr(2 * dr(X))
#[inline]
pub fn validate_triangle_condition(b: u64, x: u64) -> Choice {
    let dr_b = digital_root(b);
    let dr_x = digital_root(x);
    let target = digital_root(2 * dr_x);
    dr_b.ct_eq(&target)
}

/// Generates the linear family of solutions based on the step vector (A + 9k, B - 19k)
/// Optionally filters to only include pairs that satisfy the triangle condition
pub fn generate_representation_family(n: u64) -> Vec<DiophantinePair> {
    let mut family = Vec::new();
    let a_0 = calculate_anchor(n);
    let r_n = calculate_popoviciu_cardinality(n);

    for k in 0..r_n {
        let a = a_0 + (9 * k);
        let b = (n - (19 * a)) / 9;
        
        // Alleen toevoegen als het voldoet aan de triangle condition
        // Dit maakt de functie consistent met count_triangle_filtered_closed_form
        if validate_triangle_condition(b, n).unwrap_u8() == 1 {
            family.push(DiophantinePair { a, b });
        }
    }

    family
}

/// Generates ALL representations without triangle filtering (for debugging)
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
