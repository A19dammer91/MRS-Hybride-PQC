use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};
use zeroize::Zeroize;

/// Struct die een enkele representatie (A, B) op een laag vertegenwoordigt
#[derive(Debug, Clone, Copy, Zeroize)]
#[zeroize(drop)]
pub struct DiophantinePair {
    pub a: u64,
    pub b: u64,
}

/// Controleert of het hoofdgetal N voldoet aan de Frobenius-grens (N >= 144)
#[inline]
pub fn check_frobenius_bound(n: u64) -> Choice {
    // 143 is het grootste onmogelijk te schrijven getal; alles daarboven is geldig
    n.gt(&143).into()
}

/// Berekent de wiskundig zuivere ankerwaarde A_0 = N mod 9
/// Voorkomt de digitale-wortelfout bij veelvouden van 9
#[inline]
pub fn calculate_anchor(n: u64) -> u64 {
    n % 9
}

/// Berekent het exacte aantal geldige representaties op een laag via Popoviciu
/// Formule: R(N) = floor((N - 19*A_0) / 171) + 1
pub fn calculate_popoviciu_cardinality(n: u64) -> u64 {
    let a_0 = calculate_anchor(n);
    let subtrahend = 19 * a_0;
    
    if n < subtrahend {
        return 0;
    }
    
    ((n - subtrahend) / 171) + 1
}

/// Genereert de lineaire familie van oplossingen op basis van stapvector (A + 9k, B - 19k)
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

