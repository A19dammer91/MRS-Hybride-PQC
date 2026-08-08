use crate::core::diophantine::{calculate_popoviciu_cardinality, generate_representation_family, DiophantinePair};
use zeroize::Zeroize;

/// Struct die een volledige 3-laagse keten (Matryoshka) vasthoudt
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

/// Berekent de digitale wortel (digital root) van een getal constant-time zonder loops
#[inline]
pub fn digital_root(n: u64) -> u64 {
    if n == 0 {
        0
    } else {
        1 + ((n - 1) % 9)
    }
}

/// Implementeert de Check-Ahead logica uit de formele specificatie.
/// Controleert of een gekozen waarde op de lagere niveaus wel minimaal 2 alibi's heeft (R(A) >= 2).
#[inline]
pub fn check_ahead_valid(a_value: u64) -> bool {
    let r_next = calculate_popoviciu_cardinality(a_value);
    r_next >= 2
}

/// Controleert de harmonische Triangle-eis: dr(B) == dr(2 * dr(X))
/// Dit verdeelt de alibi's uniform over de negen residuklassen volgens v3.0
#[inline]
pub fn validate_triangle_condition(b: u64, x: u64) -> bool {
    let dr_b = digital_root(b);
    let dr_x = digital_root(x);
    let target = digital_root(2 * dr_x);
    dr_b == target
}

/// Berekent het hiërarchische gewicht van een tak om uniformiteit te garanderen (Forest Symmetry).
pub fn calculate_layer_weights(n: u64) -> Vec<u64> {
    let family = generate_representation_family(n);
    let mut weights = Vec::with_capacity(family.len());
    
    for pair in &family {
        let w = calculate_popoviciu_cardinality(pair.a);
        weights.push(w);
    }
    
    weights
}

/// Rekent een 3-laagse Matryoshka-keten door op basis van invoer-seeds
/// Deze functie koppelt de lagen recursief aan elkaar met check-ahead controles
pub fn sample_three_layers(root_n: u64, seed_x: u64) -> Option<MrsChain> {
    let mut chain = Vec::with_capacity(3);
    let mut current_n = root_n;
    
    for _ in 0..3 {
        let family = generate_representation_family(current_n);
        let mut chosen_pair: Option<DiophantinePair> = None;
        
        // Loop door de familie om een paar te vinden dat voldoet aan de eisen
        for pair in family {
            // Pas de Triangle-eis en de Check-Ahead logica toe om doodlopende wegen te voorkomen
            if validate_triangle_condition(pair.b, seed_x) && check_ahead_valid(pair.a) {
                chosen_pair = Some(pair);
                break;
            }
        }
        
        if let Some(pair) = chosen_pair {
            chain.push(pair);
            // De 'A' van de huidige laag wordt het hoofdgetal 'N' van de volgende geneste laag
            current_n = pair.a;
        } else {
            // Als er geen geldig paar is dat aan de eisen voldoet, faalt de sampler veilig
            return None;
        }
    }
    
    Some(MrsChain {
        layers: chain,
        valid: true,
    })
}
