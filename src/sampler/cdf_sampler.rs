use crate::core::diophantine::{calculate_popoviciu_cardinality, generate_representation_family, DiophantinePair};
use zeroize::Zeroize;

/// Struct die een volledige 3-laagse keten (Matryoshka) vasthoudt
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

/// Implementeert de Check-Ahead logica uit de formele specificatie.
/// Controleert of een gekozen waarde op de lagere niveaus wel minimaal 2 alibi's heeft (R(A) >= 2).
#[inline]
pub fn check_ahead_valid(a_value: u64) -> bool {
    let r_next = calculate_popoviciu_cardinality(a_value);
    r_next >= 2
}

/// Berekent het hiërarchische gewicht van een tak om uniformiteit te garanderen (Forest Symmetry).
pub fn calculate_layer_weights(n: u64) -> Vec<u64> {
    let family = generate_representation_family(n);
    let mut weights = Vec::with_capacity(family.len());
    
    for pair in &family {
        // Het gewicht is afhankelijk van het aantal geldige wegen op het volgende niveau
        let w = calculate_popoviciu_cardinality(pair.a);
        weights.push(w);
    }
    
    weights
}
