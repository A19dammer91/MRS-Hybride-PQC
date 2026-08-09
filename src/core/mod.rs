pub mod diophantine;

// Exposeer de belangrijkste functies direct aan de rest van de library
pub use diophantine::{
    calculate_anchor, calculate_popoviciu_cardinality, check_frobenius_b...
    generate_representation_family, DiophantinePair,
};
