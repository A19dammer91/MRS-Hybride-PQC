pub mod diophantine;

// Expose the most important functions to the rest of the library
pub use diophantine::{
    calculate_anchor, calculate_popoviciu_cardinality, check_frobenius_bound,
    generate_representation_family, DiophantinePair,
};
