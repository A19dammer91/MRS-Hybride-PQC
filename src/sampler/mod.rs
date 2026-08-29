pub mod cdf_sampler;

// Direct imports to fix the compiler errors
pub use crate::core::diophantine::{digital_root, validate_triangle_condition};

// Active imports required by src/framework.rs
pub use cdf_sampler::{sample_three_layers, MrsChain};
