pub mod cdf_sampler;

// Exposeer de structuren en functies aan de rest van het framework
pub use cdf_sampler::{
    calculate_layer_weights, check_ahead_valid, MrsChain
};
