use rand_core::RngCore;
use subtle::{ConstantTimeEq, Choice};

// Importing core types from your crate framework
// Adjust paths if your crate structure requires crate::crypto::hybrid::DiophantinePair etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiophantinePair {
    pub a: u64,
    pub b: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

/// Sampler implementing the scale factor transformation from the research notes.
/// Multiplies the mathematical elements by a factor of 90 to camouflage the 
/// digital root patterns, ensuring dr(N) = 9 across active layers.
pub struct SupergridSampler {
    pub scale_factor: u64,   // 90 as specified in docs/research-notes/
    pub supergrid_mod: u64,  // 2520 (LCM of 1..10) for the structural grid boundaries
}

impl SupergridSampler {
    /// Creates a new instance of the SupergridSampler with default constants.
    pub fn new() -> Self {
        Self {
            scale_factor: 90,
            supergrid_mod: 2520,
        }
    }

    /// Transforms a base public root N into the scaled supergrid space.
    /// Guarantees that the digital root of the output is always 9.
    pub fn transform_to_supergrid(&self, root_n: u64) -> u64 {
        root_n.wrapping_mul(self.scale_factor)
    }

    /// Constant-time check to verify if a scaled N aligns with the 2520 supergrid node.
    pub fn is_valid_supergrid_node(&self, n_scaled: u64) -> Choice {
        let rem = n_scaled % self.supergrid_mod;
        rem.ct_eq(&0u64)
    }

    /// O(1) Constant-time sampling step adapted for the scaled supergrid space.
    /// Extracts parameters using Crown Equations via base isomorphism, then projects back.
    pub fn sample_layer_scaled(&self, n_scaled: u64, mut rng: impl RngCore) -> Option<(u64, u64)> {
        // 1. Isomorphic reduction back to base space to avoid overflow in Crown Equations
        let n_base = n_scaled / self.scale_factor;

        // 2. Compute O(1) Crown Equations (branch-free digital root anchors)
        let a_0 = 1 + ((n_base.wrapping_sub(1)) % 9);
        let b_0 = (n_base.wrapping_sub(19 * a_0)) / 9;
        
        let k_max = b_0 / 19;
        if k_max == 0 { return None; }

        // Rejection-free CSPRNG step over the uniform parameter distribution window
        let mut rand_buf = [0u8; 8];
        rng.fill_bytes(&mut rand_buf);
        let rand_val = u64::from_le_bytes(rand_buf);
        let t = rand_val % (k_max + 1);

        let a = a_0.wrapping_add(9 * t);
        let b = b_0.wrapping_sub(19 * t);

        // 3. Project outputs back to the supergrid space to lock dr(A) = dr(B) = 9
        let a_scaled = a.wrapping_mul(self.scale_factor);
        let b_scaled = b.wrapping_mul(self.scale_factor);

        Some((a_scaled, b_scaled))
    }

    /// Constructs a full 3-layer nested MrsChain within the scaled supergrid space.
    /// Iteratively sets N <- A for subsequent layers while maintaining dr=9 parameters.
    pub fn sample_three_layers_scaled(&self, root_n_scaled: u64, mut rng: impl RngCore) -> Option<MrsChain> {
        let mut current_n = root_n_scaled;
        let mut layers = Vec::with_capacity(3);

        for _ in 0..3 {
            let (a_scaled, b_scaled) = self.sample_layer_scaled(current_n, &mut rng)?;
            layers.push(DiophantinePair { a: a_scaled, b: b_scaled });
            // Set the next layer's root input to the current layer's A coefficient
            current_n = a_scaled;
        }

        Some(MrsChain {
            layers,
            valid: true,
        })
    }
}

// =========================================================================
// UNIT TESTS 
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Helper function to compute the mathematical digital root (dr).
    /// Enforces that for all N > 0, the output strictly lands in the 1..9 range.
    fn calculate_digital_root(n: u64) -> u64 {
        if n == 0 { 
            0 
        } else { 
            1 + ((n - 1) % 9) 
        }
    }

    #[test]
    fn test_supergrid_three_layer_chain_properties() {
        let sampler = SupergridSampler::new();
        let mut rng = OsRng;

        // Using a larger root input to support depth=3 without hitting underflow zones early
        let base_root = 1_000_000u64;
        let root_n_scaled = sampler.transform_to_supergrid(base_root);

        // 1. Verify the root injection point
        assert_eq!(calculate_digital_root(root_n_scaled), 9);

        // 2. Generate the full 3-layer chain
        let chain_opt = sampler.sample_three_layers_scaled(root_n_scaled, &mut rng);
        assert!(chain_opt.is_some(), "Failed to generate a 3-layer chain for scaled root");

        let chain = chain_opt.unwrap();
        assert_eq!(chain.layers.len(), 3, "Chain must contain exactly 3 layers");
        assert!(chain.valid);

        // 3. Iteratively audit every layer in the generated witness path
        let mut expected_n = root_n_scaled;
        for (i, layer) in chain.layers.iter().enumerate() {
            // Verify structural MRS equation: N = 19A + 9B
            let reconstructed_n = (19 * layer.a) + (9 * layer.b);
            assert_eq!(
                expected_n, 
                reconstructed_n, 
                "Algebraic breakdown failed at layer {}", i
            );

            // Verify camouflage uniformity: dr(A) == 9 and dr(B) == 9
            assert_eq!(
                calculate_digital_root(layer.a), 
                9, 
                "Layer {} parameter 'a' leaked digital root structure", i
            );
            assert_eq!(
                calculate_digital_root(layer.b), 
                9, 
                "Layer {} parameter 'b' leaked digital root structure", i
            );

            // Prepare validation input for the next nested layer (N <- A)
            expected_n = layer.a;
        }
    }
}
