use rand::RngCore;
use subtle::{Choice, ConstantTimeEq};

use super::{LayerParams, MrsChain};

pub struct SupergridSampler {
    pub scale_factor: u64,
    pub supergrid_mod: u64,
}

impl SupergridSampler {
    pub fn new() -> Self {
        Self {
            scale_factor: 90,
            supergrid_mod: 2520,
        }
    }

    pub fn transform_to_supergrid(&self, root_n: u64) -> u64 {
        root_n.wrapping_mul(self.scale_factor)
    }

    pub fn is_valid_supergrid_node(&self, n_scaled: u64) -> Choice {
        let rem = n_scaled % self.supergrid_mod;
        rem.ct_eq(&0u64)
    }

    pub fn sample_layer_scaled(&self, n_scaled: u64, mut rng: impl RngCore) -> Option<(u64, u64)> {
        let n_base = n_scaled.checked_div(self.scale_factor)?;

        let a_0 = 1 + ((n_base.wrapping_sub(1)) % 9);
        let b_0 = n_base.checked_sub(19 * a_0)?.checked_div(9)?;

        let k_max = b_0 / 19;
        if k_max == 0 {
            return None;
        }

        let mut rand_buf = [0u8; 8];
        rng.fill_bytes(&mut rand_buf);
        let rand_val = u64::from_le_bytes(rand_buf);
        let t = rand_val % (k_max + 1);

        let a = a_0.wrapping_add(9 * t);
        let b = b_0.wrapping_sub(19 * t);

        let a_scaled = a.checked_mul(self.scale_factor)?;
        let b_scaled = b.checked_mul(self.scale_factor)?;

        Some((a_scaled, b_scaled))
    }

    pub fn sample_three_layers_scaled(
        &self,
        root_n_scaled: u64,
        mut rng: impl RngCore,
    ) -> Option<MrsChain> {
        let mut current_n = root_n_scaled;
        let mut layers = Vec::with_capacity(3);

        for _ in 0..3 {
            let (a_scaled, b_scaled) = self.sample_layer_scaled(current_n, &mut rng)?;
            layers.push(LayerParams {
                a: a_scaled,
                b: b_scaled,
            });
            current_n = a_scaled;
        }

        Some(MrsChain {
            layers,
            valid: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

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

        let base_root = 1_000_000u64;
        let root_n_scaled = sampler.transform_to_supergrid(base_root);

        assert_eq!(calculate_digital_root(root_n_scaled), 9);

        let chain_opt = sampler.sample_three_layers_scaled(root_n_scaled, &mut rng);
        assert!(chain_opt.is_some());

        let chain = chain_opt.unwrap();
        assert_eq!(chain.layers.len(), 3);
        assert!(chain.valid);

        let mut expected_n = root_n_scaled;
        for layer in chain.layers.iter() {
            let reconstructed_n = (19 * layer.a) + (9 * layer.b);
            assert_eq!(expected_n, reconstructed_n);

            assert_eq!(calculate_digital_root(layer.a), 9);
            assert_eq!(calculate_digital_root(layer.b), 9);

            expected_n = layer.a;
        }
    }
}
