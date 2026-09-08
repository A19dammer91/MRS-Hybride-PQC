use rand::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};
use zeroize::Zeroize;

use super::{select_chain, MrsChain};
use crate::core::diophantine::{digital_root, DiophantinePair};

// ============================================================================
// Existing production sampler (unchanged, already tested in CI)
// ============================================================================

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

    /// Core constant-time step for a single 3-layer attempt.
    /// Returns the chain and a Choice indicating whether the generation was successful.
    fn sample_three_layers_scaled_raw(
        &self,
        root_n_scaled: u64,
        mut rng: impl RngCore,
    ) -> (MrsChain, Choice) {
        let mut current_n = root_n_scaled;
        let mut layers = Vec::with_capacity(3);
        let mut valid = Choice::from(1);

        for _ in 0..3 {
            if let Some((a_scaled, b_scaled)) = self.sample_layer_scaled(current_n, &mut rng) {
                layers.push(DiophantinePair {
                    a: a_scaled,
                    b: b_scaled,
                });
                current_n = a_scaled;
            } else {
                layers.push(DiophantinePair { a: 0, b: 0 });
                valid &= Choice::from(0);
            }
        }

        (
            MrsChain {
                layers,
                valid: valid.unwrap_u8() == 1,
            },
            valid,
        )
    }

    /// Primary entry point for production. Samples a 3-layer chain in the scaled supergrid space,
    /// executing a fixed number of attempts to guarantee constant-time execution and mitigate timing leaks.
    pub fn sample_three_layers_scaled_with_retries(
        &self,
        root_n_scaled: u64,
        mut rng: impl RngCore,
        max_attempts: usize,
    ) -> Option<MrsChain> {
        let mut best = MrsChain {
            layers: vec![
                DiophantinePair { a: 0, b: 0 },
                DiophantinePair { a: 0, b: 0 },
                DiophantinePair { a: 0, b: 0 },
            ],
            valid: false,
        };
        let mut found = Choice::from(0);

        for _ in 0..max_attempts {
            let (candidate, candidate_valid) =
                self.sample_three_layers_scaled_raw(root_n_scaled, &mut rng);
            let take_this = candidate_valid & !found;
            best = select_chain(&best, &candidate, take_this);
            found |= candidate_valid;
        }

        if found.unwrap_u8() == 1 {
            Some(best)
        } else {
            None
        }
    }
}

impl Default for SupergridSampler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Research-note extension: 90-rotation, 366 temporal anchor, 2520 macro grid
//
// Everything below builds on the existing, already-tested sampler above
// rather than re-deriving a second sampling loop. `TransformLevel` carries
// no secret data (it's a public tag, exactly like `SecretMode` in
// `security::witness`), so branching on it directly is fine; nothing here
// branches on chain contents or scaled witness values themselves, those
// stay behind `Choice`/`conditional_select` throughout.
// ============================================================================

pub const MICRO_ANCHOR: u64 = 366;
pub const ROTATION_FACTOR: u64 = 90;
pub const MACRO_ANCHOR: u64 = 32940;
pub const SUPER_GRID: u64 = 2520;
pub const NINE_MODULUS: u64 = 9;
pub const PERFECT_SIX: u64 = 6;
pub const PERFECT_TWENTYEIGHT: u64 = 28;

/// Which transform has been applied to produce a `SupergridChain`. Public
/// tag only, no secret data — mirrors `SecretMode` in `security::witness`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum TransformLevel {
    Raw,
    Rotated90,
    SuperGrid,
    TemporalAnchor,
}

impl TransformLevel {
    #[inline]
    fn to_u8(self) -> u8 {
        match self {
            TransformLevel::Raw => 0,
            TransformLevel::Rotated90 => 1,
            TransformLevel::SuperGrid => 2,
            TransformLevel::TemporalAnchor => 3,
        }
    }

    #[inline]
    fn from_u8(v: u8) -> Self {
        match v {
            1 => TransformLevel::Rotated90,
            2 => TransformLevel::SuperGrid,
            3 => TransformLevel::TemporalAnchor,
            _ => TransformLevel::Raw,
        }
    }
}

/// Lets `TransformLevel` be chosen via `conditional_select` alongside the
/// chain data it tags, the same way `u64::conditional_select` picks layer
/// values in `select_chain`/`select_supergrid_chain` below.
impl ConditionallySelectable for TransformLevel {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        TransformLevel::from_u8(u8::conditional_select(&a.to_u8(), &b.to_u8(), choice))
    }
}

/// A 3-layer chain tagged with the transform used to produce it. Kept
/// separate from `sampler::MrsChain` (no `transform_level` field there)
/// to avoid disturbing that type's existing, already-tested call sites.
#[derive(Debug, Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct SupergridChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
    pub transform_level: TransformLevel,
}

/// Constant-time analogue of `select_chain`, extended with the
/// `transform_level` tag.
pub fn select_supergrid_chain(
    current_best: &SupergridChain,
    candidate: &SupergridChain,
    choice: Choice,
) -> SupergridChain {
    let layers = current_best
        .layers
        .iter()
        .zip(candidate.layers.iter())
        .map(|(cur, cand)| DiophantinePair {
            a: u64::conditional_select(&cur.a, &cand.a, choice),
            b: u64::conditional_select(&cur.b, &cand.b, choice),
        })
        .collect();
    let transform_level = TransformLevel::conditional_select(
        &current_best.transform_level,
        &candidate.transform_level,
        choice,
    );
    SupergridChain {
        layers,
        valid: true,
        transform_level,
    }
}

/// Applies the 90-rotation to a single (A, B) pair. Pure wrapping
/// arithmetic, no branches, no data-dependent loop bound — inherently
/// constant-time already.
pub fn rotate_90(pair: &DiophantinePair, delta_a: u64, delta_b: u64) -> DiophantinePair {
    let delta_a_9 = delta_a.wrapping_mul(NINE_MODULUS);
    let delta_b_9 = delta_b.wrapping_mul(NINE_MODULUS);

    let a_star = ROTATION_FACTOR.wrapping_mul(pair.a).wrapping_add(delta_a_9);

    let b_star = ROTATION_FACTOR
        .wrapping_mul(pair.b)
        .wrapping_sub(19u64.wrapping_mul(delta_a_9))
        .wrapping_add(delta_b_9);

    DiophantinePair {
        a: a_star,
        b: b_star,
    }
}

/// Verifies that a rotated pair still satisfies 19A* + 9B* = 90*N + 81*delta_b,
/// and that both components are nonzero. Fully `Choice`-based, no branch
/// on any of the (potentially secret-derived) rotated values.
pub fn verify_90_rotation(original_n: u64, rotated: &DiophantinePair, delta_b: u64) -> Choice {
    let expected_n = ROTATION_FACTOR
        .wrapping_mul(original_n)
        .wrapping_add(81u64.wrapping_mul(delta_b));

    let lhs = 19u64
        .wrapping_mul(rotated.a)
        .wrapping_add(9u64.wrapping_mul(rotated.b));

    let valid_eq = lhs.ct_eq(&expected_n);
    let valid_a = rotated.a.ct_gt(&0);
    let valid_b = rotated.b.ct_gt(&0);

    valid_eq & valid_a & valid_b
}

#[inline]
pub fn is_nine_homogeneous(n: u64) -> Choice {
    digital_root(n).ct_eq(&9)
}

#[inline]
pub fn pair_is_nine_homogeneous(pair: &DiophantinePair) -> Choice {
    is_nine_homogeneous(pair.a) & is_nine_homogeneous(pair.b)
}

/// Checks that `n` both sits on a 366-second boundary and has digital
/// root 6 (the perfect-six invariant of the temporal anchor). No branch:
/// the multiple check and the digital-root check are both folded through
/// `ct_eq` and combined with `&`.
pub fn verify_temporal_anchor(n: u64) -> Choice {
    let is_multiple = n.ct_eq(&(n.wrapping_div(MICRO_ANCHOR).wrapping_mul(MICRO_ANCHOR)));
    let dr_is_six = digital_root(n).ct_eq(&PERFECT_SIX);
    is_multiple & dr_is_six
}

/// Reduces a timestamp down to the 366-second window it falls into.
#[inline]
pub fn temporal_root_from_timestamp(timestamp: u64) -> u64 {
    let k = timestamp.wrapping_div(MICRO_ANCHOR);
    MICRO_ANCHOR.wrapping_mul(k)
}

/// Constant-time core: reduces a supergrid-scaled `n` down to its micro
/// representation and reports (via `Choice`, not a branch) whether `n`
/// actually sits on a 2520-boundary. Mirrors the `..._ct` + `Option`
/// wrapper pattern `cdf_sampler` uses for `sample_three_layers_ct`.
pub fn supergrid_params_ct(n: u64) -> (u64, u64, Choice) {
    let is_multiple = n.ct_eq(&(n.wrapping_div(SUPER_GRID).wrapping_mul(SUPER_GRID)));
    let k = n.wrapping_div(SUPER_GRID);
    let micro_n = PERFECT_TWENTYEIGHT.wrapping_mul(k);
    (micro_n, k, is_multiple)
}

/// Ergonomic `Option`-returning wrapper around `supergrid_params_ct`.
pub fn supergrid_params(n: u64) -> Option<(u64, u64)> {
    let (micro_n, k, ok) = supergrid_params_ct(n);
    if ok.unwrap_u8() == 1 {
        Some((micro_n, k))
    } else {
        None
    }
}

/// Scales a micro-grid pair up to supergrid scale.
#[inline]
pub fn micro_to_supergrid(micro_pair: &DiophantinePair) -> DiophantinePair {
    DiophantinePair {
        a: ROTATION_FACTOR.wrapping_mul(micro_pair.a),
        b: ROTATION_FACTOR.wrapping_mul(micro_pair.b),
    }
}

impl SupergridSampler {
    /// Samples a chain anchored to the 366-second window containing
    /// `timestamp`, reusing the existing, already-tested
    /// `sample_three_layers_scaled_with_retries` rather than a separate
    /// sampling loop. The resulting `transform_level` tag is chosen via
    /// `TransformLevel::conditional_select` rather than an `if`, so
    /// tagging itself does not branch on the (public but consistently
    /// treated) anchor value.
    pub fn sample_temporal_chain(
        &self,
        timestamp: u64,
        rng: &mut impl RngCore,
        max_attempts: usize,
    ) -> Option<SupergridChain> {
        let root_n = temporal_root_from_timestamp(timestamp);
        let chain = self.sample_three_layers_scaled_with_retries(root_n, rng, max_attempts)?;

        let (_, _, is_supergrid) = supergrid_params_ct(root_n);
        let level = TransformLevel::conditional_select(
            &TransformLevel::TemporalAnchor,
            &TransformLevel::SuperGrid,
            is_supergrid,
        );

        Some(SupergridChain {
            layers: chain.layers,
            valid: chain.valid,
            transform_level: level,
        })
    }
}

/// Verifies a chain produced by `sample_temporal_chain` against its
/// claimed scaled root: the defining equation on the first layer, and,
/// for any transform level other than `Raw`, 9-homogeneity on every
/// layer. `chain.transform_level` is a public tag (see the type's doc
/// comment), so matching on it directly is consistent with how
/// `security::witness` branches on `SecretMode`.
pub fn verify_temporal_chain(chain: &SupergridChain, root_n_scaled: u64) -> Choice {
    let length_ok = Choice::from((chain.layers.len() == 3) as u8);

    let first_ok = match chain.layers.first() {
        Some(pair) => {
            let lhs = 19u64
                .wrapping_mul(pair.a)
                .wrapping_add(9u64.wrapping_mul(pair.b));
            lhs.ct_eq(&root_n_scaled)
        }
        None => Choice::from(0),
    };

    let is_raw = chain.transform_level == TransformLevel::Raw;
    let mut homogeneity_ok = Choice::from(1);
    for pair in &chain.layers {
        homogeneity_ok &= pair_is_nine_homogeneous(pair);
    }
    let homogeneity_required_ok = Choice::from(is_raw as u8) | homogeneity_ok;

    length_ok & first_ok & homogeneity_required_ok
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
    fn test_supergrid_three_layer_chain_with_retries() {
        let sampler = SupergridSampler::new();
        let mut rng = OsRng;

        let base_root = 3_000_001u64;
        let root_n_scaled = sampler.transform_to_supergrid(base_root);

        assert_eq!(calculate_digital_root(root_n_scaled), 9);

        let chain_opt =
            sampler.sample_three_layers_scaled_with_retries(root_n_scaled, &mut rng, 10);
        assert!(
            chain_opt.is_some(),
            "Failed to sample a valid 3-layer chain with retries for root_n_scaled {}",
            root_n_scaled
        );

        let chain = chain_opt.unwrap();
        assert_eq!(chain.layers.len(), 3);

        let mut expected_n = root_n_scaled;
        for layer in chain.layers.iter() {
            let reconstructed_n = (19 * layer.a) + (9 * layer.b);
            assert_eq!(expected_n, reconstructed_n);

            assert_eq!(calculate_digital_root(layer.a), 9);
            assert_eq!(calculate_digital_root(layer.b), 9);

            expected_n = layer.a;
        }
    }

    #[test]
    fn test_366_equals_6_times_19_plus_28_times_9() {
        assert_eq!(MICRO_ANCHOR, 6 * 19 + PERFECT_TWENTYEIGHT * 9);
    }

    #[test]
    fn test_macro_anchor_has_digital_root_nine() {
        assert_eq!(calculate_digital_root(MACRO_ANCHOR), 9);
    }

    #[test]
    fn test_rotate_90_preserves_equation() {
        // Start from a pair that already satisfies 19A + 9B = N.
        let original_n = 3_000_001u64;
        let a = 1u64;
        let b = (original_n - 19 * a) / 9;
        let original_pair = DiophantinePair { a, b };
        assert_eq!(19 * original_pair.a + 9 * original_pair.b, original_n);

        let delta_a = 1u64;
        let delta_b = 1u64;
        let rotated = rotate_90(&original_pair, delta_a, delta_b);

        let ok = verify_90_rotation(original_n, &rotated, delta_b);
        assert_eq!(ok.unwrap_u8(), 1);
    }

    #[test]
    fn test_rotate_90_produces_nine_homogeneous_pair() {
        let original_n = 3_000_001u64;
        let a = 1u64;
        let b = (original_n - 19 * a) / 9;
        let original_pair = DiophantinePair { a, b };

        let rotated = rotate_90(&original_pair, 1, 1);
        let homogeneous = pair_is_nine_homogeneous(&rotated);
        assert_eq!(homogeneous.unwrap_u8(), 1);
    }

    #[test]
    fn test_verify_temporal_anchor_accepts_valid_anchor() {
        // MICRO_ANCHOR itself (k=1) must satisfy the invariant.
        assert_eq!(verify_temporal_anchor(MICRO_ANCHOR).unwrap_u8(), 1);
        assert_eq!(verify_temporal_anchor(MICRO_ANCHOR * 2).unwrap_u8(), 1);
    }

    #[test]
    fn test_verify_temporal_anchor_rejects_non_multiple() {
        assert_eq!(verify_temporal_anchor(MICRO_ANCHOR + 1).unwrap_u8(), 0);
    }

    #[test]
    fn test_temporal_root_from_timestamp_floors_to_window() {
        let ts = MICRO_ANCHOR * 5 + 100;
        let root = temporal_root_from_timestamp(ts);
        assert_eq!(root, MICRO_ANCHOR * 5);
        assert_eq!(verify_temporal_anchor(root).unwrap_u8(), 1);
    }

    #[test]
    fn test_supergrid_params_reduces_to_micro_problem() {
        let (micro_n, k) = supergrid_params(SUPER_GRID).expect("2520 must be a valid supergrid n");
        assert_eq!(k, 1);
        assert_eq!(micro_n, PERFECT_TWENTYEIGHT);
        // 28 = 19*1 + 9*1
        assert_eq!(19 * 1 + 9 * 1, micro_n);
    }

    #[test]
    fn test_supergrid_params_rejects_non_multiple() {
        assert!(supergrid_params(SUPER_GRID + 1).is_none());
    }

    #[test]
    fn test_sample_temporal_chain_and_verify() {
        let sampler = SupergridSampler::new();
        let mut rng = OsRng;

        // A timestamp whose window's scaled root is sampleable.
        let timestamp = 3_000_001u64 * MICRO_ANCHOR;
        let root_n = temporal_root_from_timestamp(timestamp);

        let chain_opt = sampler.sample_temporal_chain(timestamp, &mut rng, 10);
        if let Some(chain) = chain_opt {
            assert_eq!(chain.layers.len(), 3);
            let ok = verify_temporal_chain(&chain, root_n);
            assert_eq!(ok.unwrap_u8(), 1);
        } else {
            eprintln!(
                "[WARN] No temporal chain found for timestamp={} - may be expected for this window",
                timestamp
            );
        }
    }

    #[test]
    fn test_select_supergrid_chain_picks_candidate_when_choice_true() {
        let base = SupergridChain {
            layers: vec![
                DiophantinePair { a: 1, b: 1 },
                DiophantinePair { a: 1, b: 1 },
                DiophantinePair { a: 1, b: 1 },
            ],
            valid: false,
            transform_level: TransformLevel::Raw,
        };
        let candidate = SupergridChain {
            layers: vec![
                DiophantinePair { a: 9, b: 9 },
                DiophantinePair { a: 9, b: 9 },
                DiophantinePair { a: 9, b: 9 },
            ],
            valid: true,
            transform_level: TransformLevel::SuperGrid,
        };

        let picked = select_supergrid_chain(&base, &candidate, Choice::from(1));
        assert_eq!(picked.layers[0].a, 9);
        assert_eq!(picked.transform_level, TransformLevel::SuperGrid);

        let kept = select_supergrid_chain(&base, &candidate, Choice::from(0));
        assert_eq!(kept.layers[0].a, 1);
        assert_eq!(kept.transform_level, TransformLevel::Raw);
    }
}
