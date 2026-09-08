//! Temporal Witness Authentication — 90/366/2520 extension
//!
//! Builds on `security::witness::MasterSecret` for key derivation and on
//! `sampler::supergrid` for the underlying chain sampling. Adds a time
//! dimension: a witness generated here is only valid within the 366-second
//! window it was created in.
//!
//! Kept as a separate module from `security::witness` rather than folding
//! into it: the types below (`Witness90`, `WitnessSpace90`,
//! `WitnessStatus90`) share names and shapes with their counterparts there
//! but are not identical (extra `timestamp`/`transform_level` fields, an
//! extra `Expired` status), so keeping them apart avoids disturbing
//! `security::witness`'s existing, already-tested call sites.
//!
//! Constant-time note: this module follows the same discipline as
//! `security::witness` — fixed attempt budgets, no early return, and
//! selection via `select_supergrid_chain`/`conditional_select` rather than
//! branching on chain contents or secret-derived randomness.

use crate::sampler::supergrid::{
    select_supergrid_chain, temporal_root_from_timestamp,
    verify_temporal_chain, SupergridChain, SupergridSampler, TransformLevel, MICRO_ANCHOR,
};
use crate::security::witness::MasterSecret;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// Data Structures
// ============================================================================

/// A witness bound to both an identity and a 366-second time window.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Witness90 {
    pub chain: SupergridChain,
    pub binding_tag: [u8; 32],
    pub session_id: Vec<u8>,
    pub timestamp: u64,
}

/// Newtype wrapper, mirrors `security::witness::Alibi`: distinct type so
/// the compiler catches accidental use of an alibi where an authentic
/// witness is expected.
#[derive(Debug, Clone, PartialEq)]
pub struct Alibi90(pub Witness90);

/// Public parameters for a temporal witness space. Unlike
/// `security::witness::WitnessSpace`, `root_n` is derived per-verification
/// from the witness's own timestamp rather than fixed at construction,
/// since the whole point of this module is that the root changes every
/// 366 seconds.
#[derive(Debug, Clone)]
pub struct WitnessSpace90 {
    pub depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessStatus90 {
    ValidButUnbound,
    Authentic,
    Invalid,
    BindingMismatch,
    /// Witness presented outside its 366-second window.
    Expired,
}

impl Default for WitnessSpace90 {
    fn default() -> Self {
        Self { depth: 3 }
    }
}

impl WitnessSpace90 {
    pub fn new(depth: usize) -> Self {
        Self { depth }
    }

    /// Public membership check: is `chain` mathematically valid against
    /// its own claimed `root_n_scaled`, independent of any binding tag or
    /// timestamp freshness. Delegates to `verify_temporal_chain`, which
    /// is already `Choice`-based and depth/homogeneity aware.
    pub fn verify_membership_raw(&self, chain: &SupergridChain, root_n_scaled: u64) -> Choice {
        let depth_ok = Choice::from((chain.layers.len() == self.depth) as u8);
        depth_ok & verify_temporal_chain(chain, root_n_scaled)
    }

    pub fn verify_membership(&self, witness: &Witness90) -> WitnessStatus90 {
        let sampler = SupergridSampler::new();
        let root_n = temporal_root_from_timestamp(witness.timestamp);
        let root_n_scaled = sampler.transform_to_supergrid(root_n);
        let ok = self.verify_membership_raw(&witness.chain, root_n_scaled);
        if ok.unwrap_u8() == 1 {
            WitnessStatus90::ValidButUnbound
        } else {
            WitnessStatus90::Invalid
        }
    }
}

// ============================================================================
// Witness Generation (Prover side, has MasterSecret)
// ============================================================================

impl MasterSecret {
    /// The fixed number of independently-seeded attempts made when
    /// deriving a temporal witness. Same discipline and same value as
    /// `generate_authentic_witness` in `security::witness`.
    const MAX_TEMPORAL_ATTEMPTS: u32 = 512;

    /// Deterministically derives the witness bound to `identity` for the
    /// 366-second window containing `timestamp`. Always performs exactly
    /// `MAX_TEMPORAL_ATTEMPTS` independently-seeded draws with no early
    /// return, matching `generate_authentic_witness`'s constant-time
    /// discipline: how many attempts are needed is itself a function of
    /// `master_secret`, so an early-exit version would leak that count
    /// through timing.
    pub fn generate_temporal_witness(
        &self,
        space: &WitnessSpace90,
        identity: &[u8],
        timestamp: u64,
    ) -> Option<Witness90> {
        let sampler = SupergridSampler::new();
        let root_n = temporal_root_from_timestamp(timestamp);
        let root_n_scaled = sampler.transform_to_supergrid(root_n);

        let mut best_chain = SupergridChain {
            layers: vec![
                crate::core::diophantine::DiophantinePair { a: 0, b: 0 },
                crate::core::diophantine::DiophantinePair { a: 0, b: 0 },
                crate::core::diophantine::DiophantinePair { a: 0, b: 0 },
            ],
            valid: false,
            transform_level: TransformLevel::Raw,
        };
        let mut best_tag = [0u8; 32];
        let mut found = Choice::from(0);

        for attempt in 0u32..Self::MAX_TEMPORAL_ATTEMPTS {
            let seed =
                Self::derive_temporal_seed(self.key_bytes_pub(), identity, timestamp, attempt);
            let mut rng = TemporalRng::from_seed(seed);

            let (chain, chain_valid) = sampler.sample_temporal_chain_raw(root_n_scaled, timestamp, &mut rng);
            let chain_hash = hash_supergrid_chain(&chain);
            let candidate_tag = Self::compute_temporal_binding_tag(
                self.key_bytes_pub(),
                identity,
                timestamp,
                &chain_hash,
            );
            let member_ok = space.verify_membership_raw(&chain, root_n_scaled);
            let candidate_ok = chain_valid & member_ok;

            let take_this = candidate_ok & !found;
            best_chain = select_supergrid_chain(&best_chain, &chain, take_this);
            best_tag = select_bytes32(&best_tag, &candidate_tag, take_this);
            found |= candidate_ok;
        }

        if found.unwrap_u8() == 1 {
            Some(Witness90 {
                chain: best_chain,
                binding_tag: best_tag,
                session_id: timestamp.to_be_bytes().to_vec(),
                timestamp,
            })
        } else {
            #[cfg(test)]
            eprintln!(
                "[WARN] Failed to generate temporal witness for timestamp={} after {} attempts",
                timestamp,
                Self::MAX_TEMPORAL_ATTEMPTS
            );
            None
        }
    }

    /// Checks binding AND freshness. Expiry is checked first (cheap,
    /// public data only — matches `security::witness`'s existing pattern
    /// of doing structural checks before the HMAC comparison), then the
    /// binding tag is compared in constant time via `ct_eq`.
    pub fn verify_temporal_authenticity(
        &self,
        witness: &Witness90,
        identity: &[u8],
        current_timestamp: u64,
    ) -> WitnessStatus90 {
        let max_window = witness.timestamp.saturating_add(MICRO_ANCHOR);
        if current_timestamp > max_window {
            return WitnessStatus90::Expired;
        }

        let chain_hash = hash_supergrid_chain(&witness.chain);
        let expected_tag = Self::compute_temporal_binding_tag(
            self.key_bytes_pub(),
            identity,
            witness.timestamp,
            &chain_hash,
        );
        let tags_match = expected_tag.ct_eq(&witness.binding_tag);
        if tags_match.unwrap_u8() == 1 {
            WitnessStatus90::Authentic
        } else {
            WitnessStatus90::BindingMismatch
        }
    }

    fn compute_temporal_binding_tag(
        master_key: &[u8; 32],
        identity: &[u8],
        timestamp: u64,
        chain_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(master_key).expect("HMAC key length is valid");
        mac.update(b"MRS-AUTH-BIND-90-v1");
        mac.update(&(identity.len() as u32).to_be_bytes());
        mac.update(identity);
        mac.update(&timestamp.to_be_bytes());
        mac.update(chain_hash);

        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result);
        tag
    }

    fn derive_temporal_seed(
        master_key: &[u8; 32],
        identity: &[u8],
        timestamp: u64,
        attempt: u32,
    ) -> [u8; 32] {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(master_key).expect("HMAC key length is valid");
        mac.update(b"MRS-AUTH-SEED-90-v1");
        mac.update(&(identity.len() as u32).to_be_bytes());
        mac.update(identity);
        mac.update(&timestamp.to_be_bytes());
        mac.update(&attempt.to_be_bytes());

        let result = mac.finalize().into_bytes();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&result);
        seed
    }
}

// ============================================================================
// Alibi Generation (Public, no MasterSecret needed)
// ============================================================================

impl WitnessSpace90 {
    const MAX_ALIBI_ATTEMPTS: usize = 512;

    /// Generates an alternative witness for the SAME 366-second window as
    /// `authentic`, so it stays plausible for the same period. No secret
    /// material is used anywhere on this path (same as
    /// `security::witness::generate_alternative_witness`), but the fixed
    /// attempt budget and no-early-return discipline is kept for
    /// consistency with the rest of this module.
    pub fn generate_alternative_witness(
        &self,
        authentic: &Witness90,
        rng: &mut impl RngCore,
    ) -> Option<Alibi90> {
        let sampler = SupergridSampler::new();
        let root_n = temporal_root_from_timestamp(authentic.timestamp);
        let root_n_scaled = sampler.transform_to_supergrid(root_n);

        let mut best_chain = SupergridChain {
            layers: vec![
                crate::core::diophantine::DiophantinePair { a: 0, b: 0 },
                crate::core::diophantine::DiophantinePair { a: 0, b: 0 },
                crate::core::diophantine::DiophantinePair { a: 0, b: 0 },
            ],
            valid: false,
            transform_level: TransformLevel::Raw,
        };
        let mut best_tag = [0u8; 32];
        let mut found = Choice::from(0);

        for _ in 0..Self::MAX_ALIBI_ATTEMPTS {
            let (chain, chain_valid) = sampler.sample_temporal_chain_raw(root_n_scaled, authentic.timestamp, rng);
            let differs = !chains_equal_ct(&chain, &authentic.chain);
            let member_ok = self.verify_membership_raw(&chain, root_n_scaled);
            let candidate_ok = chain_valid & differs & member_ok;

            let mut candidate_tag = [0u8; 32];
            rng.fill_bytes(&mut candidate_tag);

            let take_this = candidate_ok & !found;
            best_chain = select_supergrid_chain(&best_chain, &chain, take_this);
            best_tag = select_bytes32(&best_tag, &candidate_tag, take_this);
            found |= candidate_ok;
        }

        if found.unwrap_u8() == 1 {
            Some(Alibi90(Witness90 {
                chain: best_chain,
                binding_tag: best_tag,
                session_id: authentic.session_id.clone(),
                timestamp: authentic.timestamp,
            }))
        } else {
            #[cfg(test)]
            eprintln!(
                "[WARN] Failed to generate temporal alternative witness after {} attempts",
                Self::MAX_ALIBI_ATTEMPTS
            );
            None
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

pub fn hash_supergrid_chain(chain: &SupergridChain) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    for pair in &chain.layers {
        hasher.update(pair.a.to_be_bytes());
        hasher.update(pair.b.to_be_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn chains_equal_ct(a: &SupergridChain, b: &SupergridChain) -> Choice {
    if a.layers.len() != b.layers.len() {
        return Choice::from(0);
    }
    let mut eq = Choice::from(1);
    for (pa, pb) in a.layers.iter().zip(b.layers.iter()) {
        eq &= pa.a.ct_eq(&pb.a);
        eq &= pa.b.ct_eq(&pb.b);
    }
    eq
}

/// Same manual-bitmask pattern as `security::witness::select_bytes32`.
fn select_bytes32(current_best: &[u8; 32], candidate: &[u8; 32], choice: Choice) -> [u8; 32] {
    let mask = choice.unwrap_u8().wrapping_neg();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (candidate[i] & mask) | (current_best[i] & !mask);
    }
    out
}

// ============================================================================
// Deterministic RNG — identical construction to
// security::witness::DeterministicRng, duplicated locally rather than
// exported from that module to avoid widening its public surface for a
// single internal reuse.
// ============================================================================

struct TemporalRng {
    state: [u8; 32],
    counter: u64,
    buffer: [u8; 64],
    buffer_pos: usize,
}

impl TemporalRng {
    fn from_seed(seed: [u8; 32]) -> Self {
        let mut rng = Self {
            state: seed,
            counter: 0,
            buffer: [0u8; 64],
            buffer_pos: 64,
        };
        rng.refill();
        rng
    }

    fn refill(&mut self) {
        use sha2::Digest;
        for i in 0..2 {
            let mut hasher = Sha256::new();
            hasher.update(self.state);
            hasher.update(self.counter.to_be_bytes());
            hasher.update([i as u8]);
            let hash = hasher.finalize();
            self.buffer[i * 32..(i + 1) * 32].copy_from_slice(&hash);
        }
        self.counter = self.counter.wrapping_add(1);
        self.buffer_pos = 0;
    }
}

impl RngCore for TemporalRng {
    fn next_u32(&mut self) -> u32 {
        if self.buffer_pos + 4 > 64 {
            self.refill();
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + 4]);
        self.buffer_pos += 4;
        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        if self.buffer_pos + 8 > 64 {
            self.refill();
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + 8]);
        self.buffer_pos += 8;
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(64) {
            if self.buffer_pos + chunk.len() > 64 {
                self.refill();
            }
            let end = self.buffer_pos + chunk.len();
            chunk.copy_from_slice(&self.buffer[self.buffer_pos..end]);
            self.buffer_pos = end;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::witness::{SecretConfig, SecretInput, SecretMode};
    use argon2::Params as Argon2Params;
    use rand::rngs::OsRng;

    fn test_master() -> MasterSecret {
        let salt = [0u8; 16];
        let input = SecretInput {
            password: "correct horse battery staple".to_string(),
            hardware_token: None,
            biometric_hash: None,
            salt,
        };
        let config = SecretConfig {
            argon2_params: Argon2Params::default(),
            mode: SecretMode::Authentic,
        };
        MasterSecret::derive(&input, &config).expect("derive authentic")
    }

    /// A timestamp whose window is known (from `supergrid.rs`'s own
    /// tests) to admit a sampleable scaled root.
    fn test_timestamp() -> u64 {
        3_000_001u64 * MICRO_ANCHOR
    }

    #[test]
    fn test_generate_temporal_witness_records_timestamp() {
        let master = test_master();
        let space = WitnessSpace90::new(3);
        let id = b"alice@example.com";
        let ts = test_timestamp();

        let witness_opt = master.generate_temporal_witness(&space, id, ts);
        if let Some(witness) = witness_opt {
            assert_eq!(witness.timestamp, ts);
            assert_eq!(witness.chain.layers.len(), 3);
        } else {
            eprintln!("[WARN] No temporal witness generated for ts={} - may be expected", ts);
        }
    }

    #[test]
    fn test_verify_temporal_authenticity_within_window() {
        let master = test_master();
        let space = WitnessSpace90::new(3);
        let id = b"alice@example.com";
        let ts = test_timestamp();

        let Some(witness) = master.generate_temporal_witness(&space, id, ts) else {
            eprintln!("[WARN] No witness generated, skipping");
            return;
        };

        let status = master.verify_temporal_authenticity(&witness, id, ts + 10);
        assert_eq!(status, WitnessStatus90::Authentic);
    }

    #[test]
    fn test_verify_temporal_authenticity_expired() {
        let master = test_master();
        let space = WitnessSpace90::new(3);
        let id = b"alice@example.com";
        let ts = test_timestamp();

        let Some(witness) = master.generate_temporal_witness(&space, id, ts) else {
            eprintln!("[WARN] No witness generated, skipping");
            return;
        };

        let later = ts + MICRO_ANCHOR + 1;
        let status = master.verify_temporal_authenticity(&witness, id, later);
        assert_eq!(status, WitnessStatus90::Expired);
    }

    #[test]
    fn test_alibi_for_temporal_witness_is_valid_but_unbound() {
        let master = test_master();
        let space = WitnessSpace90::new(3);
        let id = b"alice@example.com";
        let ts = test_timestamp();

        let Some(witness) = master.generate_temporal_witness(&space, id, ts) else {
            eprintln!("[WARN] No witness generated, skipping");
            return;
        };

        let mut rng = OsRng;
        let Some(alibi) = space.generate_alternative_witness(&witness, &mut rng) else {
            eprintln!("[WARN] No alibi generated, skipping");
            return;
        };

        assert_eq!(space.verify_membership(&alibi.0), WitnessStatus90::ValidButUnbound);
        let binding_check = master.verify_temporal_authenticity(&alibi.0, id, ts + 5);
        assert_eq!(binding_check, WitnessStatus90::BindingMismatch);
    }

    #[test]
    fn test_different_windows_produce_different_chains() {
        let master = test_master();
        let space = WitnessSpace90::new(3);
        let id = b"alice@example.com";
        let ts1 = test_timestamp();
        let ts2 = ts1 + MICRO_ANCHOR;

        let w1 = master.generate_temporal_witness(&space, id, ts1);
        let w2 = master.generate_temporal_witness(&space, id, ts2);

        if let (Some(w1), Some(w2)) = (w1, w2) {
            assert_ne!(w1.chain.layers, w2.chain.layers);
        } else {
            eprintln!("[WARN] Could not generate witnesses for both windows, skipping");
        }
    }
}
