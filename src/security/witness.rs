//! Witness Authentication & Coercion-Resistance Engine
//!
//! Core design principle:
//! The MRS Diophantine space W_N contains many valid witnesses.
//! Only one is cryptographically bound to the intended identity.
//! Under coercion, the user reveals an alternative witness w' ∈ W_N
//! that is mathematically valid but NOT bound to the identity.
//!
//! Security guarantee:
//! Without the master_secret, all witnesses in W_N are computationally
//! indistinguishable. The adversary's advantage in detecting the
//! authentic witness is negligible in the security parameter.

use crate::sampler::{sample_three_layers_ct, MrsChain};
use rand::RngCore;
use sha2::{Sha256, Digest};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};
use hmac::{Hmac, Mac};

/// Type alias for the HMAC primitive used in witness binding.
type HmacSha256 = Hmac<Sha256>;

// =============================================================================
// Data Structures
// =============================================================================

/// A witness is a mathematically valid MRS chain plus a cryptographic
/// binding tag that links it (optionally) to an identity.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Witness {
    /// The underlying MRS Diophantine chain (public or semi-public).
    pub chain: MrsChain,
    /// Cryptographic binding tag: HMAC(master_secret, identity || session || chain_hash).
    /// Empty if this is an unbound alternative witness (alibi).
    pub binding_tag: [u8; 32],
    /// Session identifier this witness was generated for.
    pub session_id: Vec<u8>,
}

/// The prover's long-term secret. From this, all per-session authentic
/// witnesses are deterministically derived.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret {
    pub key: [u8; 32],
}

/// Public parameters for a witness space W_N.
/// Anyone can verify membership of a witness in W_N using only these params.
#[derive(Debug, Clone)]
pub struct WitnessSpace {
    /// The public session root N.
    pub root_n: u64,
    /// Depth of the MRS chain (fixed at 3 in MRS-AUTH).
    pub depth: usize,
}

/// Result of a witness verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessStatus {
    /// Witness is mathematically valid in W_N but NOT bound to any identity.
    ValidButUnbound,
    /// Witness is mathematically valid AND correctly bound to the claimed identity.
    Authentic,
    /// Witness is mathematically INVALID (fails N = 19A + 9B checks).
    Invalid,
    /// Witness is mathematically valid but binding tag does NOT match.
    BindingMismatch,
}

// =============================================================================
// Master Secret & Authentic Witness Generation
// =============================================================================

impl MasterSecret {
    /// Derive a master secret from high-entropy input (e.g., OS CSPRNG or KDF output).
    pub fn from_entropy(entropy: &[u8; 32]) -> Self {
        Self { key: *entropy }
    }

    /// Deterministically derive the "intended" witness for a given identity
    /// and session. This witness is the ONE that authenticates the identity.
    ///
    /// `sample_three_layers_ct` can legitimately return `None` for a given
    /// seed even when `space.root_n` itself admits valid chains — the
    /// weighted random walk through non-final layers can dead-end. A
    /// single fixed seed gets no second chance at that point, so this
    /// folds an attempt counter into the seed derivation and retries,
    /// exactly like `generate_alternative_witness` already does — instead
    /// of silently depending on every (identity, session_id) pair happening
    /// to land on a successful draw on the very first try.
    pub fn generate_authentic_witness(
        &self,
        space: &WitnessSpace,
        identity: &[u8],
        session_id: &[u8],
    ) -> Option<Witness> {
        for attempt in 0u32..256 {
            let seed = Self::derive_seed(&self.key, identity, session_id, attempt);
            let mut rng = DeterministicRng::from_seed(seed);
            if let Some(chain) = sample_three_layers_ct(space.root_n, &mut rng) {
                let chain_hash = hash_chain(&chain);
                let binding_tag =
                    Self::compute_binding_tag(&self.key, identity, session_id, &chain_hash);
                return Some(Witness {
                    chain,
                    binding_tag,
                    session_id: session_id.to_vec(),
                });
            }
        }
        None
    }

    /// Under coercion: generate an alternative witness w' ∈ W_N that is
    /// mathematically valid but NOT bound to the identity.
    pub fn generate_alternative_witness(
        &self,
        space: &WitnessSpace,
        authentic: &Witness,
        rng: &mut impl RngCore,
    ) -> Option<Witness> {
        for _ in 0..256 {
            if let Some(chain) = sample_three_layers_ct(space.root_n, rng) {
                let same = chains_equal_ct(&chain, &authentic.chain);
                if same.unwrap_u8() == 0 {
                    return Some(Witness {
                        chain,
                        binding_tag: [0u8; 32],
                        session_id: authentic.session_id.clone(),
                    });
                }
            }
        }
        None
    }

    /// Compute binding tag: HMAC(master_secret, "MRS-AUTH-BIND" || identity || session_id || chain_hash)
    fn compute_binding_tag(
        master_key: &[u8; 32],
        identity: &[u8],
        session_id: &[u8],
        chain_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(master_key)
            .expect("HMAC key length is valid");
        mac.update(b"MRS-AUTH-BIND-v1");
        mac.update(identity);
        mac.update(session_id);
        mac.update(chain_hash);
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result);
        tag
    }

    /// Derive a deterministic 32-byte seed from master_secret + context +
    /// attempt number. Folding `attempt` in lets `generate_authentic_witness`
    /// retry with a fresh, still-fully-deterministic seed if a given
    /// attempt's sample turns out invalid, without ever touching real
    /// randomness for the "authentic" path.
    fn derive_seed(master_key: &[u8; 32], identity: &[u8], session_id: &[u8], attempt: u32) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(master_key)
            .expect("HMAC key length is valid");
        mac.update(b"MRS-AUTH-SEED-v1");
        mac.update(identity);
        mac.update(session_id);
        mac.update(&attempt.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&result);
        seed
    }
}

// =============================================================================
// Public Verification (Verifier side — does NOT have master_secret)
// =============================================================================

impl WitnessSpace {
    pub fn new(root_n: u64, depth: usize) -> Self {
        Self { root_n, depth }
    }

    /// Verify whether a witness is a mathematically valid member of W_N.
    /// This is a PUBLIC operation — anyone can run it.
    pub fn verify_membership(&self, witness: &Witness) -> WitnessStatus {
        let chain = &witness.chain;
        if chain.layers.len() != self.depth {
            return WitnessStatus::Invalid;
        }

        let mut current_n = self.root_n;
        for pair in &chain.layers {
            let lhs = 19u64.wrapping_mul(pair.a).wrapping_add(9u64.wrapping_mul(pair.b));
            if lhs != current_n {
                return WitnessStatus::Invalid;
            }
            if pair.a == 0 && pair.b == 0 && current_n > 0 {
                return WitnessStatus::Invalid;
            }
            current_n = pair.a;
        }

        WitnessStatus::ValidButUnbound
    }
}

/// Verify the cryptographic binding of a witness to an identity.
/// This REQUIRES the master_secret and is run by the legitimate verifier.
pub fn verify_witness_authenticity(
    master_secret: &MasterSecret,
    witness: &Witness,
    identity: &[u8],
) -> WitnessStatus {
    let chain_hash = hash_chain(&witness.chain);
    let expected_tag = MasterSecret::compute_binding_tag(
        &master_secret.key,
        identity,
        &witness.session_id,
        &chain_hash,
    );

    let tags_match = expected_tag.ct_eq(&witness.binding_tag);

    if tags_match.unwrap_u8() == 1 {
        WitnessStatus::Authentic
    } else {
        WitnessStatus::BindingMismatch
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// SHA-256 hash of an MRS chain.
pub fn hash_chain(chain: &MrsChain) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for pair in &chain.layers {
        hasher.update(&pair.a.to_be_bytes());
        hasher.update(&pair.b.to_be_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Constant-time equality check for two MrsChain structures.
fn chains_equal_ct(a: &MrsChain, b: &MrsChain) -> Choice {
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

// =============================================================================
// Deterministic RNG for reproducible authentic witness derivation
// =============================================================================

struct DeterministicRng {
    state: [u8; 32],
    counter: u64,
    buffer: [u8; 64],
    buffer_pos: usize,
}

impl DeterministicRng {
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
        for i in 0..2 {
            let mut hasher = Sha256::new();
            hasher.update(&self.state);
            hasher.update(&self.counter.to_be_bytes());
            hasher.update(&[i as u8]);
            let hash = hasher.finalize();
            self.buffer[i * 32..(i + 1) * 32].copy_from_slice(&hash);
        }
        self.counter = self.counter.wrapping_add(1);
        self.buffer_pos = 0;
    }
}

impl RngCore for DeterministicRng {
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::diophantine::DiophantinePair;
    use rand::rngs::OsRng;

    #[test]
    fn test_authentic_witness_reproducible() {
        let master = MasterSecret::from_entropy(&[42u8; 32]);
        let space = WitnessSpace::new(3_000_001, 3);
        let id = b"alice@example.com";
        let session = b"session-2026-08-28";

        let w1 = master.generate_authentic_witness(&space, id, session).unwrap();
        let w2 = master.generate_authentic_witness(&space, id, session).unwrap();

        assert!(chains_equal_ct(&w1.chain, &w2.chain).unwrap_u8() == 1);
        assert_eq!(w1.binding_tag, w2.binding_tag);
    }

    #[test]
    fn test_authentic_witness_different_sessions() {
        let master = MasterSecret::from_entropy(&[42u8; 32]);
        let space = WitnessSpace::new(3_000_001, 3);
        let id = b"alice@example.com";

        let w1 = master.generate_authentic_witness(&space, id, b"sess-1").unwrap();
        let w2 = master.generate_authentic_witness(&space, id, b"sess-2").unwrap();

        assert!(chains_equal_ct(&w1.chain, &w2.chain).unwrap_u8() == 0);
    }

    #[test]
    fn test_alternative_witness_differs_from_authentic() {
        let master = MasterSecret::from_entropy(&[42u8; 32]);
        let space = WitnessSpace::new(3_000_001, 3);
        let id = b"alice@example.com";
        let session = b"session-2026-08-28";

        let authentic = master.generate_authentic_witness(&space, id, session).unwrap();
        let mut rng = OsRng;
        let alibi = master.generate_alternative_witness(&space, &authentic, &mut rng).unwrap();

        assert!(chains_equal_ct(&authentic.chain, &alibi.chain).unwrap_u8() == 0);
        assert_eq!(alibi.binding_tag, [0u8; 32]);
    }

    #[test]
    fn test_membership_verification_valid() {
        let master = MasterSecret::from_entropy(&[42u8; 32]);
        let space = WitnessSpace::new(3_000_001, 3);
        let id = b"alice@example.com";
        let session = b"session-2026-08-28";

        let authentic = master.generate_authentic_witness(&space, id, session).unwrap();
        let status = space.verify_membership(&authentic);

        assert_eq!(status, WitnessStatus::ValidButUnbound);
    }

    #[test]
    fn test_membership_verification_invalid() {
        let space = WitnessSpace::new(3_000_001, 3);
        let fake_witness = Witness {
            chain: MrsChain {
                layers: vec![
                    DiophantinePair { a: 1, b: 1 },
                    DiophantinePair { a: 1, b: 1 },
                    DiophantinePair { a: 1, b: 1 },
                ],
                valid: true,
            },
            binding_tag: [0u8; 32],
            session_id: b"test".to_vec(),
        };

        let status = space.verify_membership(&fake_witness);
        assert_eq!(status, WitnessStatus::Invalid);
    }

    #[test]
    fn test_binding_authenticity_success() {
        let master = MasterSecret::from_entropy(&[42u8; 32]);
        let space = WitnessSpace::new(3_000_001, 3);
        let id = b"alice@example.com";
        let session = b"session-2026-08-28";

        let authentic = master.generate_authentic_witness(&space, id, session).unwrap();
        let status = verify_witness_authenticity(&master, &authentic, id);

        assert_eq!(status, WitnessStatus::Authentic);
    }

    #[test]
    fn test_binding_authenticity_wrong_identity() {
        let master = MasterSecret::from_entropy(&[42u8; 32]);
        let space = WitnessSpace::new(3_000_001, 3);
        let id = b"alice@example.com";
        let session = b"session-2026-08-28";

        let authentic = master.generate_authentic_witness(&space, id, session).unwrap();
        let status = verify_witness_authenticity(&master, &authentic, b"eve@evil.com");

        assert_eq!(status, WitnessStatus::BindingMismatch);
    }

    #[test]
    fn test_alibi_passes_membership() {
        let master = MasterSecret::from_entropy(&[42u8; 32]);
        let space = WitnessSpace::new(3_000_001, 3);
        let id = b"alice@example.com";
        let session = b"session-2026-08-28";

        let authentic = master.generate_authentic_witness(&space, id, session).unwrap();
        let mut rng = OsRng;
        let alibi = master.generate_alternative_witness(&space, &authentic, &mut rng).unwrap();

        let status = space.verify_membership(&alibi);
        assert_eq!(status, WitnessStatus::ValidButUnbound);

        let binding_check = verify_witness_authenticity(&master, &alibi, id);
        assert_eq!(binding_check, WitnessStatus::BindingMismatch);
    }

    #[test]
    fn test_coercion_resistance_indistinguishability() {
        let master = MasterSecret::from_entropy(&[42u8; 32]);
        let space = WitnessSpace::new(10_000_001, 3);
        let id = b"alice@example.com";

        let mut authentic_a_sums = Vec::new();
        let mut alibi_a_sums = Vec::new();
        let mut rng = OsRng;

        // 100 sessions is too small a sample for a 5% threshold on a sum
        // of three weighted draws — sampling noise alone can exceed 5%.
        // 2000 keeps runtime under a second while making the test
        // actually discriminate a real bias from statistical noise.
        for i in 0..2000 {
            let session = format!("sess-{}", i);
            let auth = master.generate_authentic_witness(&space, id, session.as_bytes()).unwrap();
            let alibi = master.generate_alternative_witness(&space, &auth, &mut rng).unwrap();

            let auth_sum: u64 = auth.chain.layers.iter().map(|p| p.a).sum();
            let alibi_sum: u64 = alibi.chain.layers.iter().map(|p| p.a).sum();

            authentic_a_sums.push(auth_sum);
            alibi_a_sums.push(alibi_sum);
        }

        let auth_mean = authentic_a_sums.iter().sum::<u64>() as f64 / authentic_a_sums.len() as f64;
        let alibi_mean = alibi_a_sums.iter().sum::<u64>() as f64 / alibi_a_sums.len() as f64;
        let diff_pct = (auth_mean - alibi_mean).abs() / auth_mean;

        assert!(
            diff_pct < 0.05,
            "Authentic and alibi witnesses are statistically distinguishable: {} vs {}",
            auth_mean, alibi_mean
        );
    }
        }
    
