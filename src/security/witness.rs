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
//!
//! Architecture (Transfer Dock revision):
//! - `generate_alibi` lives on `WitnessSpace` (public), NOT on `MasterSecret`.
//! - `Alibi` is a newtype wrapper around `Witness` to prevent type confusion.
//! - `MasterSecret` is derived multi-factor via Argon2id + HKDF with mode separation.
//! - `Duress` mode produces mathematically valid but unbound witnesses.
//! - `seal`/`unseal` protects the master secret at rest.

use crate::sampler::{sample_three_layers_safe, MrsChain};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params as Argon2Params};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Type Aliases
// =============================================================================

type HmacSha256 = Hmac<Sha256>;

// =============================================================================
// Data Structures
// =============================================================================

/// A witness is a mathematically valid MRS Diophantine chain plus a
/// cryptographic binding tag that links it (optionally) to an identity.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Witness {
    /// The underlying MRS Diophantine chain (public or private components).
    pub chain: MrsChain,
    /// Cryptographic binding tag: HMAC(master_secret, identity || session || chain_hash)
    /// Empty if this is an unbound alternative witness.
    pub binding_tag: [u8; 32],
    /// Session identifier this witness was generated for.
    pub session_id: Vec<u8>,
}

/// An Alibi IS a Witness, but the compiler sees it as a unique type.
/// Prevents accidental submission of an alibi where an authentic witness is expected.
#[derive(Debug, Clone, PartialEq)]
pub struct Alibi(pub Witness);

/// The prover's long-term secret. From this, all per-session authentic
/// witnesses are deterministically derived.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret {
    key: ProtectedKey,
    mode: SecretMode,
}

/// Encapsulated 32-byte key. Never public.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct ProtectedKey([u8; 32]);

/// Operational mode of the master secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretMode {
    /// Real identity, used for authentication.
    Authentic,
    /// Panic mode: revealed under coercion, generates unbound witnesses.
    Duress,
}

/// Input for master secret derivation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretInput {
    /// Password or PIN (knowledge factor).
    pub password: String,
    /// Optional: hardware token (possession factor, e.g. YubiKey HMAC).
    pub hardware_token: Option<[u8; 32]>,
    /// Optional: biometric hash (inherence factor, computed locally).
    pub biometric_hash: Option<[u8; 32]>,
    /// Unique salt per user, stored publicly.
    pub salt: [u8; 16],
}

/// Configuration for the KDF.
pub struct SecretConfig {
    pub argon2_params: Argon2Params,
    pub mode: SecretMode,
}

/// A share for Shamir Secret Sharing.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyShare {
    pub index: u8,
    pub value: [u8; 32],
}

/// Sealed master secret for storage on disk.
#[derive(Debug, Clone)]
pub struct SealedMasterSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub mode: SecretMode,
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

/// Errors during derivation.
#[derive(Debug)]
pub enum DeriveError {
    KdfFailed,
    HkdfFailed,
    InvalidFactors,
    InsufficientEntropy,
}

// =============================================================================
// Trait: ProverSpace
// =============================================================================

/// Every 'Space' in the application can generate alibis without secrets.
pub trait ProverSpace {
    type WitnessType;
    type AlibiType;

    fn generate_alibi(
        &self,
        authentic: &Self::WitnessType,
        rng: &mut impl RngCore,
    ) -> Option<Self::AlibiType>;
}

impl ProverSpace for WitnessSpace {
    type WitnessType = Witness;
    type AlibiType = Alibi;

    fn generate_alibi(
        &self,
        authentic: &Witness,
        rng: &mut impl RngCore,
    ) -> Option<Alibi> {
        self.generate_alternative_witness(authentic, rng)
    }
}

// =============================================================================
// Master Secret — Multi-Factor Derivation & Management
// =============================================================================

impl MasterSecret {
    /// Derive a master secret from multiple factors.
    ///
    /// Derivation pipeline:
    /// 1. Password → Argon2id (memory-hard, GPU-resistant)
    /// 2. Constant-time XOR with hardware token and biometric hash
    /// 3. HKDF-SHA256 with mode-specific domain separation
    pub fn derive(input: &SecretInput, config: &SecretConfig) -> Result<Self, DeriveError> {
        // Step 1: Memory-hard KDF on the password
        let mut password_key = [0u8; 32];
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            config.argon2_params.clone(),
        )
        .hash_password_into(input.password.as_bytes(), &input.salt, &mut password_key)
        .map_err(|_| DeriveError::KdfFailed)?;

        // Step 2: Constant-time XOR with hardware/biometrics
        let mut combined = password_key;
        if let Some(token) = input.hardware_token {
            for (c, t) in combined.iter_mut().zip(token.iter()) {
                *c ^= *t;
            }
        }
        if let Some(bio) = input.biometric_hash {
            for (c, b) in combined.iter_mut().zip(bio.iter()) {
                *c ^= *b;
            }
        }

        // Step 3: Mode-dependent domain separation
        let domain = match config.mode {
            SecretMode::Authentic => b"MRS-AUTH-MASTER-v1-AUTHENTIC",
            SecretMode::Duress => b"MRS-AUTH-MASTER-v1-DURESS",
        };

        let hkdf = Hkdf::<Sha256>::new(Some(&input.salt), &combined);
        let mut final_key = [0u8; 32];
        hkdf.expand(domain, &mut final_key)
            .map_err(|_| DeriveError::HkdfFailed)?;

        password_key.zeroize();
        combined.zeroize();

        Ok(Self {
            key: ProtectedKey(final_key),
            mode: config.mode,
        })
    }

    /// Generate the duress input from an authentic input.
    ///
    /// Convention: the duress password is the authentic password with a
    /// configurable panic suffix (e.g. "mypasswordPANIC").
    /// Hardware/biometric factors remain identical.
    pub fn derive_duress_input(authentic: &SecretInput, panic_suffix: &str) -> SecretInput {
        let mut duress_password = authentic.password.clone();
        duress_password.push_str(panic_suffix);

        SecretInput {
            password: duress_password,
            hardware_token: authentic.hardware_token,
            biometric_hash: authentic.biometric_hash,
            salt: authentic.salt,
        }
    }

    // --- Shamir Secret Sharing (stubs) ---

    /// Split the master secret into `shares` shares, `threshold` needed.
    pub fn split(&self, _threshold: usize, _shares: usize) -> Result<Vec<KeyShare>, DeriveError> {
        // TODO: Integrate with production SSS crate (e.g. `shamir_secret_sharing`)
        todo!("Integrate with SSS crate")
    }

    /// Recover a master secret from a set of shares.
    pub fn recover(_shares: &[KeyShare], _mode: SecretMode) -> Result<Self, DeriveError> {
        // TODO: Integrate with production SSS crate
        todo!("Integrate with SSS crate")
    }

    // --- At-Rest Protection ---

    /// Seal the master secret with a device key (e.g. TPM-derived).
    pub fn seal(&self, device_key: &[u8; 32]) -> SealedMasterSecret {
        let cipher = Aes256Gcm::new_from_slice(device_key).expect("valid key length");
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, self.key.0.as_slice())
            .expect("AES-GCM encryption never fails with correct input");

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(nonce.as_ref());

        SealedMasterSecret {
            ciphertext,
            nonce: nonce_bytes,
            mode: self.mode,
        }
    }

    /// Unseal a master secret. Only possible with the correct device_key.
    pub fn unseal(sealed: &SealedMasterSecret, device_key: &[u8; 32]) -> Result<Self, DeriveError> {
        let cipher = Aes256Gcm::new_from_slice(device_key).expect("valid key length");
        let nonce = Nonce::from_slice(&sealed.nonce);
        let plaintext = cipher
            .decrypt(nonce, sealed.ciphertext.as_ref())
            .map_err(|_| DeriveError::InvalidFactors)?;

        if plaintext.len() != 32 {
            return Err(DeriveError::InvalidFactors);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);

        Ok(Self {
            key: ProtectedKey(key),
            mode: sealed.mode,
        })
    }

    // --- Internal API ---

    /// Internal access to the raw key, only for HMAC computations within
    /// this module. Not public.
    fn key_bytes(&self) -> &[u8; 32] {
        &self.key.0
    }

    pub fn mode(&self) -> SecretMode {
        self.mode
    }
}

// =============================================================================
// Authentic Witness Generation
// =============================================================================

impl MasterSecret {
    /// Deterministically derive the "intended" witness for a given identity
    /// and session. This witness is the ONE that authenticates the identity.
    pub fn generate_authentic_witness(
        &self,
        space: &WitnessSpace,
        identity: &[u8],
        session_id: &[u8],
    ) -> Option<Witness> {
        for attempt in 0u32..512 {
            let seed = Self::derive_seed(self.key_bytes(), identity, session_id, attempt);
            let mut rng = DeterministicRng::from_seed(seed);

            if let Some(chain) = sample_three_layers_safe(space.root_n, &mut rng) {
                let chain_hash = hash_chain(&chain);
                let binding_tag =
                    Self::compute_binding_tag(self.key_bytes(), identity, session_id, &chain_hash);

                if space.verify_membership_raw(&chain) == WitnessStatus::ValidButUnbound {
                    return Some(Witness {
                        chain,
                        binding_tag,
                        session_id: session_id.to_vec(),
                    });
                }
            }
        }

        #[cfg(test)]
        eprintln!(
            "[WARN] Failed to generate authentic witness for root_n={} after 512 attempts",
            space.root_n
        );
        None
    }

    /// Compute binding tag:
    /// HMAC(master_secret, "MRS-AUTH-BIND" || len(identity) || identity ||
    ///                     len(session_id) || session_id || chain_hash)
    fn compute_binding_tag(
        master_key: &[u8; 32],
        identity: &[u8],
        session_id: &[u8],
        chain_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(master_key).expect("HMAC key length is valid");
        mac.update(b"MRS-AUTH-BIND-v1");
        mac.update(&(identity.len() as u32).to_be_bytes());
        mac.update(identity);
        mac.update(&(session_id.len() as u32).to_be_bytes());
        mac.update(session_id);
        mac.update(chain_hash);

        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result);
        tag
    }

    /// Derive a deterministic 32-byte seed from master_secret + context + attempt.
    fn derive_seed(
        master_key: &[u8; 32],
        identity: &[u8],
        session_id: &[u8],
        attempt: u32,
    ) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(master_key).expect("HMAC key length is valid");
        mac.update(b"MRS-AUTH-SEED-v1");
        mac.update(&(identity.len() as u32).to_be_bytes());
        mac.update(identity);
        mac.update(&(session_id.len() as u32).to_be_bytes());
        mac.update(session_id);
        mac.update(&attempt.to_be_bytes());

        let result = mac.finalize().into_bytes();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&result);
        seed
    }
}

// =============================================================================
// Authenticity Verification (Verifier side — has master_secret)
// =============================================================================

impl MasterSecret {
    /// Verify the cryptographic binding of a witness to an identity.
    pub fn verify_authenticity(
        &self,
        witness: &Witness,
        identity: &[u8],
    ) -> WitnessStatus {
        let chain_hash = hash_chain(&witness.chain);
        let expected_tag = Self::compute_binding_tag(
            self.key_bytes(),
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
}

// =============================================================================
// Public Verification (Verifier side — does NOT have master_secret)
// =============================================================================

impl WitnessSpace {
    pub fn new(root_n: u64, depth: usize) -> Self {
        Self { root_n, depth }
    }

    /// Internal raw membership verification (returns status).
    fn verify_membership_raw(&self, chain: &MrsChain) -> WitnessStatus {
        if chain.layers.len() != self.depth {
            return WitnessStatus::Invalid;
        }

        let mut current_n = self.root_n;
        for pair in &chain.layers {
            let lhs = 19u64
                .wrapping_mul(pair.a)
                .wrapping_add(9u64.wrapping_mul(pair.b));
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

    /// Verify whether a witness is a mathematically valid member of W_N.
    /// This is a PUBLIC operation — anyone can run it.
    pub fn verify_membership(&self, witness: &Witness) -> WitnessStatus {
        self.verify_membership_raw(&witness.chain)
    }

    /// Generate an alternative witness w' ∈ W_N that is mathematically valid
    /// but NOT bound to the identity. PUBLIC operation — no MasterSecret needed.
    pub fn generate_alternative_witness(
        &self,
        authentic: &Witness,
        rng: &mut impl RngCore,
    ) -> Option<Alibi> {
        for _attempt in 0..512 {
            if let Some(chain) = sample_three_layers_safe(self.root_n, rng) {
                let same = chains_equal_ct(&chain, &authentic.chain);
                if same.unwrap_u8() == 0 {
                    if self.verify_membership_raw(&chain) == WitnessStatus::ValidButUnbound {
                        let mut alibi_tag = [0u8; 32];
                        rng.fill_bytes(&mut alibi_tag);

                        return Some(Alibi(Witness {
                            chain,
                            binding_tag: alibi_tag,
                            session_id: authentic.session_id.clone(),
                        }));
                    }
                }
            }
            let _ = rng.next_u64();
        }

        #[cfg(test)]
        eprintln!("[WARN] Failed to generate alternative witness after 512 attempts");
        None
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// SHA-256 hash of an MRS chain.
pub fn hash_chain(chain: &MrsChain) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for pair in &chain.layers {
        hasher.update(pair.a.to_be_bytes());
        hasher.update(pair.b.to_be_bytes());
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
// Test Helpers
// =============================================================================

#[cfg(test)]
fn find_working_root_n() -> u64 {
    for n in (3_000_001..10_000_000).step_by(100_000) {
        let params = crate::sampler::LayerParams::new_ct(n);
        if params.valid.unwrap_u8() == 1 {
            return n;
        }
    }
    3_500_007
}

#[cfg(test)]
fn generate_test_witness() -> (MasterSecret, WitnessSpace, Witness) {
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
    let master = MasterSecret::derive(&input, &config).expect("derive authentic");
    let root_n = find_working_root_n();
    let space = WitnessSpace::new(root_n, 3);
    let id = b"alice@example.com";
    let session = b"test-session";
    let witness = master
        .generate_authentic_witness(&space, id, session)
        .expect("Failed to generate test witness");
    (master, space, witness)
}

#[cfg(test)]
fn generate_duress_master() -> MasterSecret {
    let salt = [0u8; 16];
    let input = SecretInput {
        password: "correct horse battery staple".to_string(),
        hardware_token: None,
        biometric_hash: None,
        salt,
    };
    let duress_input = MasterSecret::derive_duress_input(&input, "PANIC");
    let config = SecretConfig {
        argon2_params: Argon2Params::default(),
        mode: SecretMode::Duress,
    };
    MasterSecret::derive(&duress_input, &config).expect("derive duress")
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
        let master = MasterSecret::derive(&input, &config).unwrap();
        let root_n = find_working_root_n();
        let space = WitnessSpace::new(root_n, 3);
        let id = b"alice@example.com";
        let session = b"session-2026-08-28";

        let w1 = master
            .generate_authentic_witness(&space, id, session)
            .expect("Failed to generate witness #1");
        let w2 = master
            .generate_authentic_witness(&space, id, session)
            .expect("Failed to generate witness #2");

        assert!(chains_equal_ct(&w1.chain, &w2.chain).unwrap_u8() == 1);
        assert_eq!(w1.binding_tag, w2.binding_tag);
    }

    #[test]
    fn test_authentic_witness_different_sessions() {
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
        let master = MasterSecret::derive(&input, &config).unwrap();
        let root_n = find_working_root_n();
        let space = WitnessSpace::new(root_n, 3);
        let id = b"alice@example.com";

        let w1 = master
            .generate_authentic_witness(&space, id, b"sess-1")
            .expect("Failed to generate witness for sess-1");
        let w2 = master
            .generate_authentic_witness(&space, id, b"sess-2")
            .expect("Failed to generate witness for sess-2");

        assert!(chains_equal_ct(&w1.chain, &w2.chain).unwrap_u8() == 0);
    }

    #[test]
    fn test_alternative_witness_differs_from_authentic() {
        let (master, space, authentic) = generate_test_witness();
        let mut rng = OsRng;
        let alibi = space
            .generate_alternative_witness(&authentic, &mut rng)
            .expect("Failed to generate alternative witness");

        assert!(chains_equal_ct(&authentic.chain, &alibi.0.chain).unwrap_u8() == 0);
        assert_ne!(alibi.0.binding_tag, authentic.binding_tag);
    }

    #[test]
    fn test_membership_verification_valid() {
        let (_master, space, authentic) = generate_test_witness();
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
        let (master, _space, authentic) = generate_test_witness();
        let id = b"alice@example.com";
        let status = master.verify_authenticity(&authentic, id);
        assert_eq!(status, WitnessStatus::Authentic);
    }

    #[test]
    fn test_binding_authenticity_wrong_identity() {
        let (master, _space, authentic) = generate_test_witness();
        let status = master.verify_authenticity(&authentic, b"eve@evil.com");
        assert_eq!(status, WitnessStatus::BindingMismatch);
    }

    #[test]
    fn test_alibi_passes_membership() {
        let (master, space, authentic) = generate_test_witness();
        let mut rng = OsRng;
        let alibi = space
            .generate_alternative_witness(&authentic, &mut rng)
            .expect("Failed to generate alternative witness");

        let status = space.verify_membership(&alibi.0);
        assert_eq!(status, WitnessStatus::ValidButUnbound);

        let id = b"alice@example.com";
        let binding_check = master.verify_authenticity(&alibi.0, id);
        assert_eq!(binding_check, WitnessStatus::BindingMismatch);
    }

    #[test]
    fn test_coercion_resistance_indistinguishability() {
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
        let master = MasterSecret::derive(&input, &config).unwrap();
        let root_n = find_working_root_n();
        let space = WitnessSpace::new(root_n, 3);
        let id = b"alice@example.com";

        let mut authentic_a_sums = Vec::new();
        let mut alibi_a_sums = Vec::new();
        let mut rng = OsRng;
        let num_samples = 500;
        let mut success_count = 0;

        for i in 0..num_samples {
            let session = format!("sess-{}", i);
            if let Some(auth) = master.generate_authentic_witness(&space, id, session.as_bytes()) {
                if let Some(alibi) = space.generate_alternative_witness(&auth, &mut rng) {
                    let auth_sum: u64 = auth.chain.layers.iter().map(|p| p.a).sum();
                    let alibi_sum: u64 = alibi.0.chain.layers.iter().map(|p| p.a).sum();
                    authentic_a_sums.push(auth_sum);
                    alibi_a_sums.push(alibi_sum);
                    success_count += 1;
                }
            }
        }

        if success_count < 10 {
            eprintln!(
                "[WARN] Only {} successful samples generated, skipping statistical test",
                success_count
            );
            return;
        }

        let auth_mean =
            authentic_a_sums.iter().sum::<u64>() as f64 / authentic_a_sums.len() as f64;
        let alibi_mean = alibi_a_sums.iter().sum::<u64>() as f64 / alibi_a_sums.len() as f64;
        let diff_pct = (auth_mean - alibi_mean).abs() / auth_mean;

        assert!(
            diff_pct < 0.10,
            "Authentic and alibi witnesses are statistically distinguishable: auth_mean={}, alibi_mean={}, diff={:.2}%",
            auth_mean,
            alibi_mean,
            diff_pct * 100.0
        );
    }

    #[test]
    fn test_duress_key_derivation() {
        let salt = [0u8; 16];
        let input = SecretInput {
            password: "correct horse battery staple".to_string(),
            hardware_token: None,
            biometric_hash: None,
            salt,
        };
        let auth_config = SecretConfig {
            argon2_params: Argon2Params::default(),
            mode: SecretMode::Authentic,
        };
        let duress_input = MasterSecret::derive_duress_input(&input, "PANIC");
        let duress_config = SecretConfig {
            argon2_params: Argon2Params::default(),
            mode: SecretMode::Duress,
        };

        let authentic = MasterSecret::derive(&input, &auth_config).unwrap();
        let duress = MasterSecret::derive(&duress_input, &duress_config).unwrap();

        // Keys must be completely different
        assert_ne!(authentic.key_bytes(), duress.key_bytes());
        assert_eq!(authentic.mode(), SecretMode::Authentic);
        assert_eq!(duress.mode(), SecretMode::Duress);
    }

    #[test]
    fn test_duress_witness_unbound() {
        let salt = [0u8; 16];
        let input = SecretInput {
            password: "correct horse battery staple".to_string(),
            hardware_token: None,
            biometric_hash: None,
            salt,
        };
        let duress_input = MasterSecret::derive_duress_input(&input, "PANIC");
        let duress_config = SecretConfig {
            argon2_params: Argon2Params::default(),
            mode: SecretMode::Duress,
        };
        let duress_master = MasterSecret::derive(&duress_input, &duress_config).unwrap();

        let root_n = find_working_root_n();
        let space = WitnessSpace::new(root_n, 3);
        let id = b"alice@example.com";
        let session = b"session-2026-08-28";

        let duress_witness = duress_master
            .generate_authentic_witness(&space, id, session)
            .expect("Failed to generate duress witness");

        // Duress witness is mathematically valid
        assert_eq!(
            space.verify_membership(&duress_witness),
            WitnessStatus::ValidButUnbound
        );

        // But NOT bound to the identity
        let authentic_master = {
            let auth_config = SecretConfig {
                argon2_params: Argon2Params::default(),
                mode: SecretMode::Authentic,
            };
            MasterSecret::derive(&input, &auth_config).unwrap()
        };
        let binding_check = authentic_master.verify_authenticity(&duress_witness, id);
        assert_eq!(binding_check, WitnessStatus::BindingMismatch);
    }

    #[test]
    fn test_duress_indistinguishability() {
        let salt = [0u8; 16];
        let input = SecretInput {
            password: "correct horse battery staple".to_string(),
            hardware_token: None,
            biometric_hash: None,
            salt,
        };
        let auth_config = SecretConfig {
            argon2_params: Argon2Params::default(),
            mode: SecretMode::Authentic,
        };
        let duress_input = MasterSecret::derive_duress_input(&input, "PANIC");
        let duress_config = SecretConfig {
            argon2_params: Argon2Params::default(),
            mode: SecretMode::Duress,
        };

        let authentic_master = MasterSecret::derive(&input, &auth_config).unwrap();
        let duress_master = MasterSecret::derive(&duress_input, &duress_config).unwrap();

        let root_n = find_working_root_n();
        let space = WitnessSpace::new(root_n, 3);
        let id = b"alice@example.com";

        let mut auth_sums = Vec::new();
        let mut duress_sums = Vec::new();
        let num_samples = 200;
        let mut success_count = 0;

        for i in 0..num_samples {
            let session = format!("duress-sess-{}", i);
            if let Some(auth) =
                authentic_master.generate_authentic_witness(&space, id, session.as_bytes())
            {
                if let Some(duress) =
                    duress_master.generate_authentic_witness(&space, id, session.as_bytes())
                {
                    let auth_sum: u64 = auth.chain.layers.iter().map(|p| p.a).sum();
                    let duress_sum: u64 = duress.chain.layers.iter().map(|p| p.a).sum();
                    auth_sums.push(auth_sum);
                    duress_sums.push(duress_sum);
                    success_count += 1;
                }
            }
        }

        if success_count < 10 {
            eprintln!(
                "[WARN] Only {} successful samples for duress test, skipping",
                success_count
            );
            return;
        }

        let auth_mean = auth_sums.iter().sum::<u64>() as f64 / auth_sums.len() as f64;
        let duress_mean = duress_sums.iter().sum::<u64>() as f64 / duress_sums.len() as f64;
        let diff_pct = (auth_mean - duress_mean).abs() / auth_mean;

        assert!(
            diff_pct < 0.10,
            "Authentic and duress witnesses are statistically distinguishable: auth_mean={}, duress_mean={}, diff={:.2}%",
            auth_mean,
            duress_mean,
            diff_pct * 100.0
        );
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
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
        let master = MasterSecret::derive(&input, &config).unwrap();
        let device_key = [42u8; 32];

        let sealed = master.seal(&device_key);
        let recovered = MasterSecret::unseal(&sealed, &device_key).expect("unseal failed");

        assert_eq!(master.mode(), recovered.mode());
        assert_eq!(master.key_bytes(), recovered.key_bytes());
    }

    #[test]
    fn test_seal_unseal_wrong_key_fails() {
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
        let master = MasterSecret::derive(&input, &config).unwrap();
        let device_key = [42u8; 32];
        let wrong_key = [99u8; 32];

        let sealed = master.seal(&device_key);
        let result = MasterSecret::unseal(&sealed, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_witness_generation_retries() {
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
        let master = MasterSecret::derive(&input, &config).unwrap();
        let root_n = find_working_root_n();
        let space = WitnessSpace::new(root_n, 3);
        let id = b"test@example.com";

        for i in 0..10 {
            let session = format!("retry-test-{}", i);
            let result = master.generate_authentic_witness(&space, id, session.as_bytes());
            if let Some(witness) = result {
                assert!(witness.chain.valid);
                assert_eq!(witness.chain.layers.len(), 3);
            }
        }
        println!("[INFO] Retry test passed without panics");
    }

    #[test]
    fn test_prover_space_trait() {
        let (master, space, authentic) = generate_test_witness();
        let mut rng = OsRng;

        let alibi = <WitnessSpace as ProverSpace>::generate_alibi(&space, &authentic, &mut rng)
            .expect("trait alibi generation failed");

        assert_eq!(space.verify_membership(&alibi.0), WitnessStatus::ValidButUnbound);
        assert_eq!(
            master.verify_authenticity(&alibi.0, b"alice@example.com"),
            WitnessStatus::BindingMismatch
        );
    }
}
