//! Top-level framework that ties Kyber1024, the MRS(19,9) Diophantine
//! sampler, and the AES-256-GCM hybrid coupling together into the
//! single `keygen` / `full_encrypt` / `full_decrypt` API described in
//! README.md.
//!
//! # Design note: why the chain travels with the ciphertext
//!
//! [`crate::sampler::sample_three_layers`] draws its authentic chain
//! uniformly at random (via `OsRng`) from the Diophantine forest, as
//! required by the Forest Symmetry Theorem for deniability. That
//! randomness means the receiver cannot regenerate the identical chain
//! from `session_id` alone -- so the chain that was actually used for
//! this message must travel alongside the ciphertext. It is not
//! secret: deniability comes from every chain in the forest being
//! structurally indistinguishable, not from hiding which one was used
//! (see the Diophantine Deniability paper, section 3). This is why
//! [`SecureEnvelope`] carries `mrs_chain` in the clear, next to the
//! Kyber ciphertext and the AES-GCM payload.

use pqc_kyber::{decapsulate, encapsulate, keypair, KyberError};
use rand::thread_rng;

use crate::crypto::{
    decrypt_payload_hybrid, derive_hybrid_key, encrypt_payload_hybrid, HybridCiphertextPacket,
};
use crate::sampler::{sample_three_layers, MrsChain};

/// A Kyber1024 keypair.
pub struct Keypair {
    pub public_key: [u8; pqc_kyber::KYBER_PUBLICKEYBYTES],
    pub secret_key: [u8; pqc_kyber::KYBER_SECRETKEYBYTES],
}

/// Everything the receiver needs to authenticate and decrypt a message:
/// the Kyber ciphertext, the AES-256-GCM payload, and the MRS chain
/// used to derive the hybrid key for this message (see the module-level
/// design note on why the chain is not secret).
pub struct SecureEnvelope {
    pub packet: HybridCiphertextPacket,
    pub mrs_chain: MrsChain,
}

/// Errors surfaced by the framework's top-level operations.
#[derive(Debug)]
pub enum FrameworkError {
    Kyber(KyberError),
    ChainSamplingFailed,
    Crypto(&'static str),
}

impl From<KyberError> for FrameworkError {
    fn from(e: KyberError) -> Self {
        FrameworkError::Kyber(e)
    }
}

/// Derives the public Diophantine root parameter N for this session from
/// `session_id`. N is a public parameter (see paper section 7.1); it is
/// not the secret -- the secret is which chain in the forest of N gets
/// sampled. This is a plain, non-cryptographic fold, not a security
/// boundary: its only job is to turn an arbitrary-length session
/// identifier into a u64 that satisfies the Frobenius bound (N >= 144)
/// with enough headroom for a 3-layer chain to exist.
fn derive_session_root(session_id: &[u8]) -> u64 {
    let mut acc: u64 = 0x9E3779B97F4A7C15; // arbitrary odd seed for spreading
    for &byte in session_id {
        acc = acc.wrapping_mul(0x100000001B3).wrapping_add(byte as u64);
    }
    // Force the result into a range where the forest is large enough
    // for a 3-layer chain to exist reliably (see paper section 3.4).
    1_000_000_000u64 + (acc % 1_000_000_000u64)
}

pub struct MrsAuthFramework;

impl MrsAuthFramework {
    /// Generates a new Kyber1024 keypair.
    pub fn keygen() -> Result<Keypair, FrameworkError> {
        let mut rng = thread_rng();
        let keys = keypair(&mut rng)?;
        Ok(Keypair {
            public_key: keys.public,
            secret_key: keys.secret,
        })
    }

    /// Full deniable encapsulation: Kyber encapsulate -> sample an MRS
    /// chain -> derive the hybrid key -> AES-256-GCM encrypt.
    ///
    /// `session_id` and `hkdf_context` are public parameters that feed
    /// the hybrid key derivation (see `derive_hybrid_key`). `nonce` must
    /// be 12 bytes and unique per key; `associated_data` is
    /// authenticated but not encrypted.
    pub fn full_encrypt(
        public_key: &[u8; pqc_kyber::KYBER_PUBLICKEYBYTES],
        session_id: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<SecureEnvelope, FrameworkError> {
        let mut rng = thread_rng();
        let (kyber_ciphertext, shared_secret) = encapsulate(public_key, &mut rng)?;

        let root_n = derive_session_root(session_id);

        // GECORRIGEERD: Voeg &mut rng toe als tweede argument voor de u64 sampler engine
        let mrs_chain =
            sample_three_layers(root_n, &mut rng).ok_or(FrameworkError::ChainSamplingFailed)?;

        let hybrid_key = derive_hybrid_key(&shared_secret, &mrs_chain, session_id)
            .map_err(FrameworkError::Crypto)?;

        let aes_payload = encrypt_payload_hybrid(&hybrid_key, nonce, plaintext, associated_data)
            .map_err(FrameworkError::Crypto)?;

        Ok(SecureEnvelope {
            packet: HybridCiphertextPacket {
                kyber_ciphertext,
                aes_payload,
            },
            mrs_chain,
        })
    }

    /// Full authenticated decryption: Kyber decapsulate -> re-derive the
    /// hybrid key using the transmitted MRS chain -> AES-256-GCM decrypt
    /// and verify.
    pub fn full_decrypt(
        secret_key: &[u8; pqc_kyber::KYBER_SECRETKEYBYTES],
        envelope: &SecureEnvelope,
        session_id: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, FrameworkError> {
        let shared_secret = decapsulate(&envelope.packet.kyber_ciphertext, secret_key)?;

        let hybrid_key = derive_hybrid_key(&shared_secret, &envelope.mrs_chain, session_id)
            .map_err(FrameworkError::Crypto)?;

        let plaintext = decrypt_payload_hybrid(
            &hybrid_key,
            nonce,
            &envelope.packet.aes_payload,
            associated_data,
        )
        .map_err(FrameworkError::Crypto)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_round_trip() {
        let keypair = MrsAuthFramework::keygen().expect("keygen should not fail");
        let session_id = b"session-2026-08-24";
        let nonce = [7u8; 12];
        let aad = b"envelope-header";
        let plaintext = b"a message that survives the round trip";

        let envelope =
            MrsAuthFramework::full_encrypt(&keypair.public_key, session_id, &nonce, aad, plaintext)
                .expect("encryption should succeed");

        let recovered =
            MrsAuthFramework::full_decrypt(&keypair.secret_key, &envelope, session_id, &nonce, aad)
                .expect("decryption should succeed");

        assert_eq!(plaintext.to_vec(), recovered);
    }
}
