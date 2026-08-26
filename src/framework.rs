//! Top-level framework tying Kyber1024, MRS(19,9) sampling, and AES-256-GCM.

use pqc_kyber::{decapsulate, encapsulate, keypair, KyberError};
use rand::thread_rng;

use crate::crypto::{decrypt_payload_hybrid, derive_hybrid_key, encrypt_payload_hybrid, HybridCiphertextPacket};
use crate::sampler::{sample_three_layers, MrsChain, SamplerInt};

pub struct Keypair {
    pub public_key: [u8; pqc_kyber::KYBER_PUBLICKEYBYTES],
    pub secret_key: [u8; pqc_kyber::KYBER_SECRETKEYBYTES],
}

/// Everything the receiver needs: Kyber ciphertext, AES payload, MRS chain.
///
/// Generic over `T` so the same envelope works for `U64` (benchmark) and
/// `U256` (cryptographic scale).
pub struct SecureEnvelope<T: SamplerInt> {
    pub packet: HybridCiphertextPacket,
    pub mrs_chain: MrsChain<T>,
}

#[derive(Debug)]
pub enum FrameworkError {
    Kyber(KyberError),
    ChainSamplingFailed,
    Crypto(&'static str),
}

impl From<KyberError> for FrameworkError {
    fn from(e: KyberError) -> Self { FrameworkError::Kyber(e) }
}

/// Derives the public Diophantine root N from `session_id`.
///
/// Returns `T` so it works for any width (`U64`, `U256`, ...).
fn derive_session_root<T: SamplerInt>(session_id: &[u8]) -> T {
    let mut acc: u64 = 0x9E3779B97F4A7C15;
    for &byte in session_id {
        acc = acc.wrapping_mul(0x100000001B3).wrapping_add(byte as u64);
    }
    let base = 1_000_000_000u64 + (acc % 1_000_000_000u64);
    T::from(base)
}

pub struct MrsAuthFramework;

impl MrsAuthFramework {
    pub fn keygen() -> Result<Keypair, FrameworkError> {
        let mut rng = thread_rng();
        let keys = keypair(&mut rng)?;
        Ok(Keypair { public_key: keys.public, secret_key: keys.secret })
    }

    pub fn full_encrypt<T: SamplerInt>(
        public_key: &[u8; pqc_kyber::KYBER_PUBLICKEYBYTES],
        session_id: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<SecureEnvelope<T>, FrameworkError> {
        let mut rng = thread_rng();
        let (kyber_ciphertext, shared_secret) = encapsulate(public_key, &mut rng)?;

        let root_n = derive_session_root::<T>(session_id);
        let mrs_chain = sample_three_layers(&root_n, &mut rng)
            .ok_or(FrameworkError::ChainSamplingFailed)?;

        let hybrid_key = derive_hybrid_key(&shared_secret, &mrs_chain, session_id)
            .map_err(FrameworkError::Crypto)?;

        let aes_payload = encrypt_payload_hybrid(&hybrid_key, nonce, plaintext, associated_data)
            .map_err(FrameworkError::Crypto)?;

        Ok(SecureEnvelope {
            packet: HybridCiphertextPacket { kyber_ciphertext, aes_payload },
            mrs_chain,
        })
    }

    pub fn full_decrypt<T: SamplerInt>(
        secret_key: &[u8; pqc_kyber::KYBER_SECRETKEYBYTES],
        envelope: &SecureEnvelope<T>,
        session_id: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, FrameworkError> {
        let shared_secret = decapsulate(&envelope.packet.kyber_ciphertext, secret_key)?;

        let hybrid_key = derive_hybrid_key(&shared_secret, &envelope.mrs_chain, session_id)
            .map_err(FrameworkError::Crypto)?;

        decrypt_payload_hybrid(&hybrid_key, nonce, &envelope.packet.aes_payload, associated_data)
            .map_err(FrameworkError::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U64;

    #[test]
    fn full_round_trip_u64() {
        let keypair = MrsAuthFramework::keygen().expect("keygen ok");
        let session_id = b"session-2026-08-24";
        let nonce = [7u8; 12];
        let aad = b"envelope-header";
        let plaintext = b"round-trip message";

        let envelope: SecureEnvelope<U64> = MrsAuthFramework::full_encrypt(
            &keypair.public_key, session_id, &nonce, aad, plaintext,
        ).expect("encrypt ok");

        let recovered = MrsAuthFramework::full_decrypt(
            &keypair.secret_key, &envelope, session_id, &nonce, aad,
        ).expect("decrypt ok");

        assert_eq!(plaintext.to_vec(), recovered);
    }
}
