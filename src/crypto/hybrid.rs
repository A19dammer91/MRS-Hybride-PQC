//! Hybrid Post-Quantum Coupling module implementing strict HKDF-SHA256
//! key derivation and authenticated encryption via AES-256-GCM.

use crate::sampler::MrsChain;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::Mac;
use pqc_kyber::KYBER_SSBYTES;
use sha2::Sha256;
use zeroize::Zeroize;

type HkdfMac = hmac::Hmac<Sha256>;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct HybridCiphertextPacket {
    pub kyber_ciphertext: [u8; pqc_kyber::KYBER_CIPHERTEXTBYTES],
    pub aes_payload: Vec<u8>,
}

/// Derives a cryptographically strong 256-bit symmetric key by mixing the
/// post-quantum Kyber shared secret with the deniable MRS chain under HKDF-SHA256.
pub fn derive_hybrid_key(
    kyber_ss: &[u8; KYBER_SSBYTES],
    mrs_chain: &MrsChain,
    session_id: &[u8],
) -> Result<[u8; 32], &'static str> {
    // 1. Serialize the full 3-layer Diophantine chain path seamlessly into bytes
    let mut mrs_bytes = Vec::with_capacity(mrs_chain.layers.len() * 16);
    for pair in &mrs_chain.layers {
        mrs_bytes.extend_from_slice(&pair.a.to_be_bytes());
        mrs_bytes.extend_from_slice(&pair.b.to_be_bytes());
    }

    // 2. HKDF-Extract Phase: Extract pseudorandom key (PRK) from high-entropy inputs
    let mut extract = <HkdfMac as Mac>::new_from_slice(session_id)
        .map_err(|_| "HKDF-Extract initialization error")?;

    <HkdfMac as Mac>::update(&mut extract, kyber_ss);
    <HkdfMac as Mac>::update(&mut extract, &mrs_bytes);
    let prk = extract.finalize().into_bytes();

    // 3. HKDF-Expand Phase: Expand into the final 256-bit key using localized context
    let info = b"MRS-AUTH Hybrid Coupling v1";
    let mut expand =
        <HkdfMac as Mac>::new_from_slice(&prk).map_err(|_| "HKDF-Expand initialization error")?;

    <HkdfMac as Mac>::update(&mut expand, info);
    <HkdfMac as Mac>::update(&mut expand, &[1u8]); // Enforce RFC 5869 single-block constant counter
    let okm = expand.finalize().into_bytes();

    let mut hybrid_key = [0u8; 32];
    hybrid_key.copy_from_slice(&okm[0..32]);

    Ok(hybrid_key)
}
// ============================================================================
// Authenticated Encryption Layer (AES-256-GCM)
// ============================================================================

/// Encrypts plaintext using AES-256-GCM with associated authenticated data (AAD).
pub fn encrypt_payload_hybrid(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| "AES-GCM encryption failed")?;

    Ok(payload)
}

/// Decrypts ciphertext and verifies integrity tags using AES-256-GCM.
pub fn decrypt_payload_hybrid(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| "AES-GCM decryption failed (integrity check failed)")?;

    Ok(plaintext)
}
