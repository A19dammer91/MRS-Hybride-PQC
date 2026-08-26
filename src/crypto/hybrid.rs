```rust
use crate::sampler::{MrsChain, SamplerInt};
use pqc_kyber::KYBER_SSBYTES;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use sha2::Sha256;
use zeroize::Zeroize;
use hmac::Mac;

type HkdfExtract = hmac::Hmac<Sha256>;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct HybridCiphertextPacket {
    pub kyber_ciphertext: [u8; pqc_kyber::KYBER_CIPHERTEXTBYTES],
    pub aes_payload: Vec<u8>,
}

/// Derives the hybrid AES-256 key from Kyber SS + MRS chain + session_id.
///
/// Generic over `T: SamplerInt` so it works for both `U64` and `U256`.
pub fn derive_hybrid_key<T: SamplerInt>(
    kyber_ss: &[u8; KYBER_SSBYTES],
    mrs_chain: &MrsChain<T>,
    session_id: &[u8]
) -> Result<[u8; 32], &'static str> {
    let mut mrs_bytes = Vec::new();
    for pair in &mrs_chain.layers {
        mrs_bytes.extend_from_slice(&pair.a.to_be_bytes_vec());
        mrs_bytes.extend_from_slice(&pair.b.to_be_bytes_vec());
    }

    let mut extract = <HkdfExtract as Mac>::new_from_slice(session_id)
        .map_err(|_| "HKDF-Extract init error")?;

    <HkdfExtract as Mac>::update(&mut extract, kyber_ss);
    <HkdfExtract as Mac>::update(&mut extract, &mrs_bytes);

    let prk = extract.finalize().into_bytes();
    let mut hybrid_key = [0u8; 32];
    hybrid_key.copy_from_slice(&prk[0..32]);

    Ok(hybrid_key)
}

pub fn encrypt_payload_hybrid(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8]
) -> Result<Vec<u8>, &'static str> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad: associated_data })
        .map_err(|_| "AES-GCM encryption failed")
}

pub fn decrypt_payload_hybrid(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8]
) -> Result<Vec<u8>, &'static str> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad: associated_data })
        .map_err(|_| "AES-GCM decryption failed")
}
```
