use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};

pub const P_COEFF: u64 = 19;
pub const Q_COEFF: u64 = 9;

pub struct KyberKeypair {
    pub public_key:  kyber1024::PublicKey,
    pub secret_key:  kyber1024::SecretKey,
}

pub struct EncapsulatedPacket {
    pub kyber_ciphertext: kyber1024::Ciphertext,
    pub aead_ciphertext:  Vec<u8>,
}

pub struct MrsAuthKem;

impl MrsAuthKem {
    pub fn kyber_keygen() -> KyberKeypair {
        let (pk, sk) = kyber1024::keypair();
        KyberKeypair { public_key: pk, secret_key: sk }
    }

    pub fn kyber_encapsulate(public_key: &kyber1024::PublicKey) -> (kyber1024::Ciphertext, [u8; 32]) {
        let (shared_secret, kyber_ct) = kyber1024::encapsulate(public_key);
        let mut k1 = [0u8; 32];
        k1.copy_from_slice(shared_secret.as_bytes());
        (kyber_ct, k1)
    }

    pub fn kyber_decapsulate(secret_key: &kyber1024::SecretKey, kyber_ciphertext: &kyber1024::Ciphertext) -> [u8; 32] {
        let shared_secret = kyber1024::decapsulate(kyber_ciphertext, secret_key);
        let mut k1 = [0u8; 32];
        k1.copy_from_slice(shared_secret.as_bytes());
        k1
    }

    pub fn derive_mrs_master_key(n: u64, hkdf_context: &[u8]) -> [u8; 32] {
        let a0 = n % Q_COEFF;
        let b0 = (n - P_COEFF * a0) / Q_COEFF;

        let mut chain_bytes = Vec::with_capacity(16);
        chain_bytes.extend_from_slice(&a0.to_be_bytes());
        chain_bytes.extend_from_slice(&b0.to_be_bytes());

        let mut hasher = Sha256::new();
        hasher.update(&chain_bytes);
        hasher.update(hkdf_context);

        let mut mk = [0u8; 32];
        mk.copy_from_slice(&hasher.finalize());
        mk
    }

    pub fn hybrid_coupling(k1: &[u8; 32], mk: &[u8; 32]) -> [u8; 32] {
        let mut k_combined = [0u8; 32];
        for i in 0..32 {
            k_combined[i] = k1[i] ^ mk[i];
        }
        k_combined
    }

    pub fn encrypt_payload(k_combined: &[u8; 32], nonce_bytes: &[u8; 12], associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let key    = Key::<Aes256Gcm>::from_slice(k_combined);
        let cipher = Aes256Gcm::new(key);
        let nonce  = Nonce::from_slice(nonce_bytes);
        cipher.encrypt(nonce, Payload { msg: plaintext, aad: associated_data })
    }

    pub fn decrypt_payload(k_combined: &[u8; 32], nonce_bytes: &[u8; 12], associated_data: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let key    = Key::<Aes256Gcm>::from_slice(k_combined);
        let cipher = Aes256Gcm::new(key);
        let nonce  = Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, Payload { msg: ciphertext, aad: associated_data })
    }

    pub fn full_encrypt(public_key: &kyber1024::PublicKey, session_id: u64, hkdf_context: &[u8], nonce_bytes: &[u8; 12], associated_data: &[u8], plaintext: &[u8]) -> Result<EncapsulatedPacket, aes_gcm::Error> {
        let (kyber_ct, k1) = Self::kyber_encapsulate(public_key);
        let mk = Self::derive_mrs_master_key(session_id, hkdf_context);
        let k_combined = Self::hybrid_coupling(&k1, &mk);
        let aead_ct = Self::encrypt_payload(&k_combined, nonce_bytes, associated_data, plaintext)?;
        Ok(EncapsulatedPacket { kyber_ciphertext: kyber_ct, aead_ciphertext: aead_ct })
    }

    pub fn full_decrypt(secret_key: &kyber1024::SecretKey, packet: &EncapsulatedPacket, session_id: u64, hkdf_context: &[u8], nonce_bytes: &[u8; 12], associated_data: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let k1 = Self::kyber_decapsulate(secret_key, &packet.kyber_ciphertext);
        let mk = Self::derive_mrs_master_key(session_id, hkdf_context);
        let k_combined = Self::hybrid_coupling(&k1, &mk);
        Self::decrypt_payload(&k_combined, nonce_bytes, associated_data, &packet.aead_ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_pqc_protocol_end_to_end() {
        let keypair = MrsAuthKem::kyber_keygen();
        let session_id      = 958u64;
        let hkdf_context    = b"mrs_auth_quantum_shield_v1";
        let nonce           = [0x07u8; 12];
        let associated_data = b"Domain_Separated_Metadata_2026";
        let plaintext       = b"Order in numbers dictates absolute chaos for the adversary.";

        let packet = MrsAuthKem::full_encrypt(&keypair.public_key, session_id, hkdf_context, &nonce, associated_data, plaintext).expect("Encryptie mag niet falen");
        assert_ne!(packet.aead_ciphertext, plaintext.to_vec());

        let recovered = MrsAuthKem::full_decrypt(&keypair.secret_key, &packet, session_id, hkdf_context, &nonce, associated_data).expect("Decryptie en AEAD-verificatie moeten slagen");
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn test_kyber_shared_secret_agreement() {
        let keypair = MrsAuthKem::kyber_keygen();
        let (kyber_ct, k1_sender) = MrsAuthKem::kyber_encapsulate(&keypair.public_key);
        let k1_receiver = MrsAuthKem::kyber_decapsulate(&keypair.secret_key, &kyber_ct);
        assert_eq!(k1_sender, k1_receiver, "Kyber gedeeld geheim moet aan beide zijden identiek zijn");
    }

    #[test]
    fn test_mrs_decomposition_correctness() {
        let n: u64 = 958;
        let a0 = n % 9;
        let b0 = (n - 19 * a0) / 9;
        assert_eq!(19 * a0 + 9 * b0, n);
        assert_eq!(a0, 4);
        assert_eq!(b0, 98);
    }

    #[test]
    fn test_adversarial_tamper_resistance() {
        let k_combined  = [0x9Fu8; 32];
        let nonce       = [0x02u8; 12];
        let aad         = b"Valid_Metadata";
        let plaintext   = b"Strikte getaltheoretische orde.";
        let mut ciphertext = MrsAuthKem::encrypt_payload(&k_combined, &nonce, aad, plaintext).unwrap();
        ciphertext[0] ^= 0xFF;
        let result = MrsAuthKem::decrypt_payload(&k_combined, &nonce, aad, &ciphertext);
        assert!(result.is_err(), "Gemanipuleerde payload mag nooit worden geaccepteerd");
    }

    #[test]
    fn test_wrong_secret_key_fails() {
        let keypair_alice = MrsAuthKem::kyber_keygen();
        let keypair_eve   = MrsAuthKem::kyber_keygen();
        let session_id      = 100u64;
        let hkdf_context    = b"mrs_auth_quantum_shield_v1";
        let nonce           = [0x01u8; 12];
        let aad             = b"Metadata";
        let plaintext       = b"Geheim bericht.";
        let packet = MrsAuthKem::full_encrypt(&keypair_alice.public_key, session_id, hkdf_context, &nonce, aad, plaintext).unwrap();
        let result = MrsAuthKem::full_decrypt(&keypair_eve.secret_key, &packet, session_id, hkdf_context, &nonce, aad);
        assert!(result.is_err(), "Decryptie met verkeerde sleutel moet falen");
    }
}
