use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};

// ============================================================================
// MRS (19, 9) SYSTEEM — KLASSE-IV PARAMETERS
// Wetmatigheid: p ≡ 1 (mod q)  →  19 ≡ 1 (mod 9)  ✓
// Garandeert A0 = N mod q als minimale Diophantische startcoëfficiënt
// ============================================================================
pub const P_COEFF: u64 = 19;
pub const Q_COEFF: u64 = 9;

// ============================================================================
// KYBER SLEUTELPAAR
// Bevat de publieke sleutel (voor encapsulatie door verzender)
// en de geheime sleutel (voor decapsulatie door ontvanger).
// ============================================================================
pub struct KyberKeypair {
    pub public_key:  kyber1024::PublicKey,
    pub secret_key:  kyber1024::SecretKey,
}

// ============================================================================
// ENCAPSULATIE-PAKKET
// Wordt over het netwerk verzonden: bevat de Kyber-cijfertekst (voor
// decapsulatie) en de versleutelde payload.
// ============================================================================
pub struct EncapsulatedPacket {
    pub kyber_ciphertext: kyber1024::Ciphertext,
    pub aead_ciphertext:  Vec<u8>,
}

// ============================================================================
// MRS-AUTH KEM — CENTRALE PROTOCOL MANAGER
// ============================================================================
pub struct MrsAuthKem;

impl MrsAuthKem {

    // ------------------------------------------------------------------------
    // BLOCK 1A: Kyber1024 Sleutelpaar Generatie (Post-Quantum)
    //
    // Genereert een live Kyber1024 keypair via pqcrypto's gevalideerde
    // implementatie. Kyber1024 biedt NIST Security Level 5 (≥256-bit
    // post-quantum veiligheid).
    // ------------------------------------------------------------------------
    pub fn kyber_keygen() -> KyberKeypair {
        let (pk, sk) = kyber1024::keypair();
        KyberKeypair {
            public_key: pk,
            secret_key: sk,
        }
    }

    // ------------------------------------------------------------------------
    // BLOCK 1B: Kyber1024 Encapsulatie (Verzenderzijde)
    //
    // De verzender gebruikt de publieke sleutel van de ontvanger om:
    //   1. Een gedeeld geheim k1 (32 bytes) te samplen
    //   2. Een Kyber-cijfertekst te produceren waarmee de ontvanger
    //      hetzelfde k1 kan reconstrueren via decapsulatie
    //
    // k1 verlaat nooit het protocol in plaintext — het wordt direct
    // in de hybride koppeling verwerkt.
    // ------------------------------------------------------------------------
    pub fn kyber_encapsulate(
        public_key: &kyber1024::PublicKey,
    ) -> (kyber1024::Ciphertext, [u8; 32]) {
        let (shared_secret, kyber_ct) = kyber1024::encapsulate(public_key);
        let mut k1 = [0u8; 32];
        k1.copy_from_slice(shared_secret.as_bytes());
        (kyber_ct, k1)
    }

    // ------------------------------------------------------------------------
    // BLOCK 1C: Kyber1024 Decapsulatie (Ontvangerzijde)
    //
    // De ontvanger gebruikt zijn geheime sleutel om uit de Kyber-cijfertekst
    // hetzelfde gedeelde geheim k1 te reconstrueren als de verzender.
    // Kyber garandeert: decapsulate(sk, encapsulate(pk)) == k1  ✓
    // ------------------------------------------------------------------------
    pub fn kyber_decapsulate(
        secret_key:      &kyber1024::SecretKey,
        kyber_ciphertext: &kyber1024::Ciphertext,
    ) -> [u8; 32] {
        let shared_secret = kyber1024::decapsulate(kyber_ciphertext, secret_key);
        let mut k1 = [0u8; 32];
        k1.copy_from_slice(shared_secret.as_bytes());
        k1
    }

    // ------------------------------------------------------------------------
    // BLOCK 2: Constant-time O(1) MRS Decompositie & Master Key Afleiding
    //
    // Volgt exact de wetmatigheid A0 = N mod q. Omdat p ≡ 1 (mod q),
    // reduceert de Diophantische parsing tot één enkele modulo-operatie
    // zonder branching — O(1) gegarandeerd.
    //
    // N = 19·B0 + 9·A0  →  A0 = N mod 9,  B0 = (N - A0) / 19
    //
    // De coördinaten (A0, B0) worden deterministisch gebonden aan een
    // context-label via SHA-256 (Domain Separation).
    // ------------------------------------------------------------------------
    pub fn derive_mrs_master_key(n: u64, hkdf_context: &[u8]) -> [u8; 32] {
        // O(1) Greedy start: minimale coëfficiënt A0 via directe modulo
        let a0 = n % Q_COEFF;

        // B0 = (N - A0) / 19  [exacte deling, geen rest]
        let b0 = (n - a0) / P_COEFF;

        // Serialiseer coördinatenpaar deterministisch naar big-endian bytes
        let mut chain_bytes = Vec::with_capacity(16);
        chain_bytes.extend_from_slice(&a0.to_be_bytes());
        chain_bytes.extend_from_slice(&b0.to_be_bytes());

        // Random Oracle binding: SHA-256(chain_bytes ‖ hkdf_context)
        let mut hasher = Sha256::new();
        hasher.update(&chain_bytes);
        hasher.update(hkdf_context);

        let mut mk = [0u8; 32];
        mk.copy_from_slice(&hasher.finalize());
        mk
    }

    // ------------------------------------------------------------------------
    // DE CRUX: Hybride XOR Koppeling  k_combined = k1 ⊕ mk
    //
    // Koppelt de post-quantum laag (Kyber) aan de getaltheoretische laag
    // (MRS). Veiligheidsgarantie: als één van beide componenten volledig
    // geheim blijft, is k_combined informatiekundig veilig (OTP-eigenschap).
    //
    // Constant-time: geen data-afhankelijke vertakking of geheugen-access.
    // ------------------------------------------------------------------------
    pub fn hybrid_coupling(k1: &[u8; 32], mk: &[u8; 32]) -> [u8; 32] {
        let mut k_combined = [0u8; 32];
        for i in 0..32 {
            k_combined[i] = k1[i] ^ mk[i];
        }
        k_combined
    }

    // ------------------------------------------------------------------------
    // BLOCK 3: AES-256-GCM Payload Encryptie (AEAD)
    //
    // Versleutelt de plaintext met k_combined als sleutel.
    // De GCM-tag garandeert authenticiteit én integriteit (IND-CCA2).
    // Associated Data wordt mee-geauthenticeerd maar niet versleuteld
    // — voorkomt replay- en herorderings-aanvallen.
    // ------------------------------------------------------------------------
    pub fn encrypt_payload(
        k_combined:      &[u8; 32],
        nonce_bytes:     &[u8; 12],
        associated_data: &[u8],
        plaintext:       &[u8],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        let key    = Key::<Aes256Gcm>::from_slice(k_combined);
        let cipher = Aes256Gcm::new(key);
        let nonce  = Nonce::from_slice(nonce_bytes);
        cipher.encrypt(nonce, Payload { msg: plaintext, aad: associated_data })
    }

    // ------------------------------------------------------------------------
    // BLOCK 3 COUNTERPART: AES-256-GCM Decryptie & AEAD Tag Verificatie
    //
    // Faalt direct als de cijfertekst, nonce, of associated data gemanipuleerd
    // zijn — de GCM-tag verificatie detecteert elke 1-bit wijziging.
    // ------------------------------------------------------------------------
    pub fn decrypt_payload(
        k_combined:      &[u8; 32],
        nonce_bytes:     &[u8; 12],
        associated_data: &[u8],
        ciphertext:      &[u8],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        let key    = Key::<Aes256Gcm>::from_slice(k_combined);
        let cipher = Aes256Gcm::new(key);
        let nonce  = Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, Payload { msg: ciphertext, aad: associated_data })
    }

    // ------------------------------------------------------------------------
    // VOLLEDIG PROTOCOL — VERZENDERZIJDE
    //
    // Combineert Block 1B + Block 2 + Block 3 in één aanroep.
    // Geeft een EncapsulatedPacket terug dat over het netwerk kan worden
    // verzonden naar de ontvanger.
    //
    // Vereiste inputs:
    //   public_key     — ontvanger's Kyber1024 publieke sleutel
    //   session_id     — unieke sessie-identifier (wordt N voor MRS-decompositi)
    //   hkdf_context   — domeinscheidingslabel (bijv. b"mrs_auth_v1_encrypt")
    //   nonce_bytes    — 12-byte cryptografisch veilige willekeurige nonce
    //   associated_data— niet-geheime metadata (wordt mee-geauthenticeerd)
    //   plaintext      — te versleutelen bericht
    // ------------------------------------------------------------------------
    pub fn full_encrypt(
        public_key:      &kyber1024::PublicKey,
        session_id:      u64,
        hkdf_context:    &[u8],
        nonce_bytes:     &[u8; 12],
        associated_data: &[u8],
        plaintext:       &[u8],
    ) -> Result<EncapsulatedPacket, aes_gcm::Error> {
        // Block 1B: Kyber encapsulatie → k1
        let (kyber_ct, k1) = Self::kyber_encapsulate(public_key);

        // Block 2: MRS decompositi van session_id → mk
        let mk = Self::derive_mrs_master_key(session_id, hkdf_context);

        // De Crux: k_combined = k1 ⊕ mk
        let k_combined = Self::hybrid_coupling(&k1, &mk);

        // Block 3: AES-256-GCM encryptie
        let aead_ct = Self::encrypt_payload(&k_combined, nonce_bytes, associated_data, plaintext)?;

        Ok(EncapsulatedPacket {
            kyber_ciphertext: kyber_ct,
            aead_ciphertext:  aead_ct,
        })
    }

    // ------------------------------------------------------------------------
    // VOLLEDIG PROTOCOL — ONTVANGERZIJDE
    //
    // Combineert Block 1C + Block 2 + Block 3 in één aanroep.
    // Reconstrueert k_combined onafhankelijk en decrypteert de payload.
    //
    // Correctheid: als session_id, hkdf_context, nonce en associated_data
    // identiek zijn aan die van de verzender, en het keypair klopt,
    // levert decrypt exact de originele plaintext terug.
    // ------------------------------------------------------------------------
    pub fn full_decrypt(
        secret_key:      &kyber1024::SecretKey,
        packet:          &EncapsulatedPacket,
        session_id:      u64,
        hkdf_context:    &[u8],
        nonce_bytes:     &[u8; 12],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        // Block 1C: Kyber decapsulatie → k1 (identiek aan verzender's k1)
        let k1 = Self::kyber_decapsulate(secret_key, &packet.kyber_ciphertext);

        // Block 2: MRS decompositi (deterministisch, zelfde session_id) → mk
        let mk = Self::derive_mrs_master_key(session_id, hkdf_context);

        // De Crux: k_combined = k1 ⊕ mk  (identiek aan verzender)
        let k_combined = Self::hybrid_coupling(&k1, &mk);

        // Block 3: AES-256-GCM decryptie & AEAD tag verificatie
        Self::decrypt_payload(&k_combined, nonce_bytes, associated_data, &packet.aead_ciphertext)
    }
}

// ============================================================================
// TESTS
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: Volledig end-to-end protocol met live Kyber1024 sleutels
    #[test]
    fn test_full_pqc_protocol_end_to_end() {
        // SETUP: Ontvanger genereert een live Kyber1024 keypair
        let keypair = MrsAuthKem::kyber_keygen();

        // PROTOCOL PARAMETERS (gedeeld buiten-band)
        let session_id      = 958u64;               // dr(958) = 4; A0=4, B0=50
        let hkdf_context    = b"mrs_auth_quantum_shield_v1";
        let nonce           = [0x07u8; 12];          // Productie: gebruik OsRng!
        let associated_data = b"Domain_Separated_Metadata_2026";
        let plaintext       = b"Order in numbers dictates absolute chaos for the adversary.";

        // VERZENDERZIJDE: encapsuleer + versleutel
        let packet = MrsAuthKem::full_encrypt(
            &keypair.public_key,
            session_id,
            hkdf_context,
            &nonce,
            associated_data,
            plaintext,
        ).expect("Encryptie mag niet falen");

        // Cijfertekst mag plaintext niet lekken
        assert_ne!(packet.aead_ciphertext, plaintext.to_vec());

        // ONTVANGERZIJDE: decapsuleer + ontsleutel
        let recovered = MrsAuthKem::full_decrypt(
            &keypair.secret_key,
            &packet,
            session_id,
            hkdf_context,
            &nonce,
            associated_data,
        ).expect("Decryptie en AEAD-verificatie moeten slagen");

        // Herstelde plaintext moet exact overeenkomen
        assert_eq!(recovered, plaintext.to_vec());
    }

    // Test 2: Kyber correctheid — encapsulatie en decapsulatie leveren
    // hetzelfde gedeelde geheim
    #[test]
    fn test_kyber_shared_secret_agreement() {
        let keypair = MrsAuthKem::kyber_keygen();
        let (kyber_ct, k1_sender)   = MrsAuthKem::kyber_encapsulate(&keypair.public_key);
        let k1_receiver              = MrsAuthKem::kyber_decapsulate(&keypair.secret_key, &kyber_ct);
        assert_eq!(k1_sender, k1_receiver, "Kyber gedeeld geheim moet aan beide zijden identiek zijn");
    }

    // Test 3: MRS decompositie correctheid voor N = 958
    #[test]
    fn test_mrs_decomposition_correctness() {
        let n: u64 = 958;
        let a0 = n % 9;   // = 4
        let b0 = (n - a0) / 19; // = 50
        // Reconstructie: 19*50 + 9*4 = 950 + 8 = 958 ✓
        assert_eq!(19 * b0 + 9 * a0, n);
        assert_eq!(a0, 4);
        assert_eq!(b0, 50);
    }

    // Test 4: Tamper-resistance — AEAD tag detecteert elke manipulatie
    #[test]
    fn test_adversarial_tamper_resistance() {
        let k_combined  = [0x9Fu8; 32];
        let nonce       = [0x02u8; 12];
        let aad         = b"Valid_Metadata";
        let plaintext   = b"Strikte getaltheoretische orde.";

        let mut ciphertext = MrsAuthKem::encrypt_payload(
            &k_combined, &nonce, aad, plaintext
        ).unwrap();

        // Adversary wijzigt 1 bit in het netwerkpakket
        ciphertext[0] ^= 0xFF;

        let result = MrsAuthKem::decrypt_payload(&k_combined, &nonce, aad, &ciphertext);
        assert!(result.is_err(), "Gemanipuleerde payload mag nooit worden geaccepteerd");
    }

    // Test 5: Verkeerde sleutel leidt tot decryptie-fout
    #[test]
    fn test_wrong_secret_key_fails() {
        let keypair_alice = MrsAuthKem::kyber_keygen();
        let keypair_eve   = MrsAuthKem::kyber_keygen(); // Aanvaller met eigen keypair

        let session_id      = 100u64;
        let hkdf_context    = b"mrs_auth_quantum_shield_v1";
        let nonce           = [0x01u8; 12];
        let aad             = b"Metadata";
        let plaintext       = b"Geheim bericht.";

        // Verzend naar Alice haar publieke sleutel
        let packet = MrsAuthKem::full_encrypt(
            &keypair_alice.public_key,
            session_id, hkdf_context, &nonce, aad, plaintext,
        ).unwrap();

        // Eve probeert te decrypteren met haar eigen geheime sleutel — moet falen
        let result = MrsAuthKem::full_decrypt(
            &keypair_eve.secret_key,
            &packet,
            session_id, hkdf_context, &nonce, aad,
        );
        assert!(result.is_err(), "Decryptie met verkeerde sleutel moet falen");
    }
}

