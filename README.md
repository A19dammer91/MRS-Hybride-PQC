# MRS Hybride PQC

Hybrid Post-Quantum cryptographic library combining Kyber1024 KEM, 
MRS(19,9) Diophantine key derivation, and AES-256-GCM encryption.

## Architecture

- **Block 1**: Kyber1024 key encapsulation (NIST Security Level 5)
- **Block 2**: MRS(19,9) Diophantine decomposition → master key derivation (A₀ = N mod 9)
- **Hybrid Coupling**: k_combined = k1 ⊕ mk (XOR-based key combination)
- **Block 3**: AES-256-GCM AEAD payload encryption/decryption

## Usage

```rust
let keypair = MrsAuthKem::kyber_keygen();
let packet = MrsAuthKem::full_encrypt(&keypair.public_key, session_id, context, &nonce, aad, plaintext)?;
let plaintext = MrsAuthKem::full_decrypt(&keypair.secret_key, &packet, session_id, context, &nonce, aad)?;
