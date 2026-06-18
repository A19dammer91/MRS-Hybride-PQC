
# MRS Hybride PQC

Hybrid Post-Quantum cryptographic library combining Kyber1024 KEM,
MRS(19,9) Diophantine key derivation, and AES-256-GCM encryption.

## Overview

This library couples a post-quantum key encapsulation mechanism
(Kyber1024, NIST Security Level 5) with a classical number-theoretic
key derivation step based on the MRS(19,9) Diophantine decomposition
system. The two derived secrets are combined via XOR into a single
session key, which is then used for authenticated encryption.

## Architecture

| Stage | Function | Description |
|---|---|---|
| Block 1 | `kyber_keygen`, `kyber_encapsulate`, `kyber_decapsulate` | Kyber1024 key encapsulation |
| Block 2 | `derive_mrs_master_key` | MRS(19,9) decomposition → master key (A₀ = N mod 9) |
| Hybrid Coupling | `hybrid_coupling` | k_combined = k1 ⊕ mk |
| Block 3 | `encrypt_payload`, `decrypt_payload` | AES-256-GCM AEAD encryption/decryption |

## Usage

```rust
use mrs_auth_pqc::MrsAuthKem;

// Receiver generates a Kyber1024 keypair
let keypair = MrsAuthKem::kyber_keygen();

// Sender encrypts a message
let packet = MrsAuthKem::full_encrypt(
    &keypair.public_key,
    session_id,
    hkdf_context,
    &nonce,
    associated_data,
    plaintext,
)?;

// Receiver decrypts the message
let plaintext = MrsAuthKem::full_decrypt(
    &keypair.secret_key,
    &packet,
    session_id,
    hkdf_context,
    &nonce,
    associated_data,
)?;
```

## Build & Test

```bash
cargo test
```

## Dependencies

- `pqcrypto-kyber` — Kyber1024 post-quantum KEM
- `aes-gcm` — AES-256-GCM AEAD encryption
- `sha2` — SHA-256 for MRS master key derivation

## License

Apache-2.0

## Author

Bilal El Issaoui
