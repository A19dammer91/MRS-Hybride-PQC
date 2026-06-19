# MRS Hybride PQC

Hybrid Post-Quantum cryptographic library combining Kyber1024 KEM,
MRS(19,9) Diophantine key derivation, and AES-256-GCM encryption.

## Overview

This library couples a post-quantum key encapsulation mechanism
(Kyber1024, NIST Security Level 5) with a fast, constant-time
number-theoretic key derivation step based on the MRS(19,9) Diophantine
decomposition system. The two derived values are combined via XOR into
a single session key, which is then used for authenticated encryption.

## Architecture

| Stage | Function | Description |
|---|---|---|
| Block 1 | `kyber_keygen`, `kyber_encapsulate`, `kyber_decapsulate` | Kyber1024 key encapsulation |
| Block 2 | `derive_mrs_master_key` | MRS(19,9) decomposition → fast O(1) key derivation (A0 = N mod 9) |
| Coupling | `hybrid_coupling` | k_combined = k1 XOR mk |
| Block 3 | `encrypt_payload`, `decrypt_payload` | AES-256-GCM AEAD encryption/decryption |

**Important:** the MRS(19,9) component is a constant-time, O(1)
key-derivation step, not an independent security layer. When
`session_id` is public (the default usage pattern), `derive_mrs_master_key`
contributes no additional entropy; all cryptographic security in that
case comes from Kyber1024's `k1`. See Limitations below for when this
step does add independent security value.

## Usage

```rust
use mrs_auth_pqc::MrsAuthKem;

let keypair = MrsAuthKem::kyber_keygen();

let packet = MrsAuthKem::full_encrypt(
    &keypair.public_key, 
    session_id, 
    hkdf_context, 
    &nonce, 
    associated_data, 
    plaintext, 
)?;

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

To validate the internal number-theoretic tests:
```bash
cargo test
```

To bench the official microsecond/nanosecond speed performance yourself:
```bash
cargo bench
```

## Limitations

- `derive_mrs_master_key` is deterministic and operates on whatever `session_id` it is given. If `session_id` is known to an attacker (the common case), `mk` provides no security margin. All confidentiality relies entirely on Kyber1024's `k1`.
- For the MRS step to contribute independent entropy, `session_id` would need to be a secret shared via a channel independent of this library, which introduces its own key-distribution problem.
- This library has not undergone external cryptographic review.
- The primary demonstrated contribution of MRS(19,9) is speed: a constant-time O(1) derivation path, not an additional security guarantee, when used with public session identifiers.


## Dependencies

- pqcrypto-kyber - Kyber1024 post-quantum KEM
- aes-gcm - AES-256-GCM AEAD encryption
- sha2 - SHA-256 for MRS master key derivation

## License

Apache-2.0

## Author

Bilal El Issaoui
