
# MRS-AUTH (Multiple Representation Systems Authentication)
### Post-Quantum Coercion-Resistant Authentication Framework

# MRS-AUTH (Multiple Representation Systems Authentication)
### Post-Quantum Coercion-Resistant Authentication Framework

[![DOI](https://zenodo.org)](https://doi.org) ![Status](https://shields.io) ![Verification](https://shields.io)


Hybrid Post-Quantum cryptographic library combining Kyber-KEM, multi-layer MRS(19,9) Diophantine chain sampling, and authenticated encryption.

## Overview

**MRS-AUTH** is a post-quantum authentication framework engineered to provide unconditional, information-theoretic deniability against unbounded passive adversaries, maintaining robust coercion resistance. 

Unlike traditional cryptographic infrastructures relying on unique secret keys, MRS-AUTH leverages the vertical multiplicity of representations within a nested linear Diophantine system ($N = 19A + 9B$). By recursively nesting this decomposition across three functional layers ($L=3$), the protocol guarantees that an external attacker and a coerced user stand in computationally isomorphic positions. A user under duress can supply an alternative, mathematical "alibi" chain that is information-theoretically indistinguishable from the true credential.

## Architecture

| Stage | Function / Module | Description |
| :--- | :--- | :--- |
| **Block 1** | `kyber_keygen`, `kyber_encapsulate` | Post-quantum Key Encapsulation Mechanism (Kyber-768/1024, IND-CCA2). |
| **Block 2** | `sample_mrs_hierarchical_cdf` | Multi-layer Diophantine decomposition via a Weighted CDF Sampler ($A_0 = N \pmod 9$). |
| **Block 3** | `k_acceptance_merkle_commitment` | Fixed-depth balanced tree combining the authentic path with $k-1$ decoy chains. |
| **Block 4** | `lwe_chain_isolation` | Encapsulation of the target chain within an LWE instance ($b = A \cdot s + e$). |
| **Coupling** | `hybrid_hkdf_coupling` | Asymmetric key-derivation via HKDF paired with `HMAC-SHA256` time-codes. |
| **Block 5** | `encrypt_payload`, `decrypt_payload` | AES-256-GCM AEAD authenticated encryption/decryption. |

## Usage

```rust
use mrs_auth_pqc::MrsAuthFramework;

// 1. Generate post-quantum keypair and initialize framework parameters
let keypair = MrsAuthFramework::keygen();

// 2. Execute full deniable encapsulation with active-verifier security
let packet = MrsAuthFramework::full_encrypt(
    &keypair.public_key,
    &session_id,
    &hkdf_context,
    &nonce,
    associated_data,
    plaintext,
);

// 3. Authenticate and decrypt using time-locked forward secrecy
let plaintext = MrsAuthFramework::full_decrypt(
    &keypair.secret_key,
    &packet,
    &session_id,
    &hkdf_context,
    &nonce,
    associated_data,
);
```

## Build & Test

To validate the internal number-theoretic verification tests and EasyCrypt-aligned test vectors:
```bash
cargo test
```

To bench the microsecond constant-time execution performance:
```bash
cargo bench
```

## Formal Verification Status

All core security properties, algorithmic non-interference vectors, and uniformity theorems are formalized and machine-verified using the **EasyCrypt** proof assistant.

* `MRS_AUTH.ec`: Core formalization of the linear Diophantine step family.
* `MRS_Sampling.ec`: Machine proof of the Hierarchical Weighted CDF Sampler.
* `temporal_barrier_noninterference`: Formally proven resilience against active timing-analysis.

## Implementation Safeguards & Limitations

* **Constant-Time Operations**: Logical comparisons and core arithmetic branches utilize the `subtle` crate to enforce branch-free execution paths and eliminate timing side-channels.
* **Temporal Barrier**: Hard runtime execution limits (`sample_mrs_eea_timed`) are enforced to abort execution and return `None` upon timing disruptions or active network probing.
* **Memory Lifecycles**: All transient intermediate secret states and Diophantine representation arrays are bound to the `Zeroize` compiler trait to ensure immediate sanitization from RAM upon dropping out of scope.
* **Review Status**: While the underlying mathematical model and core cryptographic games are fully machine-verified via EasyCrypt, this library represents a research-phase framework and has not undergone independent external production-grade security audits.

## Citation & Documentation

For the complete theoretical proofs, mathematical derivations, and EasyCrypt code listings, please refer to the official specification published on Zenodo:

> **Title**: The Forest Analogy: Full Specification of the MRS-AUTH Cryptographic Framework  
> **Author**: Bilal El Issaoui  
> **Permanent DOI**: [10.5281/zenodo.21852606](https://doi.org)
