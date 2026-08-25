```markdown
# MRS-AUTH
### *Post-Quantum Coercion-Resistant Authentication Framework*

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21852606.svg)](https://doi.org/10.5281/zenodo.21852606)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](CI_URL)
[![Crates.io](https://img.shields.io/crates/v/mrs_auth_pqc)](https://crates.io/crates/mrs_auth_pqc)
[![Verified](https://img.shields.io/badge/verified-EasyCrypt-blue)](proofs/)

> Hybrid post-quantum cryptographic library combining Kyber‑1024 KEM (IND‑CCA2), multi‑layer MRS(19,9) Diophantine chain sampling, and AES‑256‑GCM authenticated encryption.  
> Provides **unconditional, information‑theoretic deniability** against unbounded passive adversaries.

---

## Overview

MRS‑AUTH is a post‑quantum authentication framework engineered to provide **coercion resistance** through mathematical deniability.

Unlike traditional cryptographic infrastructures that rely on unique secret keys, MRS‑AUTH leverages the **vertical multiplicity of representations** within the nested linear Diophantine system:

\[
N = 19A + 9B
\]

By recursively nesting this decomposition across three functional layers (\(L=3\)), the protocol guarantees that an external attacker and a coerced user stand in **computationally isomorphic positions**. A user under duress can supply an alternative, mathematical *alibi* chain that is information‑theoretically indistinguishable from the true credential.

---

## Architecture

| Stage | Function / Module | Description |
| :--- | :--- | :--- |
| **Block 1** | `kyber_keygen`, `kyber_encapsulate` | Post‑quantum Key Encapsulation Mechanism (Kyber‑768/1024, IND‑CCA2). |
| **Block 2** | `sample_mrs_hierarchical_cdf` | Multi‑layer Diophantine decomposition via a Weighted CDF Sampler (bias \(A_0 = N \mod 9\)). |
| **Block 3** | `k_acceptance_merkle_commitment` | Fixed‑depth balanced tree combining the authentic path with \(k-1\) decoy chains. |
| **Block 4** | `lwe_chain_isolation` | Encapsulation of the target chain within an LWE instance (\(b = A \cdot s + e\)). |
| **Coupling** | `hybrid_hkdf_coupling` | Asymmetric key derivation via HKDF paired with HMAC‑SHA256 time‑codes. |
| **Block 5** | `encrypt_payload`, `decrypt_payload` | AES‑256‑GCM AEAD authenticated encryption/decryption. |

---

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
mrs_auth_pqc = { git = "https://github.com/A19dammer91/MRS-Hybride-PQC" }
```

For local development:

```bash
git clone https://github.com/A19dammer91/MRS-Hybride-PQC.git
cd MRS-Hybride-PQC
cargo build --release
```

Note: Requires Rust 1.70+ and a nightly toolchain for some constant‑time features.

---

Usage Example

```rust
use mrs_auth_pqc::MrsAuthFramework;
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    // 1. Generate a post‑quantum keypair
    let keypair = MrsAuthFramework::keygen(&mut rng);

    // 2. Define session parameters
    let session_id = [0u8; 32];
    let hkdf_context = b"my-app-context";
    let nonce = [0u8; 12];
    let associated_data = b"metadata";
    let plaintext = b"Top secret message!";

    // 3. Encrypt
    let packet = MrsAuthFramework::full_encrypt(
        &keypair.public_key,
        &session_id,
        hkdf_context,
        &nonce,
        associated_data,
        plaintext,
    )?;

    // 4. Decrypt
    let decrypted = MrsAuthFramework::full_decrypt(
        &keypair.secret_key,
        &packet,
        &session_id,
        hkdf_context,
        &nonce,
        associated_data,
    )?;

    assert_eq!(decrypted, plaintext);
    println!("✅ Decryption successful!");
    Ok(())
}
```

---

Build & Test

```bash
cargo test
cargo bench
```

---

Formal Verification

All core security properties are machine‑verified with EasyCrypt.
See the proofs/ directory for the complete formalisation:

File Content
MRS_Core.ec Diophantine algebra and number‑theoretic lemmas.
MRS_Chain.ec Construction and verification of MRS chains.
MRS_Honey.ec Honey encryption layer (AEAD with HKDF).
MRS_AUTH.ec Temporal barrier, HMAC‑based authentication (EUF‑CMA + forward secrecy).
MRS_Sampling.ec Correctness of the Weighted CDF Sampler.
MRS_AUTH_KEM_Hybrid.ec IND‑CCA2 security proof of the hybrid KEM.
MRS_Deny.ec Formal proof of deniability (coercion resistance).

Key proven theorems:

· temporal_barrier_noninterference – resilience against timing attacks.
· mrs_auth_kem_ind_cca2 – hybrid KEM is IND‑CCA2 secure.
· timecode_euf_cma – time‑code authentication is EUF‑CMA secure.
· timecode_forward_secrecy – forward secrecy holds after key compromise.

---

Implementation Safeguards

· Constant‑time – branch‑free operations via subtle.
· Temporal Barrier – runtime limits abort on timeout (sample_mrs_eea_timed).
· Zeroize – secrets are automatically cleared from RAM.
· Formally verified – core security properties machine‑checked.

---

Limitations & Disclaimer

· Research‑phase – not yet audited for production.
· Performance – not fully optimised.
· Deniability – requires proper protocol integration.

---

Citation

Title: The Forest Analogy: Full Specification of the MRS-AUTH Cryptographic Framework
Author: Bilal El Issaoui
DOI: 10.5281/zenodo.21852606

---

License

MIT – see LICENSE for details.

```
