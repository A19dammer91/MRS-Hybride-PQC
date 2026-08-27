# MRS-AUTH

<p align="center">
  <em>Post-Quantum Coercion-Resistant Authentication Framework</em>
</p>

<p align="center">
  <a href="https://doi.org/10.5281/zenodo.21852606"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.21852606.svg" alt="DOI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://github.com/A19dammer91/MRS-Hybride-PQC/actions/workflows/rust.yml"><img src="https://img.shields.io/github/actions/workflow/status/A19dammer91/MRS-Hybride-PQC/rust.yml?branch=main&label=Tests" alt="Build Status"></a>
  <a href="https://github.com/A19dammer91/MRS-Hybride-PQC/actions/workflows/benchmark.yml"><img src="https://img.shields.io/github/actions/workflow/status/A19dammer91/MRS-Hybride-PQC/benchmark.yml?branch=main&label=Benchmark" alt="Benchmark"></a>
  <img src="https://img.shields.io/badge/Rust-1.70%2B-orange.svg" alt="Rust 1.70+">
  <img src="https://img.shields.io/badge/EasyCrypt-Verified-blue.svg" alt="EasyCrypt Verified">
</p>

> **MRS-AUTH** is a hybrid post-quantum cryptographic library combining **Kyber-1024 KEM** (NIST Level 5, IND-CCA2), **MRS(19,9) Diophantine chain sampling**, and **AES-256-GCM authenticated encryption**.
>
> It provides **information-theoretic deniability** — a coerced user can always produce a mathematically valid alternative credential (an *alibi chain*) that is indistinguishable from the true secret.

---

## Table of Contents

- [Overview](#overview)
  - [How Deniability Works](#how-deniability-works)
- [Comparison with Existing Systems](COMPARISON.md)
- [Security Properties](#security-properties)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Formal Verification](#formal-verification)
- [Benchmarks](#benchmarks)
- [Implementation Safeguards](#implementation-safeguards)
- [Project Structure](#project-structure)
- [Citation](#citation)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Overview

### How Deniability Works

MRS-AUTH provides **information-theoretic deniability** through *mathematical multiplicity*. Instead of a single secret key, the protocol builds a [forest of valid Diophantine chains](DENIABILITY.md) rooted in `N = 19A + 9B`. The authentic chain is drawn uniformly at random; every other chain is a mathematically perfect alibi. A coerced user can reveal *any* valid chain — the attacker cannot prove it is not the true one.

For the complete visual explanation, see [`DENIABILITY.md`](DENIABILITY.md).

Traditional authentication relies on a **single, unique secret**. Under coercion, a user has no recourse: revealing the secret compromises security; refusing reveals its existence.

MRS-AUTH solves this through **mathematical multiplicity**. The protocol is built on the nested linear Diophantine system:

```
N = 19A + 9B
```

For any valid `N`, there exist exponentially many representation families `(A, B)`. By recursively nesting this decomposition across **three functional layers** (`L = 3`), MRS-AUTH creates a *forest* of valid chains. The authentic chain is drawn uniformly at random from this forest. Every other chain in the forest is a **perfect alibi** — mathematically valid, structurally indistinguishable, and information-theoretically equivalent.

This gives the framework its core property: **the attacker and the coerced user stand in computationally isomorphic positions**.

> **Want the full picture?** See [`DENIABILITY.md`](DENIABILITY.md) for a visual, step-by-step explanation of the Forest Analogy, the three-layer Matryoshka nesting, and why the coerced user can always produce a perfect alibi.
>
> For a detailed comparison with existing coercion-resistant systems, see [`COMPARISON.md`](COMPARISON.md).

---

## Security Properties

| Property | Mechanism | Guarantee |
| :------- | :-------- | :-------- |
| **Post-Quantum Confidentiality** | Kyber-1024 KEM | IND-CCA2 secure against quantum adversaries (NIST Level 5) |
| **Deniability** | MRS(19,9) Diophantine forest sampling | Information-theoretic; unlimited alibi chains exist for every session |
| **Forward Secrecy** | Per-session ephemeral keys + HKDF | Compromise of long-term keys does not decrypt past sessions |
| **Integrity** | AES-256-GCM AEAD | Authenticated encryption with 128-bit authentication tag |
| **Timing Attack Resistance** | Constant-time operations via `subtle` | Branch-free comparison and selection |
| **Memory Safety** | `zeroize` + RAII drops | Secrets cleared from RAM on scope exit |
| **Computational Scale** | Native `u64` arithmetic | Supports N up to ~10¹⁸ with sub-microsecond sampling |

---

## Architecture

The protocol is organized into five functional blocks plus a hybrid coupling layer:

| Block | Module | Function | Description |
| :---- | :----- | :------- | :---------- |
| **1** | `crypto::hybrid` | `kyber_keygen` / `kyber_encapsulate` | Post-quantum Key Encapsulation (Kyber-1024) |
| **2** | `sampler::cdf_sampler` | `sample_three_layers` | O(1) triangle-valid sampling per layer with branch-free CDF selection |
| **3** | `security::merkle` | `build_k_acceptance_root` / `verify_k_acceptance_proof` | Balanced Merkle commitment mixing authentic and decoy chains |
| **4** | `security::lwe` | `isolate_chain_parameter` / `verify_lwe_match` | LWE-based masking of chain parameters (`b = A·s + e`) |
| **Coupling** | `crypto::hybrid` | `derive_hybrid_key` | HKDF-SHA256 key derivation mixing Kyber SS + MRS chain + session context |
| **5** | `crypto::hybrid` | `encrypt_payload_hybrid` / `decrypt_payload_hybrid` | AES-256-GCM AEAD encryption/decryption |
| **Auth** | `security::timecode` | `generate_timecode` | HMAC-SHA256 time-based authentication codes |

### Design Note: Why the Chain Travels in the Clear

The MRS chain is carried inside [`SecureEnvelope`](src/framework.rs) alongside the ciphertext. This is **not a leak**: deniability does not rely on hiding *which* chain was used, but on the fact that *every* chain in the forest is structurally identical. The receiver cannot regenerate the chain from `session_id` alone because sampling is cryptographically random (via `OsRng`). See the [Forest Symmetry Theorem](https://doi.org/10.5281/zenodo.21852606) (§3) for the formal proof.

---

## Installation

### Requirements

- **Rust** 1.70 or newer
- A **nightly toolchain** is recommended for full constant-time guarantees (some `subtle` features)

### From Git

Add to your `Cargo.toml`:

```toml
[dependencies]
mrs_auth_pqc = { git = "https://github.com/A19dammer91/MRS-Hybride-PQC" }
```

### Local Development

```bash
git clone https://github.com/A19dammer91/MRS-Hybride-PQC.git
cd MRS-Hybride-PQC
cargo build --release
```

---

## Quick Start

```rust
use mrs_auth_pqc::MrsAuthFramework;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate a post-quantum Kyber-1024 keypair
    let keypair = MrsAuthFramework::keygen()?;

    // 2. Define session parameters
    let session_id = b"session-2026-08-24";
    let nonce = [7u8; 12];          // Must be unique per key
    let associated_data = b"metadata";
    let plaintext = b"Top secret message!";

    // 3. Encrypt
    let envelope = MrsAuthFramework::full_encrypt(
        &keypair.public_key,
        session_id,
        &nonce,
        associated_data,
        plaintext,
    )?;

    // 4. Decrypt
    let decrypted = MrsAuthFramework::full_decrypt(
        &keypair.secret_key,
        &envelope,
        session_id,
        &nonce,
        associated_data,
    )?;

    assert_eq!(decrypted, plaintext);
    println!("Decryption successful!");
    Ok(())
}
```

---

## API Reference

### Top-Level Framework

Defined in [`src/framework.rs`](src/framework.rs).

```rust
pub struct MrsAuthFramework;

impl MrsAuthFramework {
    /// Generate a new Kyber-1024 keypair.
    pub fn keygen() -> Result<Keypair, FrameworkError>;

    /// Full deniable encapsulation: Kyber encapsulate → sample MRS chain
    /// → derive hybrid key → AES-256-GCM encrypt.
    pub fn full_encrypt(
        public_key: &[u8; KYBER_PUBLICKEYBYTES],
        session_id: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<SecureEnvelope, FrameworkError>;

    /// Full authenticated decryption.
    pub fn full_decrypt(
        secret_key: &[u8; KYBER_SECRETKEYBYTES],
        envelope: &SecureEnvelope,
        session_id: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, FrameworkError>;
}
```

### Core Types

| Type | Module | Description |
| :--- | :----- | :---------- |
| `Keypair` | `framework` | Kyber-1024 public/secret key pair |
| `SecureEnvelope` | `framework` | Carries Kyber ciphertext + AES payload + MRS chain |
| `HybridCiphertextPacket` | `crypto::hybrid` | Inner packet: Kyber ciphertext + AES-GCM payload |
| `MrsChain` | `sampler` | A 3-layer Diophantine chain with validity flag |
| `DiophantinePair` | `core::diophantine` | Single `(A, B)` representation at one layer |
| `TimeCode` | `security::timecode` | HMAC-SHA256 time-based authentication token |
| `LweInstance` | `security::lwe` | LWE masking instance (`b = A·s + e`) |
| `MerkleProof` | `security::merkle` | Merkle inclusion proof for k-acceptance |

### Low-Level Primitives

```rust
// --- Sampler ---
pub fn sample_three_layers(root_n: u64) -> Option<MrsChain>;

// --- Crypto ---
pub fn derive_hybrid_key(
    kyber_ss: &[u8; KYBER_SSBYTES],
    mrs_chain: &MrsChain,
    session_id: &[u8]
) -> Result<[u8; 32], &'static str>;

pub fn encrypt_payload_hybrid(
    key: &[u8; 32], nonce: &[u8; 12],
    plaintext: &[u8], associated_data: &[u8]
) -> Result<Vec<u8>, &'static str>;

pub fn decrypt_payload_hybrid(
    key: &[u8; 32], nonce: &[u8; 12],
    ciphertext: &[u8], associated_data: &[u8]
) -> Result<Vec<u8>, &'static str>;

// --- Security ---
pub fn generate_timecode(secret_anchor: &[u8], timestamp: u64) -> Result<TimeCode, &'static str>;

pub fn isolate_chain_parameter(
    secret_s: &[u64], noise_e: &[u64], modulus_q: u64
) -> Option<LweInstance>;

pub fn verify_lwe_match(
    instance: &LweInstance, claimed_s: &[u64],
    allowed_noise_bound: u64, modulus_q: u64
) -> Choice;

pub fn build_k_acceptance_root(
    chain_hashes: &[[u8; 32]], k_param: usize
) -> Option<[u8; 32]>;

pub fn verify_k_acceptance_proof(
    root: &[u8; 32], leaf_hash: &[u8; 32], proof: &MerkleProof
) -> Choice;
```

---

## Formal Verification

All core security properties are machine-verified in **EasyCrypt**. The proof scripts live in the [`proofs/`](proofs/) directory.

| File | Content |
| :--- | :------ |
| [`MRS_Core.ec`](proofs/MRS_Core.ec) | Diophantine algebra, Popoviciu cardinality, Frobenius bound |
| [`MRS_Chain.ec`](proofs/MRS_Chain.ec) | Construction and structural verification of MRS chains |
| [`MRS_Sampling.ec`](proofs/MRS_Sampling.ec) | Correctness of the weighted CDF sampler (Forest Symmetry) |
| [`MRS_Honey.ec`](proofs/MRS_Honey.ec) | Honey encryption layer (AEAD + HKDF) |
| [`MRS_AUTH.ec`](proofs/MRS_AUTH.ec) | Temporal barrier, HMAC authentication (EUF-CMA + forward secrecy) |
| [`MRS_AUTH_KEM_Hybrid.ec`](proofs/MRS_AUTH_KEM_Hybrid.ec) | IND-CCA2 security of the hybrid KEM construction |
| [`MRS_Deny.ec`](proofs/MRS_Deny.ec) | Formal proof of coercion resistance / deniability |

### Key Theorems

- **`temporal_barrier_noninterference`** — Runtime abort limits prevent timing side-channels.
- **`mrs_auth_kem_ind_cca2`** — The hybrid KEM satisfies IND-CCA2.
- **`timecode_euf_cma`** — Time-code authentication is EUF-CMA secure.
- **`timecode_forward_secrecy`** — Forward secrecy holds after long-term key compromise.
- **`deniability_unbounded`** — For every authentic chain there exist infinitely many alibi chains information-theoretically indistinguishable to any adversary.

---

## Benchmarks

Run the Criterion benchmark suite:

```bash
cargo bench --bench sampler_bench
```

### Sampling throughput (`u64`)

| Scale | Root N | Typical Time |
| :---- | :----- | :----------- |
| Small | ~10⁶ | < 1 µs |
| Moderate | ~10⁹ | ~1 µs |
| Large | ~10¹² | ~1–2 µs |
| Max `u64` | ~10¹⁸ | ~2–5 µs |

> **Note:** The sampler uses an **O(1) triangle fast-path** that avoids materialising the full representation family. This makes sampling practical even for the largest `u64` values, while the previous CDF-based approach required O(R(N)) memory and time.

Benchmark results are automatically generated in CI via [`.github/workflows/benchmark.yml`](.github/workflows/benchmark.yml).

---

## Implementation Safeguards

| Safeguard | Implementation |
| :-------- | :------------- |
| **Constant-Time** | All sensitive comparisons use `subtle::Choice` and `ConstantTimeEq`; no branch-on-secret. |
| **Zeroize** | All secret-bearing structs (`Keypair`, `MrsChain`, `TimeCode`, `LweInstance`, `HybridCiphertextPacket`) derive `Zeroize` with `#[zeroize(drop)]`. |
| **CSPRNG Sampling** | `sample_three_layers` draws from `OsRng` with rejection-sampling to eliminate modulo bias. |
| **Temporal Barrier** | Sampler enforces runtime bounds; aborts safely on timeout. |
| **Check-Ahead Filtering** | Triangle-condition validation + `R'(A) ≥ 2` lookahead guarantees every sampled path can be completed to a full 3-layer chain. |
| **Branch-Free Selection** | CDF index selection uses `ConditionallySelectable` over the full candidate slice — no early break, no secret-dependent branches. |

---

## Project Structure

```
MRS-Hybride-PQC/
├── Cargo.toml
├── LICENSE
├── README.md
├── .github/
│   └── workflows/
│       ├── rust.yml          # CI test runner
│       └── benchmark.yml     # Criterion benchmark CI
├── benches/
│   └── sampler_bench.rs      # u64 performance benchmarks
├── proofs/
│   ├── MRS_Core.ec
│   ├── MRS_Chain.ec
│   ├── MRS_Sampling.ec
│   ├── MRS_Honey.ec
│   ├── MRS_AUTH.ec
│   ├── MRS_AUTH_KEM_Hybrid.ec
│   └── MRS_Deny.ec
└── src/
    ├── lib.rs                # Public API re-exports
    ├── framework.rs          # MrsAuthFramework: encrypt/decrypt
    ├── core/
    │   ├── mod.rs
    │   └── diophantine.rs    # N = 19A + 9B algebra, Popoviciu, Frobenius
    ├── crypto/
    │   ├── mod.rs
    │   └── hybrid.rs         # HKDF key derivation + AES-256-GCM
    ├── sampler/
    │   ├── mod.rs
    │   └── cdf_sampler.rs    # O(1) triangle sampler + branch-free CDF fallback
    └── security/
        ├── mod.rs
        ├── timecode.rs       # HMAC-SHA256 time-codes
        ├── lwe.rs            # LWE chain isolation
        └── merkle.rs         # k-acceptance Merkle commitments
```

---

## Citation

If you use MRS-AUTH in academic work, please cite:

```bibtex
@misc{elissaoui2026forest,
  title        = {The Forest Analogy: Full Specification of the MRS-AUTH Cryptographic Framework},
  author       = {Bilal El Issaoui},
  year         = {2026},
  doi          = {10.5281/zenodo.21852606},
  howpublished = {Zenodo}
}
```

---

## Disclaimer

> **Research Prototype — Not for Production Use.**
>
> MRS-AUTH is an active **research-phase cryptographic framework**. It has not undergone independent third-party security audit, formal code review, or red-team penetration testing. The implementation, protocol integration, and deniability guarantees are subject to ongoing academic scrutiny and refinement.
>
> **Do not deploy in production environments** without further independent security review. The deniability properties require correct application-layer protocol integration; incorrect usage may void the information-theoretic guarantees claimed in the formal specification.

---

## License

This project is licensed under the **Apache-2.0** — see [LICENSE](LICENSE) for details.
