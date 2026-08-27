<div align="center">

[![Rust 1.70+](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-cargo%20test-brightgreen)]()
[![Benchmark](https://img.shields.io/badge/Benchmark-Criterion-yellow)]()
[![EasyCrypt](https://img.shields.io/badge/EasyCrypt-Verified-blueviolet)]()

</div>

# MRS-AUTH

### Post-Quantum Coercion-Resistant Authentication Framework

> **MRS-AUTH** is a hybrid post-quantum cryptographic library combining **ML-KEM-1024** (NIST FIPS 203, IND-CCA2), **MRS(19,9) Diophantine chain sampling**, and **AES-256-GCM authenticated encryption**.
>
> It provides **information-theoretic deniability** — a coerced user can always produce a mathematically valid alternative credential (an *alibi chain*) that is indistinguishable from the true secret.

---

## Table of Contents

- [Overview](#overview)
- [The Crown Equations (Mathematical Core)](#-the-crown-equations-mathematical-core)
- [Security Properties](#security-properties)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Active Security Hardening & Formal Games](#active-security-hardening--formal-games)
- [Formal Verification](#formal-verification)
- [Benchmarks](#benchmarks)
- [Citation](#citation)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Overview

MRS-AUTH solves the critical real-world problem of physical coercion, extortion, and duress in digital authentication. Traditional cryptographic systems rely on a **single, unique secret key**. Under coercion, a user has no recourse: revealing the secret compromises security, while refusing to cooperate plaintextly proves the secret's existence.

MRS-AUTH introduces **mathematical multiplicity** through nested linear Diophantine systems. Instead of a single static key, the protocol builds an infinite forest of valid cryptographic chains rooted in the foundational equation:

$$\mathbf{N = 19A + 9B}$$

The authentic chain is drawn uniformly at random from this distribution; every other chain in the forest acts as a mathematically perfect alibi. By recursively nesting this decomposition across **three functional layers** ($L = 3$), the framework ensures that a coerced user can safely hand over an alternative "alibi" credential. Because all paths within the forest are structurally indistinguishable, an attacker stands in a computationally isomorphic position and can never prove it is not the true secret.

---

## 👑 The Crown Equations (Mathematical Core)

To eliminate the need for heavy $O(N)$ processing memory loops or brute-force enumeration, the framework compresses the entire Diophantine forest parameter calculations into a highly elegant set of constant-time, closed-form equations.

These equations allow the `cdf_sampler` engine to complete the full 3-layer nesting process in **sub-microsecond execution loops** while maintaining complete side-channel immunity:

### 1. The Core Anchor Equation

$$A_0 = \text{dr}(N) = \begin{cases} 0 & N = 0 \\ 1 + ((N - 1) \bmod 9) & N > 0 \end{cases}$$

> *Strips away the scale of the public session root $N$ using the branch-free digital root to lock the absolute mathematical starting anchor ($1 \le A_0 \le 9$ for all $N > 0$).*
>
> *Crucially, `dr(N)` never returns 0 for $N > 0$, whereas `N mod 9` would. This guarantees that every layer in the `DEPTH = 3` Matryoshka chain always has a valid successor — a property `N mod 9` cannot ensure.*

### 2. The Maximum Base Reconstruction

$$B_0 = \frac{N - 19A_0}{9}$$

> *Algebraically isolates the maximum starting boundary for the $B$-coefficient, ensuring perfect modulo divisibility across layers without underflow leaks.*

### 3. The Structural Bounds Filter ($K_{max}$)

$$K_{max} = \left\lfloor \frac{B_0}{19} \right\rfloor \quad \text{or} \quad K_{max} = R(N) - 1$$

> *Defines the exact window of valid alibi transformations via Popoviciu's cardinality formula before the parameters underflow, mathematically establishing the boundaries of the alibi forest.*

---

## Security Properties

| Property | Mechanism | Guarantee |
| :--- | :--- | :--- |
| **Post-Quantum Confidentiality** | ML-KEM-1024 | IND-CCA2 secure against quantum adversaries (NIST Level 5) |
| **Deniability** | MRS(19,9) Diophantine forest sampling | Information-theoretic; unlimited alibi chains exist for every session |
| **Forward Secrecy** | Per-session ephemeral keys + HKDF | Compromise of long-term keys does not decrypt past sessions |
| **Integrity** | AES-256-GCM AEAD | Authenticated encryption with 128-bit authentication tag |
| **Timing Attack Resistance** | Constant-time operations via `subtle` | Branch-free comparison and selection |
| **Memory Safety** | `zeroize` + RAII drops | Secrets cleared from RAM on scope exit |
| **Computational Scale** | Native `u64` (default) / `U256` (feature) | Supports standard machine words alongside an optional path for scaling up to $N \approx 10^{42}$ via features. |

---

## Architecture

The protocol is organized into five functional blocks plus a hybrid coupling layer:

| Block | Module | Function | Description |
| :--- | :--- | :--- | :--- |
| **1** | `crypto::hybrid` | `kyber_keygen` / `kyber_encapsulate` | Post-quantum Key Encapsulation (ML-KEM-1024) |
| **2** | `sampler::cdf_sampler` | `sample_three_layers` | O(1) closed-form triangle-valid sampling per layer with correct $K_{max}$ structural bounds filtering (see **Crown Equation 3**) |
| **3** | `security::merkle` | `build_k_acceptance_root` / `verify_k_acceptance_proof` | Balanced Merkle commitment mixing authentic and decoy chains |
| **4** | `security::lwe` | `isolate_chain_parameter` / `verify_lwe_match` | LWE-based masking of chain parameters ($b = A \cdot s + e$) |
| **Coupling** | `crypto::hybrid` | `derive_hybrid_key` | HKDF-SHA256 key derivation mixing ML-KEM SS + MRS chain + session context |
| **5** | `crypto::hybrid` | `encrypt_payload_hybrid` / `decrypt_payload_hybrid` | AES-256-GCM AEAD encryption/decryption |
| **Auth** | `security::timecode` | `generate_timecode` / `run_with_temporal_barrier` | HMAC-SHA256 time-bound authentication codes protected via an interactive hardware clock barrier |
| **Alibi** | `security::alibi` | `generate_alibi_proof` | Forges computationally indistinguishable LWE secrets and Merkle paths under coercion |

---

## Project Structure

```
MRS-Hybride-PQC/
├── Cargo.toml              # Crate manifest (features: default, bigint)
├── LICENSE                 # Apache-2.0
├── README.md               # This file
├── benches/
│   └── sampler_bench.rs    # Criterion benchmark suite
├── proofs/                 # EasyCrypt formal verification scripts
│   ├── MRS_Core.ec         # Diophantine algebra, Popoviciu cardinality, Frobenius bound
│   ├── MRS_Chain.ec        # Construction and structural verification of MRS chains
│   ├── MRS_Sampling.ec     # Correctness of the weighted CDF sampler (Forest Symmetry)
│   ├── MRS_Honey.ec        # Honey encryption layer (AEAD + HKDF)
│   ├── MRS_AUTH.ec         # Temporal barrier, HMAC authentication (EUF-CMA + forward secrecy)
│   ├── MRS_AUTH_KEM_Hybrid.ec  # IND-CCA2 security of the hybrid KEM construction
│   └── MRS_Deny.ec         # Formal proof of coercion resistance / deniability
└── src/
    ├── lib.rs              # Public API exports
    ├── framework.rs        # Top-level MrsAuthFramework
    ├── core/
    │   ├── mod.rs
    │   └── diophantine.rs  # DiophantinePair, Frobenius bound, Popoviciu cardinality
    ├── crypto/
    │   ├── mod.rs
    │   └── hybrid.rs       # HKDF-SHA256 key derivation + AES-256-GCM AEAD
    ├── sampler/
    │   ├── mod.rs
    │   └── cdf_sampler.rs  # Weighted CDF sampler, 3-layer Matryoshka chain builder
    └── security/
        ├── mod.rs
        ├── timecode.rs     # Temporal barrier, HMAC timecodes, EUF-CMA & forward-secrecy games
        ├── lwe.rs          # LWE-based parameter masking
        └── merkle.rs       # Merkle commitment and inclusion proofs
```

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

### With BigInt Support (Optional)

For advanced multi-word operations matching the paper's largest entropy parameter sets ($N \approx 10^{42}$):

```toml
[dependencies]
mrs_auth_pqc = { git = "https://github.com/A19dammer91/MRS-Hybride-PQC", features = ["bigint"] }
```

### Local Development

```bash
git clone https://github.com/A19dammer91/MRS-Hybride-PQC.git
cd MRS-Hybride-PQC
cargo build --release
```

### Running Tests

```bash
cargo test                         # Unit tests across all modules
cargo test --all-features          # Include bigint extension tests
cargo bench --bench sampler_bench  # Criterion benchmarks
```

---

## Quick Start

```rust
use mrs_auth_pqc::MrsAuthFramework;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Generate a post-quantum ML-KEM-1024 keypair
    let keypair = MrsAuthFramework::keygen()?;

    // 2. Define session parameters
    let session_id = b"session-2026-08-24";
    let nonce = [7u8; 12]; // Must be unique per key
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

Defined in `src/framework.rs`.

```rust
pub struct MrsAuthFramework;

impl MrsAuthFramework {
    pub fn keygen() -> Result<Keypair, FrameworkError>;

    pub fn full_encrypt(
        public_key: &[u8; KYBER_PUBLICKEYBYTES],
        session_id: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<SecureEnvelope, FrameworkError>;

    pub fn full_decrypt(
        secret_key: &[u8; KYBER_SECRETKEYBYTES],
        envelope: &SecureEnvelope,
        session_id: &[u8],
        nonce: &[u8; 12],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, FrameworkError>;
}
```

### Key Types

```rust
pub struct Keypair {
    pub public_key: [u8; pqc_kyber::KYBER_PUBLICKEYBYTES],
    pub secret_key: [u8; pqc_kyber::KYBER_SECRETKEYBYTES],
}

pub struct SecureEnvelope {
    pub packet: HybridCiphertextPacket,
    pub mrs_chain: MrsChain,
}

pub struct MrsChain {
    pub layers: Vec<DiophantinePair>,
    pub valid: bool,
}

pub struct DiophantinePair {
    pub a: u64,
    pub b: u64,
}
```

### Low-Level Primitives

```rust
// --- Sampler ---
pub fn sample_three_layers(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain>;

// --- Security & Hardening Games ---
pub fn run_with_temporal_barrier<F, T>(timeout: Duration, f: F) -> Option<T>
where F: FnOnce() -> T, T: Zeroize;

pub fn run_euf_cma_game(adversary: &dyn EufCmaAdversary, secret_anchor: &[u8]) -> bool;
pub fn run_forward_secrecy_game(
    adversary: &dyn ForwardSecrecyAdversary,
    secret_anchor: &[u8],
    current_t: u64,
    rng: &mut impl RngCore
) -> bool;

pub fn generate_alibi_proof(
    public_root: &[u8; 32],
    alibi_chain: MrsChain,
    instance: &LweInstance,
    sibling_hashes: Vec<[u8; 32]>,
    allowed_noise_bound: u64,
    modulus_q: u64,
) -> AlibiEvidence;

// --- LWE Masking ---
pub fn isolate_chain_parameter(secret_s: &[u64], noise_e: &[u64], modulus_q: u64) -> Option<LweInstance>;
pub fn verify_lwe_match(instance: &LweInstance, claimed_s: &[u64], allowed_noise_bound: u64, modulus_q: u64) -> Choice;

// --- Merkle Commitments ---
pub fn build_k_acceptance_root(chain_hashes: &[[u8; 32]], k_param: usize) -> Option<[u8; 32]>;
pub fn verify_k_acceptance_proof(root: &[u8; 32], leaf_hash: &[u8; 32], proof: &MerkleProof) -> Choice;
```

---

## Active Security Hardening & Formal Games

The framework implements strict runtime safeguards and interactive simulation games directly mapped from our formal computer-checked verification proofs (`MRS_AUTH.ec`):

- **Part I: Temporal Barrier & RAM Zeroization:** Standard execution logs are actively decoupled from cryptographic exposure. If the hardware execution timeline monitored via `std::time::Instant` hits a policy threshold, internal state registers are instantly overwritten via `.zeroize()` to completely mitigate timing side-channel leaks.
- **Part III: EUF-CMA Forgery Resistance:** Natively tested via an integrated `BlindForger` adversary simulation to mathematically prove that unauthorized token generation on un-queried epochs is computationally infeasible.
- **Part IV: Forward Secrecy Indistinguishability:** Evaluated against an active epoch compromise engine (`PassiveGuesser` environment) to ensure that historical keys remain structurally indistinguishable from pure binomial entropy noise.

### 🔌 Feature Flag: Cryptographic Scale Scaling

By default, the core engine leverages bare-metal `u64` types to ensure lightning-fast benchmarks. For advanced multi-word operations matching the paper's largest entropy parameter sets ($N \approx 10^{42}$), a modular `crypto-bigint` stack can be toggled on-demand:

```bash
cargo test --features bigint
cargo build --release --features bigint
```

---

## Formal Verification

All core security properties are machine-verified in **EasyCrypt**. The proof scripts live in the `proofs/` directory.

| File | Content |
| :--- | :--- |
| `MRS_Core.ec` | Diophantine algebra, Popoviciu cardinality, Frobenius bound |
| `MRS_Chain.ec` | Construction and structural verification of MRS chains |
| `MRS_Sampling.ec` | Correctness of the weighted CDF sampler (Forest Symmetry) |
| `MRS_Honey.ec` | Honey encryption layer (AEAD + HKDF) |
| `MRS_AUTH.ec` | Temporal barrier, HMAC authentication (EUF-CMA + forward secrecy) |
| `MRS_AUTH_KEM_Hybrid.ec` | IND-CCA2 security of the hybrid KEM construction |
| `MRS_Deny.ec` | Formal proof of coercion resistance / deniability |

---

## Benchmarks

Run the Criterion benchmark suite:

```bash
cargo bench --bench sampler_bench
```

### Sampling throughput (`u64`)

| Scale | Root N | Typical Time |
| :--- | :--- | :--- |
| Small | $\sim 10^6$ | < 1 µs |
| Moderate | $\sim 10^9$ | $\sim 1$ µs |
| Large | $\sim 10^{12}$ | $\sim 1$–$2$ µs |
| Max `u64` | $\sim 10^{18}$ | $\sim 2$–$5$ µs |

---

## Citation

If you use MRS-AUTH in academic work, please cite:

```bibtex
@misc{elissaoui2026forest,
  title = {The Forest Analogy: Full Specification of the MRS-AUTH Cryptographic Framework},
  author = {Bilal El Issaoui},
  year = {2026},
  doi = {10.5281/zenodo.21852606},
  howpublished = {Zenodo}
}
```

---

## Disclaimer

> **Research Prototype — Not for Production Use.**
> MRS-AUTH is an active research-phase cryptographic framework. It has not undergone independent third-party security audit, formal code review, or red-team penetration testing. Do not deploy in production environments without further independent security review.

---

## License

This project is licensed under the **Apache-2.0** — see [LICENSE](LICENSE) for details.
