<!-- README.md: MRS-AUTH -->
<div align="center">

[![CI](https://github.com/A19dammer91/MRS-Hybride-PQC/actions/workflows/ci.yml/badge.svg)](https://github.com/A19dammer91/MRS-Hybride-PQC/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/github/actions/workflow/status/A19dammer91/MRS-Hybride-PQC/rust.yml?label=tests&style=flat-square&logo=githubactions&logoColor=white)](https://github.com/A19dammer91/MRS-Hybride-PQC/actions/workflows/rust.yml)
[![Benchmarks](https://img.shields.io/github/actions/workflow/status/A19dammer91/MRS-Hybride-PQC/benchmark.yml?label=benchmarks&style=flat-square&logo=githubactions&logoColor=white)](https://github.com/A19dammer91/MRS-Hybride-PQC/actions/workflows/benchmark.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![NIST](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20ML--KEM--1024-informational?style=flat-square)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Interactive Demo](https://img.shields.io/badge/demo-security%20game-ff69b4?style=flat-square&logo=googlechrome&logoColor=white)](demo/mrs-auth-security-game.html)

# MRS-AUTH

### Hybrid Post-Quantum Coercion-Resistant Authentication Framework

> **MRS-AUTH** is an experimental hybrid PQC authentication construction. It uses **NIST-standardized ML-KEM-1024** (FIPS 203, IND-CCA2) as its post-quantum confidentiality mechanism, and adds an independent **witness-space / coercion-resistance layer** on top, built on the structural multiplicity of MRS(19,9) Diophantine representations.
>
> It provides **witness ambiguity**: a coerced user can produce a mathematically valid alternative credential (an alternative witness), computationally indistinguishable from the authentic one without the master derivation key.

</div>

---

## Table of Contents

- [Overview](#overview)
- [The Crown Equations (Mathematical Core)](#-the-crown-equations-mathematical-core)
- [Why (19, 9)](#why-19-9)
- [Security Properties](#security-properties)
- [Threat Model: What This Does and Does Not Protect Against](#threat-model-what-this-does-and-does-not-protect-against)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Test Suite & Continuous Integration](#test-suite--continuous-integration)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Active Security Hardening & Formal Games](#active-security-hardening--formal-games)
- [Formal Verification](#formal-verification)
- [Benchmarks](#benchmarks)
- [Interactive Demo](#interactive-demo)
- [Research Notes](#research-notes)
- [Citation](#citation)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Overview

MRS-AUTH addresses the real-world threat of physical coercion, extortion, and duress in digital authentication. Traditional cryptographic systems rely on a **single, unique secret key**. Under coercion, a user has no recourse: revealing the secret compromises security, while refusal plaintextly proves the secret's existence.

MRS-AUTH introduces **mathematical multiplicity** through nested linear Diophantine systems. Instead of a single static key, the protocol constructs a **combinatorially large witness space** of valid credential chains rooted in the foundational equation:

$$\mathbf{N = 19A + 9B}$$

The authentic witness is deterministically derived from a master secret and bound to the user's identity via a cryptographic tag. Every other valid chain in the witness space acts as a valid, structurally equivalent alternative. By recursively nesting this decomposition across **three functional layers** ($L = 3$), the framework ensures that a coerced user can safely hand over an alternative witness. Because all witnesses within the space are structurally isomorphic without the master derivation key, an attacker stands in a computationally symmetric position and can never prove that a revealed witness is not the authentic one.

---

## 👑 The Crown Equations (Mathematical Core)

To eliminate the need for heavy $O(N)$ processing loops or brute-force enumeration, the framework compresses the entire Diophantine witness-space parameter calculations into a set of constant-time, closed-form equations.

These equations allow the `cdf_sampler` engine to complete the full 3-layer nesting process in **sub-microsecond execution loops** while maintaining complete side-channel immunity:

### 1. The Core Anchor Equation

$$A_0 = \text{dr}(N) = \begin{cases} 0 & N = 0 \\ 1 + ((N - 1) \bmod 9) & N > 0 \end{cases}$$

> _Strips away the scale of the public session root $N$ using the branch-free digital root to lock the absolute mathematical starting anchor ($1 \le A_0 \le 9$ for all $N > 0$)._
>
> _Crucially, `dr(N)` never returns 0 for $N > 0$, whereas `N mod 9` would. This guarantees that every layer in the `DEPTH = 3` chain always has a valid successor, a property `N mod 9` cannot ensure._

### 2. The Maximum Base Reconstruction

$$B_0 = \frac{N - 19A_0}{9}$$

> _Algebraically isolates the maximum starting boundary for the $B$-coefficient, ensuring perfect divisibility across layers without underflow leaks._

### 3. The Structural Bounds Filter ($K_{max}$)

$$K_{max} = \left\lfloor \frac{B_0}{19} \right\rfloor$$

> _Defines the exact window of valid transformations via Popoviciu's cardinality formula before the parameters underflow, mathematically establishing the boundaries of the witness space. The total number of representations at a layer is $R(N) = K_{max} + 1$._

### 4. The Triangle Condition (Closed-Form Filter)

The sampler further filters candidates via the harmonic triangle requirement:

$$\text{dr}(B) = \text{dr}(2 \cdot \text{dr}(N))$$

> _Only representations satisfying this digital-root triangle condition are admitted into the weighted CDF sampling pool. The closed-form count is computed in $O(1)$ via modular arithmetic on the step index $k$._

### 5. The O(1) Triangle Fast-Path Sampling Step

Given $a_0 = \text{dr}(N)$ and $b_0 = (N - 19a_0)/9$, the sampler draws a single valid representation in constant time:

$$\text{target} = \text{dr}(2 \cdot a_0)$$

$$k_0 = (b_0 + 9 - \text{target}) \bmod 9$$

$$k_{max} = \left\lfloor \frac{b_0}{19} \right\rfloor$$

$$t_{max} = \left\lfloor \frac{k_{max} - k_0}{9} \right\rfloor$$

$$t \sim \mathcal{U}[0, t_{max}] \quad \text{(rejection-free CSPRNG)}$$

$$k = k_0 + 9t$$

$$a = a_0 + 9k \qquad b = b_0 - 19k$$

> _Reconstructs the exact $(a, b)$ pair for the current layer in $O(1)$ without enumeration. For the 3-layer `sample_three_layers` engine this loop repeats with $N \leftarrow a$ until depth is reached._

---

## Why (19, 9)

The pair (19, 9) is not an arbitrary choice of constants. It is the smallest pair that generates the exact structural property the entire coercion resistance construction is built on, and this can be shown directly from the algebra.

### General setting

Consider equations of the general form

$$N = pA + qB, \qquad p \equiv 1 \pmod{q}$$

Write $p = mq + 1$.

### The parameter $m$

When $m = 1$ (for example $p = 10$, $q = 9$), level and row coincide. Every representability row occurs exactly once.

When $m = 2$, the case of the pair (19, 9), every row occurs exactly twice in succession. This is precisely what produces a real distinction between a row and a level: a level is composed of $m$ identical rows stacked together. With $m = 1$ that distinction cannot exist at all, because there is nothing to stack.

### The smallest interesting pair

(19, 9) is the smallest pair satisfying $p \equiv 1 \pmod{q}$ for which $m \ge 2$. It is therefore the simplest possible system in which the repeated-row structure becomes visible. This has been verified experimentally by systematically enumerating every value of $N$ from $0$ to $(p-1)(q-1) - 1$.

### The clock analogy

A 12 hour clock never reveals that a day contains two rounds; only a single round is ever visible on the dial. It takes a 24 hour clock, built from two full cycles of 12, to make the repetition visible: hour 1 and hour 13 land on the same position on the face, yet they are different moments of the day.

The same principle governs the Diophantine system. At $m = 1$ you only ever see the rows. At $m = 2$, as with 19 and 9, the repetition becomes visible and a genuine level structure emerges.

This is the mathematical reason MRS(19, 9) was chosen as the foundation of the framework. It is the smallest system in which the row/level distinction that the witness-space construction depends on exists in the first place.

---

## Security Properties

| Property | Mechanism | Guarantee |
|---|---|---|
| **Confidentiality** | ML-KEM-1024 (FIPS 203) | IND-CCA2, NIST Level 5 |
| **Coercion-Resistance** | MRS(19,9) witness ambiguity | Computationally indistinguishable witnesses without master key |
| **Forward Secrecy** | Per-session ephemeral keys + HKDF | Compromise of long-term keys does not decrypt past sessions |
| **Integrity** | AES-256-GCM AEAD | Authenticated encryption with 128-bit authentication tag |
| **Timing Attack Resistance** | Constant-time operations via `subtle` | Branch-free comparison and selection |
| **Memory Safety** | `zeroize` + RAII drops | Secrets cleared from RAM on scope exit |
| **Computational Scale** | Native `u64` (default) / `U256` (feature) | Supports standard machine words alongside an optional path for scaling up to $N \approx 10^{42}$ via features. |

---

## Threat Model: What This Does and Does Not Protect Against

Coercion resistant cryptography protects against a specific and well defined threat, and MRS-AUTH is precise about that scope by design.

MRS-AUTH is a mathematical descendant of Rubberhose (Assange et al.), the deniable filesystem built to resist rubber hose cryptanalysis. Rubberhose achieved plausible deniability by physically filling a disk with indistinguishable encrypted chaff: hiding 10 GB of real data convincingly meant padding out to something like 1 TB and pre-writing plausible decoy content in advance. MRS-AUTH moves that haystack from disk space into abstract mathematics. A single small three-layer chain (`MrsChain`) travels with the message, and alternative mathematical witnesses are generated on the fly by the Crown Equations sampler rather than stored in advance. It is a smaller, faster, post-quantum, storage-free evolution of the same idea, and it inherits Rubberhose's one structural limitation along with its strengths.

Under the assumptions described in [`DENIABILITY.md`](DENIABILITY.md) and [`proofs/WITNESS-INDISTINGUISHABILITY.md`](proofs/WITNESS-INDISTINGUISHABILITY.md), an adversary who obtains a witness cannot mathematically prove whether it is the authentic one or an alternative. The coerced user hands over a genuine, verifiable answer whose authenticity cannot be proven, replacing the binary choice ("reveal the real secret" or "refuse and confirm one exists") that traditional single-secret schemes force on the victim.

That guarantee operates at the level of mathematical proof, not psychology. An attacker who refuses to accept any witness short of a proof that no alternative witness exists will not be stopped by the mathematics, because that proof does not exist by design and cannot be produced. This is the same well understood limit shared by every deniable encryption or plausible deniability scheme, Rubberhose included: it defeats forensic and mathematical proof, and it always will, but it was never designed to override the intentions of the person applying coercion.

Verification power is deliberately concentrated. `MasterSecret::verify_authenticity` requires `master_secret` to distinguish `Authentic` from `BindingMismatch`, while the public `WitnessSpace::verify_membership` path only ever sees `ValidButUnbound`. Whoever holds `master_secret` in a given deployment, whether a server, the user's own device, or a split arrangement, is exactly whoever can tell an authentic witness from an alibi, and is therefore the natural target for a compromised-server or key-theft attacker seeking that same ability.

The intended deployment model reflects this directly. `master_secret` is held server-side, ideally inside a sealed enclave or microservice that runs `generate_authentic_witness` and `verify_authenticity` internally and never exports the key. At registration, the client receives one legitimate `Witness`, a mathematically valid path over the public `N`, and nothing else. If the client is later coerced, it computes an alternative path itself via `generate_alternative_witness`, using only the public `N` (through `WitnessSpace`) and its own randomness. `master_secret` is never needed for, and is never present in, that computation.

`generate_alternative_witness` lives on `WitnessSpace`, built only from public `N`, rather than on `MasterSecret`, even though earlier revisions defined it as a `MasterSecret` method that simply never touched the key. The boundary is enforced by the type system: client code producing an alibi has no path by which a `MasterSecret` value could even be constructed or passed in.

The result is a clean split. Against a coercer pressuring the client, coercion resistance holds exactly as designed: the client produces a valid alternative witness without ever needing, holding, or exposing `master_secret`. Against a compromised server or enclave, the model makes no claim: whoever holds `master_secret` can always distinguish authentic from alternative, which is inherent to centralized verification rather than a defect of this implementation.

MRS-AUTH has not undergone independent third-party audit and carries no formal certification of any kind, NIST or otherwise. The ML-KEM-1024 component follows the NIST FIPS 203 standard; MRS-AUTH's own coercion-resistance layer is a research construction with EasyCrypt proofs of the abstract model, not a certified or externally audited implementation.

---

## Architecture

The protocol is organized into five functional blocks plus a hybrid coupling layer:

| Block | Module | Function | Description |
|---|---|---|---|
| **1** | `crypto::hybrid` | `kyber_keygen` / `kyber_encapsulate` | Post-quantum Key Encapsulation (ML-KEM-1024) |
| **2** | `sampler::cdf_sampler` | `sample_three_layers` | $O(1)$ closed-form triangle-valid sampling per layer with correct $K_{max}$ structural bounds filtering |
| **3** | `security::witness` | `generate_authentic_witness` / `generate_alternative_witness` | Deterministic identity-bound witness derivation and coercion-resistant alternative witness generation |
| **4** | `security::merkle` | `build_k_acceptance_root` / `verify_k_acceptance_proof` | Balanced Merkle commitment over the witness space |
| **Coupling** | `crypto::hybrid` | `derive_hybrid_key` | HKDF-SHA256 key derivation mixing ML-KEM SS + MRS witness + session context |
| **5** | `crypto::hybrid` | `encrypt_payload_hybrid` / `decrypt_payload_hybrid` | AES-256-GCM AEAD encryption/decryption |
| **Auth** | `security::timecode` | `generate_timecode` / `run_with_temporal_barrier` | HMAC-SHA256 time-bound authentication codes protected via an interactive hardware clock barrier |

---

## Project Structure

```
MRS-Hybride-PQC/
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions: test, clippy, fmt, bench
├── Cargo.toml              # Crate manifest (features: default, bigint)
├── LICENSE                 # Apache-2.0
├── README.md               # This file
├── benches/
│   └── sampler_bench.rs    # Criterion benchmark suite
├── demo/
│   └── mrs-auth-security-game.html  # Interactive browser-based security demo
├── docs/
│   ├── user-manual.md      # English user manual for the interactive demo
│   └── research-notes/     # Exploratory ideas, not part of the crate API
│       ├── 90-366-2520-transformation.md
│       ├── sampler-90-366.md
│       └── witness-90-366.md
├── proofs/                 # EasyCrypt formal verification scripts
│   ├── MRS_Core.ec         # Diophantine algebra, Popoviciu cardinality, Frobenius bound
│   ├── MRS_Chain.ec        # Construction and structural verification of MRS chains
│   ├── MRS_Sampling.ec     # Correctness of the weighted CDF sampler (Witness Symmetry)
│   ├── MRS_Honey.ec        # Honey encryption layer (AEAD + HKDF)
│   ├── MRS_AUTH.ec         # Temporal barrier, HMAC authentication (EUF-CMA + forward secrecy)
│   ├── MRS_AUTH_KEM_Hybrid.ec  # IND-CCA2 security of the hybrid KEM construction
│   └── MRS_Deny.ec         # Formal proof of coercion resistance via witness ambiguity
└── src/
    ├── lib.rs              # Public API exports
    ├── framework.rs        # Top-level MrsAuthFramework
    ├── core/
    │   ├── mod.rs
    │   └── diophantine.rs  # DiophantinePair, Frobenius bound, Popoviciu cardinality
    ├── crypto/
    │   ├── mod.rs
    │   ├── hybrid.rs       # HKDF-SHA256 key derivation + AES-256-GCM AEAD
    │   └── shamir.rs       # Shamir Secret Sharing over GF(2^8) with commitment verification
    ├── sampler/
    │   ├── mod.rs
    │   └── cdf_sampler.rs  # Weighted CDF sampler, 3-layer chain builder
    └── security/
        ├── mod.rs
        ├── witness.rs      # Witness generation, identity binding, coercion resistance
        ├── timecode.rs     # Temporal barrier, HMAC timecodes, EUF-CMA & forward-secrecy games
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

---

## Test Suite & Continuous Integration

The complete cryptographic stack is covered by a comprehensive test suite that runs on every push via GitHub Actions. The current test matrix validates:

- **Authenticity & binding**: reproducible witness generation, session isolation, binding-tag verification.
- **Coercion-resistance**: statistical indistinguishability tests (authentic vs. alibi vs. duress).
- **Shamir Secret Sharing**: split/recover roundtrips, commitment-mismatch detection, subset recovery, duplicate detection.
- **At-rest protection**: AES-256-GCM seal/unseal roundtrip and wrong-key rejection.
- **Sampler correctness**: structural validity of generated Diophantine chains across all layers.
- **Cross-module integration**: end-to-end framework encryption/decryption.

```bash
cargo test                         # Run all unit tests
cargo test --all-features          # Include bigint extension tests
cargo bench --bench sampler_bench  # Criterion benchmarks
cargo fmt -- --check               # Verify formatting compliance
cargo clippy -- -D warnings        # Lint check
```

All tests pass in CI with zero failures. The suite exercises both the happy path and the adversarial edge cases (insufficient Shamir shares, wrong commitments, corrupted binding tags, duress-mode derivation) to ensure that error conditions are caught explicitly rather than silently ignored.

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

### Witness Authentication & Coercion Resistance

Defined in `src/security/witness.rs`.

`MasterSecret` is a multi-factor-derived, at-rest-sealable secret. Its
internal key material is private: it is only ever produced via `derive`,
recovered via `unseal`/`recover`, and consumed by the methods below.
`generate_alternative_witness` deliberately lives on `WitnessSpace`, not
on `MasterSecret`. See the [Threat Model](#threat-model-what-this-does-and-does-not-protect-against)
section above for why that boundary matters.

```rust
/// Operational mode of a MasterSecret. Contains no secret data, a tag only.
pub enum SecretMode {
    /// Real identity, used for authentication.
    Authentic,
    /// Panic mode: revealed under coercion, generates unbound witnesses.
    Duress,
}

/// Multi-factor input to MasterSecret::derive.
pub struct SecretInput {
    pub password: String,
    pub hardware_token: Option<[u8; 32]>,
    pub biometric_hash: Option<[u8; 32]>,
    pub salt: [u8; 16],
}

/// KDF configuration for MasterSecret::derive.
pub struct SecretConfig {
    pub argon2_params: Argon2Params,
    pub mode: SecretMode,
}

/// A share for Shamir Secret Sharing over GF(2^8).
pub struct KeyShare {
    pub index: u8,
    pub value: [u8; 32],
}

/// A MasterSecret encrypted at rest under a device key.
pub struct SealedMasterSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub mode: SecretMode,
}

/// The prover's long-term secret. Internal key material is private.
pub struct MasterSecret { /* private fields */ }

pub struct Witness {
    pub chain: MrsChain,
    pub binding_tag: [u8; 32],
    pub session_id: Vec<u8>,
}

/// An Alibi IS a Witness, but the type system treats it as distinct,
/// preventing accidental submission of an alibi where an authentic
/// witness is expected.
pub struct Alibi(pub Witness);

pub struct WitnessSpace {
    pub root_n: u64,
    pub depth: usize,
}

pub enum WitnessStatus {
    /// Mathematically valid in W_N but NOT bound to any identity.
    ValidButUnbound,
    /// Mathematically valid AND correctly bound to the claimed identity.
    Authentic,
    /// Fails the N = 19A + 9B structural checks.
    Invalid,
    /// Mathematically valid but the binding tag does not match.
    BindingMismatch,
}

pub enum DeriveError {
    KdfFailed,
    HkdfFailed,
    InvalidFactors,
    InsufficientEntropy,
    /// Not enough shares provided for recovery.
    InsufficientShares,
    /// Duplicate share indices detected.
    DuplicateShares,
    /// Recovered secret does not match the commitment (wrong or corrupted shares).
    CommitmentMismatch,
}

impl MasterSecret {
    /// Derive a master secret: Argon2id on the password, constant-time XOR
    /// with optional hardware/biometric factors, then HKDF-SHA256 with
    /// mode-specific domain separation.
    pub fn derive(input: &SecretInput, config: &SecretConfig) -> Result<Self, DeriveError>;

    /// Build the duress SecretInput from an authentic one (same factors,
    /// password + panic suffix).
    pub fn derive_duress_input(authentic: &SecretInput, panic_suffix: &str) -> SecretInput;

    /// Deterministically derive the identity- and session-bound authentic
    /// witness. Requires master_secret.
    pub fn generate_authentic_witness(
        &self,
        space: &WitnessSpace,
        identity: &[u8],
        session_id: &[u8],
    ) -> Option<Witness>;

    /// Verify the cryptographic binding of a witness to an identity.
    /// Requires master_secret. This is the verifier-side operation and
    /// is the only way to distinguish Authentic from BindingMismatch.
    pub fn verify_authenticity(&self, witness: &Witness, identity: &[u8]) -> WitnessStatus;

    /// Encrypt the master secret at rest under a device key (e.g. TPM-derived).
    pub fn seal(&self, device_key: &[u8; 32]) -> SealedMasterSecret;

    /// Recover a MasterSecret from a SealedMasterSecret. Fails if device_key
    /// is wrong.
    pub fn unseal(sealed: &SealedMasterSecret, device_key: &[u8; 32]) -> Result<Self, DeriveError>;

    pub fn mode(&self) -> SecretMode;

    /// Split the master secret into `shares` shares, `threshold` needed.
    /// Delegates to `crypto::shamir` (GF(2^8) with AES polynomial 0x11B).
    /// Returns the shares together with a public SHA-256 commitment to the
    /// original secret. The commitment must be stored alongside the shares
    /// and supplied to `recover` for integrity verification.
    pub fn split(&self, threshold: usize, shares: usize) -> Result<(Vec<KeyShare>, [u8; 32]), DeriveError>;

    /// Recover a master secret from a set of shares.
    /// Uses Lagrange interpolation in GF(2^8). The supplied `commitment`
    /// must be the value returned by `split` for this secret. Recovery
    /// fails with `CommitmentMismatch` if too few, wrong, or corrupted
    /// shares are supplied.
    pub fn recover(
        shares: &[KeyShare],
        commitment: &[u8; 32],
        mode: SecretMode,
    ) -> Result<Self, DeriveError>;
}

impl WitnessSpace {
    pub fn new(root_n: u64, depth: usize) -> Self;

    /// PUBLIC operation. Anyone can verify mathematical membership in W_N.
    /// Does NOT require master_secret and can only distinguish
    /// ValidButUnbound from Invalid, never Authentic or BindingMismatch.
    pub fn verify_membership(&self, witness: &Witness) -> WitnessStatus;

    /// PUBLIC operation. No MasterSecret needed anywhere in this call.
    /// Generates a mathematically valid witness that is NOT bound to any
    /// identity, suitable for handing over under coercion.
    pub fn generate_alternative_witness(
        &self,
        authentic: &Witness,
        rng: &mut impl RngCore,
    ) -> Option<Alibi>;
}

/// Implemented by WitnessSpace. Lets client code generate an alibi through
/// a trait object without ever having a MasterSecret value in scope.
pub trait ProverSpace {
    type WitnessType;
    type AlibiType;

    fn generate_alibi(
        &self,
        authentic: &Self::WitnessType,
        rng: &mut impl RngCore,
    ) -> Option<Self::AlibiType>;
}

/// SHA-256 hash of an MrsChain, used inside binding-tag computation.
pub fn hash_chain(chain: &MrsChain) -> [u8; 32];
```

### Low-Level Primitives

```rust
// --- Sampler ---
pub fn sample_three_layers_ct(root_n: u64, rng: &mut impl RngCore) -> Option<MrsChain>;

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

### 🎭 Witness Ambiguity: Mathematical Foundation

When a user is coerced, the `security::witness` module generates a mathematically valid alternative witness $w' \in \mathcal{W}_N$. This witness:

1. Satisfies the public Diophantine equations $N = 19A + 9B$ at every layer.
2. Is a member of the same witness space as the authentic witness.
3. Carries **no cryptographic binding tag**, so it cannot be linked to any identity.

Because all witnesses in $\mathcal{W}_N$ are structurally isomorphic without the master derivation key, the coercer cannot determine whether $w'$ is the authentic witness or an alternative, under a qualitative computational-indistinguishability argument (reducing to HMAC-SHA256 as a PRF and the underlying CSPRNG). This has not yet been reduced to a concrete, quantified adversary-advantage bound.

### 🔌 Feature Flag: Cryptographic Scale Scaling

By default, the core engine leverages bare-metal `u64` types to ensure lightning-fast benchmarks. For advanced multi-word operations matching the paper's largest entropy parameter sets ($N \approx 10^{42}$), a modular `crypto-bigint` stack can be toggled on-demand:

```bash
cargo test --features bigint
cargo build --release --features bigint
```

---

## Formal Verification

All core security properties are machine-verified in **EasyCrypt**. The proof scripts live in the `proofs/` directory.

> **Scope note:** these proofs verify properties of the abstract mathematical model, the Diophantine algebra, the sampler's idealized distribution, and the security games. They are not a line-by-line verification of the Rust implementation. The Rust code is built to correctly implement that mathematics, and implementation correctness is established through unit and regression tests rather than a formal link between the `.ec` scripts and the `.rs` source. Several implementation bugs were found and fixed this way during development, independently of the EasyCrypt proofs, which is exactly what that testing layer is for.

| File | Content |
|---|---|
| `MRS_Core.ec` | Diophantine algebra, Popoviciu cardinality, Frobenius bound |
| `MRS_Chain.ec` | Construction and structural verification of MRS chains |
| `MRS_Sampling.ec` | Correctness of the weighted CDF sampler (Witness Symmetry) |
| `MRS_Honey.ec` | Honey encryption layer (AEAD + HKDF) |
| `MRS_AUTH.ec` | Temporal barrier, HMAC authentication (EUF-CMA + forward secrecy) |
| `MRS_AUTH_KEM_Hybrid.ec` | IND-CCA2 security of the hybrid KEM construction |
| `MRS_Deny.ec` | Formal proof of coercion resistance via witness ambiguity, for the abstract model described above |

---

## Benchmarks

Run the Criterion benchmark suite:

```bash
cargo bench --bench sampler_bench
```

### Sampler Benchmark Results

Measured on a shared GitHub Actions runner (`ubuntu-latest`) via the CI
benchmark workflow. Absolute times reflect that specific shared runner
environment rather than dedicated, isolated hardware, so they are read
as throughput figures, not as side-channel claims (see the
[Formal Verification](#formal-verification) scope note above). Repeated
runs on shared runners can show more variance, occasionally into the
390 to 400 µs range depending on background load. The figures below are
from a low-noise run and stand as the representative baseline.

| Benchmark | Root N | Median Time | 95% CI |
|---|---|---|---|
| `sample_three_layers/small_1e6` | $\sim 10^6$ | 351.26 µs | [351.03, 351.62] µs |
| `sample_three_layers/moderate_1e9` | $\sim 10^9$ | 351.57 µs | [351.13, 352.16] µs |
| `sample_three_layers/large_1e12` | $\sim 10^{12}$ | 351.11 µs | [350.97, 351.28] µs |
| `sample_three_layers/max_u64_range_1e18` | $\sim 10^{18}$ | 352.03 µs | [351.00, 354.22] µs |

The near-constant timing across six orders of magnitude in `N` is the
expected result of the $O(1)$ closed-form Crown Equations sampling
described above: cost does not scale with the size of the public root,
only with the fixed `DEPTH = 3` layer count.

A handful of measurements per run are flagged by Criterion as mild/severe
outliers (typically 7–14 out of 100 samples); this is normal scheduling
noise on a shared, non-isolated CI runner rather than a property of the
algorithm itself.

---

## Interactive Demo

An interactive, browser-based visualization of the security proof is
available in [`demo/mrs-auth-security-game.html`](demo/mrs-auth-security-game.html).
It covers the Forest Game (Game⁰ vs. Game¹), adaptive attacker strategies,
per-field distribution histograms, a rolling accuracy timeline, and a
Shamir Secret Sharing walkthrough.

No build step, server, or external dependency is required; open the file
directly in any modern browser (Chrome, Firefox, Safari, Edge).

See [`docs/user-manual.md`](docs/user-manual.md) for a full walkthrough of
each tab, expected results, and troubleshooting tips.

---

## Research Notes

Exploratory extensions to the core framework, not implemented in `src/`
and not part of the crate's API, are documented in
[`docs/research-notes/`](docs/research-notes/).

The current note explores a transformation that multiplies a witness
pair by a constant factor of 90, which forces the digital root of every
resulting number to 9. An accompanying EasyCrypt proof draft formally
establishes that this transformation preserves the underlying MRS
equation, and that a bijection exists between the witness space for
N = 366 and its scaled counterpart at N = 32940, generalizing to a
larger supergrid at multiples of 2520. The proof further shows that an
adversary limited to checking digital roots gains no advantage in
distinguishing an authentic witness from an alibi in the transformed
space, consistent with the "A₀ Bias" strategy already tested empirically
in the [interactive demo](#interactive-demo).

- [`90-366-2520-transformation.md`](docs/research-notes/90-366-2520-transformation.md): the mathematical background and the formal findings
- [`sampler-90-366.md`](docs/research-notes/sampler-90-366.md): the draft sampler implementing the transformation
- [`witness-90-366.md`](docs/research-notes/witness-90-366.md): the draft authentication layer, including a related time-windowed witness scheme

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

> **Research Prototype.**
> MRS-AUTH is an active research-phase cryptographic framework, built on machine-checked EasyCrypt proofs of its abstract model and a comprehensive test suite for its Rust implementation. It has not undergone independent third-party security audit, formal code review, or red-team penetration testing, and it carries no certification of any kind, NIST or otherwise. Independent review is welcome, and treat production deployment accordingly until that review has happened.

---

## License

This project is licensed under the **Apache-2.0**: see LICENSE for details.
