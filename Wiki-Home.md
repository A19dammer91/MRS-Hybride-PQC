# Welcome to the MRS-AUTH Wiki

> **MRS-AUTH** -- A hybrid post-quantum cryptographic library combining Kyber-1024 KEM, MRS(19,9) Diophantine chain sampling, and AES-256-GCM authenticated encryption with information-theoretic deniability.

---

## Documentation

| Document | Description |
|----------|-------------|
| [README](../blob/main/README.md) | Main project overview, installation, quick start, API reference |
| [DENIABILITY.md](../blob/main/DENIABILITY.md) | Visual explanation of the Forest Analogy, 3-layer Matryoshka nesting, and how deniability works |
| [COMPARISON.md](../blob/main/COMPARISON.md) | Detailed comparison with existing coercion-resistant systems (TrueCrypt, HoneyWords, Shadowfax, etc.) |
| [LICENSE](../blob/main/LICENSE) | MIT License |

---

## Quick Links

- **Source Code**: [src/](../tree/main/src)
- **Formal Proofs**: [proofs/](../tree/main/proofs) (EasyCrypt)
- **Benchmarks**: [benches/](../tree/main/benches)
- **CI Status**: [GitHub Actions](../actions)
- **Zenodo DOI**: [10.5281/zenodo.21852606](https://doi.org/10.5281/zenodo.21852606)

---

## Architecture Overview

```
+-------------------------------------------------------------+
|                      MRS-AUTH Pipeline                       |
+-------------------------------------------------------------+
|  Block 1: Kyber-1024 KEM          ->  Post-quantum keypair  |
|  Block 2: MRS(19,9) Sampler       ->  3-layer Diophantine   |
|  Block 3: Merkle Commitment       ->  k-acceptance tree     |
|  Block 4: LWE Isolation           ->  Mask chain params     |
|  Coupling: HKDF-SHA256            ->  Hybrid key derivation |
|  Block 5: AES-256-GCM             ->  Authenticated encrypt |
|  Auth: HMAC Time-Codes            ->  Temporal verification |
+-------------------------------------------------------------+
```

---

## Formal Verification

All core security properties are machine-verified in EasyCrypt:

| Proof File | Property |
|------------|----------|
| `MRS_Core.ec` | Diophantine algebra & Popoviciu cardinality |
| `MRS_Chain.ec` | MRS chain construction & verification |
| `MRS_Sampling.ec` | Weighted CDF sampler correctness |
| `MRS_Honey.ec` | Honey encryption layer (AEAD + HKDF) |
| `MRS_AUTH.ec` | Temporal barrier, EUF-CMA, forward secrecy |
| `MRS_AUTH_KEM_Hybrid.ec` | IND-CCA2 security of hybrid KEM |
| `MRS_Deny.ec` | Formal proof of deniability |

---

## Development

```bash
# Clone
git clone https://github.com/A19dammer91/MRS-Hybride-PQC.git
cd MRS-Hybride-PQC

# Build
cargo build --release

# Test
cargo test

# Benchmark
cargo bench --bench sampler_bench
```

---

## Citation

```bibtex
@misc{elissaoui2025forest,
  title  = {The Forest Analogy: Full Specification of the MRS-AUTH Cryptographic Framework},
  author = {Bilal El Issaoui},
  year   = {2025},
  doi    = {10.5281/zenodo.21852606}
}
```

---

## Disclaimer

MRS-AUTH is a **research-phase cryptographic framework**. It has not undergone independent third-party security audit and is **not recommended for production use** without further review.
