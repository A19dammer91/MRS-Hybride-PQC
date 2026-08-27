# How Deniability Works in MRS-AUTH

> **The Forest Analogy** — *Every tree in the forest looks identical to the lumberjack, but only the owner knows which one is home.*

---

## The Problem with Traditional Secrets

In conventional cryptography, authentication relies on a **single secret**:

```
User  ──►  Secret Key  ──►  Proof of Identity
```

Under coercion, the user faces an impossible choice:
- **Reveal** the secret → security is broken forever.
- **Refuse** → the attacker knows a secret exists, and escalates pressure.

There is **no middle ground**. The secret is a binary liability.

---

## The MRS-AUTH Solution: Mathematical Multiplicity

MRS-AUTH replaces the single secret with a **forest of mathematically equivalent secrets**.

### The Core Equation

Every session is rooted in the Diophantine equation:

```
N = 19A + 9B
```

For any valid `N`, there are exponentially many pairs `(A, B)` that satisfy this equation. We call each pair a **representation**.

### Layer 1: The Representation Family

For a given `N`, all valid representations form a **family**:

```
N = 366
│
├── (A=6,  B=28)      ← valid ✓   [19×6 + 9×28 = 114 + 252 = 366]
├── (A=15, B=9)       ← valid ✓   [19×15 + 9×9 = 285 + 81 = 366]
├── (A=24, B=-10)     ← invalid (B negative)
└── ...
```

Using Popoviciu's formula, the number of valid representations is:

```
R(N) = floor((N - 19·A₀) / 171) + 1
```

where `A₀ = dr(N) = 1 + ((N - 1) mod 9)` (the digital root, never 0 for N > 0).

For `N = 366`: `A₀ = dr(366) = 1 + (365 mod 9) = 1 + 5 = 6`, so:
```
R(366) = floor((366 - 19×6) / 171) + 1
       = floor((366 - 114) / 171) + 1
       = floor(252 / 171) + 1
       = 1 + 1
       = 2 valid representations.
```

The two valid representations are **(A=6, B=28)** and **(A=15, B=9)**.

---

## The Three-Layer Matryoshka

A single layer is not enough. MRS-AUTH nests the decomposition **three layers deep**:

```
Layer 0 (Root N)
    │
    ├──► Pick (A₀, B₀) from family of N
    │       │
    │       └──► A₀ becomes the new N for Layer 1
    │
    Layer 1 (N = A₀)
        │
        ├──► Pick (A₁, B₁) from family of A₀
        │       │
        │       └──► A₁ becomes the new N for Layer 2
        │
        Layer 2 (N = A₁)
            │
            └──► Pick (A₂, B₂) from family of A₁
```

This creates a **chain**: `N → (A₀,B₀) → (A₁,B₁) → (A₂,B₂)`

### Visual: The Chain as a Path

```
                    Layer 0                    Layer 1                    Layer 2
                      │                          │                          │
    ┌─────────────────┼─────────────────┐      ┌─┼─┐                      ┌─┼─┐
    │                 │                 │      │ │ │                      │ │ │
  (A=6,B=28)    (A=15,B=9)         ...    (A=?,B=?)   ...            (A=?,B=?)   ...
    │                 │
    │                 │
    ▼                 ▼
  [Chain A]       [Chain B]
  (authentic)     (alibi)
```

Both Chain A and Chain B are **mathematically valid**. Both decrypt the message. Both are structurally indistinguishable.

---

## The Triangle Condition: Filtering the Forest

Not every representation can be nested. The **harmonic triangle condition** ensures only "nestable" pairs survive:

```
digital_root(B) == digital_root(2 × digital_root(X))
```

where `X` is the parent value at the current layer.

This acts as a **filter**: it removes dead-end branches from the forest, ensuring every remaining path can be extended to a full 3-layer chain.

### Example

```
Parent X = 5
  digital_root(5) = 5
  Target = digital_root(2 × 5) = digital_root(10) = 1

Candidate B = 10 → digital_root(10) = 1  ✓ VALID
Candidate B = 9  → digital_root(9)  = 9  ✗ INVALID
```

---

## The Forest Symmetry Theorem

Here is the critical insight:

> **Every complete 3-layer chain in the filtered forest is sampled with exactly equal probability.**

The sampler uses a **weighted CDF** where each candidate's weight equals the number of valid continuation chains beneath it. This guarantees uniform distribution over the entire forest of depth-3 chains.

### What This Means for Deniability

```
Attacker intercepts:  SecureEnvelope { kyber_ct, aes_payload, mrs_chain }

Attacker knows:
  ✓ The root N (derived from public session_id)
  ✓ The chain that was used (carried in the envelope)
  ✗ Which chain is "authentic" vs. "alibi"

Why? Because:
  • The sampler chose the chain randomly from the forest
  • Every other chain in the forest is mathematically valid
  • The user can plausibly claim ANY other chain was the "real" one
```

---

## The Coercion Scenario

```
┌─────────────────────────────────────────────────────────────────────┐
│                        COERCION SCENARIO                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Coercer                    User (under duress)                    │
│      │                            │                                 │
│      │  "Give me your secret!"   │                                 │
│      │───────────────────────────►│                                 │
│      │                            │                                 │
│      │  "Here is my chain:       │                                 │
│      │   (A=6, B=28) →           │                                 │
│      │   (A=3, B=2) →            │                                 │
│      │   (A=1, B=0)"             │                                 │
│      │◄───────────────────────────│                                 │
│      │                            │                                 │
│      │  Coercer verifies:         │                                 │
│      │  ✓ Chain is mathematically │                                 │
│      │    valid (passes all       │                                 │
│      │    Diophantine checks)     │                                 │
│      │  ✓ Chain decrypts the      │                                 │
│      │    message successfully    │                                 │
│      │  ✗ Coercer CANNOT prove    │                                 │
│      │    this was the ONLY       │                                 │
│      │    valid chain             │                                 │
│      │                            │                                 │
│   ┌──┴────────────────────────────┴──┐                              │
│   │   INFORMATION-THEORETIC          │                              │
│   │   ISOMORPHISM                    │                              │
│   │                                    │                              │
│   │   Attacker's knowledge  ≡  User's  │                              │
│   │   knowledge under coercion         │                              │
│   └────────────────────────────────────┘                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

The user gave a **real, working chain** — but it is not provably the *authentic* chain. The true chain remains hidden in the forest, and the user retains **plausible deniability**.

---

## Why the Chain Travels in the Clear

A common question: *"If deniability is the goal, why is the MRS chain sent alongside the ciphertext? Isn't that a leak?"*

**Answer: No.** Deniability does not rely on hiding *which* chain was used. It relies on the fact that *every* chain in the forest is **structurally and mathematically equivalent**.

```
Traditional deniability (hiding):
  "You can't prove I used chain X because you never saw it."

MRS-AUTH deniability (multiplicity):
  "You saw chain X, but chain Y, Z, W... are all equally valid.
   I could have used any of them. Prove I didn't."
```

The receiver needs the chain to re-derive the hybrid key for decryption. The chain is not secret — the **random choice** of which chain to use is the secret, and that randomness is gone after sampling.

---

## The Weighted CDF Sampler: Ensuring True Uniformity

Early versions of the sampler picked the "first valid" pair — this was **deterministic** and broke deniability (same `N` always produced the same chain).

The current implementation uses **cryptographically secure weighted sampling**:

```
1. Generate all triangle-valid candidates for current N
2. For each candidate, count how many valid 3-layer chains
   continue beneath it (check-ahead: R'(A) ≥ 2)
3. Assign weight = number of valid continuations
4. Draw from weighted distribution using OsRng + rejection sampling
5. Descend to next layer with chosen A as new N
```

This guarantees that **every complete chain in the forest has exactly the same probability** of being selected. No chain is "special."

---

## Summary: The Three Pillars of Deniability

| Pillar | Mechanism | Guarantee |
|--------|-----------|-----------|
| **Multiplicity** | `N = 19A + 9B` with Popoviciu cardinality | Exponentially many valid representations per layer |
| **Nesting** | 3-layer Matryoshka with triangle filtering | Every path is a complete, valid, nestable chain |
| **Uniformity** | Weighted CDF sampling via `OsRng` | No chain is distinguishable as "more likely" than any other |

Together, these create **information-theoretic deniability**: even an attacker with unbounded computational power cannot determine which chain was the authentic one.

---

## Further Reading

- [Full Paper (Zenodo)](https://doi.org/10.5281/zenodo.21852606) — Formal proofs of the Forest Symmetry Theorem
- [`proofs/MRS_Deny.ec`](proofs/MRS_Deny.ec) — EasyCrypt machine verification of deniability
- [`src/sampler/cdf_sampler.rs`](src/sampler/cdf_sampler.rs) — Implementation of the weighted sampler
- [`src/core/diophantine.rs`](src/core/diophantine.rs) — Diophantine algebra and Popoviciu formulas
