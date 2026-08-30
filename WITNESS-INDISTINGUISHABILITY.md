# Computational Indistinguishability of Witnesses

> **Status: informal hybrid argument, not machine-verified.** This document
> is a hand-written cryptographic reduction, not a formal proof in the
> sense of `MRS_Deny.ec` and the other scripts in this directory. It has
> not been independently reviewed. Treat it as a design-level argument for
> *why* witness indistinguishability should hold, not as an established
> security guarantee.

## 1. Goal

For a public value $N$, let $W_1, W_2, \dots, W_k$ denote the valid witness
presentations for $N$ (i.e. the members of the witness space
$\mathcal{W}_N$ produced by the sampler). We want:

$$W_i \approx_c W_j \quad \text{for all } i, j$$

where $\approx_c$ denotes computational indistinguishability: no efficient
adversary, given two witnesses without the master secret, can determine
which one is the identity-bound "authentic" witness and which is an
"alternative" (alibi) witness, except with negligible advantage.

## 2. Notation and Setup

Let $N$ be public, and fix `master_secret`, `id`. Define:

- **`Gen(N, id, s)`**: compute
  $\mathit{seed} = \mathrm{HMAC}(\mathit{master\_secret}, \texttt{"MRS-AUTH-SEED-v1"} \,\|\, \mathit{id} \,\|\, s \,\|\, \mathit{attempt})$,
  then run `sample_three_layers_ct_with_retries(N, DeterministicRng(seed), ·)`.
  Output: $W_{\mathrm{auth}}$.

- **`Alt(N, W_auth)`**: run the *same* sampler with `OsRng` in place of
  `DeterministicRng(seed)`, rejecting the result if it equals
  $W_{\mathrm{auth}}$. Output: $W_{\mathrm{alt}}$.

## 3. Experiment $\mathrm{Exp}_0$ (the real game)

1. Challenger computes $W_{\mathrm{auth}} = \mathrm{Gen}(N,\mathit{id},s)$,
   $W_{\mathrm{alt}} = \mathrm{Alt}(N, W_{\mathrm{auth}})$.
2. $b \leftarrow_\$ \{0,1\}$; give $(W_b, W_{1-b})$ to adversary $\mathcal{A}$
   (without `master_secret`).
3. $\mathcal{A}$ outputs a guess $b'$.
4. $\mathcal{A}$ wins iff $b' = b$.

$$\mathrm{Adv}_0(\mathcal{A}) := \left| \Pr[b'=b] - \tfrac{1}{2} \right|$$

**Goal:** show $\mathrm{Adv}_0(\mathcal{A})$ is negligible for every
efficient $\mathcal{A}$.

## 4. Hybrid 1 ($\mathrm{Exp}_1$): replace the seed derivation

Identical to $\mathrm{Exp}_0$, except that $\mathit{seed}$ in `Gen` is not
derived via HMAC, but drawn uniformly at random:
$\mathit{seed} \leftarrow_\$ \{0,1\}^{256}$, independent of
`master_secret`, `id`, `s`, `attempt`.

**Claim.**
$$\left| \mathrm{Adv}_0(\mathcal{A}) - \mathrm{Adv}_1(\mathcal{A}) \right| \le \mathrm{Adv}^{\mathrm{PRF}}_{\mathrm{HMAC}}(\mathcal{B})$$
for an efficient PRF-distinguisher $\mathcal{B}$.

**Reduction.** $\mathcal{B}$ has oracle access to either
$\mathrm{HMAC}(k, \cdot)$ or a genuine random function $f$. $\mathcal{B}$
simulates the experiment for $\mathcal{A}$, answering every call to
`derive_seed` by querying its oracle instead of computing HMAC itself, and
forwards $\mathcal{A}$'s output. If the oracle is real HMAC, this is
$\mathrm{Exp}_0$; if the oracle is random, this is $\mathrm{Exp}_1$. Any
gap in $\mathcal{A}$'s winning probability is therefore a PRF
distinguisher against HMAC-SHA256.

## 5. Hybrid 2 ($\mathrm{Exp}_2$): replace the RNG stream

Identical to $\mathrm{Exp}_1$, except that `DeterministicRng(seed)`'s
output stream (the SHA256-counter-mode buffer) is replaced by a genuinely
uniform random bitstream of the same length, independent of $\mathit{seed}$.

**Claim.**
$$\left| \mathrm{Adv}_1(\mathcal{A}) - \mathrm{Adv}_2(\mathcal{A}) \right| \le \mathrm{Adv}^{\mathrm{PRG}}_{\mathrm{SHA256\text{-}CTR}}(\mathcal{C})$$
for an efficient distinguisher $\mathcal{C}$ against SHA256-counter-mode
as a pseudorandom generator.

**Reduction.** Analogous — $\mathcal{C}$ replaces every buffer-refill call
with its own oracle answer (genuine SHA256-counter-mode output, or true
randomness) and forwards $\mathcal{A}$'s distinguishing output.

*Note:* because $\mathit{seed}$ in $\mathrm{Exp}_1$ is already uniform and
independent (thanks to Hybrid 1), this step is justified without any
further assumption about `derive_seed` itself.

## 6. Key Lemma: $\mathrm{Exp}_2$ is perfectly symmetric

In $\mathrm{Exp}_2$, `Gen` now also uses pure, uniform randomness — exactly
as `Alt` already does via `OsRng`. Both then call **the same** randomized
function, `sample_three_layers_ct_with_retries(N, ·)`, with independent
true coins.

Let $\mathcal{D}_N$ be the probability distribution this function induces
over $\{\text{valid witnesses in } \mathcal{W}_N\} \cup \{\bot\}$ (the
exhausted-attempts case). Then $W_{\mathrm{auth}}$ and $W_{\mathrm{alt}}$
in $\mathrm{Exp}_2$ are **two independent draws from the same**
$\mathcal{D}_N$, up to the rejection step enforcing
$W_{\mathrm{alt}} \ne W_{\mathrm{auth}}$ — a rejection that is symmetric
and carries no information about the label $b$.

Consequently, the pair $(W_b, W_{1-b})$, given $b$, is **identically
distributed regardless of $b$**: there is no statistical — let alone
computational — asymmetry in the outputs themselves that $\mathcal{A}$
could exploit to guess $b$.

$$\Rightarrow \quad \mathrm{Adv}_2(\mathcal{A}) = 0 \quad \text{for every, even computationally unbounded, } \mathcal{A}.$$

## 7. Final Result

$$\mathrm{Adv}_0(\mathcal{A}) \;\le\; \mathrm{Adv}^{\mathrm{PRF}}_{\mathrm{HMAC}}(\mathcal{B}) \;+\; \mathrm{Adv}^{\mathrm{PRG}}_{\mathrm{SHA256\text{-}CTR}}(\mathcal{C})$$

Both terms on the right are negligible under standard assumptions
(HMAC-SHA256 as a PRF; SHA256-counter-mode as a PRG, justified under the
random-oracle model for SHA256, which is already assumed implicitly
elsewhere in this scheme — `hash_chain`, `compute_binding_tag`). Hence
**$W_i \approx_c W_j$** follows, for any pair of witnesses produced by
`Gen` and `Alt` on the same $N$.

## 8. Explicit Scope Limitations

This argument does **not** cover the following, and should not be read as
establishing them:

1. **Timing side channels.** The argument above concerns black-box
   indistinguishability of the *outputs* $(W_b, W_{1-b})$. If an adversary
   can also measure wall-clock time, memory access patterns, or the exact
   number of RNG calls, that is a **separate** claim, standing or falling
   on the actual constant-time property of the implementation (the
   `Choice`/`subtle` discipline) rather than on this computational
   argument. Given how fragile the sampler logic turned out to be under
   review, this should not be assumed without dedicated verification
   (e.g. `dudect`-style statistical timing tests).

2. **Retry-count leakage at low success probability.** For $N$ with low
   per-attempt success probability $p$ (e.g. the ~88%-success cases found
   during review, as opposed to ~99%+ cases), the tail of the retry
   distribution is heavier. The argument above shows the *distribution* of
   the number of attempts is identical for both paths — but says nothing
   about how much information an adversary could extract from a single
   observation of "how many retries were needed," if that count is ever
   observable (e.g. via power analysis).

3. **Sampler bias is not covered by, but is harmless to, this proof.** As
   discussed separately: $W_i \approx_c W_j$ remains intact as long as
   `Gen` and `Alt` go through the **same** (possibly biased) sampler
   function — which is the case here. The argument above explicitly uses
   "`Gen` and `Alt` call the same function" as its starting assumption,
   not "the sampler is uniform." A sampler bias that is *symmetric*
   between the two paths is a correctness problem, not a distinguishing
   attack; an *asymmetric* bias between the authentic-generation and
   alternative-generation code paths would break this argument and has
   not been ruled out by any test in this repository.
