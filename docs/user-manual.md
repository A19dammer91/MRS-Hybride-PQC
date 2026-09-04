# MRS-AUTH — The Forest Analogy

## Complete Security Dashboard — User Manual


---

## 1. Overview

This interactive web demo visualizes the core security guarantee of the MRS-AUTH cryptographic framework. It formally demonstrates why an attacker cannot distinguish an **Authentic Witness** (Game⁰) from an **Alibi Witness** (Game¹) — while a server holding the MasterSecret can.

The dashboard consists of 5 tabs:

- **Forest Game** — Generate witnesses and observe indistinguishability
- **Adaptive Attacker** — Test 6 attack strategies
- **Histogram** — Compare per-field distributions
- **Timeline** — Rolling accuracy over time
- **Shamir SSS** — Secret sharing with commitment verification

Open `mrs-auth-security-game.html` in any modern browser (Chrome, Firefox, Safari, Edge). No internet connection is required; all code runs locally.

---

## 2. Tab 1: Forest Game

### 2.1 Purpose

Demonstrate that an attacker without the MasterSecret cannot determine the mode, despite full visibility of all 33 fields.

### 2.2 Buttons

| Button | Description |
|---|---|
| **Game⁰ — Authentic** | Generates a witness with an HMAC-SHA256 binding tag, cryptographically bound to identity + session + MasterSecret. |
| **Game¹ — Alibi** | Generates a witness with a random 32-byte binding tag. Mathematically valid, but unbound. |
| **🚨 Duress Mode** | Generates a witness using a "panic suffix" on the password. The chain is valid, but the HMAC tag mismatches against the server. |
| **Auto-run 50×** | Generates 50 random witnesses (fast). |
| **Auto-run 200×** | Generates 200 random witnesses. |
| **Reset All** | Clears all statistics and history. |

### 2.3 What you see

- **3-layer forest visualization**: root N → L1 → L2 → L3. The selected branch is highlighted; other branches are gray alibis.
- **Statistics**: total, attacker accuracy, server accuracy, duress counter
- **Progress bar**: converges toward 50% (indistinguishable)
- **Sparkline**: last 20 guesses (green = correct, red = incorrect)
- **Attacker log**: every guess with ✓/✗
- **Server panel**: always 100% correct — the server knows the MasterSecret
- **33 fields**: full transcript of the latest witness

### 2.4 Expected result

After 200+ runs: attacker accuracy ≈ 48–52%. The attacker performs no better than random guessing. The server remains at 100%.

---

## 3. Tab 2: Adaptive Attacker

### 3.1 Purpose

Test whether a "smart" attacker using heuristics can still distinguish between modes.

### 3.2 Strategies

| Strategy | Hypothesis |
|---|---|
| **Random (baseline)** | 50/50 guess, expected ~50% |
| **Tag Entropy** | AUTH tags have lower entropy |
| **T-Pattern** | t-values are correlated |
| **A₀ Bias** | Digital root a₀ clusters differently |
| **Chain Ratio** | The A/B ratio differs |
| **Combined** | Majority vote across all heuristics |

### 3.3 Usage

Click a strategy. The demo generates 100 (or 500) witnesses, applies the heuristic, and displays the accuracy as a bar chart.

### 3.4 Expected result

All strategies score ~45–55%. Bars within ±3% of 50% (shown in green) demonstrate that the attacker finds no structural signal. The dashed line marks the 50% baseline.

---

## 4. Tab 3: Histogram

### 4.1 Purpose

Compare the empirical distribution of each visible field between AUTH and ALIBI. If they are identical, the witnesses are computationally indistinguishable.

### 4.2 Usage

1. Click **Generate 1,000 samples** or **Generate 5,000 samples**
2. Select a field from the dropdown (e.g. "Layer 1: A")
3. Observe the overlapping histograms

### 4.3 Statistics

The Kolmogorov-Smirnov D-statistic and p-value are computed.

- **p > 0.05** → "✓ Distributions identical" (fail to reject H₀)
- **p ≤ 0.05** → "✗ Distributions differ" (reject H₀)

### 4.4 Expected result

For **all 12 fields**: p > 0.05. The histograms overlap almost perfectly. This demonstrates that the sampler produces the same distribution regardless of mode.

---

## 5. Tab 4: Timeline

### 5.1 Purpose

Show that attacker accuracy converges to 50% over time. This is the central security proof of MRS-AUTH.

### 5.2 Usage

Click **Run 100**, **Run 500**, or **Run 1,000**. The timeline shows a rolling-window accuracy (last 50 witnesses).

### 5.3 What you see

- Blue line: accuracy over time
- Dashed line: 50% baseline
- Filled area: spread around the line
- Stats below: mean, standard deviation, range

### 5.4 Expected result

Mean ≈ 50%, std ≈ 5–8%, range ≈ 30–70%. The line oscillates around the baseline with no systematic bias. This is the visual proof of Theorem 1 (Forest Symmetry) from the specification.

---

## 6. Tab 5: Shamir SSS

### 6.1 Purpose

Demonstrate Shamir Secret Sharing over GF(2⁸) with SHA-256 commitment. Show that "silent failure" (incorrect recovery without detection) is eliminated.

### 6.2 Usage

**Step 1: Split Secret (3-of-5)**
- Generates a random 32-byte secret
- Computes a SHA-256 commitment
- Splits it into 5 shares via a degree-2 polynomial over GF(2⁸) (AES irreducible polynomial: x⁸ + x⁴ + x³ + x + 1 = 0x11B)

**Step 2: Choose a recovery scenario**

| Button | Result |
|---|---|
| **Recover 3 shares ✓** | Correct recovery, commitment matches |
| **Recover 2 shares ✗** | Below threshold, commitment mismatch |
| **Recover tampered ✗** | 3 shares but 1 byte altered — commitment detects tampering |

**Step 3:** Click **Reset** to start over

### 6.3 What you see

- **Secret**: the original 32-byte secret (hex)
- **Commitment**: SHA-256 hash of the secret
- **5 share cards**: index + first 4 bytes (hex)
- **Vault status**: 🔒 locked / 🔓 open / ❌ failed

### 6.4 Expected result

Only "Recover 3 shares ✓" opens the vault. The other two scenarios fail explicitly with a "commitment mismatch" error — no silently wrong output.

---

## 7. Demonstration Tips

1. Start with **Forest Game**: generate 5–10 witnesses manually to show the structure (green = AUTH, red = ALIBI, orange = DURESS).
2. Run **Auto-run 200×** and switch to **Timeline**. Show the convergence.
3. Switch to **Histogram**, generate 5,000 samples, and step through all 12 fields. Emphasize that **all** p-values are > 0.05.
4. Switch to **Adaptive Attacker**, run "All Strategies (500×)". Show that even the "Combined" strategy stays below 55%.
5. Finish with **Shamir SSS**: split, show the shares, and demonstrate that tampering is detected. This is the "recovery mechanism" of the framework.

---

## 8. Formal Context

- **Game⁰** = Authentic Witness = HMAC(MasterSecret, identity ‖ session)
- **Game¹** = Alibi Witness = UniformRandom(32 bytes)
- **Adv** = |Pr[A(T⁰)=1] − Pr[A(T¹)=1]| ≤ negligible

The demo empirically verifies that Adv ≈ 0 across all 33 visible fields, all 6 adaptive strategies, and over 10,000+ samples.

Server-side distinguishability is **by design**: only the party holding the MasterSecret can verify the HMAC tag. A physical coercer does not have this key.

---

## 9. Technical Details

- **Sampler**: O(1) closed-form Crown Equations (N = 19A + 9B)
- **Depth**: 3 layers (L = 3)
- **Triangle condition**: dr(B) = dr(2·dr(N))
- **Digital root**: dr(n) = 1 + ((n − 1) mod 9)
- **GF(2⁸)**: AES polynomial 0x11B, branch-free Russian peasant multiplication
- **Commitment**: SHA-256 with domain separator
- **Charts**: HTML5 Canvas, no external libraries
- **Dark mode**: automatic via `prefers-color-scheme`

---

## 10. Troubleshooting

**Q: The canvas is empty / blurry**
A: Refresh the page. The canvas scales automatically with `devicePixelRatio`.

**Q: Auto-run seems stuck**
A: At 200×, it takes about 5 seconds. For extremely large N, the sampler can rarely fail; the demo skips these cases.

**Q: The Shamir vault won't open with 3 shares**
A: Make sure you clicked **Split Secret** first. Shares are not persisted — they are lost on page refresh.

**Q: The histogram shows "Generate samples"**
A: You need to click **Generate 1,000 samples** before a field can be selected.

---

*End of user manual*
