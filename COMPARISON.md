# MRS-AUTH in Perspective: A Comparison with Coercion-Resistant Systems

> To paint an honest picture: I compare MRS-AUTH with the most influential coercion-resistant systems, but note that most of these protect encryption (confidentiality), whereas MRS-AUTH focuses on authentication (proof of identity) under duress.

---

## 🛡️ Existing Approaches Compared

### 1. Hidden Volumes (TrueCrypt / VeraCrypt)

This is the best-known method for plausible deniability. A hidden volume hides inside the free space of a normal volume; the correct key unlocks one, a different key unlocks the other. It protects against forced decryption of a disk.

**Weakness:** The presence of a hidden volume is not always invisible. Research shows that detailed ciphertext analysis can reveal the existence of such a volume. Moreover, the design is vulnerable to write patterns on SSDs. The technology is fundamentally limited to two layers and protects data, not identity.

---

### 2. Chaffing and Winnowing (Rivest)

Rivest devised a system where a message is split into packets ('wheat') and fake packets ('chaff'). Only the receiver with the correct authentication key can separate the wheat from the chaff.

**Weakness:** Security depends on the attacker's inability to distinguish wheat from chaff. It offers no protection if an attacker can force the secret key out. It is an elegant idea, but operationally vulnerable and provides no protection against compelled key disclosure.

---

### 3. KEM Combiners (e.g., Shadowfax)

Modern post-quantum protocols such as PQXDH have often lost their deniability. Shadowfax is a hybrid KEM combiner specifically designed to preserve deniability during the transition to quantum-safe cryptography.

**Focus:** It preserves existing deniability properties of classical systems in a post-quantum context. It is a preserving, not an innovating, approach to the problem.

---

### 4. Anamorphic Encryption

A recent technique where a hidden communication channel is embedded inside normal-looking encryption. However, the standard and secret decryption processes are structurally asymmetric. An adversary who holds all keys can recognise the 'normal' channel, undermining deniability.

---

### 5. HoneyWords / Honey Encryption (Juels & Rivest, 2013; Tyagi et al., 2015)

This system stores multiple 'honey' passwords alongside the real one. An attacker who forces a password disclosure has a 1/k chance of picking the right one. Honey Encryption generates plausible-looking but false plaintext for every wrong password.

**Weakness:** The honey passwords must be explicitly generated and stored. Security depends on a central 'checker' that tracks which password is real — a single point of failure. Moreover, it requires explicit storage of false keys, introducing an operational vulnerability.

---

## ⚖️ How Does MRS-AUTH Compare?

MRS-AUTH differs fundamentally on three points:

### 1. Different Objective: Authentication, Not Confidentiality

Hidden volumes, chaffing, and anamorphic encryption protect the content of a message. They try to hide a secret. MRS-AUTH, by contrast, protects identity and authentication. The goal is not to hide a message, but to present a mathematically correct identity under duress without betraying the real one.

### 2. Mathematical Rather Than Operational Deniability

Hidden volumes are operationally vulnerable (forensic traces, SSD issues). HoneyWords require explicit storage of false keys. MRS-AUTH is built on a mathematical property: the multiplicity of representations in the Diophantine system `N = 19A + 9B`. For every `N`, multiple valid `(A,B)` pairs exist.

For a passive adversary who observes only a single session, all valid chains are a priori equiprobable. There is no structural difference between the observed chain and any other path in the forest. A coerced user can present any of these pairs as an 'alibi'. The system offers a forest of possible paths. The adversary observes one path, but because every path is mathematically equivalent, the user can plausibly claim that this is an alibi. There is no structural 'fingerprint' that distinguishes the real path from a false one.

### 3. Scalability and Future-Proofing

A hidden volume is limited to two layers. The MRS system is scalable and can be extended to systems with more dimensions under mild divisibility conditions. It is furthermore designed to be combined with post-quantum KEMs such as Kyber.

Core security properties are formally verified in EasyCrypt under the protocol model (see `proofs/`). This provides machine-checked guarantees about the design, but does not replace an independent cryptographic audit.

---

## 🏆 Why Is This Better?

MRS-AUTH is not 'better' in an absolute sense, but it is better for the specific problem of coercion-resistant authentication.

| System | Goal | Fundamental Weakness |
|--------|------|---------------------|
| Hidden volumes | Data encryption | Forensic traces, SSD vulnerability, limited to 2 layers |
| Chaffing | Message authentication | No protection against key coercion |
| Shadowfax | KEM deniability | Preserving, not creating new deniability |
| Anamorphic encryption | Hidden channels | Structural asymmetry recognisable upon full key compromise |
| HoneyWords | Password authentication | Explicit storage of false keys; single point of failure (checker) |
| **MRS-AUTH** | **Authentication under duress** | **Requires correct protocol integration; research phase** |

- **Hidden volumes** are a container for data, not identity. They are vulnerable to forensic analysis and offer no protection for authentication.
- **Chaffing** is a creative but vulnerable technique that offers no protection against key coercion.
- **Shadowfax** is an elegant solution to preserve existing deniability, but it does not create a new, stronger form of it.
- **Anamorphic encryption** is structurally recognisable, which undermines deniability.
- **HoneyWords** require explicit storage and a central checker; MRS-AUTH needs no external checker or stored alibis — the alibis are inherent to the mathematical structure.

MRS-AUTH, by contrast, offers a mathematically grounded, scalable solution specifically designed for the problem of forced authentication. It is not a workaround (like a hidden volume), but a fundamentally different paradigm: a system where mathematics itself generates the alibis, rather than them having to be hidden in the implementation.

---

## Conclusion

MRS-AUTH is not merely a variant of existing deniability systems; it addresses a different problem (authentication vs. encryption) with a fundamentally different, mathematically strong approach. Where other systems struggle with operational vulnerabilities, structural asymmetry, or explicit storage of false keys, MRS-AUTH offers a scalable solution in which deniability is inherent to the algebraic design.

> **Important nuance:** MRS-AUTH is in the research phase. The formal verification in EasyCrypt provides machine-checked guarantees about the protocol model, but does not replace an independent security audit or peer review at a reputable cryptography venue.
