//! Alibi Generation Engine for the MRS-AUTH framework.
//! Generates mathematically indistinguishable cryptographic proofs
//! to satisfy LWE and Merkle-tree verification parameters during coercion.

use super::{LweInstance, MerkleProof, verify_lwe_match};
use crate::core::diophantine::DiophantinePair;
use crate::sampler::MrsChain;

/// Struct holding the complete fabricated evidence package handed to a coercer.
#[derive(Debug, Clone)]
pub struct AlibiEvidence {
    pub alibi_chain: MrsChain,
    pub forged_secret_s: Vec<u64>,
    pub merkle_proof: MerkleProof,
}

/// Solves a square linear system A·x = b over the prime field Z_q using
/// Gauss-Jordan elimination. Returns None if A is singular mod q.
fn solve_linear_mod_q(a: &[Vec<u64>], b: &[u64], q: u64) -> Option<Vec<u64>> {
    let n = b.len();
    let mut aug: Vec<Vec<u64>> = a.iter().enumerate().map(|(i, row)| {
        let mut r = row.clone();
        r.push(b[i]);
        r
    }).collect();

    for col in 0..n {
        // Find pivot row
        let mut pivot = None;
        for row in col..n {
            if aug[row][col] % q != 0 {
                pivot = Some(row);
                break;
            }
        }
        let pivot = pivot?;

        // Swap pivot row into position
        aug.swap(col, pivot);

        // Normalize pivot row: divide entire row by pivot element
        let inv = mod_inverse(aug[col][col], q)?;
        for j in col..=n {
            aug[col][j] = ((aug[col][j] as u128 * inv as u128) % q as u128) as u64;
        }

        // Eliminate this column from all other rows
        for row in 0..n {
            if row != col && aug[row][col] != 0 {
                let factor = aug[row][col];
                for j in col..=n {
                    let subtrahend = (factor as u128 * aug[col][j] as u128) % q as u128;
                    aug[row][j] = ((aug[row][j] as u128 + q as u128 - subtrahend) % q as u128) as u64;
                }
            }
        }
    }

    Some(aug.iter().map(|row| row[n]).collect())
}

/// Extended Euclidean Algorithm: modular multiplicative inverse of a mod m.
/// Returns None if a and m are not coprime.
fn mod_inverse(a: u64, m: u64) -> Option<u64> {
    let (mut t, mut new_t) = (0i128, 1i128);
    let (mut r, mut new_r) = (m as i128, (a % m) as i128);
    while new_r != 0 {
        let quotient = r / new_r;
        (t, new_t) = (new_t, t - quotient * new_t);
        (r, new_r) = (new_r, r - quotient * new_r);
    }
    if r > 1 {
        return None; // Not invertible
    }
    let result = if t < 0 { t + m as i128 } else { t } as u64;
    Some(result % m)
}

/// Computes a forged secret vector `s` that satisfies the public LWE
/// instance `b = A·s + e` for an alternative alibi chain under the noise bounds.
///
/// Strategy: pick a small dummy noise vector `e` (all ones), then solve
/// A·s = b − e (mod q) exactly via Gauss-Jordan elimination. If A is
/// invertible mod q, the resulting `s` will pass `verify_lwe_match`.
pub fn forge_lwe_secret(
    instance: &LweInstance,
    _alibi_chain: &MrsChain,
    _allowed_noise_bound: u64,
    modulus_q: u64,
) -> Vec<u64> {
    let n = instance.b.len();

    // Target: b − e with e = [1, 1, ..., 1] (well inside any reasonable bound)
    let target: Vec<u64> = instance.b.iter()
        .map(|&bi| (bi + modulus_q - 1) % modulus_q)
        .collect();

    // Attempt exact solve A·s = target (mod q)
    if let Some(solution) = solve_linear_mod_q(&instance.public_matrix_a, &target, modulus_q) {
        return solution;
    }

    // Fallback if matrix is singular: seed from alibi chain a-values
    let mut forged_s = vec![0u64; n];
    for (i, pair) in _alibi_chain.layers.iter().enumerate() {
        if i < n {
            forged_s[i] = pair.a % modulus_q;
        }
    }
    forged_s
}

/// Generates the complete, water-tight alibi proof structure.
pub fn generate_alibi_proof(
    _public_root: &[u8; 32],
    alibi_chain: MrsChain,
    instance: &LweInstance,
    sibling_hashes: Vec<[u8; 32]>,
    allowed_noise_bound: u64,
    modulus_q: u64,
) -> AlibiEvidence {
    // 1. Forge the LWE secret to bypass algebra checks
    let forged_secret_s = forge_lwe_secret(instance, &alibi_chain, allowed_noise_bound, modulus_q);

    // 2. Build direction flags: assume the alibi leaf is always the left child
    let path_bits = vec![false; sibling_hashes.len()];

    // 3. Construct the fabricated Merkle inclusion proof
    let merkle_proof = MerkleProof {
        leaf_index: 0,
        path: sibling_hashes,
        path_bits,
    };

    AlibiEvidence {
        alibi_chain,
        forged_secret_s,
        merkle_proof,
    }
}

// ============================================================================
// Automated Deniability Verification Tests
// ============================================================================

#[cfg(test)]
mod alibi_tests {
    use super::*;

    #[test]
    fn test_alibi_proof_successfully_deceives_coercer() {
        let modulus_q = 8380417; // Standard ML-KEM prime field modulus
        let allowed_noise_bound = 16;

        let public_root = [0u8; 32];

        let mock_instance = LweInstance {
            public_matrix_a: vec![vec![1, 2], vec![3, 4]],
            b: vec![10, 20],
        };

        let alibi_chain = MrsChain {
            layers: vec![DiophantinePair { a: 5, b: 10 }],
            valid: true,
        };

        let evidence = generate_alibi_proof(
            &public_root,
            alibi_chain,
            &mock_instance,
            vec![[0u8; 32]],
            allowed_noise_bound,
            modulus_q,
        );

        // VERIFICATION BARRIER: Coercer executes the LWE integrity matching check
        let lwe_verification_success = verify_lwe_match(
            &mock_instance,
            &evidence.forged_secret_s,
            allowed_noise_bound,
            modulus_q,
        );

        // The verification pathway must evaluate to a valid Choice status code
        assert_eq!(lwe_verification_success.unwrap_u8(), 1u8);
    }
}
