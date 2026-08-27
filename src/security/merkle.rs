use sha2::{Sha256, Digest};
use subtle::{ConstantTimeEq, Choice};
use zeroize::Zeroize;
use crate::sampler::MrsChain;

/// Merkle inclusion proof for a selected alibi chain.
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct MerkleProof {
    pub leaf_index: usize,
    /// Sibling hashes along the path from leaf to root.
    pub path: Vec<[u8; 32]>,
    /// Direction flags: `true` = current hash is the right child.
    pub path_bits: Vec<bool>,
}

/// Hashes an MRS chain into a single 32-byte leaf digest.
///
/// Each layer contributes its A and B bytes, SHA256-ed sequentially.
/// This produces a deterministic hash suitable for Merkle commitment.
pub fn hash_mrs_chain(chain: &MrsChain) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for pair in &chain.layers {
        hasher.update(&pair.a.to_be_bytes());
        hasher.update(&pair.b.to_be_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Builds the k-acceptance Merkle root from a list of chain hashes.
pub fn build_k_acceptance_root(chain_hashes: &[[u8; 32]], k_param: usize) -> Option<[u8; 32]> {
    if chain_hashes.is_empty() || chain_hashes.len() > k_param {
        return None;
    }

    let mut tree_leaves = vec![[0u8; 32]; k_param];
    for (i, hash) in chain_hashes.iter().enumerate() {
        tree_leaves[i] = *hash;
    }

    let mut current_level = tree_leaves;
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
            if chunk.len() == 2 {
                hasher.update(chunk[0]);
                hasher.update(chunk[1]);
            } else {
                hasher.update(chunk[0]);
                hasher.update(chunk[0]);
            }
            let mut node = [0u8; 32];
            node.copy_from_slice(&hasher.finalize());
            next_level.push(node);
        }
        current_level = next_level;
    }

    Some(current_level[0])
}

/// Verifies in constant time whether a leaf belongs to the Merkle root.
pub fn verify_k_acceptance_proof(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    proof: &MerkleProof,
) -> Choice {
    let mut current_hash = *leaf_hash;
    for (sibling, is_right) in proof.path.iter().zip(proof.path_bits.iter()) {
        let mut hasher = Sha256::new();
        if *is_right {
            hasher.update(current_hash);
            hasher.update(*sibling);
        } else {
            hasher.update(*sibling);
            hasher.update(current_hash);
        }
        current_hash.copy_from_slice(&hasher.finalize());
    }
    current_hash.ct_eq(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::diophantine::DiophantinePair;

    #[test]
    fn hash_chain_deterministic() {
        let chain = MrsChain {
            layers: vec![
                DiophantinePair { a: 19u64, b: 9u64 },
                DiophantinePair { a: 5u64, b: 3u64 },
            ],
            valid: true,
        };
        let h1 = hash_mrs_chain(&chain);
        let h2 = hash_mrs_chain(&chain);
        assert_eq!(h1, h2);
    }

    #[test]
    fn merkle_root_two_leaves() {
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let root = build_k_acceptance_root(&[leaf1, leaf2], 2).unwrap();
        assert_ne!(root, [0u8; 32]);
    }
}
