use sha2::{Sha256, Digest};
use subtle::{ConstantTimeEq, Choice};
use zeroize::Zeroize;

/// Representatie van een Merkle-proof voor een geselecteerde alibi-keten
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub lemmas: Vec<[u8; 32]>,
    pub path_bits: Vec<bool>,
}

/// Bouwt de wortel (Root Commitment) van een k-acceptance boom op basis van k keten-hashes
pub fn build_k_acceptance_root(chain_hashes: &[[u8; 32]], k_param: usize) -> Option<[u8; 32]> {
    if chain_hashes.is_empty() || chain_hashes.len() > k_param {
        return None;
    }

    // Dwing een gebalanceerde boom af door aan te vullen met veilige dummy paden (padding)
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
                // Symmetrische hashing voor oneven knopen om dieptedistributie gelijk te houden
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

/// Verifieert in constante-tijd of een gepresenteerde chain thuishoort in de k-acceptance commitment root
pub fn verify_k_acceptance_proof(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    proof: &MerkleProof
) -> Choice {
    let mut current_hash = *leaf_hash;

    for (sibling, is_right) in proof.lemmas.iter().zip(proof.path_bits.iter()) {
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

    // Verifieer de berekende wortel tegen de opgeslagen root commitment
    current_hash.ct_eq(root)
}
