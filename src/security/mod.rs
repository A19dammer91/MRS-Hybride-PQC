pub mod timecode;
pub mod lwe;
pub mod merkle;
pub mod alibi;

// Expose the submodules directly to the rest of the framework
pub use timecode::{
    generate_timecode, TimeCode, run_euf_cma_game, run_forward_secrecy_game,
    EufCmaAdversary, ForwardSecrecyAdversary
};
pub use lwe::{isolate_chain_parameter, verify_lwe_match, LweInstance};
pub use merkle::{build_k_acceptance_root, verify_k_acceptance_proof, MerkleProof};
pub use alibi::{generate_alibi_proof, forge_lwe_secret, AlibiEvidence};
