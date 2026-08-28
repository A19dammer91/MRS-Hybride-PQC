pub mod witness;
pub mod merkle;
pub mod timecode;

// Expose the submodules directly to the rest of the framework
pub use timecode::{
    generate_timecode, TimeCode, run_euf_cma_game, run_forward_secrecy_game,
    EufCmaAdversary, ForwardSecrecyAdversary,
};

pub use merkle::{
    build_k_acceptance_root, verify_k_acceptance_proof, MerkleProof,
};

pub use witness::{
    MasterSecret, Witness, WitnessSpace, WitnessStatus,
    verify_witness_authenticity, hash_chain,
};
