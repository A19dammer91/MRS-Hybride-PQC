pub mod merkle;
pub mod timecode;
pub mod witness;
pub mod witness_supergrid;   // toegevoegd

pub use timecode::{
    generate_timecode, run_euf_cma_game, run_forward_secrecy_game, EufCmaAdversary,
    ForwardSecrecyAdversary, TimeCode,
};

pub use merkle::{build_k_acceptance_root, verify_k_acceptance_proof, MerkleProof};

pub use witness::{hash_chain, MasterSecret, Witness, WitnessSpace, WitnessStatus};

// Optioneel hergebruik
pub use witness_supergrid::{Witness90, WitnessSpace90, WitnessStatus90, Alibi90};
