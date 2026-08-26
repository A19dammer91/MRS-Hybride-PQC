// Register the framework's internal submodules
pub mod core;
pub mod crypto;
pub mod framework;
pub mod sampler;
pub mod security;

// Expose base types directly from the library root
pub use crate::core::{
    BranchFreeResult, DiophantinePair, MrsInt, ToBytes, MyU64, MyU256
};
pub use crate::crypto::{
    derive_hybrid_key, encrypt_payload_hybrid, decrypt_payload_hybrid, HybridCiphertextPacket
};
pub use crate::framework::{MrsAuthFramework, SecureEnvelope, Keypair, FrameworkError};
pub use crate::sampler::{
    MrsChain, SamplerInt, FromRandom, sample_three_layers, sample_triangle
};
pub use crate::security::{
    TimeCode, generate_timecode, LweInstance, ToLweCoefficient, MerkleProof, hash_mrs_chain
};
