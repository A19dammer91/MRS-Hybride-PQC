// Register the framework's internal submodules
pub mod core;
pub mod crypto;
pub mod framework;
pub mod sampler;
pub mod security;

// Expose the most important base types directly from the library root
pub use crate::core::DiophantinePair;
pub use crate::crypto::{
    decrypt_payload_hybrid, derive_hybrid_key, encrypt_payload_hybrid, HybridCiphertextPacket,
};
pub use crate::framework::{FrameworkError, Keypair, MrsAuthFramework, SecureEnvelope};
pub use crate::sampler::MrsChain;
pub use crate::security::TimeCode;

// Expose the witness authentication & coercion-resistance API
pub use crate::security::witness::{
    hash_chain, MasterSecret, Witness, WitnessSpace, WitnessStatus,
};
