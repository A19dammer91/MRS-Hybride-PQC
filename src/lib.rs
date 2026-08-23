// Register the framework's internal submodules
pub mod core;
pub mod crypto;
pub mod sampler;
pub mod security;

// Expose the most important base types directly from the library root
pub use crate::core::DiophantinePair;
pub use crate::crypto::{derive_hybrid_key, encrypt_payload_hybrid, decrypt_payload_hybrid, HybridCiphertextPacket};
pub use crate::sampler::MrsChain;
pub use crate::security::TimeCode;
