//! UltraHonk proving and verification.
//!
//! Phase 4: KZG polynomial commitments, prover, and verifier.
//! The verifier module compiles to both Solana BPF and native targets.

pub mod transcript;
pub mod srs;
pub mod kzg;
pub mod prover;
pub mod verifier;
pub mod serialization;
pub mod api;
