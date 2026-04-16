//! UltraHonk proving and verification.
//!
//! Phase 4: KZG polynomial commitments, prover, and verifier.
//! The verifier module compiles to both Solana BPF and native targets.

pub mod types;
pub mod transcript;
pub mod srs;
// KZG helpers are prover-side: commit/open/batch_open/compute_quotient plus
// the poly_* utilities all run in ark-native form. The verifier has no call
// sites into this module — it inlines `pairing_check` via `genshi-math`.
#[cfg(feature = "prover")]
pub mod kzg;
#[cfg(feature = "prover")]
pub mod prover;
pub mod verifier;
pub mod serialization;
pub mod api;

// Semver shim: preserve `genshi_core::proving::{Proof, VerificationKey}` as a
// top-level re-export. Older downstream crates import from this path.
pub use types::{Proof, VerificationKey};
