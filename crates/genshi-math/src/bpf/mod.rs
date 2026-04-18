//! BPF backend for genshi-math.
//!
//! Hand-rolled Montgomery-form Fr arithmetic over 4×u64 limbs, plus thin
//! wrappers around Solana's `sol_alt_bn128_{addition,multiplication,pairing}`
//! syscalls for G1/G2/pairing. No arkworks dependency at runtime (arkworks is
//! only used in `#[cfg(not(target_os = "solana"))]` test fallbacks).
//!
//! The types exposed here are API-identical to the `native` module: the
//! verifier code imports `genshi_math::{Fr, G1Affine, ...}` and compiles
//! against whichever backend is active.

extern crate alloc;

pub mod fr;
pub mod curve;
mod pairing;

pub use fr::Fr;
pub use curve::{G1Affine, G1Projective, G2Affine, G2Projective};
pub use pairing::pairing_check;
