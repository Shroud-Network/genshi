//! Cryptographic primitives for shroud-honk.
//!
//! All primitives are defined here as the single source of truth,
//! ensuring consistency across native, WASM, and BPF compilation targets.

pub mod fields;
pub mod curves;
pub mod poseidon2;
pub mod pedersen;
