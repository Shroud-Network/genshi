//! Cryptographic primitives for the Janus framework.
//!
//! Single source of truth for every hash, curve, and field operation.
//! Parameters here (round constants, NUMS generators, field definitions)
//! are reused bit-for-bit by the Solidity verifier emitter, the Solana
//! BPF verifier, the WASM prover, and the native prover. Any drift between
//! these is a framework invariant violation (see J4 in Technical_Req.md).

pub mod fields;
pub mod curves;
pub mod poseidon2;
pub mod pedersen;
