//! Reusable in-circuit gadgets.
//!
//! Each gadget takes a `&mut UltraCircuitBuilder` and adds constraints that
//! enforce a specific cryptographic operation. Gadgets are application-agnostic
//! primitives — applications compose them to build concrete statements.
//!
//! Available gadgets:
//! - [`poseidon2_gadget`] — in-circuit Poseidon2 permutation and hashes (arities 2–5)
//! - [`merkle`] — generic 4-ary Poseidon2 Merkle inclusion proofs
//! - [`range_proof`] — plookup-backed range checks (8/16/32/64-bit)

pub mod poseidon2_gadget;
pub mod merkle;
pub mod range_proof;
