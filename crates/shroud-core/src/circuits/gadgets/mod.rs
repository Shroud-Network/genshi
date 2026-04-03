//! Circuit gadgets — reusable constrained sub-circuits.
//!
//! Each gadget takes a `&mut UltraCircuitBuilder` and adds gates that
//! constrain a specific cryptographic operation. The gadget's output
//! must match the native computation for the same inputs.
//!
//! **GUARDRAIL G5**: All Poseidon2 operations in gadgets use the SAME
//! round constants as the native implementation in `crypto::poseidon2`.

pub mod poseidon2_gadget;
pub mod merkle;
pub mod nullifier;
pub mod note_commitment;
pub mod range_proof;
