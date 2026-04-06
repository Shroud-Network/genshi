//! EVM verifier generation for shroud-honk.
//!
//! Generates Solidity verifier contracts from verification keys.
//!
//! The Solidity verifier uses only universal BN254 precompiles (Guardrail G8):
//! - ecAdd (0x06)
//! - ecMul (0x07)
//! - ecPairing (0x08)
//! - modexp (0x05)
//!
//! Target chains: Avalanche, Ethereum, Arbitrum, Polygon, Base, and any EVM L2.
//! Verification cost: ~300-500K gas.

pub mod solidity_emitter;
pub mod poseidon2_sol;
