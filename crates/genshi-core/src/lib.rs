//! # genshi-core
//!
//! Core of the genshi dual-VM zero-knowledge proving framework.
//!
//! genshi produces proofs that verify bytewise-identically on both EVM and
//! Solana. This crate ships the cryptographic primitives, constraint system,
//! gadgets, prover, and verifier. It is application-agnostic: no notes,
//! pools, nullifiers, bridges, or domain-specific types live here.
//!
//! ## Stack
//! - Curves: BN254 (pairing) + Grumpkin (in-circuit EC)
//! - Hash: Poseidon2 (in-circuit) + Keccak-256 (Fiat-Shamir transcript)
//! - Arithmetization: 4-wire PLONKish with custom gates and lookup tables
//! - Proving system: PLONK with KZG commitments, universal SRS (Aztec PoT)
//!
//! ## Compilation targets
//! This crate is `no_std` compatible and compiles to:
//! - Native (server-side proving, CLI)
//! - `wasm32-unknown-unknown` (browser client proving via `genshi-wasm`)
//! - Solana BPF (on-chain verification via `sol_alt_bn128_*` syscalls)
//!
//! ## Authoring circuits
//! Applications define circuits by implementing the [`Circuit`] trait
//! and passing a mutable [`arithmetization::ultra_circuit_builder::UltraCircuitBuilder`]
//! through the framework's gadgets. See the `genshi-core` README for an example.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod crypto;
pub mod arithmetization;
pub mod gadgets;
pub mod proving;
pub mod circuit;

pub use circuit::Circuit;

/// Build a proof for a [`Circuit`] using the supplied SRS.
///
/// Convenience re-export of [`proving::api::prove`].
pub use proving::api::prove;

/// Verify a proof for a [`Circuit`] against its verification key.
///
/// Convenience re-export of [`proving::api::verify`].
pub use proving::api::verify;

/// Extract the verification key for a [`Circuit`] without proving.
///
/// Convenience re-export of [`proving::api::extract_vk`].
pub use proving::api::extract_vk;
