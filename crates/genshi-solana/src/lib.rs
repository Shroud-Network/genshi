//! Solana BPF verifier for the genshi framework.
//!
//! This crate provides Solana-specific primitives for verifying genshi proofs
//! on-chain. Architecture:
//!
//! - `verify_prepare()` from `genshi-core` handles transcript reconstruction
//!   and the PLONK constraint equation (pure field arithmetic, no pairings).
//! - `sol_alt_bn128_pairing` syscalls handle the BN254 pairing checks
//!   (available on Solana since v1.16).
//!
//! Applications ship their own Solana program. That program's instruction
//! handlers call [`verify::verify_from_bytes`] (or [`verify::verify_with_syscalls`]
//! if they already have deserialized types) to validate a proof, then apply
//! whatever state transition the application defines. genshi stays entirely
//! application-agnostic — it does not prescribe account layouts, PDAs, or
//! instruction shapes.
//!
//! Target verification cost: ≤1.4M CU for typical application circuits.

pub mod crypto;
pub mod verify;
