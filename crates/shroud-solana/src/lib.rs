//! Solana program module for shroud-honk on-chain verification.
//!
//! This crate provides Solana-specific wrappers around `shroud-core`'s verifier.
//!
//! Architecture:
//! - `verify_prepare()` from shroud-core handles transcript reconstruction and
//!   constraint equation checking (pure field arithmetic, no pairings)
//! - `sol_alt_bn128_pairing` syscalls handle the BN254 pairing checks
//!   (available since Solana v1.16)
//!
//! The full Anchor program wrapping these functions would use:
//! - PDAs for nullifier storage (existence = spent)
//! - PDAs for pool state (Merkle tree + root history)
//! - Instructions: deposit, transfer, withdraw
//!
//! Estimated verification cost: ~800K-1.4M CU.

pub mod crypto;
pub mod verify;
