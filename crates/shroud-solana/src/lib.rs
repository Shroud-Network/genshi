//! Solana Anchor program for shroud-honk on-chain verification.
//!
//! TODO: Phase 6 — Anchor program that re-exports shroud-core verifier.
//!
//! Uses `sol_alt_bn128_*` syscalls (available since Solana v1.16):
//! - sol_alt_bn128_addition
//! - sol_alt_bn128_multiplication
//! - sol_alt_bn128_pairing
//!
//! Nullifier storage: PDA per nullifier (Light Protocol compressed accounts).
//! Pool state: PDA accounts.
//! Estimated verification cost: ~800K-1.4M CU.

pub mod crypto;
