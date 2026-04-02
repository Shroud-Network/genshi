//! Cryptographic verification module for Solana BPF target.
//!
//! TODO: Phase 6 — Re-export shroud-core verifier for Solana on-chain verification.
//!
//! The verifier from shroud-core compiles directly to Solana BPF because
//! shroud-core is no_std compatible. No separate verifier generation step
//! is needed (unlike EVM where a Solidity contract is generated).
//!
//! This module provides Solana-specific wrappers for:
//! - Proof deserialization from transaction data
//! - Public input encoding (little-endian field elements)
//! - CPI calls to sol_alt_bn128_* syscalls
