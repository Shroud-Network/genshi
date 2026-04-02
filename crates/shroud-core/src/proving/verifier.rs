//! UltraHonk proof verification — pure Rust, no_std compatible.
//!
//! TODO: Phase 4 — Implement UltraHonk verification.
//!
//! This module MUST remain no_std compatible because it compiles to:
//! - Solana BPF (on-chain verifier using sol_alt_bn128_* syscalls)
//! - Browser WASM (client-side verification)
//! - Native (server-side)
//!
//! GUARDRAIL G7: One proof format, both VMs. The same proof bytes must
//! verify on both EVM and Solana.
