//! Browser WASM SDK for shroud-honk.
//!
//! TODO: Phase 6 — wasm-bindgen exports for browser proving.
//!
//! This crate is the SINGLE WASM entry point shared across both EVM and Solana.
//! The proving side is 100% shared — same proof bytes, same WASM module.
//! Only the on-chain verifier contracts differ (Solidity vs Rust BPF).
//!
//! Exports:
//! - Proof generation (transfer, withdraw)
//! - Note commitment computation
//! - Nullifier derivation
//! - SRS loading with IndexedDB caching
