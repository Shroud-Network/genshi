//! # shroud-core
//!
//! Core cryptographic library for the shroud-honk proving scheme.
//! Implements Rust-native UltraHonk proving with Grumpkin commitments
//! and Poseidon2 hashing for Shroud Network privacy infrastructure.
//!
//! This crate is `no_std` compatible to support compilation to:
//! - Browser WASM (client-side proving)
//! - Solana BPF (on-chain verification via `sol_alt_bn128_*` syscalls)
//! - Native binary (server-side proving)

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod crypto;
pub mod arithmetization;
pub mod circuits;
pub mod proving;
pub mod note;
