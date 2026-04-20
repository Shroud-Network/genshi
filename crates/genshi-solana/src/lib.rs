#![allow(deprecated)]
//! Solana BPF verifier for the genshi framework.
//!
//! **Deprecated.** Use [`genshi-emit-solana`](https://crates.io/crates/genshi-emit-solana)
//! instead, which generates self-contained Anchor programs from verification
//! keys with zero runtime dependency on `genshi-core`. See `MIGRATION.md` in
//! the repository root for migration instructions.
//!
//! This crate attempted to compile the full `genshi-core` verifier to Solana
//! BPF, but the prover code causes frame-corruption errors and the verifier
//! exceeds the 4 KB BPF stack limit. The codegen approach in
//! `genshi-emit-solana` resolves both issues.

#[deprecated(
    since = "0.2.0",
    note = "Use genshi-emit-solana instead. See MIGRATION.md for details."
)]
pub mod crypto;

#[deprecated(
    since = "0.2.0",
    note = "Use genshi-emit-solana instead. See MIGRATION.md for details."
)]
pub mod verify;
