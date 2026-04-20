//! Anchor program codegen for genshi PLONK-KZG verifiers on Solana.
//!
//! Given one or more [`VerificationKey`]s and an [`SRS`], emits a complete,
//! self-contained Anchor program that verifies genshi proofs on-chain using
//! only `sol_alt_bn128_*` syscalls. The emitted program has **zero runtime
//! dependency on `genshi-core`** — the verifier algorithm and transcript are
//! copied verbatim at emit time and pinned to the emit-time version.
//!
//! This mirrors the EVM story (`genshi-evm` emits a self-contained Solidity
//! contract) and gives deployers an auditable, version-pinned artifact.
//!
//! # Usage
//!
//! ```ignore
//! use genshi_emit_solana::{EmitConfig, emit_program};
//! use genshi_core::proving::srs::SRS;
//!
//! let srs = SRS::insecure_for_testing(256);
//! let vk_bytes: Vec<u8> = /* serialized VK from genshi CLI */;
//!
//! let mut config = EmitConfig::new("my-verifier", "./out/");
//! config.add_circuit("withdraw", vk_bytes);
//!
//! emit_program(&config, &srs).expect("emit failed");
//! ```

pub mod config;
pub mod emitter;
pub mod templates;

pub use config::EmitConfig;
pub use emitter::{emit_program, EmitError};
