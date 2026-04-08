//! EVM verifier generation for the Janus framework.
//!
//! Given a [`janus_core::proving::prover::VerificationKey`], this crate emits
//! a self-contained Solidity verifier contract that verifies Janus PLONK-KZG
//! proofs using only universal BN254 precompiles:
//!
//! - ecAdd   (0x06)
//! - ecMul   (0x07)
//! - ecPairing (0x08)
//! - modexp  (0x05)
//!
//! Plus the KECCAK256 opcode for the Fiat-Shamir transcript (Invariant J2).
//!
//! Target chains: any EVM L1/L2 that supports the precompiles above — Ethereum,
//! Arbitrum, Base, Avalanche, Polygon, Monad, and so on.
//! Verification cost target: ≤500K gas per verify.
//!
//! # Reusable Solidity libraries
//!
//! In addition to the generator, this crate ships ready-to-import Solidity
//! libraries that consumer applications can drop into their `contracts/`
//! directory. The library sources live in `crates/janus-evm/contracts/library/`
//! and currently include:
//!
//! - `MerkleTree.sol`    — append-only 4-ary Poseidon2 Merkle tree
//! - `NullifierSet.sol`  — replay-protection set
//! - `RootHistory.sol`   — circular buffer of recent roots
//!
//! The matching `Poseidon2.sol` library is generated on demand via
//! [`poseidon2_sol::generate_poseidon2_sol`] (or `janus emit-sol --poseidon2`).
//! The generated round constants are guaranteed by Invariant J4 to match the
//! janus-core circuit gadget byte-for-byte.

pub mod solidity_emitter;
pub mod poseidon2_sol;

/// Returns the source of a built-in Solidity library shipped under
/// `crates/janus-evm/contracts/library/`.
///
/// Available libraries (case-sensitive): `"MerkleTree"`, `"NullifierSet"`,
/// `"RootHistory"`. Returns `None` for unknown names.
///
/// Embedded at compile time via `include_str!`, so consumers don't need to
/// know the on-disk crate layout — they can call this from build scripts to
/// stage the libraries into their own contract directories.
pub fn library_source(name: &str) -> Option<&'static str> {
    match name {
        "MerkleTree" => Some(include_str!("../contracts/library/MerkleTree.sol")),
        "NullifierSet" => Some(include_str!("../contracts/library/NullifierSet.sol")),
        "RootHistory" => Some(include_str!("../contracts/library/RootHistory.sol")),
        _ => None,
    }
}

/// Returns the names of all reusable libraries shipped by janus-evm.
pub fn library_names() -> &'static [&'static str] {
    &["MerkleTree", "NullifierSet", "RootHistory"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_sources_available() {
        for name in library_names() {
            let src = library_source(name).expect("library should exist");
            assert!(src.contains(&format!("library {name}")), "{name}.sol must declare library");
            assert!(src.contains("SPDX-License-Identifier"), "{name}.sol must have SPDX header");
        }
    }

    #[test]
    fn library_unknown_returns_none() {
        assert!(library_source("ShieldedPool").is_none());
        assert!(library_source("DoesNotExist").is_none());
    }

    #[test]
    fn library_names_match_sources() {
        // Sanity: every name in library_names() resolves.
        assert_eq!(library_names().len(), 3);
        for name in library_names() {
            assert!(library_source(name).is_some());
        }
    }
}
