//! Keccak-256 hasher for the native backend.
//!
//! Host-side proving and WASM browser verification both run here. Uses
//! `tiny-keccak` — the same primitive the BPF backend falls back to when
//! built off-target, so byte-for-byte parity is automatic.
//!
//! The input shape mirrors the BPF backend: a slice of byte slices so a
//! Fiat-Shamir transcript (`label || data || label || data || …`) hashes
//! in one call without first concatenating into a temporary `Vec`.

use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 of the concatenation of `parts`.
pub fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}
