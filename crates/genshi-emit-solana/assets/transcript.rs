//! Fiat-Shamir transcript for the genshi PLONK prover/verifier.
//!
//! Uses Keccak-256 in a streaming absorb/squeeze pattern to convert
//! an interactive proof protocol into a non-interactive one.
//!
//! **Invariant J2**: Keccak is the native EVM hash opcode (KECCAK256 at
//! 30 + 6 gas/word) and ensures the same transcript can be reconstructed
//! cheaply on-chain. The transcript encoding is deterministic and
//! platform-independent. The same proof produces the same challenges on
//! native, WASM, and Solana BPF — the foundation of genshi's
//! "one proof verifies on both VMs" guarantee.
//!
//! # Protocol
//!
//! ```text
//! 1. Initialize with domain separator
//! 2. Absorb public inputs, commitments, evaluations
//! 3. Squeeze challenges (alpha, beta, gamma, etc.)
//! ```
//!
//! Each squeeze resets the hasher state to prevent state reuse attacks.
//!
//! # Byte encoding (Invariant J2)
//!
//! The transcript uses **EVM-native big-endian uncompressed encoding** so
//! that a Solidity verifier can absorb the exact same bytes directly from
//! `calldata` without decompression or byte swapping:
//!
//! - `G1Affine` → 64 bytes: `x_be || y_be` (each 32-byte big-endian Fq).
//!   The identity element is encoded as 64 zero bytes.
//! - `Fr` → 32 bytes big-endian.
//! - `label` and `data` are prefixed with a little-endian `u32` length.
//!
//! This matches the wire format of the BN254 EVM precompiles (EIP-197) and
//! Solana's `sol_alt_bn128_*` syscalls, so the same bytes that land in
//! `calldata` / instruction data can be piped straight into Keccak.

use genshi_math::{Fr, G1Affine, keccak256};
use alloc::vec::Vec;

/// Fiat-Shamir transcript using Keccak-256.
///
/// Accumulates protocol messages (field elements, group elements, bytes)
/// and derives verifier challenges deterministically.
pub struct Transcript {
    /// Running state: accumulated bytes to be hashed on next squeeze.
    state: Vec<u8>,
}

impl Transcript {
    /// Create a new transcript with a domain separator.
    ///
    /// The domain separator ensures transcripts for different protocols
    /// don't collide, even if they share the same structure.
    pub fn new(domain_separator: &[u8]) -> Self {
        let mut state = Vec::new();
        state.extend_from_slice(&(domain_separator.len() as u32).to_le_bytes());
        state.extend_from_slice(domain_separator);
        Self { state }
    }

    /// Absorb raw bytes into the transcript.
    pub fn absorb_bytes(&mut self, label: &[u8], data: &[u8]) {
        self.state.extend_from_slice(&(label.len() as u32).to_le_bytes());
        self.state.extend_from_slice(label);
        self.state.extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.state.extend_from_slice(data);
    }

    /// Absorb a scalar field element as 32 bytes big-endian.
    pub fn absorb_scalar(&mut self, label: &[u8], scalar: &Fr) {
        let bytes = scalar.to_be_bytes();
        self.absorb_bytes(label, &bytes);
    }

    /// Absorb multiple scalar field elements, each with an indexed sub-label.
    pub fn absorb_scalars(&mut self, label: &[u8], scalars: &[Fr]) {
        for (i, s) in scalars.iter().enumerate() {
            let mut sub_label = Vec::from(label);
            sub_label.extend_from_slice(&(i as u32).to_le_bytes());
            self.absorb_scalar(&sub_label, s);
        }
    }

    /// Absorb a G1 affine point as 64 bytes uncompressed big-endian.
    ///
    /// Identity encodes as 64 zero bytes; non-identity as `x_be || y_be`.
    /// See the module-level docs for why this encoding matches the wire
    /// format of both EVM precompiles and Solana `sol_alt_bn128_*` syscalls.
    pub fn absorb_point(&mut self, label: &[u8], point: &G1Affine) {
        let bytes = point.to_uncompressed_bytes();
        self.absorb_bytes(label, &bytes);
    }

    /// Absorb multiple G1 affine points, each with an indexed sub-label.
    pub fn absorb_points(&mut self, label: &[u8], points: &[G1Affine]) {
        for (i, p) in points.iter().enumerate() {
            let mut sub_label = Vec::from(label);
            sub_label.extend_from_slice(&(i as u32).to_le_bytes());
            self.absorb_point(&sub_label, p);
        }
    }

    /// Squeeze a challenge scalar from the transcript.
    ///
    /// Hashes the accumulated state with the squeeze label via Keccak-256,
    /// then re-seeds the state with the hash output (chaining construction).
    ///
    /// Routes through `genshi_math::keccak256` so the BPF backend hits the
    /// `sol_keccak256` syscall (85 + n CU) instead of compiling `tiny-keccak`
    /// into BPF (~8–15 KCU per permutation). Native/WASM builds still use
    /// `tiny-keccak` under the hood; the challenge bytes are byte-identical.
    pub fn squeeze_challenge(&mut self, label: &[u8]) -> Fr {
        let label_len_le = (label.len() as u32).to_le_bytes();
        let hash = keccak256(&[
            &self.state,
            b"squeeze",
            &label_len_le,
            label,
        ]);

        self.state.clear();
        self.state.extend_from_slice(&hash);

        Fr::from_be_bytes_mod_order(&hash)
    }

    /// Squeeze multiple challenge scalars, each with an indexed sub-label.
    pub fn squeeze_challenges(&mut self, label: &[u8], count: usize) -> Vec<Fr> {
        let mut challenges = Vec::with_capacity(count);
        for i in 0..count {
            let mut sub_label = Vec::from(label);
            sub_label.extend_from_slice(&(i as u32).to_le_bytes());
            challenges.push(self.squeeze_challenge(&sub_label));
        }
        challenges
    }

    /// Get the accumulated transcript state (for debugging/verification).
    #[allow(dead_code)]
    pub fn get_buffer(&self) -> &[u8] {
        &self.state
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_deterministic() {
        let mut t1 = Transcript::new(b"test_protocol");
        t1.absorb_scalar(b"val", &Fr::from(42u64));
        let c1 = t1.squeeze_challenge(b"alpha");

        let mut t2 = Transcript::new(b"test_protocol");
        t2.absorb_scalar(b"val", &Fr::from(42u64));
        let c2 = t2.squeeze_challenge(b"alpha");

        assert_eq!(c1, c2, "Same inputs must produce same challenge");
    }

    #[test]
    fn test_transcript_different_inputs() {
        let mut t1 = Transcript::new(b"test");
        t1.absorb_scalar(b"val", &Fr::from(1u64));
        let c1 = t1.squeeze_challenge(b"ch");

        let mut t2 = Transcript::new(b"test");
        t2.absorb_scalar(b"val", &Fr::from(2u64));
        let c2 = t2.squeeze_challenge(b"ch");

        assert_ne!(c1, c2, "Different inputs must produce different challenges");
    }

    #[test]
    fn test_transcript_different_domains() {
        let mut t1 = Transcript::new(b"protocol_A");
        t1.absorb_scalar(b"val", &Fr::from(42u64));
        let c1 = t1.squeeze_challenge(b"ch");

        let mut t2 = Transcript::new(b"protocol_B");
        t2.absorb_scalar(b"val", &Fr::from(42u64));
        let c2 = t2.squeeze_challenge(b"ch");

        assert_ne!(c1, c2, "Different domains must produce different challenges");
    }

    #[test]
    fn test_challenge_not_zero() {
        let mut t = Transcript::new(b"test");
        t.absorb_scalar(b"val", &Fr::from(1u64));
        let c = t.squeeze_challenge(b"ch");
        assert_ne!(c, Fr::zero(), "Challenge should not be zero");
    }

    #[test]
    fn test_sequential_squeezes_different() {
        let mut t = Transcript::new(b"test");
        t.absorb_scalar(b"val", &Fr::from(1u64));
        let c1 = t.squeeze_challenge(b"first");
        let c2 = t.squeeze_challenge(b"second");
        assert_ne!(c1, c2, "Sequential squeezes must differ");
    }

    #[test]
    fn test_absorb_point() {
        let g1_gen = G1Affine::generator();

        let mut t1 = Transcript::new(b"test");
        t1.absorb_point(b"comm", &g1_gen);
        let c1 = t1.squeeze_challenge(b"ch");

        let mut t2 = Transcript::new(b"test");
        t2.absorb_point(b"comm", &g1_gen);
        let c2 = t2.squeeze_challenge(b"ch");

        assert_eq!(c1, c2, "Same point must produce same challenge");
    }
}
