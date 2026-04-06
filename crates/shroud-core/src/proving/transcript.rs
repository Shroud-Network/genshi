//! Fiat-Shamir transcript for UltraHonk.
//!
//! Uses Keccak-256 in a streaming absorb/squeeze pattern to convert
//! an interactive proof protocol into a non-interactive one.
//!
//! **GUARDRAIL G7**: Keccak is the native EVM hash opcode (21 gas) and
//! ensures the same transcript can be reconstructed cheaply on-chain.
//! The transcript encoding is deterministic and platform-independent.
//! The same proof produces the same challenges on native, WASM, and
//! Solana BPF — enabling ONE proof format for both EVM and Solana.
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

use ark_bn254::{Fr, G1Affine};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use tiny_keccak::{Hasher, Keccak};
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
        // Absorb domain separator with length prefix
        state.extend_from_slice(&(domain_separator.len() as u32).to_le_bytes());
        state.extend_from_slice(domain_separator);
        Self { state }
    }

    /// Absorb raw bytes into the transcript.
    pub fn absorb_bytes(&mut self, label: &[u8], data: &[u8]) {
        // Label prefix for domain separation within the transcript
        self.state.extend_from_slice(&(label.len() as u32).to_le_bytes());
        self.state.extend_from_slice(label);
        // Data with length prefix
        self.state.extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.state.extend_from_slice(data);
    }

    /// Absorb a scalar field element (BN254 Fr).
    pub fn absorb_scalar(&mut self, label: &[u8], scalar: &Fr) {
        let mut bytes = Vec::new();
        scalar.serialize_compressed(&mut bytes).expect("Fr serialization should not fail");
        self.absorb_bytes(label, &bytes);
    }

    /// Absorb multiple scalar field elements.
    pub fn absorb_scalars(&mut self, label: &[u8], scalars: &[Fr]) {
        for (i, s) in scalars.iter().enumerate() {
            // Each scalar gets a unique sub-label
            let mut sub_label = Vec::from(label);
            sub_label.extend_from_slice(&(i as u32).to_le_bytes());
            self.absorb_scalar(&sub_label, s);
        }
    }

    /// Absorb a G1 affine point (commitment).
    pub fn absorb_point(&mut self, label: &[u8], point: &G1Affine) {
        let mut bytes = Vec::new();
        point.serialize_compressed(&mut bytes).expect("G1 serialization should not fail");
        self.absorb_bytes(label, &bytes);
    }

    /// Absorb multiple G1 affine points.
    pub fn absorb_points(&mut self, label: &[u8], points: &[G1Affine]) {
        for (i, p) in points.iter().enumerate() {
            let mut sub_label = Vec::from(label);
            sub_label.extend_from_slice(&(i as u32).to_le_bytes());
            self.absorb_point(&sub_label, p);
        }
    }

    /// Squeeze a challenge scalar from the transcript.
    ///
    /// This hashes all accumulated state with the squeeze label via Keccak-256,
    /// then re-seeds the state with the hash output (chaining construction).
    pub fn squeeze_challenge(&mut self, label: &[u8]) -> Fr {
        // Add the squeeze label to differentiate squeeze calls
        self.state.extend_from_slice(b"squeeze");
        self.state.extend_from_slice(&(label.len() as u32).to_le_bytes());
        self.state.extend_from_slice(label);

        // Hash the entire accumulated state with Keccak-256
        let mut keccak = Keccak::v256();
        keccak.update(&self.state);
        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);

        // Re-seed the state with the hash output (chaining)
        self.state.clear();
        self.state.extend_from_slice(&hash);

        // Convert 32-byte hash to field element via modular reduction
        Fr::from_be_bytes_mod_order(&hash)
    }

    /// Squeeze multiple challenge scalars.
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
    use ark_ff::Zero;

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
        use ark_ec::AffineRepr;
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
