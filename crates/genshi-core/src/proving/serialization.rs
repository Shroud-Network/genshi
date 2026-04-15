//! Canonical proof and verification key serialization.
//!
//! Provides deterministic byte encoding for cross-VM compatibility (G7).
//! Uses **uncompressed big-endian encoding** for both G1 points and Fr
//! elements so that EVM precompiles (EIP-197: `x_be || y_be`), Solana
//! `sol_alt_bn128_*` syscalls, and the Fiat-Shamir transcript can all
//! consume the same bytes without any decompression or byte swapping.
//!
//! - `G1Affine` → 64 bytes: `x_be || y_be` (each 32-byte big-endian Fq).
//!   The identity element is encoded as 64 zero bytes.
//! - `Fr` → 32 bytes big-endian.
//!
//! Public input adapters ([`public_inputs_to_bytes_be`] /
//! [`public_inputs_to_bytes_le`]) provide the two ordering conventions
//! that the two VMs' instruction encoders expect at the application
//! boundary.

use ark_bn254::{Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use alloc::vec::Vec;

use super::prover::{Proof, VerificationKey};

/// Serialization error.
#[derive(Debug)]
pub enum SerError {
    InvalidLength { expected: usize, got: usize },
    DeserializeFailed,
}

// ============================================================================
// Constants
// ============================================================================

/// Bytes per uncompressed G1Affine point (x: 32 bytes, y: 32 bytes).
const G1_UNCOMPRESSED_SIZE: usize = 64;

/// Bytes per Fr scalar field element.
const FR_SIZE: usize = 32;

// ============================================================================
// Low-level helpers
// ============================================================================

fn serialize_g1(point: &G1Affine) -> Vec<u8> {
    let mut buf = Vec::with_capacity(G1_UNCOMPRESSED_SIZE);
    if point.is_zero() {
        buf.resize(G1_UNCOMPRESSED_SIZE, 0);
        return buf;
    }
    let x: Fq = point.x().unwrap();
    let y: Fq = point.y().unwrap();
    buf.extend_from_slice(&x.into_bigint().to_bytes_be());
    buf.extend_from_slice(&y.into_bigint().to_bytes_be());
    buf
}

fn deserialize_g1(bytes: &[u8]) -> Result<G1Affine, SerError> {
    if bytes.len() < G1_UNCOMPRESSED_SIZE {
        return Err(SerError::InvalidLength {
            expected: G1_UNCOMPRESSED_SIZE,
            got: bytes.len(),
        });
    }
    // All-zero encoding represents the identity element.
    if bytes[..G1_UNCOMPRESSED_SIZE].iter().all(|&b| b == 0) {
        return Ok(G1Affine::zero());
    }
    let x = Fq::from_be_bytes_mod_order(&bytes[..32]);
    let y = Fq::from_be_bytes_mod_order(&bytes[32..64]);
    let point = G1Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerError::DeserializeFailed);
    }
    Ok(point)
}

fn serialize_fr(scalar: &Fr) -> Vec<u8> {
    scalar.into_bigint().to_bytes_be()
}

fn deserialize_fr(bytes: &[u8]) -> Result<Fr, SerError> {
    if bytes.len() < FR_SIZE {
        return Err(SerError::InvalidLength {
            expected: FR_SIZE,
            got: bytes.len(),
        });
    }
    // Strict canonical check: the 32-byte big-endian integer must be
    // strictly less than the Fr modulus. Anything else is rejected so
    // that round-tripping is truly deterministic (no silent reduction).
    let reduced = Fr::from_be_bytes_mod_order(&bytes[..FR_SIZE]);
    if reduced.into_bigint().to_bytes_be() != bytes[..FR_SIZE] {
        return Err(SerError::DeserializeFailed);
    }
    Ok(reduced)
}

// ============================================================================
// Proof serialization
// ============================================================================

/// Serialize a proof to canonical bytes (uncompressed points).
///
/// Layout:
/// - `w_comms[0..4]`: 4 x 64 bytes
/// - `z_comm`: 64 bytes
/// - `num_t_comms`: 4 bytes (u32 LE)
/// - `t_comms[0..n]`: n x 64 bytes
/// - `w_evals[0..4]`: 4 x 32 bytes
/// - `sigma_evals[0..4]`: 4 x 32 bytes
/// - `z_eval`: 32 bytes
/// - `z_omega_eval`: 32 bytes
/// - `selector_evals[0..7]`: 7 x 32 bytes
/// - `t_eval`: 32 bytes
/// - `w_zeta`: 64 bytes
/// - `w_zeta_omega`: 64 bytes
pub fn proof_to_bytes(proof: &Proof) -> Vec<u8> {
    let num_t = proof.t_comms.len();
    // Fixed: 4*64 + 64 + 4 + 4*32 + 4*32 + 32 + 32 + 7*32 + 32 + 64 + 64
    // = 256 + 64 + 4 + 128 + 128 + 32 + 32 + 224 + 32 + 64 + 64 = 1028
    // Variable: num_t * 64
    let capacity = 1028 + num_t * G1_UNCOMPRESSED_SIZE;
    let mut buf = Vec::with_capacity(capacity);

    // Wire commitments
    for comm in &proof.w_comms {
        buf.extend_from_slice(&serialize_g1(comm));
    }
    // z commitment
    buf.extend_from_slice(&serialize_g1(&proof.z_comm));
    // Quotient polynomial commitments (variable length)
    buf.extend_from_slice(&(num_t as u32).to_le_bytes());
    for comm in &proof.t_comms {
        buf.extend_from_slice(&serialize_g1(comm));
    }
    // Wire evaluations
    for eval in &proof.w_evals {
        buf.extend_from_slice(&serialize_fr(eval));
    }
    // Sigma evaluations
    for eval in &proof.sigma_evals {
        buf.extend_from_slice(&serialize_fr(eval));
    }
    // z evaluations
    buf.extend_from_slice(&serialize_fr(&proof.z_eval));
    buf.extend_from_slice(&serialize_fr(&proof.z_omega_eval));
    // Selector evaluations
    for eval in &proof.selector_evals {
        buf.extend_from_slice(&serialize_fr(eval));
    }
    // t evaluation
    buf.extend_from_slice(&serialize_fr(&proof.t_eval));
    // Opening witnesses
    buf.extend_from_slice(&serialize_g1(&proof.w_zeta));
    buf.extend_from_slice(&serialize_g1(&proof.w_zeta_omega));

    buf
}

/// Deserialize a proof from canonical bytes.
pub fn proof_from_bytes(bytes: &[u8]) -> Result<Proof, SerError> {
    let mut offset = 0;

    let read_g1 = |offset: &mut usize| -> Result<G1Affine, SerError> {
        if *offset + G1_UNCOMPRESSED_SIZE > bytes.len() {
            return Err(SerError::InvalidLength {
                expected: *offset + G1_UNCOMPRESSED_SIZE,
                got: bytes.len(),
            });
        }
        let pt = deserialize_g1(&bytes[*offset..*offset + G1_UNCOMPRESSED_SIZE])?;
        *offset += G1_UNCOMPRESSED_SIZE;
        Ok(pt)
    };

    let read_fr = |offset: &mut usize| -> Result<Fr, SerError> {
        if *offset + FR_SIZE > bytes.len() {
            return Err(SerError::InvalidLength {
                expected: *offset + FR_SIZE,
                got: bytes.len(),
            });
        }
        let s = deserialize_fr(&bytes[*offset..*offset + FR_SIZE])?;
        *offset += FR_SIZE;
        Ok(s)
    };

    // Wire commitments
    let mut w_comms = [G1Affine::default(); 4];
    for i in 0..4 {
        w_comms[i] = read_g1(&mut offset)?;
    }
    // z commitment
    let z_comm = read_g1(&mut offset)?;
    // Quotient commitments
    if offset + 4 > bytes.len() {
        return Err(SerError::InvalidLength { expected: offset + 4, got: bytes.len() });
    }
    let num_t = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    let mut t_comms = Vec::with_capacity(num_t);
    for _ in 0..num_t {
        t_comms.push(read_g1(&mut offset)?);
    }
    // Wire evaluations
    let mut w_evals = [Fr::default(); 4];
    for i in 0..4 {
        w_evals[i] = read_fr(&mut offset)?;
    }
    // Sigma evaluations
    let mut sigma_evals = [Fr::default(); 4];
    for i in 0..4 {
        sigma_evals[i] = read_fr(&mut offset)?;
    }
    // z evaluations
    let z_eval = read_fr(&mut offset)?;
    let z_omega_eval = read_fr(&mut offset)?;
    // Selector evaluations
    let mut selector_evals = [Fr::default(); 7];
    for i in 0..7 {
        selector_evals[i] = read_fr(&mut offset)?;
    }
    // t evaluation
    let t_eval = read_fr(&mut offset)?;
    // Opening witnesses
    let w_zeta = read_g1(&mut offset)?;
    let w_zeta_omega = read_g1(&mut offset)?;

    Ok(Proof {
        w_comms,
        z_comm,
        t_comms,
        w_evals,
        sigma_evals,
        z_eval,
        z_omega_eval,
        selector_evals,
        t_eval,
        w_zeta,
        w_zeta_omega,
    })
}

// ============================================================================
// Verification key serialization
// ============================================================================

/// Serialize a verification key to canonical bytes.
///
/// Layout:
/// - `q_m_comm..q_arith_comm`: 7 x 64 bytes (selector commitments)
/// - `sigma_comms[0..4]`: 4 x 64 bytes
/// - `domain_size`: 8 bytes (u64 LE)
/// - `num_public_inputs`: 8 bytes (u64 LE)
/// - `omega`: 32 bytes
/// - `k[0..4]`: 4 x 32 bytes
pub fn vk_to_bytes(vk: &VerificationKey) -> Vec<u8> {
    // 7*64 + 4*64 + 8 + 8 + 32 + 4*32 = 448 + 256 + 16 + 32 + 128 = 880
    let mut buf = Vec::with_capacity(880);

    buf.extend_from_slice(&serialize_g1(&vk.q_m_comm));
    buf.extend_from_slice(&serialize_g1(&vk.q_1_comm));
    buf.extend_from_slice(&serialize_g1(&vk.q_2_comm));
    buf.extend_from_slice(&serialize_g1(&vk.q_3_comm));
    buf.extend_from_slice(&serialize_g1(&vk.q_4_comm));
    buf.extend_from_slice(&serialize_g1(&vk.q_c_comm));
    buf.extend_from_slice(&serialize_g1(&vk.q_arith_comm));

    for comm in &vk.sigma_comms {
        buf.extend_from_slice(&serialize_g1(comm));
    }

    buf.extend_from_slice(&(vk.domain_size as u64).to_le_bytes());
    buf.extend_from_slice(&(vk.num_public_inputs as u64).to_le_bytes());
    buf.extend_from_slice(&serialize_fr(&vk.omega));

    for k in &vk.k {
        buf.extend_from_slice(&serialize_fr(k));
    }

    buf
}

/// Deserialize a verification key from canonical bytes.
pub fn vk_from_bytes(bytes: &[u8]) -> Result<VerificationKey, SerError> {
    let mut offset = 0;

    let read_g1 = |offset: &mut usize| -> Result<G1Affine, SerError> {
        if *offset + G1_UNCOMPRESSED_SIZE > bytes.len() {
            return Err(SerError::InvalidLength {
                expected: *offset + G1_UNCOMPRESSED_SIZE,
                got: bytes.len(),
            });
        }
        let pt = deserialize_g1(&bytes[*offset..*offset + G1_UNCOMPRESSED_SIZE])?;
        *offset += G1_UNCOMPRESSED_SIZE;
        Ok(pt)
    };

    let read_fr = |offset: &mut usize| -> Result<Fr, SerError> {
        if *offset + FR_SIZE > bytes.len() {
            return Err(SerError::InvalidLength {
                expected: *offset + FR_SIZE,
                got: bytes.len(),
            });
        }
        let s = deserialize_fr(&bytes[*offset..*offset + FR_SIZE])?;
        *offset += FR_SIZE;
        Ok(s)
    };

    let q_m_comm = read_g1(&mut offset)?;
    let q_1_comm = read_g1(&mut offset)?;
    let q_2_comm = read_g1(&mut offset)?;
    let q_3_comm = read_g1(&mut offset)?;
    let q_4_comm = read_g1(&mut offset)?;
    let q_c_comm = read_g1(&mut offset)?;
    let q_arith_comm = read_g1(&mut offset)?;

    let mut sigma_comms = [G1Affine::default(); 4];
    for i in 0..4 {
        sigma_comms[i] = read_g1(&mut offset)?;
    }

    if offset + 16 > bytes.len() {
        return Err(SerError::InvalidLength { expected: offset + 16, got: bytes.len() });
    }
    let domain_size = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;
    let num_public_inputs = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;

    let omega = read_fr(&mut offset)?;

    let mut k = [Fr::default(); 4];
    for i in 0..4 {
        k[i] = read_fr(&mut offset)?;
    }

    Ok(VerificationKey {
        q_m_comm,
        q_1_comm,
        q_2_comm,
        q_3_comm,
        q_4_comm,
        q_c_comm,
        q_arith_comm,
        sigma_comms,
        domain_size,
        num_public_inputs,
        omega,
        k,
    })
}

// ============================================================================
// Public input encoding
// ============================================================================

/// Encode public inputs as big-endian bytes for the EVM Solidity verifier.
///
/// Each Fr element is encoded as 32 bytes, most significant byte first.
/// This matches Solidity's `uint256` ABI encoding and the internal
/// `serialize_fr` layout, so a Solidity verifier can read public inputs
/// directly from `calldata` as `uint256[]` without any conversion.
pub fn public_inputs_to_bytes_be(inputs: &[Fr]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(inputs.len() * FR_SIZE);
    for input in inputs {
        let be_bytes = input.into_bigint().to_bytes_be();
        buf.extend_from_slice(&be_bytes);
    }
    buf
}

/// Encode public inputs as little-endian bytes.
///
/// Each Fr element is encoded as 32 bytes, least significant byte first.
/// This is the convention used by the genshi-solana instruction-data
/// encoder and `Fr::from_le_bytes_mod_order`.
pub fn public_inputs_to_bytes_le(inputs: &[Fr]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(inputs.len() * FR_SIZE);
    for input in inputs {
        buf.extend_from_slice(&input.into_bigint().to_bytes_le());
    }
    buf
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use crate::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
    use crate::proving::prover;
    use crate::proving::srs::SRS;

    fn make_simple_proof() -> (Proof, VerificationKey, Vec<Fr>) {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(3u64));
        let b = builder.add_variable(Fr::from(5u64));
        let c = builder.add(a, b);
        builder.set_public(c);
        let srs = SRS::insecure_for_testing(1024);
        let (proof, vk) = prover::prove(&builder, &srs);
        let pi = vec![Fr::from(8u64)];
        (proof, vk, pi)
    }

    #[test]
    fn test_proof_roundtrip() {
        let (proof, _, _) = make_simple_proof();
        let bytes = proof_to_bytes(&proof);
        let proof2 = proof_from_bytes(&bytes).expect("deserialization should succeed");

        // Re-serialize and compare bytes
        let bytes2 = proof_to_bytes(&proof2);
        assert_eq!(bytes, bytes2, "Proof roundtrip must produce identical bytes");
    }

    #[test]
    fn test_vk_roundtrip() {
        let (_, vk, _) = make_simple_proof();
        let bytes = vk_to_bytes(&vk);
        let vk2 = vk_from_bytes(&bytes).expect("deserialization should succeed");

        let bytes2 = vk_to_bytes(&vk2);
        assert_eq!(bytes, bytes2, "VK roundtrip must produce identical bytes");
    }

    #[test]
    fn test_proof_bytes_deterministic() {
        let (proof, _, _) = make_simple_proof();
        let bytes1 = proof_to_bytes(&proof);
        let bytes2 = proof_to_bytes(&proof);
        assert_eq!(bytes1, bytes2, "Same proof must produce same bytes");
    }

    #[test]
    fn test_deserialized_proof_verifies() {
        let (proof, vk, pi) = make_simple_proof();
        let srs = SRS::insecure_for_testing(1024);

        // Serialize and deserialize
        let bytes = proof_to_bytes(&proof);
        let proof2 = proof_from_bytes(&bytes).expect("deserialization should succeed");

        // Verify the deserialized proof
        let vk_bytes = vk_to_bytes(&vk);
        let vk2 = vk_from_bytes(&vk_bytes).expect("VK deserialization should succeed");

        assert!(
            crate::proving::verifier::verify(&proof2, &vk2, &pi, &srs),
            "Deserialized proof must verify"
        );
    }

    #[test]
    fn test_public_inputs_be_le_consistency() {
        let inputs = vec![Fr::from(42u64), Fr::from(100u64)];

        let le = public_inputs_to_bytes_le(&inputs);
        let be = public_inputs_to_bytes_be(&inputs);

        assert_eq!(le.len(), be.len());
        assert_eq!(le.len(), 64); // 2 * 32 bytes

        // Each 32-byte chunk should be reversed
        for i in 0..2 {
            let le_chunk = &le[i * 32..(i + 1) * 32];
            let be_chunk = &be[i * 32..(i + 1) * 32];
            let mut reversed = le_chunk.to_vec();
            reversed.reverse();
            assert_eq!(&reversed, be_chunk, "BE should be reversed LE");
        }
    }

    #[test]
    fn test_proof_from_truncated_bytes_fails() {
        let (proof, _, _) = make_simple_proof();
        let bytes = proof_to_bytes(&proof);
        // Truncate
        let truncated = &bytes[..bytes.len() / 2];
        assert!(proof_from_bytes(truncated).is_err());
    }

    #[test]
    fn test_proof_size() {
        let (proof, _, _) = make_simple_proof();
        let bytes = proof_to_bytes(&proof);
        let num_t = proof.t_comms.len();
        let expected = 4 * 64 + 64 + 4 + num_t * 64 + 4 * 32 + 4 * 32 + 32 + 32 + 7 * 32 + 32 + 64 + 64;
        assert_eq!(bytes.len(), expected, "Proof byte size must match layout");
    }

    // ====================================================================
    // Negative / edge-case tests
    // ====================================================================

    #[test]
    fn test_proof_from_empty_bytes_fails() {
        assert!(proof_from_bytes(&[]).is_err(), "Empty bytes should fail");
    }

    #[test]
    fn test_vk_from_empty_bytes_fails() {
        assert!(vk_from_bytes(&[]).is_err(), "Empty bytes should fail");
    }

    #[test]
    fn test_vk_from_truncated_bytes_fails() {
        let (_, vk, _) = make_simple_proof();
        let bytes = vk_to_bytes(&vk);
        let truncated = &bytes[..bytes.len() / 2];
        assert!(vk_from_bytes(truncated).is_err(), "Truncated VK should fail");
    }

    #[test]
    fn test_deserialize_corrupted_g1_point_fails() {
        // A G1 point where x,y are valid field elements but NOT on the curve
        let mut fake = vec![0u8; 64];
        // Set x = 1, y = 1 — almost certainly not on BN254 G1
        fake[31] = 1;
        fake[63] = 1;
        assert!(deserialize_g1(&fake).is_err(), "Off-curve point should fail");
    }

    #[test]
    fn test_deserialize_g1_identity() {
        let zeros = vec![0u8; 64];
        let point = deserialize_g1(&zeros).expect("All-zero should decode to identity");
        assert!(point.is_zero(), "All-zero bytes should be the identity");
    }

    #[test]
    fn test_serialize_deserialize_g1_identity_roundtrip() {
        let identity = G1Affine::zero();
        let bytes = serialize_g1(&identity);
        assert_eq!(bytes.len(), 64);
        assert!(bytes.iter().all(|&b| b == 0));
        let decoded = deserialize_g1(&bytes).unwrap();
        assert!(decoded.is_zero());
    }

    #[test]
    fn test_deserialize_fr_above_modulus_fails() {
        // Fr modulus for BN254 is ~2^254. Set all bytes to 0xFF — well above modulus.
        let all_ff = vec![0xFFu8; 32];
        assert!(
            deserialize_fr(&all_ff).is_err(),
            "Value above Fr modulus should fail canonical check"
        );
    }

    #[test]
    fn test_deserialize_fr_zero() {
        let zeros = vec![0u8; 32];
        let s = deserialize_fr(&zeros).expect("Zero should be valid");
        assert!(s.is_zero());
    }

    #[test]
    fn test_deserialize_fr_one() {
        let mut bytes = vec![0u8; 32];
        bytes[31] = 1; // big-endian 1
        let s = deserialize_fr(&bytes).expect("One should be valid");
        assert_eq!(s, Fr::from(1u64));
    }

    #[test]
    fn test_deserialize_fr_too_short_fails() {
        assert!(deserialize_fr(&[0u8; 16]).is_err(), "16 bytes should be too short for Fr");
    }

    #[test]
    fn test_deserialize_g1_too_short_fails() {
        assert!(deserialize_g1(&[0u8; 32]).is_err(), "32 bytes should be too short for G1");
    }

    #[test]
    fn test_proof_corrupted_single_byte_fails() {
        let (proof, _, _) = make_simple_proof();
        let mut bytes = proof_to_bytes(&proof);
        // Flip a byte in the middle of a G1 point
        bytes[10] ^= 0xFF;
        // This should either fail decoding or produce a different proof
        // (which won't roundtrip). Either outcome is acceptable for a
        // corruption test.
        match proof_from_bytes(&bytes) {
            Err(_) => {} // decode failed — good
            Ok(p2) => {
                let rebytes = proof_to_bytes(&p2);
                // If it somehow decoded, verify bytes differ (corruption detected)
                assert_ne!(
                    proof_to_bytes(&proof),
                    rebytes,
                    "Corrupted proof must not silently roundtrip to original"
                );
            }
        }
    }

    #[test]
    fn test_vk_corrupted_single_byte_fails() {
        let (_, vk, _) = make_simple_proof();
        let mut bytes = vk_to_bytes(&vk);
        bytes[10] ^= 0xFF;
        match vk_from_bytes(&bytes) {
            Err(_) => {}
            Ok(vk2) => {
                assert_ne!(
                    vk_to_bytes(&vk),
                    vk_to_bytes(&vk2),
                    "Corrupted VK must not silently roundtrip to original"
                );
            }
        }
    }

    #[test]
    fn test_public_inputs_empty() {
        assert!(public_inputs_to_bytes_be(&[]).is_empty());
        assert!(public_inputs_to_bytes_le(&[]).is_empty());
    }

    #[test]
    fn test_public_inputs_single_element() {
        let inputs = [Fr::from(42u64)];
        let be = public_inputs_to_bytes_be(&inputs);
        let le = public_inputs_to_bytes_le(&inputs);
        assert_eq!(be.len(), 32);
        assert_eq!(le.len(), 32);
        // BE and LE of the same scalar should be reverses
        let mut le_rev = le.clone();
        le_rev.reverse();
        assert_eq!(be, le_rev);
    }

    #[test]
    fn test_vk_domain_size_preserved() {
        let (_, vk, _) = make_simple_proof();
        let bytes = vk_to_bytes(&vk);
        let vk2 = vk_from_bytes(&bytes).unwrap();
        assert_eq!(vk.domain_size, vk2.domain_size);
        assert_eq!(vk.num_public_inputs, vk2.num_public_inputs);
        assert_eq!(vk.omega, vk2.omega);
        assert_eq!(vk.k, vk2.k);
    }
}
