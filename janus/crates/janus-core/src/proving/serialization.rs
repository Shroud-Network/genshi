//! Canonical proof and verification key serialization.
//!
//! Provides deterministic byte encoding for cross-VM compatibility (G7).
//! Uses uncompressed point encoding (64 bytes per G1Affine) so that
//! EVM precompiles and Solana syscalls can consume points directly
//! without decompression.
//!
//! Field elements are encoded as 32 bytes in little-endian (arkworks canonical).
//! Public input adapters provide big-endian (EVM) and little-endian (Solana).

use ark_bn254::{Fr, G1Affine};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
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
    point.serialize_uncompressed(&mut buf)
        .expect("G1 serialization should not fail");
    buf
}

fn deserialize_g1(bytes: &[u8]) -> Result<G1Affine, SerError> {
    G1Affine::deserialize_uncompressed(bytes)
        .map_err(|_| SerError::DeserializeFailed)
}

fn serialize_fr(scalar: &Fr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FR_SIZE);
    scalar.serialize_compressed(&mut buf)
        .expect("Fr serialization should not fail");
    buf
}

fn deserialize_fr(bytes: &[u8]) -> Result<Fr, SerError> {
    Fr::deserialize_compressed(bytes)
        .map_err(|_| SerError::DeserializeFailed)
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

/// Encode public inputs as big-endian bytes for EVM Solidity verifier.
///
/// Each Fr element is encoded as 32 bytes, most significant byte first.
/// This matches Solidity's `uint256` ABI encoding.
pub fn public_inputs_to_bytes_be(inputs: &[Fr]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(inputs.len() * FR_SIZE);
    for input in inputs {
        let le_bytes = serialize_fr(input);
        // Reverse to big-endian
        let mut be_bytes = le_bytes;
        be_bytes.reverse();
        buf.extend_from_slice(&be_bytes);
    }
    buf
}

/// Encode public inputs as little-endian bytes for Solana.
///
/// Each Fr element is encoded as 32 bytes, least significant byte first.
/// This matches arkworks canonical encoding and Solana's convention.
pub fn public_inputs_to_bytes_le(inputs: &[Fr]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(inputs.len() * FR_SIZE);
    for input in inputs {
        buf.extend_from_slice(&serialize_fr(input));
    }
    buf
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
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
}
