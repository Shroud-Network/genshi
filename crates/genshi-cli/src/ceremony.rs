//! Powers-of-Tau ceremony for genshi.
//!
//! Produces an SRS compatible with `genshi_core::proving::srs::SRS`. The
//! ceremony uses OS entropy for each participant's secret, applies it to
//! the running SRS, then zeroizes the secret from memory.
//!
//! Security model: 1-of-N trust. As long as ANY participant destroys their
//! secret, the toxic waste (tau) is unrecoverable. A single-participant
//! ceremony with proper randomness is already stronger than a deterministic
//! SRS — but multi-party ceremonies are preferred for production.
//!
//! The output is byte-identical to what `SRS::save_to_bytes()` produces,
//! so it's directly loadable by `SRS::load_from_bytes()` and compatible
//! with every genshi command that takes `--srs`.

use ark_bn254::{Bn254, Fr, G1Affine as ArkG1Affine, G1Projective, G2Affine as ArkG2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{One, UniformRand};
use genshi_math::{G1Affine, G2Affine};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use genshi_core::proving::srs::SRS;

// ============================================================================
// Contribution protocol
// ============================================================================

/// Receipt from a single contribution. Anyone can verify the contributor
/// applied a consistent scalar via the pairing check:
///   e(witness_g1, G2) == e(G1, witness_g2)
#[derive(Clone, Debug)]
pub struct ContributionReceipt {
    pub participant_index: usize,
    pub witness_g1: ArkG1Affine,
    pub witness_g2: ArkG2Affine,
}

impl ContributionReceipt {
    /// Verify the receipt is internally consistent (the same scalar was
    /// used for both G1 and G2 witnesses).
    pub fn verify_witness(&self) -> bool {
        let g1 = ArkG1Affine::generator();
        let g2 = ArkG2Affine::generator();
        // e(witness_g1, G2_gen) == e(G1_gen, witness_g2)
        Bn254::pairing(self.witness_g1, g2) == Bn254::pairing(g1, self.witness_g2)
    }
}

/// Apply one participant's secret to the running SRS.
///
/// Protocol:
///   1. Sample s from OS entropy
///   2. For i in 0..n: g1_powers[i] *= s^i  (new tau = old_tau * s)
///   3. g2_tau *= s
///   4. Zeroize s from memory
///
/// Returns a receipt proving the contributor used a consistent scalar.
pub fn contribute(srs: &mut SRS, participant_index: usize) -> ContributionReceipt {
    let mut rng = OsRng;
    let mut secret = Fr::rand(&mut rng);

    // Compute the public witness before touching the SRS
    let witness_g1 = (G1Projective::generator() * secret).into_affine();
    let witness_g2 = (G2Projective::generator() * secret).into_affine();

    // Accumulate s^0, s^1, s^2, ... across G1 powers
    let mut power = Fr::one();
    for pt in srs.g1_powers.iter_mut() {
        let proj: G1Projective = pt.to_ark().into();
        *pt = G1Affine::from_ark((proj * power).into_affine());
        power *= secret;
    }

    // G2: g2 stays (s^0 = 1), g2_tau gets multiplied by s
    let g2_tau_proj: G2Projective = srs.g2_tau.to_ark().into();
    srs.g2_tau = G2Affine::from_ark((g2_tau_proj * secret).into_affine());

    // CRITICAL: destroy the secret. This is the entire trust model.
    secret.zeroize();

    ContributionReceipt {
        participant_index,
        witness_g1,
        witness_g2,
    }
}

// ============================================================================
// Verification
// ============================================================================

/// Verify the internal consistency of a ceremony SRS.
///
/// For consecutive G1 pairs, checks the pairing relation:
///   e(g1_powers[i+1], g2) == e(g1_powers[i], g2_tau)
///
/// This confirms all G1 points encode consecutive powers of the same tau,
/// and that g2_tau is consistent with the G1 sequence.
pub fn verify_srs(srs: &SRS) -> Result<(), String> {
    let g1_gen = G1Affine::generator();
    let g2_gen = G2Affine::generator();

    if srs.g1_powers[0] != g1_gen {
        return Err("g1_powers[0] is not the generator".into());
    }

    if srs.g2 != g2_gen {
        return Err("g2 is not the G2 generator".into());
    }

    // Pairing consistency: e(g1_powers[i+1], g2) == e(g1_powers[i], g2_tau)
    for i in 0..srs.g1_powers.len() - 1 {
        let lhs = Bn254::pairing(srs.g1_powers[i + 1].to_ark(), srs.g2.to_ark());
        let rhs = Bn254::pairing(srs.g1_powers[i].to_ark(), srs.g2_tau.to_ark());

        if lhs != rhs {
            return Err(format!(
                "pairing check failed at index {i}: \
                 e([t^{}], [1]_2) != e([t^{i}], [t]_2)",
                i + 1
            ));
        }
    }

    Ok(())
}

// ============================================================================
// Full ceremony runner
// ============================================================================

/// Run a complete Powers-of-Tau ceremony and return the SRS + receipts.
///
/// The resulting SRS is directly usable by every genshi command.
pub fn run_ceremony(
    max_degree: usize,
    num_participants: usize,
) -> (SRS, Vec<ContributionReceipt>) {
    eprintln!("  genshi Powers-of-Tau ceremony");
    eprintln!("  max_degree={}, participants={}, G1 points={}",
        max_degree, num_participants, max_degree + 1);
    eprintln!();

    // Initialize at the identity state: all G1 powers = generator (tau = 1)
    let g1_gen = G1Affine::generator();
    let g2_gen = G2Affine::generator();
    let mut srs = SRS {
        g1_powers: vec![g1_gen; max_degree + 1],
        g2: g2_gen,
        g2_tau: g2_gen,
    };

    let mut receipts = Vec::with_capacity(num_participants);

    for i in 0..num_participants {
        let receipt = contribute(&mut srs, i);

        assert!(
            receipt.verify_witness(),
            "participant {i}: witness receipt failed self-check"
        );

        eprintln!(
            "  participant {}/{}: contributed and verified",
            i + 1,
            num_participants
        );
        receipts.push(receipt);
    }

    eprintln!();
    eprintln!("  verifying SRS pairing consistency...");
    match verify_srs(&srs) {
        Ok(()) => eprintln!("  SRS is valid"),
        Err(e) => panic!("  SRS verification failed: {e}"),
    }
    eprintln!();

    (srs, receipts)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremony_produces_valid_srs() {
        let (srs, receipts) = run_ceremony(15, 3);
        assert_eq!(srs.g1_powers.len(), 16);
        assert_eq!(receipts.len(), 3);
        assert!(verify_srs(&srs).is_ok());
    }

    #[test]
    fn roundtrip_serialization() {
        let (srs, _) = run_ceremony(7, 2);
        let bytes = srs.save_to_bytes();
        let recovered = SRS::load_from_bytes(&bytes);

        assert_eq!(srs.g1_powers, recovered.g1_powers);
        assert_eq!(srs.g2, recovered.g2);
        assert_eq!(srs.g2_tau, recovered.g2_tau);
        assert!(verify_srs(&recovered).is_ok());
    }

    #[test]
    fn single_participant_is_sufficient() {
        let (srs, _) = run_ceremony(7, 1);
        assert!(verify_srs(&srs).is_ok());
    }

    #[test]
    fn tampered_srs_fails_verification() {
        let (mut srs, _) = run_ceremony(7, 2);
        let rogue = (G1Projective::generator() * Fr::from(9999u64)).into_affine();
        srs.g1_powers[3] = G1Affine::from_ark(rogue);
        assert!(verify_srs(&srs).is_err());
    }

    #[test]
    fn receipt_witnesses_are_consistent() {
        let (_, receipts) = run_ceremony(7, 5);
        for r in &receipts {
            assert!(
                r.verify_witness(),
                "receipt for participant {} failed",
                r.participant_index
            );
        }
    }

    #[test]
    fn tau_zero_is_generator() {
        let (srs, _) = run_ceremony(7, 3);
        assert_eq!(srs.g1_powers[0], G1Affine::generator());
    }

    #[test]
    fn ceremony_srs_works_with_prover() {
        // End-to-end: ceremony SRS can actually prove and verify a circuit
        use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;

        let (srs, _) = run_ceremony(1023, 2);

        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(3u64));
        let b = builder.add_variable(Fr::from(5u64));
        let c = builder.add(a, b);
        builder.set_public(c);

        let vk = genshi_core::proving::prover::extract_vk_from_builder(&builder, &srs);
        let (proof, _) = genshi_core::proving::prover::prove(&builder, &srs);
        let public_inputs: Vec<genshi_math::Fr> =
            vec![genshi_math::Fr::from_ark(Fr::from(8u64))];

        assert!(
            genshi_core::proving::verifier::verify(&proof, &vk, &public_inputs, &srs),
            "proof from ceremony SRS must verify"
        );
    }
}
