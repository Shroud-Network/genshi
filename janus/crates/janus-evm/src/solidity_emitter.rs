//! Solidity verifier code generation.
//!
//! Given a [`VerificationKey`] and an [`SRS`], emits a self-contained
//! Solidity contract that verifies Janus PLONK-KZG proofs on-chain.
//!
//! The emitted verifier implements the same four steps as
//! [`janus_core::proving::verifier::verify`]:
//!
//! 1. Fiat-Shamir transcript replay (Keccak-256 — native EVM opcode).
//! 2. Constraint equation check at `ζ`:
//!    `t(ζ)·Z_H(ζ) = gate(ζ) + α·perm(ζ) + α²·boundary(ζ)`.
//! 3. Batch KZG opening check at `ζ` via a single `ecPairing` call.
//! 4. `z` opening check at `ζω` via a second `ecPairing` call.
//!
//! Only universal BN254 precompiles are used (Invariant J3):
//! - `ecAdd`   (0x06)
//! - `ecMul`   (0x07)
//! - `ecPairing` (0x08)
//! - `modexp`  (0x05)
//!
//! Plus the `KECCAK256` opcode for the transcript.
//!
//! # Byte-level compatibility (Invariant J1)
//!
//! The generated Solidity code decodes proof bytes using the exact same
//! layout as [`janus_core::proving::serialization::proof_to_bytes`]
//! (big-endian uncompressed), and replays the transcript with the exact
//! same label / length-prefix encoding as
//! [`janus_core::proving::transcript::Transcript`]. As a result, the same
//! proof bytes verified by the Rust verifier will also verify on-chain.
//!
//! # Application customization
//!
//! Applications customize the contract name and Solidity pragma via
//! [`EmitterOptions`]. The [`generate_verifier_sol`] convenience function
//! uses sensible defaults; pass [`EmitterOptions`] to
//! [`generate_verifier_sol_with`] when integrating with an existing
//! contract suite.

use core::fmt::Write;

use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

use janus_core::proving::prover::VerificationKey;
use janus_core::proving::srs::SRS;

// ===========================================================================
// Options
// ===========================================================================

/// Options for customizing emitted Solidity verifier source.
///
/// `Default` uses a generic `JanusVerifier` contract with pragma `^0.8.24`.
/// Applications should override at least `contract_name` so multiple Janus
/// circuits can coexist in the same Solidity project.
#[derive(Debug, Clone)]
pub struct EmitterOptions {
    /// Contract name to use for the generated verifier.
    pub contract_name: String,
    /// Solidity version pragma string, including any caret/range operators.
    pub solidity_pragma: String,
    /// Optional NatSpec `@title` line. If empty, the `contract_name` is used.
    pub title: String,
    /// Optional NatSpec `@notice` line shown above the contract.
    pub notice: String,
}

impl Default for EmitterOptions {
    fn default() -> Self {
        Self {
            contract_name: "JanusVerifier".to_string(),
            solidity_pragma: "^0.8.24".to_string(),
            title: String::new(),
            notice: "Janus PLONK-KZG proof verifier (auto-generated).".to_string(),
        }
    }
}

impl EmitterOptions {
    pub fn with_contract_name(mut self, name: impl Into<String>) -> Self {
        self.contract_name = name.into();
        self
    }
    pub fn with_pragma(mut self, pragma: impl Into<String>) -> Self {
        self.solidity_pragma = pragma.into();
        self
    }
    pub fn with_notice(mut self, notice: impl Into<String>) -> Self {
        self.notice = notice.into();
        self
    }
}

// ===========================================================================
// Point / scalar formatting helpers
// ===========================================================================

/// Format a G1Affine point as two Solidity uint256 hex literals (x, y).
fn g1_to_hex(point: &G1Affine) -> (String, String) {
    if point.is_zero() {
        return ("0".into(), "0".into());
    }
    let x: ark_bn254::Fq = point.x().unwrap();
    let y: ark_bn254::Fq = point.y().unwrap();
    (
        format!("0x{}", hex::encode(&x.into_bigint().to_bytes_be())),
        format!("0x{}", hex::encode(&y.into_bigint().to_bytes_be())),
    )
}

/// Format a G2Affine point as four uint256 hex literals (EIP-197 order).
fn g2_to_hex(point: &G2Affine) -> (String, String, String, String) {
    if point.is_zero() {
        return ("0".into(), "0".into(), "0".into(), "0".into());
    }
    let x = point.x().unwrap();
    let y = point.y().unwrap();
    (
        format!("0x{}", hex::encode(&x.c1.into_bigint().to_bytes_be())),
        format!("0x{}", hex::encode(&x.c0.into_bigint().to_bytes_be())),
        format!("0x{}", hex::encode(&y.c1.into_bigint().to_bytes_be())),
        format!("0x{}", hex::encode(&y.c0.into_bigint().to_bytes_be())),
    )
}

fn fr_to_hex(scalar: &Fr) -> String {
    format!("0x{}", hex::encode(&scalar.into_bigint().to_bytes_be()))
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

// ===========================================================================
// Public API
// ===========================================================================

/// Generate a Solidity verifier contract using default [`EmitterOptions`].
pub fn generate_verifier_sol(vk: &VerificationKey, srs: &SRS) -> String {
    generate_verifier_sol_with(vk, srs, &EmitterOptions::default())
}

/// Generate a complete Solidity verifier contract with VK and SRS constants
/// baked in.
pub fn generate_verifier_sol_with(
    vk: &VerificationKey,
    srs: &SRS,
    opts: &EmitterOptions,
) -> String {
    let mut out = String::with_capacity(32 * 1024);

    emit_header(&mut out, opts);
    emit_contract_open(&mut out, opts);
    emit_constants(&mut out, vk, srs);
    emit_precompiles(&mut out);
    emit_field_arith(&mut out);
    emit_transcript_helpers(&mut out);
    emit_proof_struct(&mut out);
    emit_decoder(&mut out);
    emit_transcript_replay(&mut out);
    emit_constraint_equation(&mut out);
    emit_batch_kzg(&mut out);
    emit_z_opening(&mut out);
    emit_verify_entrypoint(&mut out);
    emit_contract_close(&mut out);

    out
}

// ===========================================================================
// Emitter sections
// ===========================================================================

fn emit_header(out: &mut String, opts: &EmitterOptions) {
    let title = if opts.title.is_empty() {
        opts.contract_name.clone()
    } else {
        opts.title.clone()
    };
    let _ = writeln!(out, "// SPDX-License-Identifier: MIT");
    let _ = writeln!(out, "pragma solidity {};", opts.solidity_pragma);
    let _ = writeln!(out);
    let _ = writeln!(out, "/// @title {title}");
    let _ = writeln!(out, "/// @notice {}", opts.notice);
    let _ = writeln!(out, "/// @dev Generated by janus-evm::solidity_emitter.");
    let _ = writeln!(
        out,
        "///      Uses only universal BN254 precompiles (Invariant J3):"
    );
    let _ = writeln!(
        out,
        "///      ecAdd (0x06), ecMul (0x07), ecPairing (0x08), modexp (0x05),"
    );
    let _ = writeln!(out, "///      plus the KECCAK256 opcode for the Fiat-Shamir transcript.");
    let _ = writeln!(
        out,
        "///      The decoder consumes proof bytes in the exact layout emitted by"
    );
    let _ = writeln!(
        out,
        "///      janus_core::proving::serialization::proof_to_bytes (BE uncompressed)."
    );
}

fn emit_contract_open(out: &mut String, opts: &EmitterOptions) {
    let _ = writeln!(out, "contract {} {{", opts.contract_name);
}

fn emit_contract_close(out: &mut String) {
    let _ = writeln!(out, "}}");
}

fn emit_constants(out: &mut String, vk: &VerificationKey, srs: &SRS) {
    let (qm_x, qm_y) = g1_to_hex(&vk.q_m_comm);
    let (q1_x, q1_y) = g1_to_hex(&vk.q_1_comm);
    let (q2_x, q2_y) = g1_to_hex(&vk.q_2_comm);
    let (q3_x, q3_y) = g1_to_hex(&vk.q_3_comm);
    let (q4_x, q4_y) = g1_to_hex(&vk.q_4_comm);
    let (qc_x, qc_y) = g1_to_hex(&vk.q_c_comm);
    let (qa_x, qa_y) = g1_to_hex(&vk.q_arith_comm);

    let sigma_xy: Vec<_> = vk.sigma_comms.iter().map(g1_to_hex).collect();

    let (g2_x1, g2_x0, g2_y1, g2_y0) = g2_to_hex(&srs.g2);
    let (g2t_x1, g2t_x0, g2t_y1, g2t_y0) = g2_to_hex(&srs.g2_tau);

    let _ = writeln!(out, "    // === Field moduli ===");
    let _ = writeln!(
        out,
        "    uint256 internal constant P = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001; // Fr (scalar field)"
    );
    let _ = writeln!(
        out,
        "    uint256 internal constant Q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47; // Fq (base field)"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "    // === G1 generator ===");
    let _ = writeln!(out, "    uint256 internal constant G1_X = 1;");
    let _ = writeln!(out, "    uint256 internal constant G1_Y = 2;");
    let _ = writeln!(out);
    let _ = writeln!(out, "    // === G2 generator (SRS) ===");
    let _ = writeln!(out, "    uint256 internal constant G2_X1 = {g2_x1};");
    let _ = writeln!(out, "    uint256 internal constant G2_X0 = {g2_x0};");
    let _ = writeln!(out, "    uint256 internal constant G2_Y1 = {g2_y1};");
    let _ = writeln!(out, "    uint256 internal constant G2_Y0 = {g2_y0};");
    let _ = writeln!(out);
    let _ = writeln!(out, "    // === tau * G2 ===");
    let _ = writeln!(out, "    uint256 internal constant G2T_X1 = {g2t_x1};");
    let _ = writeln!(out, "    uint256 internal constant G2T_X0 = {g2t_x0};");
    let _ = writeln!(out, "    uint256 internal constant G2T_Y1 = {g2t_y1};");
    let _ = writeln!(out, "    uint256 internal constant G2T_Y0 = {g2t_y0};");
    let _ = writeln!(out);
    let _ = writeln!(out, "    // === Domain parameters ===");
    let _ = writeln!(out, "    uint256 internal constant N = {};", vk.domain_size);
    let _ = writeln!(
        out,
        "    uint256 internal constant NUM_PI = {};",
        vk.num_public_inputs
    );
    let _ = writeln!(out, "    uint256 internal constant OMEGA = {};", fr_to_hex(&vk.omega));
    let _ = writeln!(out, "    uint256 internal constant K0 = {};", fr_to_hex(&vk.k[0]));
    let _ = writeln!(out, "    uint256 internal constant K1 = {};", fr_to_hex(&vk.k[1]));
    let _ = writeln!(out, "    uint256 internal constant K2 = {};", fr_to_hex(&vk.k[2]));
    let _ = writeln!(out, "    uint256 internal constant K3 = {};", fr_to_hex(&vk.k[3]));
    let _ = writeln!(out);
    let _ = writeln!(out, "    // === Selector commitments (VK) ===");
    let _ = writeln!(out, "    uint256 internal constant QM_X = {qm_x};");
    let _ = writeln!(out, "    uint256 internal constant QM_Y = {qm_y};");
    let _ = writeln!(out, "    uint256 internal constant Q1_X = {q1_x};");
    let _ = writeln!(out, "    uint256 internal constant Q1_Y = {q1_y};");
    let _ = writeln!(out, "    uint256 internal constant Q2_X = {q2_x};");
    let _ = writeln!(out, "    uint256 internal constant Q2_Y = {q2_y};");
    let _ = writeln!(out, "    uint256 internal constant Q3_X = {q3_x};");
    let _ = writeln!(out, "    uint256 internal constant Q3_Y = {q3_y};");
    let _ = writeln!(out, "    uint256 internal constant Q4_X = {q4_x};");
    let _ = writeln!(out, "    uint256 internal constant Q4_Y = {q4_y};");
    let _ = writeln!(out, "    uint256 internal constant QC_X = {qc_x};");
    let _ = writeln!(out, "    uint256 internal constant QC_Y = {qc_y};");
    let _ = writeln!(out, "    uint256 internal constant QA_X = {qa_x};");
    let _ = writeln!(out, "    uint256 internal constant QA_Y = {qa_y};");
    let _ = writeln!(out);
    let _ = writeln!(out, "    // === Permutation sigma commitments (VK) ===");
    for (i, (sx, sy)) in sigma_xy.iter().enumerate() {
        let _ = writeln!(out, "    uint256 internal constant S{i}_X = {sx};");
        let _ = writeln!(out, "    uint256 internal constant S{i}_Y = {sy};");
    }
    let _ = writeln!(out);
}

fn emit_precompiles(out: &mut String) {
    let _ = out.write_str(r#"    // ================================================================
    // BN254 precompile wrappers
    // ================================================================

    function _ecAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2)
        internal view returns (uint256 x, uint256 y)
    {
        uint256[4] memory input = [x1, y1, x2, y2];
        uint256[2] memory result;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x06, input, 0x80, result, 0x40)
        }
        require(ok, "ecAdd failed");
        return (result[0], result[1]);
    }

    function _ecMul(uint256 px, uint256 py, uint256 s)
        internal view returns (uint256 x, uint256 y)
    {
        uint256[3] memory input = [px, py, s];
        uint256[2] memory result;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x07, input, 0x60, result, 0x40)
        }
        require(ok, "ecMul failed");
        return (result[0], result[1]);
    }

    function _ecNeg(uint256 px, uint256 py) internal pure returns (uint256, uint256) {
        if (px == 0 && py == 0) return (0, 0);
        return (px, Q - (py % Q));
    }

    /// Two-pair BN254 pairing check: e(a1,b1) * e(a2,b2) == 1.
    /// `b*_X1/X0` and `b*_Y1/Y0` follow EIP-197 ordering (c1 first, then c0).
    function _pairing2(
        uint256 a1x, uint256 a1y,
        uint256 b1x1, uint256 b1x0, uint256 b1y1, uint256 b1y0,
        uint256 a2x, uint256 a2y,
        uint256 b2x1, uint256 b2x0, uint256 b2y1, uint256 b2y0
    ) internal view returns (bool) {
        uint256[12] memory input = [
            a1x, a1y,
            b1x1, b1x0, b1y1, b1y0,
            a2x, a2y,
            b2x1, b2x0, b2y1, b2y0
        ];
        uint256[1] memory result;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x08, input, 0x180, result, 0x20)
        }
        require(ok, "ecPairing failed");
        return result[0] == 1;
    }

"#);
}

fn emit_field_arith(out: &mut String) {
    let _ = out.write_str(r#"    // ================================================================
    // Field arithmetic mod P (Fr)
    // ================================================================

    function _addP(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, P);
    }
    function _subP(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, P - (b % P), P);
    }
    function _mulP(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, P);
    }
    function _expP(uint256 base, uint256 exp) internal view returns (uint256 result) {
        // modexp precompile: [len_b=32, len_e=32, len_m=32, base, exp, P]
        uint256[6] memory input = [uint256(32), uint256(32), uint256(32), base, exp, P];
        uint256[1] memory out_;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x05, input, 0xc0, out_, 0x20)
        }
        require(ok, "modexp failed");
        result = out_[0];
    }
    function _invP(uint256 a) internal view returns (uint256) {
        // Fermat: a^(P-2) mod P
        return _expP(a, P - 2);
    }

"#);
}

fn emit_transcript_helpers(out: &mut String) {
    let _ = out.write_str(r#"    // ================================================================
    // Fiat-Shamir transcript (Keccak-256) — byte-for-byte mirror of
    // janus_core::proving::transcript::Transcript.
    //
    // Encoding, byte-for-byte:
    //   init:          state = u32_le(len(domain_sep)) || domain_sep
    //   absorb(l,d):   state ||= u32_le(len(l)) || l || u32_le(len(d)) || d
    //   squeeze(l):
    //       state ||= "squeeze" || u32_le(len(l)) || l
    //       hash  := keccak256(state)
    //       state := hash                     // reseed (chaining)
    //       return Fr::from_be_bytes_mod_order(hash)
    //
    // Points are absorbed as 64 bytes `x_be || y_be`; the identity is 64 zero
    // bytes. Scalars are absorbed as 32 bytes big-endian.
    // ================================================================

    struct Tr { bytes buffer; }

    /// Little-endian u32 length prefix as a 4-byte memory blob.
    function _u32le(uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(4);
        out[0] = bytes1(uint8(len));
        out[1] = bytes1(uint8(len >> 8));
        out[2] = bytes1(uint8(len >> 16));
        out[3] = bytes1(uint8(len >> 24));
    }

    function _newTranscript(bytes memory domainSep) internal pure returns (Tr memory tr) {
        tr.buffer = abi.encodePacked(_u32le(domainSep.length), domainSep);
    }

    function _absorbBytes(Tr memory tr, bytes memory label, bytes memory data) internal pure {
        tr.buffer = abi.encodePacked(
            tr.buffer,
            _u32le(label.length), label,
            _u32le(data.length),  data
        );
    }

    function _absorbScalar(Tr memory tr, bytes memory label, uint256 value) internal pure {
        bytes memory data = new bytes(32);
        assembly { mstore(add(data, 0x20), value) }
        _absorbBytes(tr, label, data);
    }

    function _absorbPoint(Tr memory tr, bytes memory label, uint256 x, uint256 y) internal pure {
        bytes memory data = new bytes(64);
        // x_be || y_be — identity encoded as 64 zero bytes (matches Rust).
        assembly {
            mstore(add(data, 0x20), x)
            mstore(add(data, 0x40), y)
        }
        _absorbBytes(tr, label, data);
    }

    function _squeeze(Tr memory tr, bytes memory label) internal pure returns (uint256 challenge) {
        bytes memory squeezeTag = "squeeze";
        bytes memory full = abi.encodePacked(
            tr.buffer,
            squeezeTag,
            _u32le(label.length), label
        );
        bytes32 h = keccak256(full);
        // Reseed the state with the hash output (chaining construction).
        tr.buffer = abi.encodePacked(h);
        // Fr::from_be_bytes_mod_order: interpret as 256-bit big-endian int, reduce mod P.
        challenge = uint256(h) % P;
    }

"#);
}

fn emit_proof_struct(out: &mut String) {
    let _ = out.write_str(r#"    // ================================================================
    // Proof struct — mirrors janus_core::proving::prover::Proof
    // (the `t_comms` field is present in the serialized bytes but is not
    //  consumed by the verifier, so the decoder just skips over it.)
    // ================================================================

    struct Proof {
        uint256[4] wX;
        uint256[4] wY;
        uint256   zX;
        uint256   zY;
        uint256[4] wEvals;
        uint256[4] sigmaEvals;
        uint256   zEval;
        uint256   zOmegaEval;
        uint256[7] selEvals;
        uint256   tEval;
        uint256   wZetaX;
        uint256   wZetaY;
        uint256   wZetaOmegaX;
        uint256   wZetaOmegaY;
    }

"#);
}

fn emit_decoder(out: &mut String) {
    let _ = out.write_str(r#"    // ================================================================
    // Proof byte decoder
    //
    // Byte layout (matches janus_core::proving::serialization::proof_to_bytes):
    //   [0..256)     w_comms[0..4]       4 * 64 bytes (x_be || y_be)
    //   [256..320)   z_comm              64 bytes
    //   [320..324)   num_t_comms         u32 little-endian
    //   [324..324+64n) t_comms[0..n]     n * 64 bytes (skipped — unused)
    //   [..]         w_evals[0..4]       4 * 32 bytes BE
    //   [..]         sigma_evals[0..4]   4 * 32 bytes BE
    //   [..]         z_eval              32 bytes BE
    //   [..]         z_omega_eval        32 bytes BE
    //   [..]         selector_evals[0..7] 7 * 32 bytes BE
    //   [..]         t_eval              32 bytes BE
    //   [..]         w_zeta              64 bytes
    //   [..]         w_zeta_omega        64 bytes
    // ================================================================

    function _readU256BE(bytes calldata proof, uint256 offset) internal pure returns (uint256 v) {
        // bytes calldata: calldataload reads 32 bytes starting at the given offset.
        assembly {
            v := calldataload(add(proof.offset, offset))
        }
    }

    function _readU32LE(bytes calldata proof, uint256 offset) internal pure returns (uint256 v) {
        // Read 4 bytes at `offset` and interpret as little-endian u32.
        uint256 word;
        assembly {
            word := calldataload(add(proof.offset, offset))
        }
        // `word` is the 32 bytes starting at offset, big-endian interpretation.
        // We want the first 4 of those bytes as little-endian.
        uint256 b0 = (word >> 248) & 0xff;
        uint256 b1 = (word >> 240) & 0xff;
        uint256 b2 = (word >> 232) & 0xff;
        uint256 b3 = (word >> 224) & 0xff;
        v = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    function _decodeProof(bytes calldata proof) internal pure returns (Proof memory p) {
        uint256 off = 0;

        // Wire commitments
        for (uint256 i = 0; i < 4; i++) {
            p.wX[i] = _readU256BE(proof, off);      off += 32;
            p.wY[i] = _readU256BE(proof, off);      off += 32;
        }
        // z commitment
        p.zX = _readU256BE(proof, off);             off += 32;
        p.zY = _readU256BE(proof, off);             off += 32;

        // Quotient commitments — unused by the verifier, skipped.
        uint256 numT = _readU32LE(proof, off);      off += 4;
        off += 64 * numT;

        // Wire evaluations
        for (uint256 i = 0; i < 4; i++) {
            p.wEvals[i] = _readU256BE(proof, off);  off += 32;
        }
        // Sigma evaluations
        for (uint256 i = 0; i < 4; i++) {
            p.sigmaEvals[i] = _readU256BE(proof, off); off += 32;
        }
        // z / z(ωζ) evaluations
        p.zEval      = _readU256BE(proof, off);     off += 32;
        p.zOmegaEval = _readU256BE(proof, off);     off += 32;
        // Selector evaluations
        for (uint256 i = 0; i < 7; i++) {
            p.selEvals[i] = _readU256BE(proof, off); off += 32;
        }
        // Quotient evaluation
        p.tEval      = _readU256BE(proof, off);     off += 32;
        // Opening witnesses
        p.wZetaX     = _readU256BE(proof, off);     off += 32;
        p.wZetaY     = _readU256BE(proof, off);     off += 32;
        p.wZetaOmegaX = _readU256BE(proof, off);    off += 32;
        p.wZetaOmegaY = _readU256BE(proof, off);    off += 32;

        require(off == proof.length, "proof length mismatch");
    }

"#);
}

fn emit_transcript_replay(out: &mut String) {
    let _ = out.write_str(r#"    // ================================================================
    // Transcript replay — returns the five Plonk challenges in order:
    //   beta, gamma, alpha, zeta, nu
    //
    // Must match verifier.rs exactly. The domain separator and every
    // label below are byte-identical to the Rust transcript.
    // ================================================================

    // `verifier.rs` absorbs `t_comms` between `alpha` and `zeta`:
    //     for c in &proof.t_comms { transcript.absorb_point(b"t", c); }
    // The Solidity decoder skips the raw t_comms region (the verifier does
    // not otherwise consume those points), so we re-read the slice directly
    // from calldata inside the transcript replay below.
    function _replayTranscriptWithT(
        Proof memory p,
        bytes calldata proof,
        uint256 tCommsOffset,
        uint256 numT
    )
        internal pure
        returns (uint256 beta, uint256 gamma, uint256 alpha, uint256 zeta, uint256 nu)
    {
        Tr memory tr = _newTranscript("janus_plonk");

        // Round 1
        _absorbPoint(tr, "w", p.wX[0], p.wY[0]);
        _absorbPoint(tr, "w", p.wX[1], p.wY[1]);
        _absorbPoint(tr, "w", p.wX[2], p.wY[2]);
        _absorbPoint(tr, "w", p.wX[3], p.wY[3]);
        beta  = _squeeze(tr, "beta");
        gamma = _squeeze(tr, "gamma");

        // Round 2
        _absorbPoint(tr, "z", p.zX, p.zY);
        alpha = _squeeze(tr, "alpha");

        // Round 3 — quotient commitments, absorbed straight from calldata
        for (uint256 i = 0; i < numT; i++) {
            uint256 tcx = _readU256BE(proof, tCommsOffset + i * 64);
            uint256 tcy = _readU256BE(proof, tCommsOffset + i * 64 + 32);
            _absorbPoint(tr, "t", tcx, tcy);
        }
        zeta = _squeeze(tr, "zeta");

        // Round 4 — evaluations
        _absorbScalar(tr, "we", p.wEvals[0]);
        _absorbScalar(tr, "we", p.wEvals[1]);
        _absorbScalar(tr, "we", p.wEvals[2]);
        _absorbScalar(tr, "we", p.wEvals[3]);
        _absorbScalar(tr, "se", p.sigmaEvals[0]);
        _absorbScalar(tr, "se", p.sigmaEvals[1]);
        _absorbScalar(tr, "se", p.sigmaEvals[2]);
        _absorbScalar(tr, "se", p.sigmaEvals[3]);
        _absorbScalar(tr, "ze", p.zEval);
        _absorbScalar(tr, "zw", p.zOmegaEval);
        for (uint256 i = 0; i < 7; i++) {
            _absorbScalar(tr, "qe", p.selEvals[i]);
        }
        _absorbScalar(tr, "te", p.tEval);

        nu = _squeeze(tr, "nu");
    }

"#);
}

fn emit_constraint_equation(out: &mut String) {
    let _ = out.write_str(r#"    // ================================================================
    // Constraint equation at ζ:
    //   t(ζ)·Z_H(ζ) = gate(ζ) + α·perm(ζ) + α²·boundary(ζ)
    // ================================================================

    /// Return (Z_H(ζ), L_1(ζ)).
    function _domainEvals(uint256 zeta) internal view returns (uint256 zhZeta, uint256 l1Zeta) {
        // Z_H(ζ) = ζ^N - 1
        uint256 zetaN = _expP(zeta, N);
        zhZeta = _subP(zetaN, 1);

        // L_1(ζ) = (ζ^N - 1) / (N * (ζ - 1))
        uint256 zetaMinusOne = _subP(zeta, 1);
        if (zetaMinusOne == 0) {
            l1Zeta = 1;
        } else {
            uint256 denom = _mulP(N, zetaMinusOne);
            l1Zeta = _mulP(zhZeta, _invP(denom));
        }
    }

    /// Evaluate the public input polynomial PI(ζ) = -Σ pi_i · L_i(ζ).
    function _piZeta(uint256[] calldata pis, uint256 zeta, uint256 zhZeta)
        internal view returns (uint256 piZeta)
    {
        piZeta = 0;
        uint256 omegaI = 1;
        for (uint256 i = 0; i < pis.length; i++) {
            uint256 zetaMinusOmegaI = _subP(zeta, omegaI);
            uint256 li;
            if (zetaMinusOmegaI == 0) {
                // Degenerate case: pi_zeta -= pi_val
                piZeta = _subP(piZeta, pis[i] % P);
            } else {
                uint256 denom = _mulP(N, zetaMinusOmegaI);
                li = _mulP(omegaI, _mulP(zhZeta, _invP(denom)));
                piZeta = _subP(piZeta, _mulP(pis[i] % P, li));
            }
            // Advance omega^i
            omegaI = _mulP(omegaI, OMEGA);
        }
    }

    function _gateEval(Proof memory p, uint256 piZeta) internal pure returns (uint256) {
        // gate = q_arith * (q_m*w1*w2 + q_1*w1 + q_2*w2 + q_3*w3 + q_4*w4 + q_c) + PI(ζ)
        uint256 w1 = p.wEvals[0];
        uint256 w2 = p.wEvals[1];
        uint256 w3 = p.wEvals[2];
        uint256 w4 = p.wEvals[3];
        uint256 qm = p.selEvals[0];
        uint256 q1 = p.selEvals[1];
        uint256 q2 = p.selEvals[2];
        uint256 q3 = p.selEvals[3];
        uint256 q4 = p.selEvals[4];
        uint256 qc = p.selEvals[5];
        uint256 qa = p.selEvals[6];

        uint256 inner = _mulP(qm, _mulP(w1, w2));
        inner = _addP(inner, _mulP(q1, w1));
        inner = _addP(inner, _mulP(q2, w2));
        inner = _addP(inner, _mulP(q3, w3));
        inner = _addP(inner, _mulP(q4, w4));
        inner = _addP(inner, qc);
        uint256 gate = _mulP(qa, inner);
        return _addP(gate, piZeta);
    }

    function _permEval(
        Proof memory p, uint256 beta, uint256 gamma, uint256 zeta
    ) internal pure returns (uint256) {
        // perm = z(ζ) * Π(w_i + β·k_i·ζ + γ) - z(ζω) * Π(w_i + β·σ_i(ζ) + γ)
        uint256 w1 = p.wEvals[0];
        uint256 w2 = p.wEvals[1];
        uint256 w3 = p.wEvals[2];
        uint256 w4 = p.wEvals[3];

        uint256 num = p.zEval;
        num = _mulP(num, _addP(w1, _addP(_mulP(beta, _mulP(K0, zeta)), gamma)));
        num = _mulP(num, _addP(w2, _addP(_mulP(beta, _mulP(K1, zeta)), gamma)));
        num = _mulP(num, _addP(w3, _addP(_mulP(beta, _mulP(K2, zeta)), gamma)));
        num = _mulP(num, _addP(w4, _addP(_mulP(beta, _mulP(K3, zeta)), gamma)));

        uint256 den = p.zOmegaEval;
        den = _mulP(den, _addP(w1, _addP(_mulP(beta, p.sigmaEvals[0]), gamma)));
        den = _mulP(den, _addP(w2, _addP(_mulP(beta, p.sigmaEvals[1]), gamma)));
        den = _mulP(den, _addP(w3, _addP(_mulP(beta, p.sigmaEvals[2]), gamma)));
        den = _mulP(den, _addP(w4, _addP(_mulP(beta, p.sigmaEvals[3]), gamma)));

        return _subP(num, den);
    }

    function _checkConstraint(
        Proof memory p,
        uint256[] calldata pis,
        uint256 beta, uint256 gamma, uint256 alpha, uint256 zeta
    ) internal view returns (bool) {
        (uint256 zhZeta, uint256 l1Zeta) = _domainEvals(zeta);
        uint256 piZeta = _piZeta(pis, zeta, zhZeta);

        uint256 gate = _gateEval(p, piZeta);
        uint256 perm = _permEval(p, beta, gamma, zeta);
        uint256 boundary = _mulP(l1Zeta, _subP(p.zEval, 1));

        uint256 lhs = _mulP(p.tEval, zhZeta);
        uint256 rhs = _addP(gate, _addP(_mulP(alpha, perm), _mulP(_mulP(alpha, alpha), boundary)));
        return lhs == rhs;
    }

"#);
}

fn emit_batch_kzg(out: &mut String) {
    let _ = out.write_str(r#"    // ================================================================
    // Batch KZG opening check at ζ.
    //
    // F  = Σ_i nu^i · C_i      where (C_i, v_i) range over the 16 opened polys:
    //                          (w_1..w_4, σ_1..σ_4, q_m..q_arith, z)
    // v  = Σ_i nu^i · eval_i
    // Check:
    //   e(F - v·G1, G2) · e(-W_ζ, τ·G2 - ζ·G2) == 1
    // ================================================================

    struct BatchAcc {
        uint256 fx;
        uint256 fy;
        uint256 v;
        uint256 nuPow;
    }

    function _accumulate(
        BatchAcc memory acc,
        uint256 commX, uint256 commY,
        uint256 eval,
        uint256 nu
    ) internal view {
        (uint256 mx, uint256 my) = _ecMul(commX, commY, acc.nuPow);
        if (acc.fx == 0 && acc.fy == 0) {
            acc.fx = mx;
            acc.fy = my;
        } else {
            (acc.fx, acc.fy) = _ecAdd(acc.fx, acc.fy, mx, my);
        }
        acc.v = _addP(acc.v, _mulP(eval, acc.nuPow));
        acc.nuPow = _mulP(acc.nuPow, nu);
    }

    function _batchKzgCheck(Proof memory p, uint256 zeta, uint256 nu) internal view returns (bool) {
        BatchAcc memory acc;
        acc.nuPow = 1;

        // w_1..w_4
        _accumulate(acc, p.wX[0], p.wY[0], p.wEvals[0], nu);
        _accumulate(acc, p.wX[1], p.wY[1], p.wEvals[1], nu);
        _accumulate(acc, p.wX[2], p.wY[2], p.wEvals[2], nu);
        _accumulate(acc, p.wX[3], p.wY[3], p.wEvals[3], nu);

        // σ_1..σ_4
        _accumulate(acc, S0_X, S0_Y, p.sigmaEvals[0], nu);
        _accumulate(acc, S1_X, S1_Y, p.sigmaEvals[1], nu);
        _accumulate(acc, S2_X, S2_Y, p.sigmaEvals[2], nu);
        _accumulate(acc, S3_X, S3_Y, p.sigmaEvals[3], nu);

        // q_m, q_1..q_4, q_c, q_arith
        _accumulate(acc, QM_X, QM_Y, p.selEvals[0], nu);
        _accumulate(acc, Q1_X, Q1_Y, p.selEvals[1], nu);
        _accumulate(acc, Q2_X, Q2_Y, p.selEvals[2], nu);
        _accumulate(acc, Q3_X, Q3_Y, p.selEvals[3], nu);
        _accumulate(acc, Q4_X, Q4_Y, p.selEvals[4], nu);
        _accumulate(acc, QC_X, QC_Y, p.selEvals[5], nu);
        _accumulate(acc, QA_X, QA_Y, p.selEvals[6], nu);

        // z
        _accumulate(acc, p.zX, p.zY, p.zEval, nu);

        // LHS_g1 = F - v·G1
        (uint256 vgx, uint256 vgy) = _ecMul(G1_X, G1_Y, acc.v);
        (uint256 negVgx, uint256 negVgy) = _ecNeg(vgx, vgy);
        (uint256 lhsX, uint256 lhsY) = _ecAdd(acc.fx, acc.fy, negVgx, negVgy);

        // RHS_g2 = τ·G2 - ζ·G2  (computed via G2 subtraction — i.e. add τG2 to (-ζG2))
        // We cannot compute ζ·G2 on-chain (no G2 scalar mul precompile), so we
        // instead move the ζ term onto the G1 side:
        //   e(lhs, G2) · e(-W_ζ, τG2) · e(-W_ζ · (-ζ), G2) == 1
        //   ⇔  e(lhs + ζ·W_ζ, G2) · e(-W_ζ, τG2) == 1
        //
        // That is the two-pair form consumed by `_pairing2` below.
        (uint256 zetaWx, uint256 zetaWy) = _ecMul(p.wZetaX, p.wZetaY, zeta);
        (lhsX, lhsY) = _ecAdd(lhsX, lhsY, zetaWx, zetaWy);

        (uint256 negWx, uint256 negWy) = _ecNeg(p.wZetaX, p.wZetaY);

        return _pairing2(
            lhsX, lhsY,
            G2_X1, G2_X0, G2_Y1, G2_Y0,
            negWx, negWy,
            G2T_X1, G2T_X0, G2T_Y1, G2T_Y0
        );
    }

"#);
}

fn emit_z_opening(out: &mut String) {
    let _ = out.write_str(r#"    // ================================================================
    // z-opening check at ζω.
    //
    //   lhs_g1 = z_comm - z(ζω)·G1
    //   e(lhs_g1, G2) · e(-W_{ζω}, τG2 - ζω·G2) == 1
    //
    // As in the batch check, we fold the ζω·G2 term onto the G1 side:
    //   e(lhs_g1 + ζω·W_{ζω}, G2) · e(-W_{ζω}, τG2) == 1
    // ================================================================

    function _zOpeningCheck(Proof memory p, uint256 zeta) internal view returns (bool) {
        // ζω = ζ · ω
        uint256 zetaOmega = _mulP(zeta, OMEGA);

        (uint256 vgx, uint256 vgy) = _ecMul(G1_X, G1_Y, p.zOmegaEval);
        (uint256 negVgx, uint256 negVgy) = _ecNeg(vgx, vgy);
        (uint256 lhsX, uint256 lhsY) = _ecAdd(p.zX, p.zY, negVgx, negVgy);

        // Fold ζω term
        (uint256 zoWx, uint256 zoWy) = _ecMul(p.wZetaOmegaX, p.wZetaOmegaY, zetaOmega);
        (lhsX, lhsY) = _ecAdd(lhsX, lhsY, zoWx, zoWy);

        (uint256 negWx, uint256 negWy) = _ecNeg(p.wZetaOmegaX, p.wZetaOmegaY);

        return _pairing2(
            lhsX, lhsY,
            G2_X1, G2_X0, G2_Y1, G2_Y0,
            negWx, negWy,
            G2T_X1, G2T_X0, G2T_Y1, G2T_Y0
        );
    }

"#);
}

fn emit_verify_entrypoint(out: &mut String) {
    let _ = out.write_str(r#"    // ================================================================
    // Public entry point
    // ================================================================

    /// @notice Verify a Janus PLONK-KZG proof.
    /// @param proof Canonical proof bytes (see `_decodeProof` for the layout).
    /// @param publicInputs Public input scalar values; each must be < P.
    /// @return True iff the proof is valid for `publicInputs` under the
    ///         baked-in verification key.
    function verify(bytes calldata proof, uint256[] calldata publicInputs)
        external view returns (bool)
    {
        require(publicInputs.length == NUM_PI, "PI count mismatch");
        Proof memory p = _decodeProof(proof);

        // Locate the `t_comms` slice inside the raw proof bytes so the
        // transcript replay can absorb them in-place.
        // Layout: 4*64 w_comms (256) + 64 z_comm = 320, then u32 numT, then numT*64.
        uint256 numT = _readU32LE(proof, 320);
        uint256 tCommsOffset = 324;

        (uint256 beta, uint256 gamma, uint256 alpha, uint256 zeta, uint256 nu) =
            _replayTranscriptWithT(p, proof, tCommsOffset, numT);

        if (!_checkConstraint(p, publicInputs, beta, gamma, alpha, zeta)) return false;
        if (!_batchKzgCheck(p, zeta, nu)) return false;
        if (!_zOpeningCheck(p, zeta)) return false;

        return true;
    }

"#);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use janus_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
    use janus_core::proving::prover;
    use janus_core::proving::srs::SRS;

    fn small_vk() -> (VerificationKey, SRS) {
        let srs = SRS::insecure_for_testing(128);
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(3u64));
        let b = builder.add_variable(Fr::from(5u64));
        let c = builder.add(a, b);
        builder.set_public(c);
        let (_, vk) = prover::prove(&builder, &srs);
        (vk, srs)
    }

    #[test]
    fn test_generate_verifier_sol_has_all_sections() {
        let (vk, srs) = small_vk();
        let sol = generate_verifier_sol(&vk, &srs);

        assert!(sol.contains("contract JanusVerifier"));
        assert!(sol.contains("pragma solidity ^0.8.24"));
        assert!(sol.contains("function verify(bytes calldata proof, uint256[] calldata publicInputs)"));

        // Field moduli
        assert!(sol.contains("uint256 internal constant P = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"));
        assert!(sol.contains("uint256 internal constant Q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"));

        // Precompile wrappers
        assert!(sol.contains("staticcall(gas(), 0x06"));
        assert!(sol.contains("staticcall(gas(), 0x07"));
        assert!(sol.contains("staticcall(gas(), 0x08"));
        assert!(sol.contains("staticcall(gas(), 0x05"));

        // Transcript + constraint + pairings
        assert!(sol.contains("_replayTranscriptWithT"));
        assert!(sol.contains("_checkConstraint"));
        assert!(sol.contains("_batchKzgCheck"));
        assert!(sol.contains("_zOpeningCheck"));

        // VK + SRS constants baked in
        assert!(sol.contains("QM_X"));
        assert!(sol.contains("S3_Y"));
        assert!(sol.contains("G2_TAU_X1") || sol.contains("G2T_X1"));

        // Domain parameters
        let expected_n = format!("uint256 internal constant N = {};", vk.domain_size);
        assert!(sol.contains(&expected_n));
        let expected_npi = format!("uint256 internal constant NUM_PI = {};", vk.num_public_inputs);
        assert!(sol.contains(&expected_npi));
    }

    #[test]
    fn test_generate_verifier_sol_no_stub() {
        // Regression guard: the old emitter emitted a `_verifyInternal` that
        // unconditionally returned `true`. Ensure the real pairings are
        // wired now.
        let (vk, srs) = small_vk();
        let sol = generate_verifier_sol(&vk, &srs);

        assert!(!sol.contains("_verifyInternal"), "stub function should be gone");
        assert!(!sol.contains("return true;\n    }\n}"), "top-level return true is a stub smell");
    }

    #[test]
    fn test_transcript_labels_match_verifier_rs() {
        let (vk, srs) = small_vk();
        let sol = generate_verifier_sol(&vk, &srs);

        // These are the exact labels used in janus_core::proving::verifier.
        for label in ["janus_plonk", "\"w\"", "\"beta\"", "\"gamma\"", "\"z\"", "\"alpha\"",
                      "\"t\"", "\"zeta\"", "\"we\"", "\"se\"", "\"ze\"", "\"zw\"",
                      "\"qe\"", "\"te\"", "\"nu\""] {
            assert!(sol.contains(label), "generated verifier missing label {label}");
        }
    }

    #[test]
    fn test_emitter_options_custom_name() {
        let (vk, srs) = small_vk();
        let opts = EmitterOptions::default()
            .with_contract_name("TransferVerifier")
            .with_pragma("^0.8.20")
            .with_notice("Generated for the Transfer circuit.");

        let sol = generate_verifier_sol_with(&vk, &srs, &opts);
        assert!(sol.contains("contract TransferVerifier"));
        assert!(sol.contains("pragma solidity ^0.8.20"));
        assert!(sol.contains("Generated for the Transfer circuit"));
        assert!(!sol.contains("contract JanusVerifier"));
    }

    #[test]
    fn test_g1_to_hex_format() {
        let g1_gen = G1Affine::generator();
        let (x, y) = g1_to_hex(&g1_gen);
        assert!(x.starts_with("0x"));
        assert!(y.starts_with("0x"));
        assert!(x.ends_with("01"));
        assert!(y.ends_with("02"));
    }

    /// Dumps the generated verifier source + a real Rust-produced proof
    /// into a scratch foundry project at `/tmp/janus_fcheck/`, so the
    /// full EVM verification path can be exercised out-of-band with
    ///
    ///     forge test --match-contract JanusVerifierTest
    ///
    /// Runs as part of the normal test suite and re-materializes the
    /// scratch project on every `cargo test`. The native verifier is
    /// asserted before any bytes are written, so a regression in proof
    /// generation surfaces here even without re-running forge.
    #[test]
    fn dump_for_forge() {
        use janus_core::proving::serialization::{proof_to_bytes, public_inputs_to_bytes_be};
        use janus_core::proving::verifier;
        use std::fs;

        // Build a small public-input circuit and prove it.
        let srs = SRS::insecure_for_testing(128);
        let mut b = UltraCircuitBuilder::new();
        let a = b.add_variable(Fr::from(3u64));
        let c = b.add_variable(Fr::from(5u64));
        let s = b.add(a, c);
        b.set_public(s);

        let (proof, vk) = prover::prove(&b, &srs);
        let pis = [Fr::from(8u64)];

        // Sanity: the Rust verifier agrees before we ship bytes to Solidity.
        assert!(
            verifier::verify(&proof, &vk, &pis, &srs),
            "native verifier must accept the proof under test"
        );

        let sol = generate_verifier_sol(&vk, &srs);
        fs::create_dir_all("/tmp/janus_fcheck/src").unwrap();
        fs::create_dir_all("/tmp/janus_fcheck/test").unwrap();
        fs::create_dir_all("/tmp/janus_fcheck/testdata").unwrap();
        fs::write("/tmp/janus_fcheck/src/JanusVerifier.sol", sol).unwrap();

        // Proof bytes as hex for `vm.parseBytes`.
        let proof_bytes = proof_to_bytes(&proof);
        let hex_proof = format!("0x{}", hex::encode(&proof_bytes));
        fs::write("/tmp/janus_fcheck/testdata/proof.hex", hex_proof).unwrap();

        // Public inputs as decimal strings (one per line) — easiest thing to
        // ingest from a forge test via `vm.readLine`.
        let pi_lines: Vec<String> = pis.iter().map(|x| format!("{x}")).collect();
        fs::write(
            "/tmp/janus_fcheck/testdata/pi.txt",
            pi_lines.join("\n"),
        )
        .unwrap();

        // Also write BE bytes for completeness (not used by the forge test).
        fs::write(
            "/tmp/janus_fcheck/testdata/pi.be",
            public_inputs_to_bytes_be(&pis),
        )
        .unwrap();

        // foundry.toml — via_ir is required because the emitted verifier
        // carries enough locals to trip the legacy stack scheduler.
        fs::write(
            "/tmp/janus_fcheck/foundry.toml",
            r#"[profile.default]
src = "src"
out = "out"
cache_path = "cache"
solc_version = "0.8.24"
optimizer = true
optimizer_runs = 200
via_ir = true
fs_permissions = [{ access = "read", path = "./testdata" }]
"#,
        )
        .unwrap();

        // Forge test: reads proof.hex and the decimal PI line, calls
        // `verifier.verify(bytes, uint256[])`, asserts it returns true.
        fs::write(
            "/tmp/janus_fcheck/test/JanusVerifier.t.sol",
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/JanusVerifier.sol";

contract JanusVerifierTest is Test {
    JanusVerifier verifier;

    function setUp() public {
        verifier = new JanusVerifier();
    }

    function _loadProof() internal view returns (bytes memory) {
        string memory hexStr = vm.readFile("./testdata/proof.hex");
        return vm.parseBytes(hexStr);
    }

    function _loadPI() internal view returns (uint256[] memory) {
        string memory txt = vm.readFile("./testdata/pi.txt");
        // Single-element PI in this test — parse the whole file as one uint.
        uint256[] memory pi = new uint256[](1);
        pi[0] = vm.parseUint(txt);
        return pi;
    }

    function testVerifyRustProof() public view {
        bytes memory proof = _loadProof();
        uint256[] memory pi = _loadPI();
        bool ok = verifier.verify(proof, pi);
        assertTrue(ok, "Rust-generated proof must verify on-chain");
    }

    function testRejectsWrongPublicInput() public {
        bytes memory proof = _loadProof();
        uint256[] memory pi = new uint256[](1);
        pi[0] = 9; // off-by-one
        bool ok = verifier.verify(proof, pi);
        assertFalse(ok, "wrong public input must be rejected");
    }
}
"#,
        )
        .unwrap();
    }
}
