# Janus Framework — Technical Specification

> Version 0.2 — April 2026
> This document is the authoritative specification for the **Janus framework** only. It contains zero application-specific content. Shroud Pool, Cross-VM Bridge, and other consumer apps are specified in their own repositories.

---

## 1. Project Identity

| Field | Value |
|---|---|
| Name | `janus` |
| Type | Rust library crates (Cargo workspace) |
| Purpose | Generalized dual-VM zero-knowledge proving framework |
| Target VMs (v1) | EVM (Ethereum, Avalanche, Monad, Base, Arbitrum, Polygon, all BN254-precompile chains) + Solana |
| Primary runtime | Browser WASM (client-side proving) |
| Secondary runtime | Native binary (server-side proving) |
| Foundation | Arkworks ecosystem |
| Distribution | Published to crates.io as `janus-core`, `janus-evm`, `janus-solana`, `janus-wasm`, `janus-cli` |

Janus is a framework. It ships no applications. Consumer apps (Shroud Pool, bridges, private DEXes, etc.) live in their own repositories and depend on Janus as a regular Cargo dependency.

---

## 2. Load-Bearing Property

> **One proof, generated once, verifies bytewise-identically on EVM and Solana without re-encoding or re-proving.**

This is the framework's only promise. Everything else follows from it.

Consequences of this property:
- Single proof format, single transcript hash, single public-input encoding
- Verifier code paths are the same on native, WASM, and BPF (only the pairing primitive is swapped for the target)
- Any circuit written against Janus inherits dual-VM verification for free
- Cross-VM applications (bridges, multi-chain privacy) become property-of-the-framework, not per-app engineering

---

## 3. Architecture Decisions (Locked)

### 3.1 Proving System

- **PLONK with KZG polynomial commitments** over BN254
- 4-wire PLONKish arithmetization
- Universal KZG setup (Aztec's Powers of Tau); never per-circuit
- Custom gates beyond add/mul (Poseidon2 gate, elliptic gate, lookup gate — roadmap item; today only arithmetic gates are implemented)
- **No DSL.** Circuits are written in Rust via the `Circuit` trait using framework-provided builder and gadget APIs.

### 3.2 Commitment Curve

- **Grumpkin** for in-circuit EC operations (native to BN254's scalar field)
- **BN254** G1/G2 for verifier-side pairings
- Crate: `ark-grumpkin = "0.5"`
- No alternative curves in v1

### 3.3 Hash Function

- **Poseidon2** over BN254 scalar field
- Arities supported: t=2, t=3, t=4, t=5
- Parameters defined once in `janus-core/src/crypto/poseidon2.rs`, imported by all framework components and all consumer apps
- Parameter mismatch across native/WASM/BPF is a P0 bug class

### 3.4 Transcript Hash

- **Keccak-256** for all verifiers (EVM, Solana, native, WASM)
- Native EVM opcode (~36 gas)
- Accessible as syscall on Solana (`sol_keccak256`)
- No alternative transcript in v1

### 3.5 Lookup Tables

- Plookup-style grand-product argument
- Standard range tables: 8-bit, 16-bit, 32-bit, 64-bit
- Application-defined custom tables via registry pattern
- Lookup tables are baked into the verification key

### 3.6 SRS Source

- Aztec's Powers of Tau ceremony output
- No custom ceremony under any circumstances
- Lazy SRS loading in WASM SDK; cached in IndexedDB after first download
- SRS bytes are loaded into the prover as `&[u8]`; serialization format is canonical (`SRS::save_to_bytes`, `SRS::load_from_bytes`)

### 3.7 `no_std` Requirement

`janus-core` **must** compile to:
- `wasm32-unknown-unknown` (browser)
- Solana BPF (`sbf-solana-solana`)
- Native (x86_64, aarch64)

from the same source with the same output semantics. This is what makes the dual-VM property mechanically enforceable.

---

## 4. Framework Primitives

### 4.1 Curve Substrate

| Primitive | Type | Purpose |
|---|---|---|
| BN254 Fr | `ark_bn254::Fr` | Main scalar field; all circuit witness elements live here |
| BN254 Fq | `ark_bn254::Fq` | Base field; used for G1 coordinates |
| BN254 G1/G2 | `ark_bn254::{G1Affine, G2Affine}` | Curve points for KZG commitments |
| Grumpkin Fr | `ark_grumpkin::Fr` | Equal to BN254 Fq |
| Grumpkin G1 | `ark_grumpkin::Affine` | Native in-circuit EC ops |

### 4.2 Hash: Poseidon2

Single canonical implementation in `janus-core/src/crypto/poseidon2.rs`. Parameters:

- Full rounds: 8
- Partial rounds: 56
- S-box: x^5
- MDS matrix: Barretenberg-compatible
- Round constants: deterministically generated from a domain-separated seed

Supported arities: t=2, t=3, t=4, t=5

### 4.3 Pedersen Commitment (on Grumpkin)

```
C = amount * G + blinding * H   (on Grumpkin curve)
```

Generators G and H are derived via hash-to-curve from a nothing-up-my-sleeve seed with a documented derivation. Discrete log relationship between G and H is unknown.

### 4.4 Constraint System

- 4 wire columns (w1, w2, w3, w4)
- Selector polynomials: q_m, q_1, q_2, q_3, q_4, q_c, q_arith, q_lookup, q_range, q_elliptic
- Copy constraints via permutation argument
- Public input selector
- Lookup table registry

API: `janus_core::arithmetization::UltraCircuitBuilder` (renamed from `ultra_circuit_builder.rs`)

### 4.5 Gadgets (Application-Agnostic Only)

Janus ships only gadgets with no domain semantics. Specifically:

- **N-ary Poseidon2 Merkle inclusion** (`janus_core::gadgets::merkle`): generic over tree depth, arity, and leaf type. Apps choose their own depth and arity.
- **64-bit range proof** (`janus_core::gadgets::range`): via lookup table. Parameterized over bit-width.
- **Poseidon2 in-circuit hasher** (`janus_core::gadgets::poseidon2`): arity-generic.

**Gadgets explicitly not shipped by Janus** (these are domain-specific and live in consumer apps):
- Nullifier derivation (depends on what "a nullifier" means to the app)
- Note commitment (depends on what "a note" means to the app)
- Any gadget whose semantics assume a specific state model

### 4.6 Circuit Authoring API

Applications implement the `Circuit` trait:

```rust
pub trait Circuit {
    /// Private witness type
    type Witness;

    /// Public inputs type (must be representable as a slice of Fr)
    type PublicInputs: AsRef<[Fr]>;

    /// Stable identifier used for VK lookup, CLI dispatch, telemetry
    const ID: &'static str;

    /// Number of public inputs (must be consistent with PublicInputs::AsRef length)
    fn num_public_inputs() -> usize;

    /// Synthesize the circuit: add constraints to the builder, return public input wires.
    fn synthesize(
        builder: &mut UltraCircuitBuilder,
        witness: &Self::Witness,
    ) -> Self::PublicInputs;

    /// Return a dummy witness for VK extraction (structure only, values unused)
    fn dummy_witness() -> Self::Witness;
}
```

Once an app implements `Circuit`, the framework provides:
- `janus_core::proving::prove::<C>(witness, srs) -> (Proof, PublicInputs)`
- `janus_core::proving::verify::<C>(proof, vk, public_inputs, srs) -> bool`
- `janus_core::proving::extract_vk::<C>(srs) -> VerificationKey`
- `janus_evm::emit_verifier_sol::<C>(vk, opts) -> String`
- `janus_solana::verify_with_syscalls(proof, vk, public_inputs, srs) -> bool`

The app never writes proving or verifier code. It only writes `impl Circuit`.

### 4.7 Prover

`janus_core::proving::prover`:

```rust
pub fn prove<C: Circuit>(
    witness: &C::Witness,
    srs: &SRS,
) -> (Proof, C::PublicInputs);
```

Pipeline:
1. Build circuit from witness
2. Compute wire polynomials via iFFT over execution trace
3. KZG-commit to wire polynomials
4. Compute permutation grand product polynomial z(x)
5. Compute lookup grand product
6. Compute quotient polynomial t(x) = (gate + perm + boundary) / Z_H(x)
7. Fiat-Shamir challenge via Keccak transcript
8. Batch KZG opening at zeta + opening of z at zeta·omega
9. Serialize to canonical proof bytes

### 4.8 Verifier

`janus_core::proving::verifier`:

```rust
pub fn verify<C: Circuit>(
    proof: &Proof,
    vk: &VerificationKey,
    public_inputs: &C::PublicInputs,
    srs: &SRS,
) -> bool;

pub fn verify_prepare(
    proof: &Proof,
    vk: &VerificationKey,
    public_inputs: &[Fr],
) -> Option<VerificationIntermediates>;
```

`verify_prepare()` runs steps 1-2 (transcript + constraint equation) without executing pairings. It returns all G1/G2 points needed for the pairing checks. This is the factoring that enables:
- Native verification (arkworks pairing)
- Solana verification (`sol_alt_bn128_pairing` syscall)
- EVM verification (adapted in Solidity emitter)

All three verifiers use the **same `verify_prepare()` code path**. Only the pairing primitive swaps.

### 4.9 Verifier Exports

**EVM** (`janus-evm`):
```rust
pub fn generate_verifier_sol(
    vk: &VerificationKey,
    opts: EmitterOptions,
) -> String;
```
Produces a pure `verify(bytes proof, uint256[] publicInputs) -> bool` Solidity contract. No app logic, no state, no events. Uses only BN254 precompiles: ecAdd (0x06), ecMul (0x07), ecPairing (0x08), modexp (0x05). Contract name, pragma, and output format configurable via `EmitterOptions`.

**Solana** (`janus-solana`):
```rust
pub fn verify_with_syscalls(
    proof: &Proof,
    vk: &VerificationKey,
    public_inputs: &[Fr],
    srs: &SRS,
) -> bool;
```
On native builds, uses arkworks pairing for testing. On `sbf-solana-solana` target, uses `sol_alt_bn128_pairing` syscalls.

---

## 5. Verifier ABI (LOCKED)

This section defines the wire format that any consumer app must use. Changes to this section are breaking and require a framework major version bump.

### 5.1 Proof Byte Format

Uncompressed encoding:
- Each G1 point: 64 bytes (x: 32 BE, y: 32 BE)
- Each G2 point: 128 bytes (x1: 32 BE, x0: 32 BE, y1: 32 BE, y0: 32 BE)
- Each Fr element: 32 bytes LE (for internal prover state) or 32 bytes BE (for EVM public input path)

Proof layout:
```
[w1_commit:     64 bytes]  // G1
[w2_commit:     64 bytes]
[w3_commit:     64 bytes]
[w4_commit:     64 bytes]
[z_commit:      64 bytes]  // permutation grand product
[t_commit_0:    64 bytes]  // quotient polynomial chunks
[t_commit_1:    64 bytes]
[t_commit_2:    64 bytes]
[w_openings:   4*32 bytes] // wire evaluations at zeta
[z_opening:    32 bytes]   // z(zeta)
[z_omega:      32 bytes]   // z(zeta*omega)
[batch_w:      64 bytes]   // batch KZG opening witness
[z_shift_w:    64 bytes]   // opening witness for z at zeta*omega
```

Total: ~1,216 bytes (current). Target after Zeromorph migration: ~500 bytes.

Exact layout is defined in `janus-core::proving::serialization::{proof_to_bytes, proof_from_bytes}`. Both functions are the canonical source of truth.

### 5.2 Verification Key Byte Format

```
[num_public_inputs:  4 bytes LE u32]
[domain_size:        4 bytes LE u32]
[omega:              32 bytes LE]
[q_m_commit:         64 bytes]   // 7 selector commitments
[q_1_commit:         64 bytes]
[q_2_commit:         64 bytes]
[q_3_commit:         64 bytes]
[q_4_commit:         64 bytes]
[q_c_commit:         64 bytes]
[q_arith_commit:     64 bytes]
[sigma_1_commit:     64 bytes]   // 4 permutation commitments
[sigma_2_commit:     64 bytes]
[sigma_3_commit:     64 bytes]
[sigma_4_commit:     64 bytes]
```

Total: 880 bytes (current).

### 5.3 Public Input Encoding

Public inputs are ordered BN254 scalar field elements. Apps are responsible for placing them in a canonical order defined by their circuit (typically matching the declaration order of `#[public]` fields).

**On EVM**: `uint256[]` calldata, each element is an Fr in **big-endian**, left-padded to 32 bytes. `uint256` values must be less than the BN254 scalar field modulus; out-of-range values cause `verify()` to revert.

**On Solana**: `&[u8]` concatenation of Fr elements in **little-endian**, each 32 bytes. The framework provides `public_inputs_to_bytes_le()` and `public_inputs_to_bytes_be()` in `janus-core::serialization`.

**The values are identical** across chains — only the byte ordering differs. An app that uses `janus-core::serialization` helpers will always produce consistent encodings.

### 5.4 SRS Byte Format

```
[num_g1_powers:      4 bytes LE u32]
[g1_powers:          64 * num_g1_powers bytes]
[g2_one:             128 bytes]
[g2_tau:             128 bytes]
```

Defined in `janus-core::proving::srs::{save_to_bytes, load_from_bytes}`.

---

## 6. Crate Architecture

```
janus/                                    ← workspace root
├── Cargo.toml                             workspace manifest
├── README.md
├── Technical_Spec.md                      this file (moved here)
├── crates/
│   ├── janus-core/                        no_std library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                     public API re-exports
│   │       ├── circuit.rs                 Circuit trait
│   │       ├── crypto/
│   │       │   ├── poseidon2.rs
│   │       │   ├── pedersen.rs
│   │       │   ├── fields/
│   │       │   └── curves/
│   │       ├── arithmetization/
│   │       │   ├── ultra_circuit_builder.rs
│   │       │   ├── lookup_tables.rs
│   │       │   └── witness.rs             (witness assignment API, not JSON)
│   │       ├── gadgets/
│   │       │   ├── merkle.rs              (N-ary Poseidon2 Merkle)
│   │       │   ├── range.rs               (lookup-based range proofs)
│   │       │   └── poseidon2.rs           (in-circuit Poseidon2 hasher)
│   │       └── proving/
│   │           ├── srs.rs
│   │           ├── kzg.rs
│   │           ├── prover.rs              generic over Circuit
│   │           ├── verifier.rs            generic + verify_prepare()
│   │           ├── transcript.rs          Keccak-256
│   │           └── serialization.rs       canonical byte formats
│   │
│   ├── janus-evm/                         Solidity emitter + contract libs
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── solidity_emitter.rs        generic: generate_verifier_sol<C>()
│   │   │   └── poseidon2_sol.rs           Poseidon2 Solidity library generator
│   │   └── contracts/library/
│   │       ├── JanusVerifier.sol          reusable verifier template
│   │       ├── Poseidon2.sol              reusable Poseidon2 library
│   │       ├── MerkleTree.sol             N-ary Poseidon2 Merkle tree
│   │       ├── NullifierSet.sol           mapping(bytes32 => bool) + helpers
│   │       └── RootHistory.sol            circular buffer of recent roots
│   │
│   ├── janus-solana/                      no_std library for BPF verification
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── crypto/mod.rs              G1/G2 encoding, pairing_check_2
│   │       └── verify.rs                  verify_with_syscalls()
│   │
│   ├── janus-wasm/                        library crate, WASM helpers
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                     prove_with_circuit<C>(), panic hook,
│   │                                      JsError conversions, getrandom setup
│   │
│   └── janus-cli/                         framework tooling binary
│       ├── Cargo.toml
│       └── src/
│           └── main.rs                    gen-srs, emit-evm, emit-sol,
│                                          inspect-proof, inspect-vk commands
│                                          (no circuit-specific commands)
│
└── benches/
    └── prove_verify.rs                    generic benchmarks on reference circuits
```

**Critical invariant**: The `janus/` directory must contain zero references to application concepts. This is enforced by:
```bash
grep -rE "(note|nullifier|pool|shroud|bridge|shield|deposit|transfer|withdraw)" janus/
```
returning only matches in unrelated contexts (e.g., the word "transfer" in "transfer learning", if that ever appeared, which it shouldn't).

---

## 7. Dependencies

### Workspace-level (`janus/Cargo.toml`)

```toml
[workspace]
members = [
    "crates/janus-core",
    "crates/janus-evm",
    "crates/janus-solana",
    "crates/janus-wasm",
    "crates/janus-cli",
]
resolver = "2"

[workspace.dependencies]
ark-bn254    = "0.5"
ark-grumpkin = "0.5"
ark-ff       = "0.5"
ark-ec       = "0.5"
ark-poly     = "0.5"
ark-std      = { version = "0.5", default-features = false }
ark-poly-commit = "0.5"
ark-serialize = "0.5"
tiny-keccak  = { version = "2.0", features = ["keccak"] }
```

### `janus-core` features

```toml
[features]
default = ["std"]
std  = ["ark-std/std", "ark-ff/std", "ark-ec/std"]
```

No `serde` feature in the framework — serialization is done via explicit canonical byte functions, not serde. Apps that want JSON witnesses implement them at their own layer.

---

## 8. Dual-VM Deployment Matrix

| Component | EVM (any BN254 chain) | Solana |
|---|---|---|
| Proof generation | Browser WASM (apps wrap `janus-wasm`) | Browser WASM (same) |
| Proof format | PLONK-KZG, Keccak transcript, canonical bytes | PLONK-KZG, Keccak transcript, canonical bytes |
| On-chain verifier | Solidity contract (from `janus-evm::generate_verifier_sol`) | Rust BPF (from `janus-solana::verify_with_syscalls`) |
| Pairing primitive | ecPairing precompile (0x08) | `sol_alt_bn128_pairing` syscall |
| Hash primitive | keccak256 opcode | `sol_keccak256` syscall |
| Public input encoding | `uint256[]` big-endian | `&[u8]` little-endian (same values) |
| Verification cost target | ≤ 500K gas | ≤ 1.4M CU |

**The proving side is 100% shared.** Apps write one circuit, ship one prover (with app-specific circuit wiring), and get both verifier contracts from the framework with no modification.

---

## 9. Framework Guardrails (Security Invariants)

These are non-negotiable. Violation is a framework-level bug.

| # | Invariant | Detail |
|---|---|---|
| J1 | One proof, two VMs | Same `verify_prepare()` code path on native/WASM/BPF; only the pairing primitive swaps |
| J2 | Canonical proof bytes | `proof_to_bytes` / `proof_from_bytes` are the only valid serialization; version-locked in the ABI section above |
| J3 | Keccak transcript everywhere | Single implementation in `janus-core::proving::transcript`; no alternatives compiled in |
| J4 | Canonical public input encoding | `public_inputs_to_bytes_be` / `public_inputs_to_bytes_le` are the only valid encoders |
| J5 | Poseidon2 parameters canonical | One parameter set in `janus-core::crypto::poseidon2`; tested across all compilation targets |
| J6 | No cross-compilation drift | Test suite produces bit-identical outputs on native/WASM/BPF for identical inputs |
| J7 | SRS from verifiable ceremony | Aztec PoT only; production code rejects custom SRS |
| J8 | `no_std` compatibility | `janus-core` compiles to WASM and BPF from the same source as native |
| J9 | EVM precompile compatibility | Solidity verifier uses only ecAdd/ecMul/ecPairing/modexp — no chain-specific opcodes |
| J10 | Lookup table completeness | Every looked-up value must exist in table; extra entries that enable range bypass are rejected |
| J11 | No application code in framework | `janus/` directory contains zero references to domain concepts |
| J12 | Framework invariants hold for every circuit | Any `impl Circuit` that compiles against Janus inherits all of the above guarantees |

---

## 10. Application Authoring Guide

This section is a stub for v1. Full guide will ship with the v1 release.

### 10.1 Minimum Viable Consumer App

```rust
// my-app/Cargo.toml
[dependencies]
janus-core = "0.1"

// my-app/src/lib.rs
use janus_core::{Circuit, UltraCircuitBuilder, Fr};
use janus_core::gadgets::{merkle, range, poseidon2};

pub struct HelloWorldCircuit;

pub struct HelloWorldWitness {
    pub preimage: Fr,
}

impl Circuit for HelloWorldCircuit {
    type Witness = HelloWorldWitness;
    type PublicInputs = [Fr; 1];
    const ID: &'static str = "hello.poseidon";

    fn num_public_inputs() -> usize { 1 }

    fn synthesize(
        builder: &mut UltraCircuitBuilder,
        witness: &Self::Witness,
    ) -> Self::PublicInputs {
        let preimage_wire = builder.add_variable(witness.preimage);
        let digest_wire = poseidon2::hash_1(builder, preimage_wire);
        builder.set_public(digest_wire);
        [builder.get_value(digest_wire)]
    }

    fn dummy_witness() -> Self::Witness {
        HelloWorldWitness { preimage: Fr::from(0u64) }
    }
}
```

### 10.2 Going Dual-VM

```rust
use janus_core::proving::{prove, SRS};
use janus_evm::generate_verifier_sol;
use janus_solana::verify_with_syscalls;

let srs = SRS::load_from_bytes(include_bytes!("srs.bin"));
let (proof, pi) = prove::<HelloWorldCircuit>(&witness, &srs);

// EVM: emit a one-shot verifier contract
let vk = janus_core::proving::extract_vk::<HelloWorldCircuit>(&srs);
let sol_source = generate_verifier_sol(&vk, EmitterOptions::named("HelloWorldVerifier"));
std::fs::write("HelloWorldVerifier.sol", sol_source)?;

// Solana: use the BPF verifier directly in an Anchor program
// (same proof bytes, same public input values, LE encoding)
```

The contents of `proof` and `pi` are identical between chains. The only per-chain work is adjusting public input byte order, which the framework does via helper functions.

### 10.3 Full Application Authoring Guide

Will ship with v1 release as a separate document: `janus/docs/authoring-guide.md`.

---

## 11. Implementation Risks & Mitigations

### R1: Prover Correctness
- PLONK permutation, lookup grand product, KZG commitments, Fiat-Shamir have subtle correctness requirements
- **Mitigation**: Cross-verify all proofs against reference implementations (Barretenberg, TaceoLabs co-snarks) for shared test vectors

### R2: Poseidon2 Parameter Drift (HIGHEST)
- Wrong parameters = silent failure
- **Mitigation**: Single source of truth in `janus-core::crypto::poseidon2`; exhaustive cross-target test suite
- **Warning**: Solana's `sol_poseidon` syscall implements Poseidon (not Poseidon2); must never be used in the framework

### R3: Grumpkin Correctness
- Pedersen generators must be deterministic hash-to-curve from NUMS seed
- **Mitigation**: Property-based tests on commitment opening, generator derivation is versioned and documented

### R4: WASM Performance
- Single-threaded WASM may cap prover speedup at 10-20x
- SharedArrayBuffer requires COOP/COEP headers
- **Mitigation**: Benchmark early; fall back to native CLI if browser threading unavailable

### R5: SRS Distribution
- SRS must be downloaded to browser; size scales with max circuit size
- **Mitigation**: Lazy loading, trim to actual circuit size, IndexedDB cache

### R6: Lookup Table Soundness
- Incorrect tables produce verifiable-but-unsound proofs
- **Mitigation**: Deterministic table generation from circuit params; tests that out-of-range values fail proving

### R7: Solana CU Budget
- Framework target is ≤1.4M CU; no production reference exists
- **Mitigation**: `verify_prepare()` factoring keeps field arithmetic in native Rust; only pairings use syscalls; profile on devnet early

### R8: Public Input Encoding Drift
- Off-by-one in endianness or padding between EVM and Solana breaks G1
- **Mitigation**: Single implementation in `janus-core::serialization`; all apps must use these helpers; integration tests verify byte-level equivalence of encoded values

### R9: Framework/App Boundary Leakage
- Domain concepts creeping into `janus-core` breaks generality
- **Mitigation**: Grep-based CI check forbidding domain keywords in `janus/`; code review rule

### R10: Circuit Upgrade Path
- Circuit changes = new VK + new on-chain verifier
- **Mitigation**: Apps own circuit versioning; framework provides stable VK/proof encoding across circuit versions

---

## 12. Build Sequence

### Phase 0 (COMPLETE)
Pre-Janus work under the `shroud-honk` name:
- Crypto primitives (Poseidon2, Pedersen, Grumpkin)
- Constraint system (UltraCircuitBuilder, lookup tables)
- Gadgets (Merkle, range, Poseidon2 in-circuit)
- KZG + PLONK prover + verifier
- Keccak transcript, canonical serialization
- Transfer + Withdraw circuits (Shroud-specific, to be moved)
- Solidity emitter, Solana BPF verifier, WASM SDK, CLI
- **159 tests passing across all crates**

### Phase 1: Janus/App Split (CURRENT)
- Create `janus/` subdirectory with independent workspace
- Create `shroud-pool/` subdirectory with independent workspace
- Move framework code to `janus/crates/janus-*`
- Move Shroud-specific code (Note, Transfer, Withdraw, ShieldedPool.sol) to `shroud-pool/`
- Rename crates and update imports
- Delete old top-level `Cargo.toml` and `crates/` directory
- Success: all 159 tests still pass, both workspaces build independently

### Phase 2: Circuit Trait & Generic Prover API
- Add `janus-core::Circuit` trait
- Make `prover::prove` and `verifier::verify` generic over `C: Circuit`
- Port Shroud Pool's Transfer/Withdraw to `impl Circuit`
- Make Solidity emitter generic over VK shape (no hardcoded public input count, no hardcoded contract name)
- Make `janus-wasm` provide `prove_with_circuit::<C>()` helper
- Remove Shroud-specific functions from `janus-wasm` (`prove_transfer`, `prove_withdraw`, `compute_commitment`, `derive_nullifier`)
- Framework CI: grep for domain keywords; must be empty

### Phase 3: Performance Tier 0 (Custom Gates)
- Custom Poseidon2 gate (one round per gate)
- Custom Grumpkin elliptic gate
- Plookup grand product argument
- Benchmark: Shroud Pool Transfer circuit should drop from ~7,400 to ~2,000 constraints

### Phase 4: Shroud Pool v1 on Janus
- Shroud Pool's circuits use the new Circuit trait
- Shroud Pool ships its own app-specific WASM cdylib using `janus-wasm` helpers
- Shroud Pool ships its own TypeScript SDK
- Deploy ShieldedPool.sol on Avalanche Fuji (imports `JanusVerifier` from `janus-evm`)
- Deploy Solana Anchor program (imports `janus-solana`)
- Success: end-to-end deposit → transfer → withdraw on both chains using one proof

### Phase 5: Cross-VM Bridge (Second Consumer — Validates Generalization)
- Separate repository
- Defines its own `BridgeCircuit`, `BridgeNote` (different from Shroud Pool's Note)
- Ships `BridgePool.sol` + Solana bridge program, both importing Janus verifiers
- Success: one proof burns on source chain, mints on destination chain

### Phase 6: Framework v1 Release
- Publish `janus-core`, `janus-evm`, `janus-solana`, `janus-wasm`, `janus-cli` to crates.io
- Publish `janus/docs/authoring-guide.md`
- Accept the first external consumer

### Phase 7: Audit + Mainnet
- Professional audit of `janus-core` and `janus-evm`
- Mainnet deployment of Shroud Pool
- Bug bounty

---

## 13. External References

| Resource | URL |
|---|---|
| Arkworks ecosystem | https://arkworks.rs |
| ark-grumpkin crate | https://crates.io/crates/ark-grumpkin |
| TaceoLabs co-snarks (reference Rust UltraHonk) | https://github.com/TaceoLabs/co-snarks |
| Barretenberg docs | https://barretenberg.aztec.network/docs |
| PLONK paper | https://eprint.iacr.org/2019/953 |
| Plookup paper | https://eprint.iacr.org/2020/315 |
| Grumpkin curve spec | https://hackmd.io/@aztec-network/ByzgNxBfd |

---

## 14. Out of Scope for Janus v1

- Any consumer application (Shroud Pool, bridge, DEX, payroll, institutional channels)
- Recursion / proof aggregation (post-v1 roadmap item)
- Custom curves beyond BN254/Grumpkin
- Additional VM targets (Sui, Aptos, NEAR, Move) — post-PMF
- ACIR compatibility — post-v1 roadmap item
- GPU-accelerated MSM — post-v1 roadmap item
- Folding schemes (Nova, ProtoStar) — post-v1 roadmap item
- ZK-friendly DSL beyond the pure-Rust `Circuit` trait

Anything in this list is **explicitly** not a v1 feature and should not be added to `janus-core` until the framework/app boundary has been proven by at least two independent consumers (Shroud Pool + Bridge).
