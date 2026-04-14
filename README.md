# Genshi

## A Generalized Dual-VM Zero-Knowledge Proving Framework

Version 0.2 — April 2026
Authors: Siddharth Manjul, Amit Sagar

> **genshi** (原始, jp.) — *origin; primordial; elemental.* The name reflects what the framework reduces dual-VM zero-knowledge proving to: a single elemental primitive. One proof, one format, two virtual machines — EVM and Solana — verified bytewise-identically.

---

## What genshi Is

genshi is a Rust-native zero-knowledge proving framework designed around a single load-bearing property:

> **One proof, written once, verifies on EVM and Solana without modification.**

The same proof byte string passes verification through the Solidity verifier on any EVM chain (Ethereum, Avalanche, Monad, Base, Arbitrum) and through the Rust BPF verifier on Solana. Public inputs use the same encoding. The transcript is Keccak on both sides. There is no per-chain reproving, no per-chain proof format, no per-chain circuit fork.

genshi is a **framework**, not an application. It has zero opinions about notes, accounts, balances, trees, or privacy schemes. Any team can write a circuit against genshi's primitives and inherit dual-VM verification for free.

---

## Why genshi Exists

The ZK tooling market today forces a choice between three bad options:

1. **Circom + Groth16**: Per-circuit trusted setup, R1CS-only (no lookup tables), slow browser proving via snarkjs, Baby Jubjub wrong-field arithmetic at ~700 constraints per scalar mul.
2. **Noir + Barretenberg**: Separate DSL, multi-stage toolchain (nargo → ACIR → bb), EVM-first with Solana support lagging, witness types duplicated across Noir and host language.
3. **Halo2**: Steep rotation/region API, no production Solana path, not designed for cross-VM proofs.

None of these treat **"the same proof verifies on both major L1 ecosystems"** as a first-class framework invariant. Every team that wants dual-VM privacy or dual-VM bridging ends up reimplementing verification glue, or worse, generating two separate proofs.

genshi exists to make that invariant load-bearing and automatic. A developer writes a circuit once in Rust, and the framework produces:

- A client-side prover (browser WASM + native CLI)
- A Solidity verifier contract
- A Solana BPF verifier program

All three verify the same proof bytes. No adapter layer. No re-encoding.

---

## Core Architecture

### Two-layer separation

genshi is deliberately split into two independent layers:

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│                                                              │
│  Shroud Pool │ Cross-VM Bridge │ Private DEX │ Payroll │ …  │
│                                                              │
│  Each app defines its own circuits using genshi primitives.  │
│  Each app ships its own contracts that import the genshi     │
│  verifier. Each app inherits dual-VM verification for free. │
└───────────────────────────┬─────────────────────────────────┘
                            │ depends on genshi-* crates
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  genshi Framework Layer                      │
│                                                              │
│  genshi-core   — constraint system, gadgets, prover, verifier│
│  genshi-evm    — Solidity verifier + reusable contract libs  │
│  genshi-solana — Rust BPF verifier                           │
│  genshi-wasm   — WASM helpers for browser provers            │
│  genshi-cli    — tooling (SRS gen, verifier emit, inspect)   │
│                                                              │
│  Zero application-specific code. Zero references to notes,  │
│  pools, nullifiers, bridges, or any domain concept.          │
└─────────────────────────────────────────────────────────────┘
```

The application layer is not distributed with the framework. genshi is published to crates.io as an independent set of crates. Applications live in their own repositories and depend on genshi as a standard Cargo dependency.

### Framework primitives

genshi provides:

- **Curve substrate.** Grumpkin (native to BN254's scalar field) for in-circuit EC ops. BN254 G1/G2 for verifier-side pairings. No alternative curves in v1.
- **Hash primitives.** Poseidon2 over BN254 with multiple arities (t=2, t=3, t=4, t=5). Identical parameters across prover, EVM verifier, Solana verifier, and SDK. Single source of truth; parameter drift is a P0 bug class.
- **Lookup tables.** Standard range checks (8/16/32/64-bit), bitwise ops, custom table registry for application-defined tables.
- **Constraint system.** 4-wire PLONKish arithmetization with custom gates. Apps write circuits via the `Circuit` trait (pure Rust, no separate DSL).
- **Proving system.** PLONK with KZG commitments on BN254. Universal setup — Aztec's Powers of Tau ceremony, never repeated. No per-circuit ceremony, ever.
- **Transcript.** Keccak-256 Fiat-Shamir on every side (prover, EVM verifier, Solana verifier, WASM, CLI). Native opcode on EVM, syscall-accessible on Solana.
- **Verifier exports.**
  - **EVM**: `genshiVerifier.sol` template using BN254 precompiles (ecAdd 0x06, ecMul 0x07, ecPairing 0x08, modexp 0x05). Generated from any verification key. Target ≤500K gas per verify.
  - **Solana**: `genshi-solana` crate compiled to BPF using `sol_alt_bn128_*` syscalls. Target ≤1.4M CU per verify.
- **Reusable Solidity libraries.** `Poseidon2.sol`, `MerkleTree.sol`, `NullifierSet.sol`, `RootHistory.sol` — building blocks apps can import without reinventing the wheel.

### Framework invariants

These are non-negotiable and enforced structurally, not by convention:

| # | Invariant | Enforcement |
|---|---|---|
| J1 | One proof, two VMs | Same code paths in `verify_prepare()` across native/WASM/BPF; only the pairing primitive is swapped |
| J2 | Keccak transcript everywhere | Single implementation in `genshi-core`; no alternatives |
| J3 | Canonical proof byte format | Fixed uncompressed G1/G2/Fr encoding in `genshi-core::serialization` |
| J4 | Canonical public input encoding | BN254 field elements, fixed-width, documented endianness per VM (big-endian EVM, little-endian Solana, same values) |
| J5 | No application code in the framework | Grep-enforced: `genshi/` must contain zero references to "note", "pool", "nullifier", "bridge", "shroud" in source or docs |
| J6 | SRS from verifiable ceremony | Aztec PoT only; custom SRS forbidden in production |
| J7 | `no_std` compatibility | `genshi-core` must compile to `wasm32-unknown-unknown` and Solana BPF from the same source |
| J8 | No cross-compilation parameter drift | Test suite produces bit-identical outputs across native/WASM/BPF targets |

### What genshi explicitly does not ship

- Any circuit with domain semantics (no `TransferCircuit`, no `BridgeCircuit`)
- Any opinionated data structure (no fixed Merkle depth, no nullifier format, no note layout)
- Any application contract beyond the verifier template
- Any opinion about how proofs are used downstream

If something in the framework references a domain concept, it's in the wrong layer. It moves to an app.

---

## Performance Targets

Framework-level guarantees that all consumer apps inherit:

| Metric | Target |
|---|---|
| Client-side proving (5K constraints, M-class laptop) | < 5 seconds |
| Client-side proving (5K constraints, mid-tier mobile) | < 15 seconds |
| WASM blob size (prover + typical app, gzipped) | < 10 MB |
| Proof size | < 1 KB |
| EVM verifier gas (any circuit) | ≤ 500K gas |
| Solana verifier compute (any circuit) | ≤ 1.4M CU |
| Poseidon2 t=3 cost in-circuit | ≤ 200 constraints (post custom-gate work) |
| Grumpkin fixed-base scalar mul in-circuit | ≤ 600 constraints |
| Per-circuit trusted setup | zero — universal KZG only |

UltraHonk's verifier cost is constant in proof size, not in circuit size, which is what makes the per-VM budgets achievable for arbitrary apps.

---

## How Applications Consume genshi

An application is any crate that depends on `genshi-core` (plus optionally `genshi-evm`, `genshi-solana`, `genshi-wasm`) and defines one or more circuits implementing the `Circuit` trait.

Minimal app skeleton:

```rust
use genshi_core::{Circuit, Builder, Prover, Verifier, SRS};
use genshi_core::gadgets::{merkle, range, poseidon2};

pub struct MyAppCircuit {
    // private witness fields
}

impl Circuit for MyAppCircuit {
    type Witness = MyWitness;
    type PublicInputs = [Fr; 3];
    const ID: &'static str = "my-app.main";

    fn synthesize(builder: &mut Builder, witness: &Self::Witness) -> Self::PublicInputs {
        // use genshi_core::gadgets to assemble constraints
        // return the public input wires
    }
}
```

Then the app:

1. Writes its own contracts (Solidity + Anchor) that import `genshiVerifier.sol` and `genshi-solana::verify_with_syscalls`
2. Writes its own SDK (TypeScript typically) that calls a small app-specific WASM cdylib using `genshi-wasm` helpers
3. Ships independently of the framework, on its own release cadence

An app never modifies genshi. If an app needs something the framework doesn't provide, the choice is either to add it as an app-level extension or to upstream it as a framework primitive — but only if it's genuinely application-agnostic.

---

## First Consumer: Shroud Pool

The first application built on genshi is **Shroud Pool** — an institutional privacy pool implementing private deposit, private transfer, and private withdraw operations using UTXO-style note commitments.

Shroud Pool lives in its own directory (`shroud-pool/`) as an independent workspace. It depends on `genshi-core`, `genshi-evm`, and `genshi-solana` as regular Cargo dependencies.

What Shroud Pool defines that genshi does not:
- The `Note` structure (amount, blinding, secret, nullifier preimage, owner pubkey, leaf index)
- Two-layer commitment scheme (Grumpkin Pedersen + Poseidon2 hash)
- Nullifier derivation (`Poseidon2(nullifier_preimage, secret, leaf_index)`)
- 4-ary Poseidon2 Merkle tree depth 10
- `TransferCircuit` and `WithdrawCircuit`
- `ShieldedPool.sol` contract
- Solana Anchor program
- TypeScript SDK with note management and memo encryption

Shroud Pool validates that genshi is consumable. Once Shroud Pool compiles against genshi with no reverse dependencies and no framework modifications, the split is proven.

### Planned Additional Consumers

The same framework will be consumed by:

- **Cross-VM Private Bridge** — A neutral burn-on-chain-A / mint-on-chain-B bridge. The mechanism is "one ZK proof submitted as calldata to two contracts on two chains; both verify identical bytes; each applies its side of a state transition." This is not a Shroud feature — it is a property of any circuit written against a framework whose verifier runs identically on both VMs. The bridge app will ship as a sibling consumer, not as a genshi feature.
- **Private Payroll** — Prove that a batch of N encrypted salaries sums to a public total, without revealing individual amounts.
- **Private DEX Venues** — Private AMM state transitions with hidden order sizes.
- **Institutional Dedicated Channels** — Permissioned payment flows between known counterparties.

Each of these consumes genshi the same way Shroud Pool does: via `cargo add genshi-core` and an `impl Circuit` block. The framework does not know any of them exist.

---

## Extensibility: Future VM Targets

Dual-VM (EVM + Solana) is the only commitment for v1. Other VMs are explicitly out of scope for the initial framework release, but the architecture is structured such that adding a new VM later is a bounded exercise: write a new verifier in the target language, touching neither the prover nor the circuit API.

Sequenced roadmap (post-PMF, not v1):

1. **v1 (now)**: EVM + Solana. Ship.
2. **Phase 2 (post-PMF)**: Move VMs — Sui and Aptos. Both have BN254 support via native modules; the verifier port is a Move package mirroring the Solidity and Rust verifiers.
3. **Phase 3**: NEAR. WASM-native runtime; the prover WASM blob already runs there; the verifier is a thin Rust wrapper.
4. **Phase 4**: Other BN254-friendly chains as demand surfaces.

**Layering test**: if a new VM port forces a change to the prover or to the circuit trait, the layering has leaked. Fix the layering, not the port.

---

## Repository Layout

```
shroudZK/                          ← umbrella git repo (will split later)
│
├─ genshi/                          ← FRAMEWORK workspace (publishable)
│   ├─ Cargo.toml                  independent workspace root
│   ├─ README.md                   framework docs
│   ├─ Technical_Spec.md           framework technical spec
│   ├─ crates/
│   │   ├─ genshi-core/             constraint system, gadgets, prover, verifier
│   │   ├─ genshi-evm/              Solidity emitter + reusable contract libs
│   │   ├─ genshi-solana/           Rust BPF verifier
│   │   ├─ genshi-wasm/             WASM helpers (library crate)
│   │   └─ genshi-cli/              framework tooling binary
│   └─ benches/                    generic prover/verifier benchmarks
│
├─ shroud-pool/                    ← APP workspace (consumer of genshi)
│   ├─ Cargo.toml                  independent workspace root
│   ├─ src/                        Note, gadgets, TransferCircuit, WithdrawCircuit
│   ├─ contracts/                  ShieldedPool.sol
│   ├─ programs/                   Anchor program (future)
│   ├─ sdk/                        TypeScript SDK (future)
│   └─ benches/                    transfer/withdraw benchmarks
│
├─ README.md                       this file
├─ Technical_Req.md                genshi framework technical spec (top-level)
└─ implementation_plan.md          phased build plan
```

Shroud Pool will eventually move to its own repository. The workspaces are already fully independent — splitting is `git mv` + `git init`.

---

## Problems genshi Solves (vs Legacy Stacks)

| Problem | Legacy | genshi |
|---|---|---|
| Client proving speed (minutes → seconds) | Circom + Groth16 + snarkjs | Rust-native prover, Keccak transcript, KZG |
| Per-circuit trusted setup | Groth16 ceremony per circuit change | Universal KZG (Aztec PoT), zero per-circuit ceremonies |
| Wrong-field arithmetic | Baby Jubjub inside BN254 R1CS (~700 constraints / scalar mul) | Grumpkin native (~50 constraints / scalar mul) |
| No lookup tables | R1CS can't express plookup | Plookup-based range checks, custom tables |
| Tree depth bloat | Binary depth-20 Poseidon, ~5,000 constraints / proof | 4-ary depth-10 Poseidon2, ~1,500 constraints / proof |
| No server-side prover fallback | Browser-only via snarkjs | Native CLI + WASM, same codebase |
| Dual-VM incompatibility | Different proof formats per chain | Same proof bytes verify on both |
| Proof format drift between EVM and Solana | Ad-hoc adapters | Canonical encoding in `genshi-core::serialization` |

---

## Status

Current state as of April 2026:

- **Framework primitives** (Poseidon2, Pedersen, Grumpkin, UltraCircuitBuilder, KZG, prover, verifier): **complete** — 145 tests passing
- **Verifier exports** (Solidity emitter, Solana BPF verifier): **complete** — 11 tests passing
- **WASM SDK**: **complete** — 3 tests passing
- **Keccak transcript, canonical serialization**: **complete**
- **Crate restructure into genshi + apps split**: **in progress** (this refactor)
- **Circuit trait for generic app authoring**: **pending**
- **Custom Poseidon2 / elliptic / lookup gates** (performance tier 0): **pending**
- **First app (Shroud Pool) against the new framework API**: **pending**
- **Cross-VM bridge as second consumer**: **future**
- **Security audit**: **future**

159 tests passing across all crates before the refactor.

---

## License

TBD. The framework and applications may have different licenses.

---

## References

- Arkworks ecosystem: https://arkworks.rs
- ark-grumpkin crate: https://crates.io/crates/ark-grumpkin
- TaceoLabs co-snarks (reference Rust UltraHonk): https://github.com/TaceoLabs/co-snarks
- Barretenberg (reference C++ UltraHonk): https://barretenberg.aztec.network/docs
- PLONK paper: https://eprint.iacr.org/2019/953
- Plookup paper: https://eprint.iacr.org/2020/315
- Grumpkin curve specification: https://hackmd.io/@aztec-network/ByzgNxBfd
