# genshi — Developer Guide

genshi is a dual-VM zero-knowledge proving framework. It produces PLONK-KZG proofs over BN254 whose **identical bytes verify on both EVM and Solana**, plus a browser WASM surface for client-side proving.

This guide covers everything you need to:

1. Lay out the workspace and run the test suite
2. Write a circuit, prove against it, and verify it
3. Generate a Solidity verifier contract for your circuit
4. Verify the same proof on Solana via BPF syscalls
5. Run the prover/verifier in a browser (WASM)
6. Publish the crates to crates.io

---

## 1. Workspace layout

```
genshi/
├── Cargo.toml                 # workspace root
└── crates/
    ├── genshi-core/            # arithmetization, prover, verifier, transcript, KZG, gadgets
    ├── genshi-evm/             # Solidity verifier emitter + reusable .sol libraries
    ├── genshi-solana/          # BPF verifier (sol_alt_bn128_pairing syscall path)
    ├── genshi-wasm/            # browser helpers + #[wasm_bindgen] surface
    └── genshi-cli/             # `genshi` CLI binary (gen-srs, emit-evm, verify, ...)
```

Dependency graph:

```
genshi-cli ──► genshi-evm ──► genshi-core
                               ▲
genshi-solana ──────────────────┤
genshi-wasm ────────────────────┘
```

`genshi-core` is the only crate every consumer needs. Pull in `genshi-evm`, `genshi-solana`, or `genshi-wasm` only when you actually want that target.

---

## 2. Prerequisites

| Tool | Version | Used for |
| --- | --- | --- |
| Rust | 1.85+ (edition 2024) | All crates |
| Foundry (`forge`) | latest | Compiling/testing the generated Solidity verifier |
| Solana CLI / `cargo build-sbf` | 1.18+ | Building `genshi-solana` for BPF |
| `wasm-pack` or `wasm-bindgen-cli` | latest | Building `genshi-wasm` for the browser |

Install Foundry and the Solana toolchain only if you intend to ship to that VM — `cargo test` works against host targets without them.

---

## 3. Testing

### Run everything

```bash
cd genshi
cargo test --workspace
```

Total Tests: **242 tests passing**

### Run a single crate

```bash
cargo test -p genshi-core
cargo test -p genshi-evm
cargo test -p genshi-solana
cargo test -p genshi-wasm
```

### Forge end-to-end (real Rust proof verifying on-chain)

`genshi-evm` ships an `#[ignore]`'d scratch-project dumper. Run it to materialize a self-contained Foundry project under `/tmp/genshi_fcheck/` containing the generated verifier contract, a real Rust-generated proof, and a Forge test that calls `verifier.verify(proof, pi)`:

```bash
cargo test -p genshi-evm --lib -- --ignored dump_for_forge
cd /tmp/genshi_fcheck
git init -q && forge install foundry-rs/forge-std
forge test --match-contract genshiVerifierTest -vvv
```

You should see:

```
[PASS] testRejectsWrongPublicInput() (gas: 136025)
[PASS] testVerifyRustProof()         (gas: 511162)
```

This is the milestone proof of correctness: **the same canonical proof bytes that the native Rust verifier accepts also pass through the emitted Solidity contract on a real EVM**.

### Building `genshi-solana` for BPF

The host build uses an arkworks pairing fallback. To compile the actual syscall path, target Solana's BPF backend:

```bash
cargo build-sbf -p genshi-solana
```

When `target_os = "solana"` is set, `pairing_check_2` routes through `sol_alt_bn128_pairing` (≈280K CU per 2-pair check).

### Building `genshi-wasm` for the browser

```bash
cd crates/genshi-wasm
wasm-pack build --target web --release
```

The output `pkg/` directory contains the JavaScript bindings: `init`, `verifyProof`, `composeProofBlob`, `proofFromBlob`, `piFromBlob`. Note that **proving** is circuit-specific, so applications that want a `proveMyCircuit()` JS export need to ship their own cdylib that wraps `genshi_wasm::prove_circuit::<MyCircuit>`.

---

## 4. Writing a circuit

A genshi application defines a type that implements the `Circuit` trait from `genshi_core::circuit`. The trait is the entire contract between your app and the framework.

### The trait

```rust
pub trait Circuit {
    type Witness;
    type PublicInputs: AsRef<[Fr]>;
    const ID: &'static str;

    fn num_public_inputs() -> usize;

    fn synthesize(
        builder: &mut UltraCircuitBuilder,
        witness: &Self::Witness,
    ) -> Self::PublicInputs;

    fn dummy_witness() -> Self::Witness;
}
```

- `Witness` carries private + public inputs in native form.
- `PublicInputs` is the public output, in the order the circuit publishes it (typically `[Fr; N]`).
- `ID` is a stable string identifier for SRS/VK bookkeeping; pick a unique value per circuit.
- `synthesize` wires constraints into the `UltraCircuitBuilder` and returns the public inputs.
- `dummy_witness` returns a zeroed witness whose synthesis produces the **same circuit shape** as a real one. This is used at setup time to extract the VK without real data.

### A minimal example

```rust
use ark_bn254::Fr;
use genshi_core::circuit::Circuit;
use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;

pub struct AddCircuit;

pub struct AddWitness {
    pub a: Fr,
    pub b: Fr,
}

impl Circuit for AddCircuit {
    type Witness = AddWitness;
    type PublicInputs = [Fr; 1];
    const ID: &'static str = "myapp.add.v1";

    fn num_public_inputs() -> usize { 1 }

    fn synthesize(
        builder: &mut UltraCircuitBuilder,
        w: &Self::Witness,
    ) -> Self::PublicInputs {
        let a = builder.add_variable(w.a);
        let b = builder.add_variable(w.b);
        let c = builder.add(a, b);
        builder.set_public(c);
        [w.a + w.b]
    }

    fn dummy_witness() -> Self::Witness {
        AddWitness { a: Fr::from(0u64), b: Fr::from(0u64) }
    }
}
```

### Available builder operations

The `UltraCircuitBuilder` exposes the primitives applications normally need:

| Method | Purpose |
| --- | --- |
| `add_variable(value: Fr) -> WireRef` | Allocate a witness wire |
| `add(a, b) -> WireRef` | Field addition |
| `sub(a, b) -> WireRef` | Field subtraction |
| `mul(a, b) -> WireRef` | Field multiplication |
| `assert_equal(a, b)` | Enforce equality between two wires |
| `set_public(wire)` | Mark a wire as a public input |
| `create_add_gate(a, b, c)` | Raw `a + b = c` gate |
| `create_mul_gate(a, b, c)` | Raw `a * b = c` gate |

For more advanced primitives, see `genshi_core::gadgets`:

- `gadgets::poseidon2_gadget` — Poseidon2 hash (matches the Solidity `Poseidon2.sol` byte-for-byte, Invariant J4)
- `gadgets::merkle` — Poseidon2 Merkle membership proof
- `gadgets::range_proof` — bit-decomposition range checks

### Proving and verifying

The high-level driver lives in `genshi_core::proving::api`:

```rust
use genshi_core::proving::{api, srs::SRS};

// 1. SRS — for testing only. Production must consume a ceremony SRS.
let srs = SRS::insecure_for_testing(1024);

// 2. Extract the verification key once at setup time
let vk = api::extract_vk::<AddCircuit>(&srs);

// 3. Prove
let witness = AddWitness { a: Fr::from(3u64), b: Fr::from(5u64) };
let (proof, _vk_again, public_inputs) = api::prove::<AddCircuit>(&witness, &srs);
assert_eq!(public_inputs, [Fr::from(8u64)]);

// 4. Verify natively
assert!(api::verify::<AddCircuit>(&proof, &vk, &public_inputs, &srs));
```

### Serializing artifacts

Canonical bytes (BE uncompressed G1, BE Fr) are produced by `genshi_core::proving::serialization`:

```rust
use genshi_core::proving::serialization::{
    proof_to_bytes, vk_to_bytes,
    public_inputs_to_bytes_le, public_inputs_to_bytes_be,
};

let proof_bytes = proof_to_bytes(&proof);
let vk_bytes    = vk_to_bytes(&vk);
let pi_le       = public_inputs_to_bytes_le(&public_inputs);  // Solana convention
let pi_be       = public_inputs_to_bytes_be(&public_inputs);  // EVM convention
```

---

## 5. Generating verifiers — the two models

Before diving into EVM and Solana specifics, understand this fundamental difference:

| | EVM | Solana |
| --- | --- | --- |
| **Verifier shape** | **One contract per circuit**, with the VK baked into constants | **One generic Rust program**, VK passed as data at runtime |
| **When VK is bound** | At emission time (Rust → Solidity source) | At runtime (or stored in an account / baked into a `const`) |
| **What you deploy** | A `.sol` file you compile and deploy once | Your BPF program that links `genshi-solana` once |
| **What changes per circuit** | Generate a new `.sol`, deploy a new verifier contract | **Nothing** — same program, different VK bytes |
| **Why the difference** | EVM has no dynamic loading and modular math is expensive; baking the VK in saves gas and enables the `via_ir` dead-code elimination pass | Solana programs are full Rust with `sol_alt_bn128_*` syscalls — no codegen trick is needed, and storing VK bytes in an account is cheap |

This matters when you think about **upgrades**: adding a new circuit to an EVM app means deploying one new verifier contract. Adding a new circuit to a Solana app means either storing a new VK blob in an account or shipping a new program binary that embeds the VK.

### The shared setup: SRS and VK

Both targets need two artifacts that you generate once per circuit, in Rust:

```rust
use genshi_core::proving::{api, srs::SRS};
use genshi_core::proving::serialization::vk_to_bytes;
use my_app::MyCircuit;

// 1. SRS — a universal trusted-setup output. Production must use a ceremony
//    SRS (genshi targets Aztec's Powers of Tau). For testing/dev, use:
let srs = SRS::insecure_for_testing(65536);
//         └── `max_degree` must be ≥ your largest circuit's gate count, rounded up to a power of two.

// 2. Verification Key — derived from the circuit shape and the SRS. This
//    does NOT need a real witness — it uses `C::dummy_witness()` internally,
//    which is why the `dummy_witness` contract on your `Circuit` impl matters.
let vk       = api::extract_vk::<MyCircuit>(&srs);
let vk_bytes = vk_to_bytes(&vk);                  // canonical bytes — feeds both targets

// (Optional) save the SRS to disk too if you want to ship it alongside the VK
std::fs::write("./setup/srs.bin", srs.save_to_bytes()).unwrap();
std::fs::write("./setup/vk.bin",  &vk_bytes).unwrap();
```

The SRS and VK are **not** secrets — publish them next to your code. The only "secret" in a trusted setup is the toxic waste from the ceremony, which must be destroyed after SRS generation.

---

## 6. EVM: emit → compile → deploy → call

The full per-circuit workflow for the EVM target. Think of it as a code-generation pipeline: Rust source (your `Circuit` impl) → Solidity source (emitted by `genshi-evm`) → EVM bytecode (compiled by Forge) → on-chain contract (deployed with `forge create`).

### 6.1 Emit the Solidity source — the CLI way

**The whole loop from "I have a `Circuit` impl" to "I have a deployable verifier contract" is two CLI commands.** You do not write a helper binary, a Rust emit script, or anything else — all of that is wrapped by the `genshi` CLI.

#### One-time setup — scaffold a project

The recommended on-ramp for new applications is:

```bash
cargo install genshi-cli                        # get the framework-generic `genshi` binary
genshi new my-zk-app                            # scaffold a new crate
cd my-zk-app
```

`genshi new` drops a Cargo crate on disk with exactly one file you ever edit (`src/lib.rs`, which starts with a stub `AddCircuit`) and one boilerplate file you never edit (`src/bin/genshi.rs`, the one-line shim that calls `genshi_cli::run()`). The `Cargo.toml`, `.gitignore`, and `README.md` are pre-wired. From that point on, adding a circuit is mechanical:

1. Define your circuit type and its `impl Circuit` in `src/lib.rs` (or any module reachable from it — see §4).
2. Drop `genshi_cli::register!(MyCircuit, "my-circuit");` right next to the impl. This is the only thing that tells the CLI the circuit exists.
3. Rebuild. Your new circuit now shows up in every circuit-aware CLI command.

The `src/bin/genshi.rs` shim is the load-bearing link between the two worlds: because it contains `use my_zk_app as _;`, the Rust linker keeps the `register!` statics from your lib alive in the final binary, and `genshi_cli::run()` enumerates them at startup. You do not touch it.

#### The emit command

Once your circuit is registered, the whole emit path is one command per circuit:

```bash
cargo run --bin genshi -- srs new --max-degree 65536 --output srs.bin
cargo run --bin genshi -- circuits list
# → withdraw    id=shroud-pool.withdraw    num_public_inputs=4
# → transfer    id=shroud-pool.transfer    num_public_inputs=4

cargo run --bin genshi -- emit-verifier \
    --circuit       withdraw \
    --srs           srs.bin \
    --contract-name WithdrawVerifier \
    --pragma        "^0.8.24" \
    --notice        "Generated from WithdrawCircuit." \
    --output        contracts/
```

That single `emit-verifier` invocation runs `api::extract_vk::<WithdrawCircuit>(&srs)` under the hood, feeds the VK through `genshi-evm::solidity_emitter::generate_verifier_sol_with`, and writes `contracts/WithdrawVerifier.sol`. There is no intermediate VK file and no Rust glue — the CLI is the glue.

All the circuit-aware subcommands follow the same `--circuit <name>` pattern:

```bash
cargo run --bin genshi -- circuits list                              # enumerate registered circuits
cargo run --bin genshi -- extract-vk    --circuit withdraw ...       # write VK bytes only
cargo run --bin genshi -- emit-verifier --circuit withdraw ...       # write Solidity verifier
```

`<name>` is the literal string you passed to `genshi_cli::register!(Type, "name")`.

#### Why you need a per-crate binary (and not just `cargo install genshi-cli`)

The `genshi` binary that ships with `cargo install genshi-cli` has no circuits linked into it, so its `circuits list` prints an empty set and `--circuit anything` rejects. Rust circuits are concrete types, not a DSL like circom, so a prebuilt universal binary physically cannot know about types that don't exist until your crate compiles. `genshi new` gives you a per-project `genshi` binary with your circuits baked in; it's the same `genshi_cli::run()` entry point, but compiled together with your code. That per-project binary is a **superset** of the generic one — all the framework commands (SRS, inspect, verify, emit-libs, emit-poseidon2, emit-evm-from-vk) are still there.

In short: install the generic `genshi` to scaffold projects and run framework-agnostic ops; then `cargo run --bin genshi` from inside any scaffolded (or manually wired) crate to run circuit-specific ops.

#### Escape hatch: circuits you only have VK bytes for

If you somehow have a `.vk` file but no source for the circuit it came from, the VK-only emit path still exists. It's the fallback, not the primary flow:

```bash
genshi emit-evm \
    --vk   setup/transfer_vk.bin \
    --srs  setup/srs.bin \
    --output contracts \
    --contract-name TransferVerifier \
    --pragma "^0.8.24"
```

#### Reusable Solidity libraries (one-shot, framework-generic)

If your application also uses genshi's built-in Solidity primitives (`MerkleTree`, `NullifierSet`, `RootHistory`, `Poseidon2`), emit them via the generic CLI — these come from `genshi-evm` and are not per-circuit:

```bash
genshi emit-libs      --output contracts/library
genshi emit-poseidon2 --output contracts/library
```

`Poseidon2.sol` is generated from the same constants as the in-circuit gadget (Invariant J4), so on-chain Merkle updates produce the same roots as the prover.

#### What the emitter actually does, for reference

Under the CLI, the work is done by `genshi_evm::solidity_emitter::generate_verifier_sol_with`. It takes a `VerificationKey`, an `SRS` (for the `G2` anchor the pairing check needs), and an `EmitterOptions` struct, and returns a complete self-contained `.sol` source string. You never call it directly when using the CLI — it's listed here only so you know what to grep if the emitted contract surprises you.

### 6.2 Compile the generated contract

The emitted verifier stores enough locals in `_checkConstraint` that Solidity's legacy code generator can't spill them to memory. You **must** enable the IR pipeline — otherwise you'll get `Stack too deep` at compile time.

```toml
# foundry.toml
[profile.default]
src = "contracts"
out = "out"
solc_version = "0.8.24"
optimizer = true
optimizer_runs = 200
via_ir = true                       # mandatory
fs_permissions = [{ access = "read", path = "./setup" }]
```

```bash
forge build
```

### 6.3 What the emitted contract looks like

Every emitted verifier exposes exactly one public entry point:

```solidity
contract TransferVerifier {
    // ... internal constants baked from the VK + SRS ...
    // ... Keccak transcript replay, constraint check, batch KZG, z-opening ...

    function verify(bytes calldata proof, uint256[] calldata publicInputs)
        external view returns (bool);
}
```

- `proof` — exactly the output of `genshi_core::proving::serialization::proof_to_bytes(&proof)`. Do **not** transform or repack — the decoder inside the contract reads the canonical layout byte-for-byte.
- `publicInputs` — one `uint256` per `Fr` in the order your `Circuit::synthesize` called `builder.set_public(...)`. Values must be `< P` (the BN254 scalar field modulus); the contract reverts with `"PI count mismatch"` if the array length is wrong.

### 6.4 Deploy and integrate

Deploy the verifier contract once (or once per version of the circuit) and hold its address in your application contract:

```solidity
// contracts/MyApp.sol
import "./TransferVerifier.sol";

interface IVerifier {
    function verify(bytes calldata proof, uint256[] calldata publicInputs)
        external view returns (bool);
}

contract MyApp {
    IVerifier public immutable transferVerifier;

    constructor(address verifier) {
        transferVerifier = IVerifier(verifier);
    }

    function submitTransfer(
        bytes calldata proof,
        uint256 merkleRoot,
        uint256 nullifier,
        uint256 outCommitment1,
        uint256 outCommitment2
    ) external {
        uint256[] memory pi = new uint256[](4);
        pi[0] = merkleRoot;
        pi[1] = nullifier;
        pi[2] = outCommitment1;
        pi[3] = outCommitment2;

        require(transferVerifier.verify(proof, pi), "invalid proof");

        // ... your app logic: insert commitments, mark nullifier spent, etc.
    }
}
```

```bash
forge create TransferVerifier   --rpc-url $RPC --private-key $KEY
forge create MyApp              --rpc-url $RPC --private-key $KEY --constructor-args $VERIFIER_ADDR
```

The public-input order in your app contract **must match** the order your `Circuit::synthesize` published them. Shroud-pool pins this with the `IDX_*` constants on `TransferPublicInputs` (`shroud-pool/src/circuits/transfer.rs:58`) — do the same for your circuits or you will silently verify the wrong thing.

### 6.5 Regenerate whenever the circuit changes

Any change that shifts the circuit shape (new gates, new public inputs, reordered `set_public` calls, domain size change) invalidates both the VK and the emitted contract. The rule is:

**If `extract_vk::<C>(&srs)` would return different bytes, re-emit and redeploy.**

Because emission is a CLI command, the regen loop is just:

```bash
cargo run --bin genshi -- emit-verifier --circuit withdraw --srs srs.bin --output contracts/ \
    && forge build \
    && forge test
```

Wire the three commands into a Makefile target / `just` recipe / npm script and re-run after every circuit edit. The `genshi` binary rebuilds incrementally, so the typical edit-re-emit loop is under a second after the first compile.

### 6.6 Reference costs

From the real shroud-pool `WithdrawCircuit` (Pedersen note commitment + Merkle depth-10 + nullifier + 64-bit range check, 4 public inputs):

| Operation | Gas |
| ---: | ---: |
| `verify(proof, pi)` accept | **601,513** |
| `verify(proof, wrong_pi)` reject | **228,028** |

Rejections short-circuit as soon as the constraint equation fails, before either pairing. Accept cost is dominated by the two `ecPairing` calls (~113K gas each) and the batch KZG G1 accumulation.

---

## 7. Solana: link → build → run (no code generation)

The Solana workflow is **simpler** than EVM because there is no per-circuit code generation. You write one Solana program that links `genshi-solana` as a library, and at runtime it verifies any genshi proof whose VK bytes you hand it.

### 7.1 The conceptual model

A Solana verifier is just a Rust function call:

```rust
verify_from_bytes(proof_bytes, vk_bytes, pi_bytes, &srs) -> Result<bool, _>
```

The VK bytes are data, not code. You can:

- **Bake the VK into the program**  as a `const &[u8]` (zero-copy, but changes require a program redeploy)
- **Store the VK in an account** that the verifying instruction reads (upgradeable without redeploy; costs one extra account read)
- **Pass the VK as instruction data** (flexible, but wastes transaction bytes)

Most apps bake the VK. Shroud-pool-style applications typically embed one VK per circuit as a `const` and pick the right one based on the instruction discriminator.

### 7.2 Add `genshi-solana` to your program

Create a normal Solana program (Anchor, pinocchio, or raw) and add the dependency:

```toml
# programs/my-app/Cargo.toml
[dependencies]
genshi-core   = { version = "0.1", default-features = false }
genshi-solana = { version = "0.1" }
# plus your usual solana-program / anchor-lang / pinocchio deps
```

`genshi-solana` is `no_std`-friendly and its host-mode tests use the arkworks pairing engine, so you can write unit tests without a BPF toolchain. When you actually build for Solana, the `target.'cfg(target_os = "solana")'` block in `genshi-solana/Cargo.toml` pulls in `solana-program` and routes the pairing through the `sol_alt_bn128_pairing` syscall automatically.

### 7.3 Bake the VK (and SRS) into the program

Generate the VK once with Rust, commit the bytes to your program's source tree:

```rust
// Rust helper, run once at setup time
use std::fs;
use genshi_core::proving::{api, srs::SRS};
use genshi_core::proving::serialization::vk_to_bytes;
use my_app::TransferCircuit;

fn main() {
    let srs = SRS::load_from_bytes(&fs::read("setup/srs.bin").unwrap());
    let vk  = api::extract_vk::<TransferCircuit>(&srs);
    fs::write("programs/my-app/src/vk_transfer.bin", vk_to_bytes(&vk)).unwrap();
}
```

Then `include_bytes!` them in your program:

```rust
// programs/my-app/src/constants.rs
pub const SRS_BYTES: &[u8]         = include_bytes!("../../../setup/srs.bin");
pub const TRANSFER_VK_BYTES: &[u8] = include_bytes!("vk_transfer.bin");
pub const WITHDRAW_VK_BYTES: &[u8] = include_bytes!("vk_withdraw.bin");
```

The SRS can be quite large for big circuits — if that's a problem, store it in a PDA account at deploy time and read it at the start of the verifying instruction instead of `include_bytes!`-ing it.

### 7.4 Write the verifying instruction

```rust
// programs/my-app/src/processor.rs
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use genshi_core::proving::srs::SRS;
use genshi_solana::verify::verify_from_bytes;

use crate::constants::{SRS_BYTES, TRANSFER_VK_BYTES};

pub fn process_transfer(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Instruction layout (app-defined):
    //   [0..4]   proof_len (u32 LE)
    //   [4..P]   proof bytes
    //   [P..]    public inputs as concatenated 32-byte LE Fr elements
    if instruction_data.len() < 4 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let proof_len = u32::from_le_bytes(instruction_data[..4].try_into().unwrap()) as usize;
    if instruction_data.len() < 4 + proof_len {
        return Err(ProgramError::InvalidInstructionData);
    }
    let proof_bytes = &instruction_data[4..4 + proof_len];
    let pi_bytes    = &instruction_data[4 + proof_len..];

    // Load the embedded SRS. This is cheap — SRS::load_from_bytes is a
    // straight deserialization, no heavy computation.
    let srs = SRS::load_from_bytes(SRS_BYTES);

    // Run the verifier. On BPF this routes through `sol_alt_bn128_pairing`.
    let ok = verify_from_bytes(proof_bytes, TRANSFER_VK_BYTES, pi_bytes, &srs)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    if !ok {
        return Err(ProgramError::Custom(1)); // proof rejected
    }

    // ... your app logic: mark nullifier spent, insert commitments, etc.
    Ok(())
}
```

**Important**: the public inputs are encoded as concatenated **32-byte little-endian** `Fr` elements on Solana (matching the `public_inputs_to_bytes_le` helper). This is different from the EVM convention (BE uint256). The `genshi_core::proving::serialization::public_inputs_to_bytes_le` / `_be` helpers produce the canonical bytes for each target — use them on the client side and never hand-roll the encoding.

### 7.5 Build for BPF

```bash
cargo build-sbf --manifest-path programs/my-app/Cargo.toml
```

When `cfg(target_os = "solana")` is active, `genshi-solana::crypto::pairing_check_2` compiles down to:

```rust
solana_program::alt_bn128::prelude::alt_bn128_pairing(&input)
```

which the BPF VM executes as a single ~280K CU syscall per 2-pair check. A full genshi verify does exactly two 2-pair checks (batch KZG + z-opening), so the pairing portion costs ~560K CU. Add the field-arithmetic portion of `verify_prepare` (transcript replay, constraint equation, batch accumulation) and a typical proof lands well inside Solana's 1.4M CU per-transaction budget.

### 7.6 Deploy and invoke

```bash
solana program deploy target/deploy/my_app.so --program-id programs/my-app/keypair.json
```

On the client side, build the instruction data from canonical bytes:

```rust
use genshi_core::proving::serialization::{proof_to_bytes, public_inputs_to_bytes_le};

let proof_bytes = proof_to_bytes(&proof);
let pi_bytes    = public_inputs_to_bytes_le(public_inputs.as_ref());

let mut instruction_data = Vec::with_capacity(4 + proof_bytes.len() + pi_bytes.len());
instruction_data.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
instruction_data.extend_from_slice(&proof_bytes);
instruction_data.extend_from_slice(&pi_bytes);

let ix = Instruction::new_with_bytes(program_id, &instruction_data, accounts);
// ... send the transaction as usual
```

### 7.7 Host-side testing without BPF

The nicest property of `genshi-solana` is that it compiles and tests on your host machine with the arkworks pairing fallback — no `cargo build-sbf` needed until you're ready to deploy. Your unit tests for the verifying instruction can call `verify_from_bytes` directly with synthesized witness data:

```rust
#[test]
fn test_process_transfer_accepts_valid_proof() {
    use genshi_core::proving::api;
    use genshi_core::proving::srs::SRS;

    let srs = SRS::insecure_for_testing(65536);
    let witness = make_test_witness();
    let (proof, vk, public_inputs) = api::prove::<TransferCircuit>(&witness, &srs);

    let proof_bytes = proof_to_bytes(&proof);
    let vk_bytes    = vk_to_bytes(&vk);
    let pi_bytes    = public_inputs_to_bytes_le(public_inputs.as_ref());

    let ok = verify_from_bytes(&proof_bytes, &vk_bytes, &pi_bytes, &srs).unwrap();
    assert!(ok);
}
```

This is exactly what `genshi-solana/src/verify.rs:88` (`test_verify_with_syscalls_simple`) and friends already do — the "syscall" path falls back to arkworks on host, so the same test code validates the BPF logic without a BPF runtime.

---

## 8. The whole loop end-to-end

Putting both targets together, here's the complete flow a dual-VM app (like shroud-pool) goes through whenever a circuit changes:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Change the Circuit impl in my-app/src/circuits/transfer.rs          │
└─────────────────────────────┬──────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. Regenerate the VK                                                   │
│      let vk = api::extract_vk::<TransferCircuit>(&srs);                │
│      fs::write("setup/transfer_vk.bin", vk_to_bytes(&vk));             │
└─────────────────────────────┬──────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────────┐   ┌──────────────────────────────────────┐
│ 3a. EVM: emit verifier      │   │ 3b. Solana: refresh embedded VK      │
│                             │   │                                      │
│  generate_verifier_sol_with │   │  cp setup/transfer_vk.bin            │
│    → TransferVerifier.sol   │   │     programs/my-app/src/vk_transfer  │
│                             │   │                                      │
│  forge build                │   │  cargo build-sbf                     │
│  forge create ...           │   │  solana program deploy ...           │
└─────────────────────────────┘   └──────────────────────────────────────┘
              │                               │
              └───────────────┬───────────────┘
                              ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 4. Client: prove with the SAME circuit + SRS, ship canonical bytes     │
│      let (proof, _, pi) = api::prove::<TransferCircuit>(&w, &srs);     │
│      let proof_bytes    = proof_to_bytes(&proof);                      │
│      let pi_be          = public_inputs_to_bytes_be(pi.as_ref());      │
│      let pi_le          = public_inputs_to_bytes_le(pi.as_ref());      │
└─────────────────────────────┬──────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────────┐   ┌──────────────────────────────────────┐
│ Send to EVM                 │   │ Send to Solana                       │
│   TransferVerifier.verify(  │   │   program instruction with           │
│     proof_bytes,            │   │     [len | proof_bytes | pi_le]      │
│     pi_be_as_uint256_array  │   │                                      │
│   )                         │   │                                      │
│ → true / false              │   │ → Ok(()) / ProgramError::Custom(1)   │
└─────────────────────────────┘   └──────────────────────────────────────┘
```

Three rules keep this loop sound:

1. **One SRS across both targets.** The VK and the emitted Solidity contract's baked G2 constants all come from the same `srs`. Mismatching SRS → guaranteed verification failure.
2. **Public input order is canonical.** Whatever order your `Circuit::synthesize` called `builder.set_public(...)` is the order the verifier expects. Lock it down with index constants like shroud-pool's `IDX_NULLIFIER = 1`.
3. **Endianness is per-target.** EVM expects BE uint256 (`public_inputs_to_bytes_be`); Solana expects LE 32-byte chunks (`public_inputs_to_bytes_le`). The client must encode correctly for whichever chain it's sending to.

---

## 7. Proving in the browser (WASM)

`genshi-wasm` ships two surfaces:

1. **Generic Rust helpers** (`prove_circuit`, `extract_vk_bytes`, `verify_proof_bytes`, `compose_proof_blob`, `split_proof_blob`) — applications wrap their own circuits in a cdylib and call these.
2. **Direct `#[wasm_bindgen]` exports** (the `wasm` submodule, only compiled when `target_arch = "wasm32"`) — `init`, `verifyProof`, `composeProofBlob`, `proofFromBlob`, `piFromBlob`. These let any JS app **verify** genshi proofs without shipping a circuit-specific wasm bundle.

### Building an application cdylib

Create a small wrapper crate:

```toml
# Cargo.toml
[lib]
crate-type = ["cdylib"]

[dependencies]
genshi-wasm = "0.1"
my-app = { path = "../my-app" }   # has your Circuit impl
wasm-bindgen = "0.2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```rust
// src/lib.rs
use wasm_bindgen::prelude::*;
use genshi_wasm::{prove_circuit, install_panic_hook};
use my_app::{MyCircuit, MyWitness};

#[wasm_bindgen(start)]
pub fn start() { install_panic_hook(); }

#[wasm_bindgen]
pub fn prove_my_app(witness_json: &str, srs_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let witness: MyWitness = serde_json::from_str(witness_json)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let (proof_blob, _vk) = prove_circuit::<MyCircuit>(&witness, srs_bytes)
        .map_err(JsError::new)?;
    Ok(proof_blob)
}
```

Build and ship:

```bash
wasm-pack build --target web --release
```

### Using it from JavaScript

```js
import init, { verifyProof } from "./pkg/my_app_wasm.js";
import { prove_my_app } from "./pkg/my_app_wasm.js";

await init();

const srs    = new Uint8Array(await (await fetch("/srs.bin")).arrayBuffer());
const vkBytes = new Uint8Array(await (await fetch("/vk.bin")).arrayBuffer());

const blob = prove_my_app(JSON.stringify(witness), srs);

// Split (proof, pi) out of the envelope, or use the helpers from genshi-wasm
const proofLen = new DataView(blob.buffer).getUint32(0, true);
const proof = blob.slice(4, 4 + proofLen);
const pi    = blob.slice(4 + proofLen);

const ok = verifyProof(proof, vkBytes, pi, srs);
console.log("verified:", ok);
```

---

## 8. SRS handling

`SRS::insecure_for_testing(max_degree)` uses a known secret tau and is **for tests only**. Production deployments must consume an SRS derived from a verifiable trusted setup (genshi targets Aztec's Powers of Tau ceremony).

```rust
let srs_bytes = std::fs::read("srs.bin")?;
let srs = SRS::load_from_bytes(&srs_bytes);
```

The `max_degree` must be ≥ the largest circuit you intend to prove against this SRS. Pick conservatively at setup time — you cannot retrofit a larger SRS without re-running the ceremony.

---

## 9. Publishing to crates.io

The crates have a strict dependency order:

```
genshi-core ──► genshi-evm ──► genshi-cli
genshi-core ──► genshi-solana
genshi-core ──► genshi-wasm
```

You must publish dependencies before dependents. crates.io will reject any crate whose published dependencies don't yet exist on the registry.

### One-time setup

```bash
cargo login                     # paste your crates.io API token
```

Make sure each crate has the metadata crates.io requires:

- `description`, `license`, `repository`, `readme`, `keywords`, `categories` in each `[package]` table
- A `LICENSE` file (or `LICENSE-MIT` + `LICENSE-APACHE`) at the workspace root
- A `README.md` referenced from each crate (or use `readme = "../../README.md"`)

The workspace already declares `license`, `repository`, and `description`; verify with:

```bash
cargo metadata --no-deps --format-version 1 | jq '.packages[] | {name, description, license, repository}'
```

### Replace path dependencies with version requirements

`crates.io` does **not** allow `path = "..."` in published manifests when there is no matching `version`. The workspace already pairs them, but double-check each crate's `Cargo.toml`. Path-only deps should look like:

```toml
genshi-core = { path = "../genshi-core", version = "0.1.0", default-features = false }
```

### Dry-run each crate in dependency order

```bash
cargo publish -p genshi-core    --dry-run
cargo publish -p genshi-evm     --dry-run
cargo publish -p genshi-solana  --dry-run
cargo publish -p genshi-wasm    --dry-run
cargo publish -p genshi-cli     --dry-run
```

Resolve any warnings about missing metadata, oversized tarballs, or unresolved deps before going live.

### Publish for real

```bash
cargo publish -p genshi-core
# wait ~30s for the registry index to update
cargo publish -p genshi-evm
cargo publish -p genshi-solana
cargo publish -p genshi-wasm
cargo publish -p genshi-cli
```

If a publish fails halfway, fix the issue, **bump the version of the failed crate and every crate that depends on it**, and try again. Published versions on crates.io are immutable — you can yank but never overwrite.

### Bumping the version

The workspace uses `version.workspace = true`, so a single edit in `genshi/Cargo.toml`:

```toml
[workspace.package]
version = "0.1.1"
```

bumps every crate in lockstep. Commit the bump, tag the release, and re-publish in dependency order.

---

## 10. Consuming the published crates

Once genshi is on crates.io, applications add it like any other Rust dependency:

```toml
[dependencies]
genshi-core = "0.1"

# Add only the targets you actually deploy to:
genshi-evm    = "0.1"   # if you generate a Solidity verifier
genshi-solana = "0.1"   # if you ship a Solana program
genshi-wasm   = "0.1"   # if you prove/verify in the browser
```

The CLI is installable as a binary:

```bash
cargo install genshi-cli
genshi --help
```

---

## 11. Where to look in the source

| Question | File |
| --- | --- |
| What does the `Circuit` trait look like? | `crates/genshi-core/src/circuit.rs` |
| How do I prove/verify generically? | `crates/genshi-core/src/proving/api.rs` |
| What gates does the builder expose? | `crates/genshi-core/src/arithmetization/ultra_circuit_builder.rs` |
| What's the canonical wire format? | `crates/genshi-core/src/proving/serialization.rs` |
| How is the Fiat-Shamir transcript built? | `crates/genshi-core/src/proving/transcript.rs` |
| How is the Solidity verifier emitted? | `crates/genshi-evm/src/solidity_emitter.rs` |
| What reusable Solidity libraries ship? | `crates/genshi-evm/contracts/library/` |
| How does the BPF pairing path work? | `crates/genshi-solana/src/crypto/mod.rs` |
| What are the WASM JS exports? | `crates/genshi-wasm/src/lib.rs` (`wasm` module) |
| What does the CLI do? | `crates/genshi-cli/src/lib.rs` |

---

## 12. Command reference

Every command you need, in the order you'll hit them. Covers scaffolding, proving, EVM, Solana, WASM, testing, and publishing. Assumes you've already run `cargo install genshi-cli` (or you're invoking the binary via `cargo run -p genshi-cli --`).

### 12.1 Toolchain install (one-time)

```bash
# Rust targets
rustup target add wasm32-unknown-unknown                  # WASM
cargo install wasm-pack                                   # WASM bundler
cargo install --git https://github.com/solana-labs/solana solana-install  # Solana CLI (or use official installer)
cargo install --git https://github.com/coral-xyz/anchor --tag v0.30.0 anchor-cli --locked  # Anchor (optional)
curl -L https://foundry.paradigm.xyz | bash && foundryup  # Foundry (forge/cast/anvil)

# genshi CLI
cargo install genshi-cli
genshi --help
```

### 12.2 Project scaffolding

```bash
# Create a new circuit crate (defaults to git deps against shroud-network/genshi)
genshi new my-circuits

# Pin a specific version or revision
genshi new my-circuits --version 0.1.0
genshi new my-circuits --source git:https://github.com/shroud-network/genshi
genshi new my-circuits --source git:https://github.com/shroud-network/genshi#rev=main
genshi new my-circuits --source path:/absolute/path/to/genshi   # local dev

# Inside the scaffolded crate
cd my-circuits
cargo build
cargo run --bin genshi -- circuits          # list registered circuits
```

### 12.3 SRS management

```bash
# Generate an insecure dev-only SRS (known tau — never use in production)
genshi srs new --max-degree 65536 --output srs.bin

# Import a production SRS from a Powers of Tau ceremony (.ptau file)
# Downloads: https://github.com/iden3/snarkjs#7-prepare-phase-2
genshi srs import --input powersOfTau28_hez_final_20.ptau \
                  --max-degree 65536 --output srs.bin

# Run a Powers-of-Tau ceremony (1-of-N trust, OS entropy, no downloads)
genshi srs ceremony --max-degree 65536 --participants 3 --output srs.bin

# Verify an existing SRS file (pairing consistency check)
genshi srs verify --file srs.bin

# Inside a scaffolded project, the per-crate binary inherits the same subcommands
cargo run --bin genshi -- srs new --max-degree 65536 --output srs.bin
cargo run --bin genshi -- srs ceremony --max-degree 65536 --participants 3 --output srs.bin
```

### 12.4 Circuit inspection

```bash
genshi circuits                                            # list every registered circuit
genshi inspect --kind vk --file transfer.vk                # validate a serialized VK
genshi inspect --kind proof --file proof.bin                # validate a serialized proof
genshi extract-vk --circuit transfer --srs srs.bin --output transfer.vk
```

### 12.5 Witness generation

```bash
# Generate a witness JSON for a circuit (valid, provable out of the box)
genshi gen-witness --circuit transfer --output witness.json

# Print to stdout (pipe into jq, redirect, etc.)
genshi gen-witness --circuit transfer
```

The generated witness satisfies all circuit constraints with default values. Edit the JSON to substitute your own data.

### 12.6 Proof generation

```bash
# Full round-trip: gen-witness → prove → verify
genshi gen-witness --circuit transfer --output witness.json
genshi prove --circuit transfer --witness witness.json --srs srs.bin --output out/
genshi verify --proof out/proof.bin --vk out/vk.bin \
              --public-inputs out/public_inputs.bin --srs srs.bin

# Outputs from prove:
#   out/proof.bin          — canonical proof bytes
#   out/vk.bin             — verification key
#   out/public_inputs.bin  — public inputs (32-byte LE Fr elements)
```

### 12.7 EVM target (Solidity)

```bash
# Generate a Solidity verifier directly from a registered circuit (one-step)
genshi emit-verifier --circuit transfer --srs srs.bin --output contracts/ \
                     --contract-name TransferVerifier

# Or generate from a pre-serialized VK file
genshi emit-evm --vk transfer.vk --srs srs.bin --output contracts/

# Emit reusable Solidity libraries (Poseidon2, MerkleTree, etc.)
genshi emit-poseidon2 --output contracts/library/
genshi emit-libs      --output contracts/library/

# Build & test with Foundry
forge build --via-ir                                      # via_ir = true is required
forge test  --via-ir -vv
forge test  --via-ir --match-contract TransferVerifier -vvv

# Deploy
forge create contracts/TransferVerifier.sol:TransferVerifier \
  --rpc-url $RPC_URL --private-key $PRIVATE_KEY --via-ir

# Gas snapshot
forge snapshot --via-ir
```

### 12.8 Solana target (BPF)

```bash
# Build the on-chain program (Solana BPF target)
cargo build-sbf --manifest-path programs/my-app/Cargo.toml

# Inspect the compiled ELF size / syscall usage
cargo build-sbf --manifest-path programs/my-app/Cargo.toml --dump

# Generate a program keypair (one-time)
solana-keygen new --outfile programs/my-app/keypair.json

# Configure RPC cluster
solana config set --url https://api.devnet.solana.com      # devnet
solana config set --url localhost                          # local validator

# Start a local validator for tests
solana-test-validator

# Deploy
solana program deploy target/deploy/my_app.so \
  --program-id programs/my-app/keypair.json

# Verify on-chain
solana program show <PROGRAM_ID>

# Anchor workflow (if using Anchor)
anchor build
anchor test
anchor deploy --provider.cluster devnet
```

### 12.9 WASM target (browser SDK)

```bash
# Build for the web (ES modules)
wasm-pack build crates/genshi-wasm --target web --release

# Build for bundlers (webpack/vite)
wasm-pack build crates/genshi-wasm --target bundler --release

# Build for Node.js
wasm-pack build crates/genshi-wasm --target nodejs --release

# Headless browser tests
wasm-pack test crates/genshi-wasm --headless --chrome
wasm-pack test crates/genshi-wasm --headless --firefox

# Size-check the output
ls -lh crates/genshi-wasm/pkg/*.wasm
wasm-opt -Oz crates/genshi-wasm/pkg/genshi_wasm_bg.wasm -o optimized.wasm  # optional
```

### 12.10 Proof verification

```bash
# Verify a proof against a VK and public inputs (native)
genshi verify \
  --circuit transfer \
  --srs srs.bin \
  --proof proof.bin \
  --public-inputs public.json

# Verify using an externally exported VK file
genshi verify \
  --vk transfer.vk \
  --proof proof.bin \
  --public-inputs public.json
```

### 12.11 Testing

```bash
# Framework tests
cargo test --release --lib -p genshi-core
cargo test --release --lib -p genshi-evm
cargo test --release --lib -p genshi-solana
cargo test --release --lib -p genshi-cli
cargo test --release                                       # everything in the workspace

# Just the circuit you're editing
cargo test --release -p my-circuits -- transfer

# Ignored / slow tests
cargo test --release -- --ignored

# With backtraces
RUST_BACKTRACE=1 cargo test --release -p genshi-core
```

### 12.12 Publishing (maintainers)

```bash
# Authenticate once
cargo login

# Dry run in dependency order
cargo publish -p genshi-core    --dry-run
cargo publish -p genshi-evm     --dry-run
cargo publish -p genshi-cli     --dry-run
cargo publish -p genshi-solana  --dry-run
cargo publish -p genshi-wasm    --dry-run

# Real publish (same order — genshi-core MUST land first)
cargo publish -p genshi-core
cargo publish -p genshi-evm
cargo publish -p genshi-cli
cargo publish -p genshi-solana
cargo publish -p genshi-wasm

# Sanity-check the metadata resolver before publishing
cargo metadata --no-deps --format-version 1 | jq '.packages[] | {name, version}'
```

### 12.13 End-to-end regen loop

When you change a circuit, rerun this loop to keep EVM + Solana + WASM artifacts in sync:

```bash
# 1. Rebuild + re-register
cargo build --bin genshi

# 2. Re-extract VK and re-emit verifier
cargo run --bin genshi -- emit-verifier \
  --circuit transfer --srs srs.bin \
  --output contracts/TransferVerifier.sol

# 3. Rebuild Solidity
forge build --via-ir && forge test --via-ir

# 4. Rebuild Solana program
cargo build-sbf --manifest-path programs/my-app/Cargo.toml

# 5. Rebuild WASM
wasm-pack build crates/genshi-wasm --target web --release
```

---

## 13. Quick-reference cheat-sheet

All commands using `cargo run` (for local development before genshi is published).

### Project scaffolding

| Command | Description |
|---------|-------------|
| `cargo run --bin genshi -- new my-app` | Scaffold a new genshi project |
| `cargo run --bin genshi -- new my-app --source path:/path/to/genshi` | Scaffold using local genshi checkout |

### Circuit registry

| Command | Description |
|---------|-------------|
| `cargo run --bin genshi -- circuits` | List all registered circuits |

### SRS generation

| Command | Description |
|---------|-------------|
| `cargo run --bin genshi -- srs new --max-degree 65536 --output srs.bin` | **Dev only** — insecure SRS with known tau (instant, never deploy) |
| `cargo run --bin genshi -- srs ceremony --max-degree 65536 --participants 3 --output srs.bin` | **Production** — Powers-of-Tau ceremony with OS entropy |
| `cargo run --bin genshi -- srs import --input ceremony.ptau --max-degree 65536 --output srs.bin` | **Production** — import from external `.ptau` file |
| `cargo run --bin genshi -- srs verify --file srs.bin` | Verify SRS pairing consistency |

> **Insecure vs Production:** `srs new` uses a hardcoded tau — anyone can forge proofs.
> `srs ceremony` and `srs import` use real entropy with 1-of-N trust — if even one participant
> honestly destroys their secret, forgery is cryptographically impossible. Never deploy with `srs new`.

### Witness generation

| Command | Description |
|---------|-------------|
| `cargo run --bin genshi -- gen-witness --circuit transfer --output witness.json` | Generate witness JSON for transfer circuit |
| `cargo run --bin genshi -- gen-witness --circuit withdraw --output witness.json` | Generate witness JSON for withdraw circuit |
| `cargo run --bin genshi -- gen-witness --circuit transfer` | Print witness JSON to stdout |

### Proving

| Command | Description |
|---------|-------------|
| `cargo run --bin genshi -- prove --circuit transfer --witness witness.json --srs srs.bin --output out/` | Generate proof from witness |

Outputs: `out/proof.bin`, `out/vk.bin`, `out/public_inputs.bin`

### Verification

| Command | Description |
|---------|-------------|
| `cargo run --bin genshi -- verify --proof out/proof.bin --vk out/vk.bin --public-inputs out/public_inputs.bin --srs srs.bin` | Verify a proof natively |

### Verification key

| Command | Description |
|---------|-------------|
| `cargo run --bin genshi -- extract-vk --circuit transfer --srs srs.bin --output transfer.vk` | Extract VK for a circuit |

### Solidity emission (EVM)

| Command | Description |
|---------|-------------|
| `cargo run --bin genshi -- emit-verifier --circuit transfer --srs srs.bin --output contracts/ --contract-name TransferVerifier` | Emit verifier contract for a circuit |
| `cargo run --bin genshi -- emit-evm --vk transfer.vk --srs srs.bin --output contracts/` | Emit verifier from standalone VK file |
| `cargo run --bin genshi -- emit-poseidon2 --output contracts/` | Emit Poseidon2 Solidity library |
| `cargo run --bin genshi -- emit-libs --output contracts/` | Emit all reusable libraries (MerkleTree, NullifierSet, RootHistory, etc.) |

### Artifact inspection

| Command | Description |
|---------|-------------|
| `cargo run --bin genshi -- inspect --kind proof --file out/proof.bin` | Validate a proof file |
| `cargo run --bin genshi -- inspect --kind vk --file out/vk.bin` | Validate a VK file |

### Production flow (end to end)

```bash
cargo run --bin genshi -- srs ceremony --max-degree 65536 --participants 3 --output srs.bin
cargo run --bin genshi -- srs verify --file srs.bin
cargo run --bin genshi -- gen-witness --circuit transfer --output witness.json
cargo run --bin genshi -- prove --circuit transfer --witness witness.json --srs srs.bin --output out/
cargo run --bin genshi -- verify --proof out/proof.bin --vk out/vk.bin --public-inputs out/public_inputs.bin --srs srs.bin
cargo run --bin genshi -- emit-verifier --circuit transfer --srs srs.bin --output contracts/ --contract-name TransferVerifier
cargo run --bin genshi -- emit-libs --output contracts/
```

