# genshi-evm

Solidity verifier generation for the [genshi](https://github.com/shroud-network/genshi) dual-VM zero-knowledge proving framework.

Takes a verification key produced by [`genshi-core`](https://crates.io/crates/genshi-core) and emits a standalone `.sol` verifier contract that calls the BN254 precompiles (`0x06`, `0x07`, `0x08`) directly. The emitted contract accepts proof bytes and public inputs in the exact same format that the `genshi-solana` BPF verifier consumes — one proof, two chains.

Also emits reusable Solidity library files:

- `Poseidon2.sol` — in-contract Poseidon2 hashing
- `MerkleTree.sol` — append-only Merkle tree with Poseidon2 leaves
- `NullifierSet.sol` — nullifier double-spend protection
- `RootHistory.sol` — bounded history of Merkle roots

Typically consumed via the `emit-verifier` and `emit-libs` commands in [`genshi-cli`](https://crates.io/crates/genshi-cli) rather than used directly.

## Example

```rust
use genshi_core::proving::api;
use genshi_core::proving::srs::SRS;
use genshi_evm::solidity_emitter::{EmitterOptions, generate_verifier_sol_with};

let srs = SRS::insecure_for_testing(65536);
let vk = api::extract_vk::<MyCircuit>(&srs);
let opts = EmitterOptions {
    contract_name: "MyVerifier".into(),
    pragma: "^0.8.24".into(),
    notice: None,
};
let source = generate_verifier_sol_with(&vk, &srs, &opts);
std::fs::write("MyVerifier.sol", source).unwrap();
```

## License

Licensed under either [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
