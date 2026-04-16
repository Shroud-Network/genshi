# genshi-math

BN254 field, curve, and pairing abstraction for the [genshi](https://github.com/shroud-network/genshi) dual-VM zero-knowledge proving framework.

Single Rust surface (`Fr`, `G1Affine`, `G2Affine`, `pairing_check`) with swappable backends:

- `native` (default): thin wrappers over arkworks (`ark-bn254`). Used on host, WASM, and for proving.
- `bpf`: hand-rolled Montgomery-form `Fr` plus wrappers over Solana's `sol_alt_bn128_{addition,multiplication,pairing}` syscalls. Used by emitted Solana verifier programs — keeps the on-chain verifier under the 4 KB BPF stack without pulling arkworks into BPF.

Both backends produce byte-identical serialized output, so a proof produced by a native prover verifies under either backend.

## Usage

```rust
use genshi_math::{Fr, G1Affine, G2Affine, pairing_check};

let a = Fr::from_be_bytes_mod_order(&[1; 32]);
let b = Fr::from_be_bytes_mod_order(&[2; 32]);
let c = a * b;

let p = G1Affine::generator();
let q = G2Affine::generator();
let neg_p = -p.into_group();
assert!(pairing_check(p, q, neg_p.into_affine(), q));
```

Features are mutually exclusive — pick exactly one of `native` or `bpf`:

```toml
# Host / WASM
genshi-math = { version = "0.2", features = ["native"] }

# Emitted Solana program
genshi-math = { version = "0.2", default-features = false, features = ["bpf"] }
```

## License

Licensed under either [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
