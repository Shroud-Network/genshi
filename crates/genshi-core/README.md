# genshi-core

Core cryptographic library for the [genshi](https://github.com/shroud-network/genshi) dual-VM zero-knowledge proving framework.

Provides:

- **PLONK-KZG** prover and verifier over the BN254 pairing-friendly curve
- **Poseidon2** hash (native + in-circuit gadget, t=4 and t=5 permutations)
- **Pedersen commitments** on the Grumpkin curve
- **Merkle inclusion** gadget with configurable depth
- **Range-proof** lookup tables
- **Nullifier** and **commitment** gadgets usable by any privacy protocol
- **Keccak-based transcript** for EVM/Solana byte-compatible Fiat–Shamir
- **`Circuit` trait** that downstream application crates implement

`no_std` compatible (enable with `default-features = false`). Serde support is gated behind the `serde` feature.

## Example

```rust
use ark_bn254::Fr;
use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use genshi_core::circuit::Circuit;

pub struct AddCircuit;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AddWitness { pub a: u64, pub b: u64 }

impl Circuit for AddCircuit {
    type Witness = AddWitness;
    type PublicInputs = [Fr; 1];
    const ID: &'static str = "example.add";

    fn num_public_inputs() -> usize { 1 }

    fn synthesize(builder: &mut UltraCircuitBuilder, w: &Self::Witness) -> Self::PublicInputs {
        let a = builder.add_variable(Fr::from(w.a));
        let b = builder.add_variable(Fr::from(w.b));
        let c = builder.add(a, b);
        builder.set_public(c);
        [Fr::from(w.a) + Fr::from(w.b)]
    }

    fn dummy_witness() -> Self::Witness { AddWitness { a: 0, b: 0 } }
}
```

Pair with [`genshi-cli`](https://crates.io/crates/genshi-cli) for a circom-style command-line workflow.

## License

Licensed under either [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
