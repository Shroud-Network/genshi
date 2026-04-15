# genshi-solana

Solana BPF verifier for the [genshi](https://github.com/shroud-network/genshi) dual-VM zero-knowledge proving framework.

Verifies genshi PLONK-KZG proofs on Solana by routing the BN254 pairing check through the `sol_alt_bn128_pairing` syscall instead of the arkworks pairing engine (which would blow the CU budget). Consumes the same proof byte format produced for EVM — one proof, two chains.

Designed to be dropped into an Anchor program's `verify` instruction.

## Usage

```rust
use genshi_solana::verify::verify_proof;

pub fn verify(ctx: Context<Verify>, proof: Vec<u8>, public_inputs: Vec<u8>) -> Result<()> {
    let vk_bytes = /* load VK from account */;
    let srs_bytes = /* load SRS from account */;
    verify_proof(&proof, &vk_bytes, &public_inputs, &srs_bytes)
        .map_err(|_| error!(MyError::InvalidProof))?;
    Ok(())
}
```

`no_std` compatible. On native host targets (tests, emulation) the crate links against the arkworks pairing engine; on the actual Solana BPF target, it routes through the BN254 syscall.

## License

Licensed under either [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE) at your option.
