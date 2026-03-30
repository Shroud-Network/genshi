# Shroud Network ZK Scheme: Technical Blueprint
 
## shroud-honk -- A Rust-Native UltraHonk Proving Scheme for Privacy Infrastructure
 
Version 0.1 -- March 2026
Authors: Brooklyn (CTO), Shroud Network
 
---
 
## Part 1: The Problems We Are Solving
 
### 1.1 Proving Speed
 
Shroud's current transfer operation takes minutes to complete. The latency is entirely on the proving side, not the chain -- Avalanche Fuji confirms transactions in 2-3 seconds.
 
Three performance penalties compound on each other in the current stack. First, snarkjs executes Groth16 proof generation in WASM inside the browser with no SIMD vectorization, running 4-8x slower than native code. Second, Baby Jubjub arithmetic is wrong-field inside BN254 R1CS, meaning every scalar multiplication costs approximately 700 constraints instead of near-zero if the curve were native to the proof system. Third, the Merkle path verification at depth 20 costs approximately 5,000 constraints, making it the single largest constraint group.
 
The transfer circuit currently has approximately 25,133 total constraints, all paying the BN254 bignum arithmetic penalty. This is not a single bottleneck with a single fix. It is a systemic architecture problem where the proving system, the commitment curve, the hash function, and the tree structure are all suboptimal simultaneously.
 
### 1.2 Proving System Architecture
 
Groth16 combined with Circom is the wrong long-term stack for a privacy protocol under active development.
 
Circom requires manual constraint management where the developer thinks like a cryptographer rather than an engineer, making circuit development slow and auditing painful. Groth16 requires a per-circuit trusted setup ceremony, meaning every bug fix, optimization, or feature addition to either circuit requires coordinating a new ceremony. snarkjs is the only practical Groth16 prover in the browser, and it is slow by design. Most critically, Groth16's R1CS arithmetization has no support for lookup tables, which means wrong-field arithmetic can never be made cheap within this stack. This is a ceiling, not a fixable bug.
 
### 1.3 Baby Jubjub Wrong-Field Arithmetic
 
Baby Jubjub is a twisted Edwards curve defined over BN254's scalar field. Inside a BN254 R1CS circuit, all Baby Jubjub curve operations must be emulated as arithmetic constraints rather than executing natively. Every keypair derivation, every Pedersen commitment, and every ownership proof pays this penalty.
 
A single scalar multiplication on Baby Jubjub costs approximately 700 constraints. The same operation on a curve native to the proof system costs near-zero. Across the full transfer circuit, Baby Jubjub wrong-field operations account for roughly 5,600 constraints (ownership proof, input Pedersen, output Pedersens combined), which is over 22% of the total circuit cost spent purely on field incompatibility overhead.
 
### 1.4 Merkle Tree Depth and Structure
 
The current binary Merkle tree at depth 20 supports 1,048,576 commitments. On testnet, there are hundreds at most. Each Merkle proof requires 20 Poseidon hash verifications, costing approximately 5,000 constraints -- the single largest constraint group in the transfer circuit.
 
This capacity is unnecessary at the current stage and the tree structure is not optimized for constraint efficiency. A 4-ary tree at depth 10 covers the same 1M leaf capacity while halving the path length.
 
### 1.5 Sequential Merkle Tree Updates
 
The single shared append-only Merkle tree serializes all operations. Two users cannot transfer simultaneously because one must wait for the other's insertion to complete and the root to update before generating a valid proof against the current state.
 
The 100-root history buffer provides some tolerance for concurrent proof generation against slightly stale roots, but it does not solve high-throughput scenarios. There is no batching mechanism -- each transfer updates the tree once, paying full insertion cost per user.
 
### 1.6 No Server-Side Prover
 
All proving currently happens in the browser via snarkjs. There is no fallback for users on low-powered devices or when browser proving times out. A server-side prover introduces a privacy tradeoff because the server sees private witness inputs, which would require either a TEE (SGX enclave with remote attestation) or explicit user-facing disclosure.
 
### 1.7 Trusted Setup Operational Risk
 
Groth16 requires a new trusted setup ceremony every time either circuit changes. Any bug fix, optimization, or feature addition triggers a new ceremony requiring coordination, time, and community participation. Universal setup systems (UltraHonk with KZG, Halo2 with KZG) require one ceremony for all circuit sizes, eliminating this burden entirely.
 
### 1.8 Solana Proving System Selection
 
The Solana build is starting from scratch with an unresolved conflict: the initial design assumed Groth16 via `sol_alt_bn128_*` syscalls, but subsequent analysis identified UltraHonk as the correct long-term stack. UltraHonk verification on Solana still uses BN254 pairings (so the same syscalls apply), but the verifier logic is different from Groth16. No production UltraHonk verifier for Solana exists yet, though TaceoLabs' co-snarks project provides a Rust-native UltraHonk prover compatible with Barretenberg that can be adapted. This decision must be resolved before the Solana build progresses further, otherwise we build the wrong verifier.
 
### 1.9 EVM and Solana Cryptographic Divergence
 
If the EVM deployment migrates to Grumpkin for commitments (required for UltraHonk to eliminate wrong-field overhead) but the Solana deployment stays on Baby Jubjub for syscall compatibility, cross-chain note portability becomes impossible without a translation layer. Every cryptographic stack decision made now either opens or closes the door on future cross-chain interoperability.
 
---