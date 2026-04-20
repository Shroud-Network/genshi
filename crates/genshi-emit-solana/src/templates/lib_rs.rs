use crate::config::EmitConfig;
use std::fmt::Write;

pub fn generate(config: &EmitConfig) -> String {
    let mut out = String::new();
    let program_name = &config.program_name;
    let mod_name = program_name.replace('-', "_");

    writeln!(out, "use anchor_lang::prelude::*;").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "mod types;").unwrap();
    writeln!(out, "mod transcript;").unwrap();
    writeln!(out, "mod verifier;").unwrap();
    writeln!(out, "mod srs;").unwrap();
    writeln!(out, "mod vk_constants;").unwrap();
    writeln!(out, "mod pairing_constants;").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "declare_id!(\"11111111111111111111111111111112\");").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[program]").unwrap();
    writeln!(out, "pub mod {mod_name} {{").unwrap();
    writeln!(out, "    use super::*;").unwrap();

    for circuit in &config.circuits {
        let fn_name = format!("verify_{}", circuit.name);
        let vk_loader = format!("load_{}_vk", circuit.name);

        writeln!(out).unwrap();
        writeln!(out, "    pub fn {fn_name}(ctx: Context<Verify>, proof_bytes: Vec<u8>, public_inputs_bytes: Vec<u8>) -> Result<()> {{").unwrap();
        writeln!(out, "        let vk = vk_constants::{vk_loader}();").unwrap();
        writeln!(out, "        let srs_stub = srs::SRS {{").unwrap();
        writeln!(out, "            g2: pairing_constants::load_g2(),").unwrap();
        writeln!(out, "            g2_tau: pairing_constants::load_g2_tau(),").unwrap();
        writeln!(out, "        }};").unwrap();
        writeln!(out, "        let proof = types::deserialize_proof(&proof_bytes)").unwrap();
        writeln!(out, "            .map_err(|_| error!(ErrorCode::InvalidProof))?;").unwrap();
        writeln!(out, "        let pis = types::deserialize_public_inputs(&public_inputs_bytes)").unwrap();
        writeln!(out, "            .map_err(|_| error!(ErrorCode::InvalidProof))?;").unwrap();
        writeln!(out, "        require!(").unwrap();
        writeln!(out, "            verifier::verify(&proof, &vk, &pis, &srs_stub),").unwrap();
        writeln!(out, "            ErrorCode::VerificationFailed").unwrap();
        writeln!(out, "        );").unwrap();
        writeln!(out, "        Ok(())").unwrap();
        writeln!(out, "    }}").unwrap();
    }

    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[derive(Accounts)]").unwrap();
    writeln!(out, "pub struct Verify {{}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[error_code]").unwrap();
    writeln!(out, "pub enum ErrorCode {{").unwrap();
    writeln!(out, "    #[msg(\"Invalid proof data\")]").unwrap();
    writeln!(out, "    InvalidProof,").unwrap();
    writeln!(out, "    #[msg(\"Proof verification failed\")]").unwrap();
    writeln!(out, "    VerificationFailed,").unwrap();
    writeln!(out, "}}").unwrap();

    out
}
