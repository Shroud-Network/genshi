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
    let pid = config.program_id.as_deref().unwrap_or("11111111111111111111111111111112");
    writeln!(out, "declare_id!(\"{pid}\");").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[program]").unwrap();
    writeln!(out, "pub mod {mod_name} {{").unwrap();
    writeln!(out, "    use super::*;").unwrap();

    // Buffer management instructions — shared across all circuits.
    writeln!(out).unwrap();
    writeln!(out, "    /// Allocate a proof/public-inputs buffer PDA.").unwrap();
    writeln!(out, "    ///").unwrap();
    writeln!(out, "    /// The payer owns the PDA until it is closed. `tag` lets callers").unwrap();
    writeln!(out, "    /// keep multiple buffers alive in parallel (e.g. `b\"proof\"`,").unwrap();
    writeln!(out, "    /// `b\"pi\"`). `size` is the total byte capacity reserved.").unwrap();
    writeln!(out, "    pub fn init_buffer(ctx: Context<InitBuffer>, tag: Vec<u8>, size: u32) -> Result<()> {{").unwrap();
    writeln!(out, "        let buf = &mut ctx.accounts.buffer;").unwrap();
    writeln!(out, "        buf.owner = ctx.accounts.payer.key();").unwrap();
    writeln!(out, "        buf.tag = tag;").unwrap();
    writeln!(out, "        buf.len = size;").unwrap();
    writeln!(out, "        buf.data = vec![0u8; size as usize];").unwrap();
    writeln!(out, "        Ok(())").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    /// Write a chunk of bytes into a buffer at `offset`.").unwrap();
    writeln!(out, "    pub fn write_buffer(ctx: Context<WriteBuffer>, offset: u32, chunk: Vec<u8>) -> Result<()> {{").unwrap();
    writeln!(out, "        let buf = &mut ctx.accounts.buffer;").unwrap();
    writeln!(out, "        require_keys_eq!(buf.owner, ctx.accounts.owner.key(), ErrorCode::BufferOwnerMismatch);").unwrap();
    writeln!(out, "        let off = offset as usize;").unwrap();
    writeln!(out, "        let end = off.checked_add(chunk.len()).ok_or(error!(ErrorCode::BufferOverflow))?;").unwrap();
    writeln!(out, "        require!(end <= buf.data.len(), ErrorCode::BufferOverflow);").unwrap();
    writeln!(out, "        buf.data[off..end].copy_from_slice(&chunk);").unwrap();
    writeln!(out, "        Ok(())").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    /// Close a buffer, refunding rent to the owner.").unwrap();
    writeln!(out, "    pub fn close_buffer(_ctx: Context<CloseBuffer>) -> Result<()> {{").unwrap();
    writeln!(out, "        Ok(())").unwrap();
    writeln!(out, "    }}").unwrap();

    for circuit in &config.circuits {
        let fn_name = format!("verify_{}", circuit.name);
        let fn_name_buf = format!("verify_{}_from_buffers", circuit.name);

        writeln!(out).unwrap();
        writeln!(out, "    /// Inline verifier for `{}`. Use this when the proof + public", circuit.name).unwrap();
        writeln!(out, "    /// inputs fit inside a single Solana transaction (~1 KB total).").unwrap();
        writeln!(out, "    pub fn {fn_name}(_ctx: Context<Verify>, proof_bytes: Vec<u8>, public_inputs_bytes: Vec<u8>) -> Result<()> {{").unwrap();
        writeln!(out, "        super::verify_{}_impl(&proof_bytes, &public_inputs_bytes)", circuit.name).unwrap();
        writeln!(out, "    }}").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "    /// Buffer-PDA verifier for `{}`. Use this when the proof exceeds", circuit.name).unwrap();
        writeln!(out, "    /// the 1232-byte transaction limit. Stream the proof into one PDA").unwrap();
        writeln!(out, "    /// and public inputs into another via `write_buffer`, then call this.").unwrap();
        writeln!(out, "    pub fn {fn_name_buf}(ctx: Context<VerifyFromBuffers>) -> Result<()> {{").unwrap();
        writeln!(out, "        let proof_data = ctx.accounts.proof_buffer.data.clone();").unwrap();
        writeln!(out, "        let pi_data = ctx.accounts.public_inputs_buffer.data.clone();").unwrap();
        writeln!(out, "        super::verify_{}_impl(&proof_data, &pi_data)", circuit.name).unwrap();
        writeln!(out, "    }}").unwrap();
    }

    writeln!(out, "}}").unwrap();

    // Helper impls — live outside `#[program]` so Anchor doesn't treat them
    // as fallback instruction handlers.
    for circuit in &config.circuits {
        let vk_loader = format!("load_{}_vk", circuit.name);

        writeln!(out).unwrap();
        writeln!(out, "#[cfg_attr(target_os = \"solana\", inline(never))]").unwrap();
        writeln!(out, "fn verify_{}_impl(proof_bytes: &[u8], pi_bytes: &[u8]) -> Result<()> {{", circuit.name).unwrap();
        writeln!(out, "    let vk = Box::new(vk_constants::{vk_loader}());").unwrap();
        writeln!(out, "    let srs_stub = Box::new(srs::SRS {{").unwrap();
        writeln!(out, "        g2: pairing_constants::load_g2(),").unwrap();
        writeln!(out, "        g2_tau: pairing_constants::load_g2_tau(),").unwrap();
        writeln!(out, "    }});").unwrap();
        writeln!(out, "    let proof = Box::new(types::deserialize_proof(proof_bytes)").unwrap();
        writeln!(out, "        .map_err(|_| error!(ErrorCode::InvalidProof))?);").unwrap();
        writeln!(out, "    let pis = types::deserialize_public_inputs(pi_bytes)").unwrap();
        writeln!(out, "        .map_err(|_| error!(ErrorCode::InvalidProof))?;").unwrap();
        writeln!(out, "    require!(").unwrap();
        writeln!(out, "        verifier::verify(&proof, &vk, &pis, &srs_stub),").unwrap();
        writeln!(out, "        ErrorCode::VerificationFailed").unwrap();
        writeln!(out, "    );").unwrap();
        writeln!(out, "    Ok(())").unwrap();
        writeln!(out, "}}").unwrap();
    }

    writeln!(out).unwrap();
    writeln!(out, "#[derive(Accounts)]").unwrap();
    writeln!(out, "pub struct Verify {{}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[account]").unwrap();
    writeln!(out, "pub struct Buffer {{").unwrap();
    writeln!(out, "    pub owner: Pubkey,").unwrap();
    writeln!(out, "    pub tag: Vec<u8>,").unwrap();
    writeln!(out, "    pub len: u32,").unwrap();
    writeln!(out, "    pub data: Vec<u8>,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[derive(Accounts)]").unwrap();
    writeln!(out, "#[instruction(tag: Vec<u8>, size: u32)]").unwrap();
    writeln!(out, "pub struct InitBuffer<'info> {{").unwrap();
    writeln!(out, "    #[account(mut)]").unwrap();
    writeln!(out, "    pub payer: Signer<'info>,").unwrap();
    writeln!(out, "    #[account(").unwrap();
    writeln!(out, "        init,").unwrap();
    writeln!(out, "        payer = payer,").unwrap();
    writeln!(out, "        space = 8 + 32 + 4 + tag.len() + 4 + 4 + size as usize,").unwrap();
    writeln!(out, "        seeds = [b\"buf\", payer.key().as_ref(), &tag],").unwrap();
    writeln!(out, "        bump,").unwrap();
    writeln!(out, "    )]").unwrap();
    writeln!(out, "    pub buffer: Account<'info, Buffer>,").unwrap();
    writeln!(out, "    pub system_program: Program<'info, System>,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[derive(Accounts)]").unwrap();
    writeln!(out, "pub struct WriteBuffer<'info> {{").unwrap();
    writeln!(out, "    #[account(mut)]").unwrap();
    writeln!(out, "    pub buffer: Account<'info, Buffer>,").unwrap();
    writeln!(out, "    pub owner: Signer<'info>,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[derive(Accounts)]").unwrap();
    writeln!(out, "pub struct CloseBuffer<'info> {{").unwrap();
    writeln!(out, "    #[account(").unwrap();
    writeln!(out, "        mut,").unwrap();
    writeln!(out, "        close = owner,").unwrap();
    writeln!(out, "        has_one = owner @ ErrorCode::BufferOwnerMismatch,").unwrap();
    writeln!(out, "    )]").unwrap();
    writeln!(out, "    pub buffer: Account<'info, Buffer>,").unwrap();
    writeln!(out, "    pub owner: Signer<'info>,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[derive(Accounts)]").unwrap();
    writeln!(out, "pub struct VerifyFromBuffers<'info> {{").unwrap();
    writeln!(out, "    pub proof_buffer: Account<'info, Buffer>,").unwrap();
    writeln!(out, "    pub public_inputs_buffer: Account<'info, Buffer>,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[error_code]").unwrap();
    writeln!(out, "pub enum ErrorCode {{").unwrap();
    writeln!(out, "    #[msg(\"Invalid proof data\")]").unwrap();
    writeln!(out, "    InvalidProof,").unwrap();
    writeln!(out, "    #[msg(\"Proof verification failed\")]").unwrap();
    writeln!(out, "    VerificationFailed,").unwrap();
    writeln!(out, "    #[msg(\"Buffer owner mismatch\")]").unwrap();
    writeln!(out, "    BufferOwnerMismatch,").unwrap();
    writeln!(out, "    #[msg(\"Buffer overflow\")]").unwrap();
    writeln!(out, "    BufferOverflow,").unwrap();
    writeln!(out, "}}").unwrap();

    out
}
