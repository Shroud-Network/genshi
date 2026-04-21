use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct CircuitConfig {
    pub name: String,
    pub vk_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EmitConfig {
    pub program_name: String,
    pub out_dir: PathBuf,
    pub circuits: Vec<CircuitConfig>,
    pub anchor_version: String,
    pub solana_program_version: String,
    pub genshi_math_version: String,
    pub emit_anchor_toml: bool,
    /// Base58 program id for the emitted `declare_id!`. If `None`, the system
    /// program id (`11111111111111111111111111111112`) is used as a stub —
    /// callers are then expected to replace it after the first `cargo
    /// build-sbf` produces a keypair under `target/deploy/`.
    pub program_id: Option<String>,
}

impl EmitConfig {
    pub fn new(program_name: impl Into<String>, out_dir: impl Into<PathBuf>) -> Self {
        Self {
            program_name: program_name.into(),
            out_dir: out_dir.into(),
            circuits: Vec::new(),
            anchor_version: "1.0.0".to_string(),
            solana_program_version: "3.0".to_string(),
            genshi_math_version: "0.2.0".to_string(),
            emit_anchor_toml: false,
            program_id: None,
        }
    }

    pub fn with_program_id(mut self, id: impl Into<String>) -> Self {
        self.program_id = Some(id.into());
        self
    }

    pub fn add_circuit(&mut self, name: impl Into<String>, vk_bytes: Vec<u8>) -> &mut Self {
        self.circuits.push(CircuitConfig {
            name: name.into(),
            vk_bytes,
        });
        self
    }
}
