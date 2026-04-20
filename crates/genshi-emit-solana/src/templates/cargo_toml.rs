use crate::config::EmitConfig;

pub fn generate(config: &EmitConfig) -> String {
    let name = &config.program_name;
    let anchor_ver = &config.anchor_version;
    let math_ver = &config.genshi_math_version;

    format!(
        r#"[workspace]

[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "lib"]
name = "{name_under}"

[dependencies]
anchor-lang = "{anchor_ver}"
genshi-math = {{ version = "{math_ver}", default-features = false, features = ["bpf"] }}
tiny-keccak = {{ version = "2.0", features = ["keccak"] }}

[features]
default = []
cpi = ["no-entrypoint"]
no-entrypoint = []
no-idl = []
no-log-ix-name = []
idl-build = ["anchor-lang/idl-build"]

[profile.release]
overflow-checks = true
"#,
        name_under = name.replace('-', "_"),
    )
}
