pub fn generate() -> String {
    r#"[target.sbf-solana-solana.dependencies.std]
features = []

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
overflow-checks = true
"#
    .to_string()
}
