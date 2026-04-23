/// Top-level `Cargo.toml` for the emitted Anchor workspace.
///
/// Anchor 1.0 expects programs to live under `programs/<name>/` with a
/// workspace manifest at the project root. The `[profile.release]` block
/// mirrors the defaults Anchor's own `anchor init` scaffold produces.
pub fn generate() -> String {
    r#"[workspace]
members = ["programs/*"]
resolver = "2"

[profile.release]
overflow-checks = true
lto = "fat"
codegen-units = 1
"#
    .to_string()
}
