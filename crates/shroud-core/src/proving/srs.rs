//! Structured Reference String (SRS) loading.
//!
//! TODO: Phase 4 — Implement SRS loading from Aztec's Powers of Tau ceremony.
//! GUARDRAIL G9: SRS must come from a verifiable ceremony;
//! never generate custom SRS for production.
//!
//! For WASM: lazy loading + IndexedDB caching.
//! Download only the SRS points needed for actual circuit size.
