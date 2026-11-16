## Summary

Describe the cryptographic improvement, research finding, optimization, or fix introduced by this PR.

## Checklist

- [ ] Strictly scoped to the CubeHash algorithm (`cubehash-core` / `cubehash-ffi` / `cubehash-cli` / docs) — no unrelated application/chat code
- [ ] `crates/cubehash-core/src/lib.rs` preserves `#![forbid(unsafe_code)]`
- [ ] `cargo fmt --all -- --check` passes cleanly
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes with zero warnings
- [ ] `cargo test --workspace` passes cleanly (`security_suite` + `ffi_smoke`)
- [ ] `cargo run --release -p cubehash-cli` passes all 7 audit stages
- [ ] Mathematical/architectural documentation (`docs/MATHEMATICS.md` / `docs/ARCHITECTURE.md`) updated if applicable
