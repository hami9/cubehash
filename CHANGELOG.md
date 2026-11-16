# Changelog

All notable releases of the **CubeHash** cryptographic engine are recorded here.

## v1.0.1 — Pure Algorithm Release, Mathematical Spec & Public CI Readiness

### Highlights
- **Focused Algorithm Workspace**: Isolated `cubehash-core` (`#![forbid(unsafe_code)]`), `cubehash-ffi` (`cubehash.h` C/C++ ABI), and `cubehash-cli` (7-stage security audit & benchmark CLI) as a standalone algorithm repository.
- **Complete Technical & Mathematical Documentation**: Added [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/MATHEMATICS.md](docs/MATHEMATICS.md), [docs/VERIFICATION.md](docs/VERIFICATION.md), and updated [README.md](README.md) with Mermaid diagrams, formal equations, TMR/bijection proofs, and audit reports.
- **Open-Source Governance & Automation**: Added dual `MIT OR Apache-2.0` license files ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), `.github/CODEOWNERS`, Dependabot configuration, GitHub CI & cross-platform Release workflows, and approval-gated PR merge automation.

### Verification
- `cargo fmt --all -- --check`: passing
- `cargo clippy --workspace --all-targets -- -D warnings`: 0 warnings
- `cargo test --workspace`: 15/15 passing (`14` security suite tests in `cubehash-core` + `1` C-ABI lifecycle smoke test in `cubehash-ffi`)
- `cargo run --release -p cubehash-cli`: 7/7 audit stages passing (`0.566 ms/msg` full 100-cube roundtrip)
