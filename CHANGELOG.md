# Changelog

All notable releases of the **CubeHash** cryptographic engine are recorded here.

## v1.0.2 — Complete `HybridTriMix v2`, Formal Game-Hopping Reductions & High-Throughput Engine (`~550 MB/s`)

### Highlights
- **Complete `HybridTriMix v2` Engine ([hybrid.rs](crates/cubehash-core/src/hybrid.rs))**: Added standalone `HybridTriMix` & streaming `HybridTriMixHasher` supporting canonical length-delimited HMAC framing, three independent subkeys (`BLAKE2b`, `SHA3`, `HMAC`), `mix_256` PRF/MAC, constant-time `verify_tag_256`, `digest_512` wide-pipe combiner, `hash_unkeyed_512`, and arbitrary-length `expand_xof`, alongside invertible cross-lane permutations $\Pi_{256} / \Pi_{512}$.
- **High-Throughput Optimizations (`60 MB/s` -> `550 MB/s`)**: Cached static custody roots & epoch keys inside `CellularMesh`, eliminated heap allocations in `voxel.rs` TMR masks via stack fast paths, bound outer `compute_packet_mac` to the AEAD Poly1305 tag (`wire-mac-aead-tag-v3`), moved transitions zero-clone via `std::mem::swap`, absorbed arbitrary payloads once in `fixed_budget_mix`, and added configurable two-tier `dh_rekey_interval` (`set_dh_rekey_interval`) pairing per-frame `HybridTriMix` forward-secure chain ratchets with periodic Curve25519 DH + cellular rotation.
- **RustCrypto Major Dependency Upgrade (`#15`)**: Upgraded `blake2 0.11`, `chacha20poly1305 0.11`, `getrandom 0.4`, `hkdf 0.13`, `hmac 0.13`, `sha2 0.11`, `sha3 0.12`, and `x25519-dalek 3.0`, removing duplicate/unused `rand_core`.
- **Formal Full-Project Proofs & Exact Reductions ([docs/SECURITY_PROOFS.md](docs/SECURITY_PROOFS.md))**: Completed full game-hopping proofs and explicit reduction simulators ($\mathcal{B}_1 \dots \mathcal{B}_7$ and $\mathcal{B}_0, \mathcal{B}_{j^*}$) for Theorems 1–2 plus component-by-component Theorems 3–9 across every layer (`custody`, `LocalClientClockGuard`, two-tier ratchet FS/PCS, TMR combinatorial recovery & hot-spare false-accept bound, `SpiralSpace` group bijectivity, zero-oracle DTE invariance, `#![forbid(unsafe_code)]`, and FFI safety).

### Verification (`v1.0.2`)
- `cargo fmt --all -- --check`: passing
- `cargo clippy --workspace --all-targets -- -D warnings`: 0 warnings
- `cargo test --workspace --locked`: 20/20 passing (`19` core security & statistical tests + `1` C-ABI smoke test)
- `cargo run --release --locked -p cubehash-cli`: `550.3 MB/s` (`64 KiB`, `dh=64`) / `554.2 MB/s` (`1 MiB`, `dh=1`) / `116.8 MB/s` full 100-cube E2E (`64 KiB`, `dh=1`, ~2x faster than `v1.0.1`).

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
