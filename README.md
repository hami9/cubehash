# CubeHash

Standalone, general-purpose hierarchical, self-healing, hardware-bound cellular cube cryptography workspace in Rust with C-ABI/FFI bindings.

## Workspace Layout

- `crates/cubehash-core` (`#![forbid(unsafe_code)]`):
  - **Configurable 3-Layer `VoxelCube`** (`src/config.rs`, `src/voxel.rs`): `sub_matrix` (default `1000` bits / `125` bytes / `250` nibbles), `core_pattern` (default `256` bits / `32` bytes), and whitened `weight_layer` (`16..=96` bytes). Includes `standard()`, `compact()`, `high_capacity()`, and custom sizing via `MeshConfig`.
  - **Bitwise Majority Voting (TMR Self-Healing)** (`src/voxel.rs`): embeds two masked shadow copies + hot-spare tag inside `sub_matrix` and automatically repairs bit-rot prior to MAC verification.
  - **3-Cube Custody & Hardware Lock** (`src/custody.rs`): separates `MotherCube`, `MainCube`, and `AuditorCube`, enforces `HardwareProvider` + `LocalClientClockGuard` monotonic anti-replay/anti-cloning, and supports cross-device 3-Cube recovery.
  - **3D Spiral Indexing & Bijective Epoch Hopping** (`src/spiral.rs`): `O(W * K)` windowed lookup in `1000^3` space plus provably invertible 3D coordinate & 250-nibble permutations.
  - **Zero-Oracle Honey Encryption / DTE** (`src/honey.rs`): structurally matching decoy chains and deterministic DTE profiles (`Bip39ChecksumPhrase`, `ChatPlaintext`, `RawUniform`) without exposing decryption errors or mutating active session state.
  - **100-Cube Cellular Mesh & Dual Payload Mode** (`src/mesh.rs`): arrival-triggered `25 select / 20 consume / 1 kill + 1 birth` lifecycle with `ACK / Rollback`, `RawCore256` (~173-byte base wire cube) and `ArbitraryCiphertext` (`XChaCha20-Poly1305` via cube-synthesized ephemeral key), plus `DuplexCubeSession` for full-duplex chat/IPC.
- `crates/cubehash-ffi`: `cdylib` / `staticlib` C-ABI bindings and `include/cubehash.h`.
- `crates/cubehash-cli`: security audit, fault-injection, and throughput benchmark runner.
- `crates/cubehash-chat`: zero-knowledge WebSocket blind relay server (`relay`, zero keys/plaintext, live inspector UI) and hardware-bound client node (`client`) with X25519 + optional PIN pairing, local browser Web UI (`--web`), and interactive terminal chat (`--cli`).

## Commands

```bash
# Run full security, FFI, and E2E chat test suite
cargo test --workspace

# Lint workspace cleanly
cargo clippy --workspace --all-targets -- -D warnings

# Run release security audit & benchmarks
cargo run --release -p cubehash-cli

# Build C-ABI shared/static library (target/release/cubehash_ffi.dll / .so / .lib)
cargo build --release -p cubehash-ffi

# Run Blind Relay Server + Two Local Web UI / CLI Chat Clients
cargo run -p cubehash-chat -- relay --listen 127.0.0.1:9000
cargo run -p cubehash-chat -- client --id alice --relay ws://127.0.0.1:9000/ws --web 127.0.0.1:8081 --cli
cargo run -p cubehash-chat -- client --id bob   --relay ws://127.0.0.1:9000/ws --web 127.0.0.1:8082 --cli
```
