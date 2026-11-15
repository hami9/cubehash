# CubeHash Security Engine & Zero-Knowledge Chat

Decoupled Rust workspace implementing the CubeHash 3-cube algebraic/AEAD security engine (`cubehash-core`), C ABI bindings (`cubehash-ffi`), benchmark/audit runner (`cubehash-cli`), and a headless TLS blind-relay encrypted chat (`cubehash-chat`).

## Workspace Crates

- **`crates/cubehash-core`** (`#![forbid(unsafe_code)]`): General-purpose security engine featuring `MotherCube` / `MainCube` / `AuditorCube` 3-cube custody, hardware-bound key derivation (`OsBoundHardwareProvider`), X25519 DH Ratchet (`WirePacket.ratchet_pub` & `DeliveryAck.next_ratchet_pub`), Triple Modular Redundancy (TMR) bit-rot healing, constant-work `decrypt_zero_oracle` honey deception, synchronized epoch hopping, and losslessly rolled-back TX/RX state transitions.
- **`crates/cubehash-ffi`**: C ABI (`cdylib` / `staticlib`) exposing the core security engine for external applications.
- **`crates/cubehash-cli`**: Security audit and performance benchmark CLI.
- **`crates/cubehash-chat`**: Headless WebSocket-over-TLS (`wss://`) blind relay server and CLI chat client with:
  - TLS 1.2/1.3 transport via `rustls` (`ring` provider) + certificate SHA-256 pinning / custom CA / WebPKI (`--insecure-ws` required to opt into plaintext `ws://`).
  - Ed25519 challenge-response relay authentication, sender ownership checks, identity pinning, and signed `PairOffer` / `PairAccept` / `EpochHopNotice` frames.
  - OS-sealed keystore (`DeviceIdentity`: Windows DPAPI + Registry `MachineGuid` + TPM 2.0 CNG probe + optional `--hw-secret` 2FA entropy).
  - X25519 pairing + explicit `/accept` confirmation (or `/psk` auto-accept) + 256-byte bucketed chat payload padding.

## Quick Commands

Run all tests and lint checks:
```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run --release -p cubehash-cli
cargo build --release -p cubehash-ffi
```

Start a headless blind TLS relay (`wss://`):
```sh
cargo run -p cubehash-chat -- relay --listen 127.0.0.1:9000
```

Connect two headless CLI chat clients using the printed `--tls-pin`:
```sh
cargo run -p cubehash-chat -- client --id alice --relay wss://127.0.0.1:9000/ws --tls-pin <sha256_hex>
cargo run -p cubehash-chat -- client --id bob   --relay wss://127.0.0.1:9000/ws --tls-pin <sha256_hex>
```
