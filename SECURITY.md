# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `1.0.x` | Yes |
| `< 1.0.0` | No |

## Reporting a Vulnerability

**Please do not open public GitHub issues for suspected cryptographic, side-channel, memory-safety, or key-custody vulnerabilities.**

1. Use GitHub **Private Vulnerability Reporting** (**Security -> Advisories -> New draft security advisory**) in `https://github.com/hami9/cubehash`.
2. Include a minimal reproduction, affected crate/module (`cubehash-core`, `cubehash-ffi`, or `cubehash-cli`), expected invariant, and observed behavior.
3. Initial acknowledgement target is within **72 hours**, with remediation prepared via private security fork before public advisory disclosure.

## Security Guarantees & Invariants

- **`cubehash-core` enforces `#![forbid(unsafe_code)]`**: no raw pointer arithmetic or unguarded memory access inside the cryptographic engine.
- **Secret Memory Hygiene**: `MotherCube`, `MainCube`, `AuditorCube`, `VoxelCube`, `SubCube`, `LocalClientClockGuard`, `EphemeralCubeAlgorithm`, and `DhRatchetState` implement `Zeroize` / `ZeroizeOnDrop`.
- **Zero-Oracle Guarantees**: `CellularMesh::decrypt_zero_oracle` must remain uniform and constant-work across malformed wire cubes, unauthorized hardware enclaves, replay sequences, TMR corruption, and MAC/AEAD failures without mutating session or monotonic clock state.
- **Non-Contributory DH Guard**: `X25519` outputs must reject low-order / non-contributory shared secrets (`!shared.was_contributory()`).
