# Verification, Security Tests & Benchmark Report

All checks below were executed on this repository's pure algorithm workspace (`cubehash-core`, `cubehash-ffi`, `cubehash-cli`).

---

## 1. Automated Security Test Suite (`cubehash-core/tests/security_suite.rs` — 14/14 Passing)

| # | Test Name | Security & Mathematical Property Verified |
| --- | --- | --- |
| 1 | `test_config_validation_and_resizing` | Rejects invalid TMR sub-matrix bounds (`< 2 * core_bytes`) & invalid quorum bounds; executes full E2E message roundtrips across `compact`, `standard`, and `high_capacity` profiles. |
| 2 | `test_dual_mode_raw_core_and_arbitrary_payload` | Verifies `RawCore256` inside the `173 B` wire cube (exact `24 B` capacity, explicit `PayloadTooLargeForCore` on `25 B`) and `ArbitraryCiphertext` multi-KB UTF-8 `XChaCha20-Poly1305` encryption + `16..=96 B` variable weight padding. |
| 3 | `test_100_cube_cellular_lifecycle_entropy_and_ram` | Verifies initial 100-cube RAM footprint (`18,100` bytes / `~17.7 KB`), 50/50 bit balance (`0.45..=0.55`), and `120` sequential message roundtrips proving **every original genesis cube dies and advances cleanly** to `generation >= 21`. |
| 4 | `test_ack_commit_and_network_drop_rollback` | Verifies arrival-triggered atomicity: sending does NOT mutate local mesh (`PendingTransactionExists` blocks concurrent unsent commits), forged ACK fails (`AckMismatch`), and `rollback_outbound` restores exact pre-send state on packet drop. |
| 5 | `test_bitwise_majority_voting_self_healing_wire_and_storage` | Injects **80 bit flips** across `partial_256b` + `shadow_a` on the wire -> heals all **80 bits** transparently before MAC check; injects **8 bit flips** into a stored cube *after* 2 epoch hops -> heals cleanly; rejects catastrophic 3-copy + hot-spare corruption with `UnrecoverableCorruption`. |
| 6 | `test_hardware_lock_cloning_attack_and_3cube_recovery` | Proves cloned state on unauthorized hardware fails (`UnauthorizedHardware`), `OsBoundHardwareProvider` separates host traits/secrets, any 2-of-3 custody subset fails to reproduce `root_cap`, and `recover_onto_new_hardware` restores Alice's session onto new hardware while revoking the old device. |
| 7 | `test_replay_and_monotonic_clock_protection` | Rejects replayed packet `sequence=1` (`ReplayDetected`) and rejects non-increasing observed clock ticks on `LocalClientClockGuard`. |
| 8 | `test_bijective_epoch_hopping_and_spiral_window_lookup` | Verifies zero-collision bijectivity & exact inverse across `500` 3D coordinates, `250`-nibble permutation round-trip, full mesh movement (`100%` of coordinates and sub-matrices change on epoch hop), and `O(W * K)` lookup within `spiral_window = 16`. |
| 9 | `test_zero_oracle_honey_encryption_and_anti_desync` | Unauthorized hardware probe and tampered-MAC probe both emit plausible Honey outputs (including SHA-256 checksum-valid 12-word `Bip39ChecksumPhrase`), with zero error oracle and zero desync on subsequent authentic decryption. |
| 10 | `test_full_duplex_concurrent_chat_session` | Verifies `DuplexCubeSession` simultaneous bidirectional in-flight transmissions without TX/RX collision. |
| 11 | `test_wire_serialization_and_subcube_layout` | Verifies `SubCube` (`32 B` core / `125 B` sub-matrix) and JSON round-trip transport of `WirePacket` and `DeliveryAck`. |
| 12 | `test_os_hardware_provider_and_all_time_algorithms` | Exercises custom `40 B / 160 B / 48-cube` config with `OsBoundHardwareProvider` across all 4 `TimeAlgorithm` variants (`Blake2b`, `Sha3_256`, `HmacSha256`, `HybridTriMix`) and `HmacTreeCombine`. |
| 13 | `test_dh_ratchet_forward_post_compromise_and_tamper_resistance` | Verifies independent initial X25519 keys, per-packet `ratchet_pub` rotation, per-ACK receiver key rotation, rejection of tampered `ratchet_pub` / non-contributory `[0u8; 32]`, tampered `ack.next_ratchet_pub`, and synchronized DH-ratcheted epoch hopping (`hop_epoch_ratchet_tx` / `rx`). |
| 14 | `test_zero_oracle_constant_work_never_mutates_on_any_failure` | Probes malformed wire dimensions, wrong hardware enclave, and wrong sequence number, proving **zero** state mutation (including unchanged `local_monotonic_tick` and `local_dh_pub`) followed by clean authentic decryption. |

---

## 2. C ABI Smoke Test (`cubehash-ffi/tests/ffi_smoke.rs` — 1/1 Passing)

- **`test_ffi_full_lifecycle_and_zero_oracle`**: Verifies FFI config construction/validation (`CUBEHASH_ERR_INVALID_CONFIG`), `cubehash_provision_device`, `cubehash_send_raw_core` + `cubehash_rollback_outbound`, `cubehash_send_message` + `cubehash_receive_authenticated` + `cubehash_commit_ack`, `cubehash_receive_zero_oracle` returning `CUBEHASH_OUTCOME_HONEY` on forged JSON then `CUBEHASH_OUTCOME_AUTHENTIC` after synchronized `cubehash_hop_epoch`, `cubehash_audit_stats_json` (`"mesh_size":100`), and clean buffer/session deallocation.

---

## 3. Reproducible Audit & Benchmark Run (`cubehash-cli --release`)

Observed live output from `cargo run --release -p cubehash-cli`:

```text
=== CubeHash Security Engine Audit & Verification ===

[1] Resizable Configuration Profiles:
  - compact        mesh=40 quorum=12/9 core=16B sub=64B (512 bits) base_wire=96B weight=8..=32B space=256^3
  - standard       mesh=100 quorum=25/20 core=32B sub=125B (1000 bits) base_wire=173B weight=16..=96B space=1000^3
  - high_capacity  mesh=160 quorum=40/32 core=64B sub=256B (2048 bits) base_wire=336B weight=32..=160B space=2000^3

[2] 100-Cube Mesh Baseline: cubes=100 ram=18100 bytes (~17.7 KB) ones_ratio=0.4993 entropy=6.878 b/B
    110-msg rotation OK -> oldest_gen=11 wire_ones_ratio=0.4997 wire_entropy=7.9922 b/B

[3] Bitwise Majority Voting (TMR): injected 64 bit flips -> repaired 64 bits, MAC verified OK

[4] Hardware Lock & 3-Cube Recovery: cloning blocked (hardware lock rejected execution on unauthorized device), recovery onto new device OK

[5] Zero-Oracle Honey DTE: attacker probe emitted checksum-valid decoy "bundle bamboo blast alter aerobic action bone balance bronze buddy add bag" without desync

[6] Rollback & Bijective Epoch Hopping: rollback clean, epoch=1, spiral lookup found slot 55 in 8 steps

[7] Fixed Step Budget & Throughput Benchmark:
  - Blake2b        avg=9.09 us/op
  - Sha3_256       avg=8.60 us/op
  - HmacSha256     avg=8.62 us/op
  - HybridTriMix   avg=8.87 us/op
  - Full 100-cube E2E roundtrip (512B send + TMR + receive + ACK): 0.566 ms/msg

ALL SECURITY AUDITS PASSED SUCCESSFULLY.
```

---

## 4. Verification Summary Command Log

```sh
cargo clippy --workspace --all-targets -- -D warnings   # 0 warnings, exit 0
cargo test --workspace                                  # 14 core + 1 FFI passed, 0 failed, 0 ignored
cargo run --release -p cubehash-cli                     # 7/7 audit stages & benchmarks passed
```
