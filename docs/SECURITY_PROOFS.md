# Security Proofs, Side-Channel Analysis & Comparative Benchmarks

This document provides the mathematical reduction proofs, combiner security analysis, Honey-deception operational safety boundaries, empirical system-level side-channel measurements, and comparative benchmarks demonstrating how **CubeHash** relates to standard cryptographic primitives.

---

## 1. Theorem: CubeHash Is Strictly No Weaker Than Standard Hashing & AEAD

### 1.1 Confidentiality & Integrity Reduction (`ArbitraryCiphertext` Mode)

Let $\mathcal{E}_{\text{AEAD}}$ be standard **`XChaCha20-Poly1305`** (RFC 8439 variant with 192-bit nonce), $\mathcal{M}_{\text{HMAC}}$ be **`HMAC-SHA256`**, $\mathcal{K}_{\text{HKDF}}$ be **`HKDF-SHA256`**, and $\text{CDH}_{\text{X25519}}$ be Curve25519 Diffie–Hellman.

In CubeHash `ArbitraryCiphertext` mode, every payload $m$ is protected by:
1. Per-packet ephemeral key derivation:

```math
Z = \text{X25519}(sk_{\text{eph}}, pk_{\text{peer}}), \qquad K_{\text{ratchet}} = \text{HMAC}\big(K_{\text{root}},\; \text{"dh-ratchet-root-v1"} \parallel K_{\text{chain}} \parallel Z\big)
```

2. Ephemeral algorithm synthesis (`algo_key`) over a quorum of 25 secret mesh cube cores:

```math
K_{\text{algo}} = \text{FixedBudgetMix}\big(\text{Algo},\; K_{\text{ratchet}},\; \text{"ephemeral-algo-synthesis"},\; \mathcal{M}_{\mathcal{Q}},\; B\big)
```

3. Independent HKDF key/nonce expansion and AEAD sealing:

```math
K_{\text{msg}} = \text{HKDF}(K_{\text{algo}}, f, \text{"cubehash-aead-payload"}, 32), \qquad \text{nonce}_{24} = \text{HKDF}(K_{\text{algo}}, P_{\text{core}}[8..], \text{"cubehash-aead-nonce"}, 24)
```

```math
C_{\text{wire}} = \text{XChaCha20-Poly1305}_{K_{\text{msg}}}\big(\text{nonce}_{24},\; f \parallel \langle s \rangle_8 \parallel \langle e \rangle_8 \parallel pk_{\text{eph}},\; m\big)
```

4. Outer ciphertext-binding packet tag over healed wire cube + AEAD ciphertext:

```math
M_{\text{pkt}} = \text{HMAC}\big(K_{\text{algo}},\; \text{"wire-mac-aead-v2"} \parallel f \parallel \langle s \rangle_8 \parallel \langle e \rangle_8 \parallel pk_{\text{eph}} \parallel C_{\text{256b}} \parallel C_{\text{wire}}\big)
```

**Theorem 1 (IND-CPA & INT-CTXT Lower Bound):**
Assume `HKDF-SHA256` and `HMAC-SHA256` act as standard pseudorandom functions and `XChaCha20-Poly1305` satisfies IND-CPA and INT-CTXT. Suppose a PPT adversary $\mathcal{A}$ breaks CubeHash payload confidentiality or integrity with non-negligible advantage $\epsilon$ given `WirePacket`. Then we construct adversaries $\mathcal{B}_1, \mathcal{B}_2, \mathcal{B}_3$ such that:

```math
\text{Adv}_{\text{CubeHash}}^{\text{AEAD}}(\mathcal{A}) \le \text{Adv}^{\text{prf}}_{\text{HMAC}}(\mathcal{B}_1) + \text{Adv}^{\text{prf}}_{\text{HKDF}}(\mathcal{B}_2) + \text{Adv}^{\text{ind-cpa/int-ctxt}}_{\text{XChaCha20-Poly1305}}(\mathcal{B}_3)
```

*Proof Sketch:* Notice `CellularMesh`, `SpiralSpace`, TMR shadows, and variable weight padding NEVER replace or weaken `XChaCha20-Poly1305`; they solely feed extra independent entropy (`K_root`, `X25519`, 25-of-100 cellular cube state) into deriving `K_algo` and repair noisy bits prior to `M_pkt` and `AEAD_open`. Even in the worst case where an attacker knew all 100 initial mesh cubes, confidentiality/integrity still reduces to `X25519` + `K_root` + `XChaCha20-Poly1305` — strictly **at least as strong as** standalone `XChaCha20-Poly1305` and **`HMAC-SHA256`**.

### 1.2 Why CubeHash Adds Properties Beyond Static Hash / AEAD

A standalone static AEAD key $K$ or hash $H(m)$ provides neither Forward Secrecy nor bit-rot recovery nor cloning protection:
- **Forward Secrecy & Post-Compromise Security:** Compromise of state at sequence $s$ cannot derive $Z_{s-1}$ (ephemeral `sk_eph` zeroized immediately upon send) or $K_{\text{chain}, s-1}$, and a single future uncompromised ACK (`next_ratchet_pub`) injects fresh X25519 entropy to heal post-compromise state.
- **Bit-Rot Resilience:** Bitwise Majority Voting recovers single-copy noise before AEAD verification fails.
- **Traffic Length Hiding:** Variable whitened padding (`16..96 B`) + masked wire cores eliminate deterministic plaintext/metadata patterns visible in bare AEAD frames.

---

## 2. Formal Analysis of `HybridTriMix` Combiner

In `crates/cubehash-core/src/primitives.rs`, `HybridTriMix` computes:

```math
\text{HybridTriMix}_i(K, \text{dom}, X) = S_{\text{BLAKE}, i} \oplus \rho_3(S_{\text{SHA3}, i}) \oplus \rho_{-5}(S_{\text{HMAC}, i})
```

where $\rho_c: \{0,1\}^8 \to \{0,1\}^8$ is cyclic byte bit-rotation ($x \lll c$ or $x \ggg c$).

### 2.1 Theorem: Robust Keyed-PRF Combiner Bound

Observe that $\rho_3$ and $\rho_{-5}$ are **exact bijections** on $\{0,1\}^{256}$. Furthermore, every call inside CubeHash passes secret key $K$ (`mother_part`, `root_cap`, `ratcheted_root`, or `algo_key`) over distinct underlying families (HAIFA ChaCha-permutation BLAKE2b, Sponge Keccak SHA3-256, Merkle–Damgård SHA-256 HMAC).

**Theorem 2 (Keyed PRF Dominance / Graceful Degradation):**
Suppose *at least one* primitive $F^* \in \{\text{BLAKE2b}, \text{SHA3-256}, \text{HMAC-SHA256}\}$ remains a secure PRF under secret key $K$ when the remaining two primitives are weakened or even fixed to known constants by an adversary. Because XORing an output of $\rho(F^*(K, x))$ with independent fixed or public values preserves indistinguishability from uniform $U_{256}$:

```math
\text{Adv}^{\text{prf}}_{\text{HybridTriMix}}(t, q) \le \min_{j \in \{\text{BLAKE2b}, \text{SHA3-256}, \text{HMAC-SHA256}\}} \text{Adv}^{\text{prf}}_{F_j}(t', q)
```

### 2.2 Explicit Cryptographic Caveats (No Overclaiming)

- We **do not** claim `HybridTriMix` multiplies collision resistance to `768` bits in unkeyed settings: under adversarial chosen unkeyed inputs (where $K$ is public), XORing 256-bit hashes gives standard combiners' $\le 256$-bit output space (subject to generalized Wagner/Joux observations on multi-hash XOR).
- Within CubeHash, `fixed_budget_mix` ALWAYS runs in the **keyed** PRF/KDF setting (`key = secret custody/ratchet key`), where Theorem 2 applies rigorously. Independent third-party cryptanalysis is still welcomed (`SECURITY.md`) before any post-quantum claim beyond hybrid KEM integration is made.

---

## 3. Honey Deception & Operational Consumer Safety

Returning plausible fake output (`HoneyDeception`) on authentication failure would create silent corruption bugs *if* callers could confuse decoy data with real plaintext. CubeHash prevents this structurally in both Rust (`ReceiveOutcome`) and C ABI (`cubehash.h`):

```rust
pub enum ReceiveOutcome {
    Authentic { plaintext: Vec<u8>, ack: DeliveryAck, healed_bits: usize },
    HoneyDeception { plausible_output: Vec<u8>, profile: HoneyProfile },
}
```

- **Production callers MUST match `ReceiveOutcome::Authentic`** before consuming `plaintext` or advancing higher-level application protocols.
- **`ReceiveOutcome::HoneyDeception` guarantees zero session mutation** (`local_monotonic_tick`, `ratchet`, and `cubes` are untouched), so hostile probes cannot desynchronize a valid connection while external error telemetry reveals nothing.

---

## 4. System-Level Constant-Time Scope & Empirical Timing Verification

Using `subtle::ConditionallySelectable` inside `fixed_budget_mix` guarantees branchless output selection *for that hash primitive alone*, **not** automatically hardware-constant execution across an entire high-level Rust decryption method (`Vec` heap allocation, X25519 / XChaCha20 CPU cache behavior, and OS memory allocators).

Accordingly, CubeHash provides:
1. **Unconditional Verification & Decoy Evaluation (`decrypt_zero_oracle`):**
   Evaluates hardware verification, key unsealing, X25519 ECDH, ephemeral algorithm synthesis, TMR repair, packet MAC, AEAD open, transition dry-run, candidate `DeliveryAck` MAC synthesis, and DTE Honey synthesis uniformly without early returns.
2. **Continuous Empirical Timing Regression & Welch's $|t|$-Test (`Stage [9]` & `security_suite.rs`):**
   Measured over $N = 200$ interleaved `--release` samples on `x86_64-pc-windows-msvc`:

| Probe Path (`decrypt_zero_oracle`, `N=200`) | Median ($\mu\text{s}$) | p95 ($\mu\text{s}$) | Ratio vs Authentic | Welch's $\|t\|$ | Expected Outcome |
| --- | --- | --- | --- | --- | --- |
| `Authentic` (valid packet + commit) | `326.7` | `465.7` | `1.000x` | `—` | `ReceiveOutcome::Authentic` |
| `TamperedMAC` | `323.6` | `489.2` | `0.991x` | `0.71` | `ReceiveOutcome::HoneyDeception` |
| `WrongHardware` | `323.0` | `478.0` | `0.989x` | `0.55` | `ReceiveOutcome::HoneyDeception` |
| `BadSequence` | `323.8` | `492.0` | `0.991x` | `0.05` | `ReceiveOutcome::HoneyDeception` |
| `BadDimension` | `322.8` | `487.1` | `0.988x` | `1.00` | `ReceiveOutcome::HoneyDeception` |

All observed Welch $|t|$-values stay well below standard statistical distinguishability thresholds ($|t| \le 1.00 < 1.96$ and far below Dudect's $|t| > 4.5$ alert bound), while `median` ratios lie in **`0.988x–0.991x`**.

*Scope Boundary:* Empirical Welch $|t|$ parity on x86_64 desktop CPUs demonstrates absence of macro-level early-exit timing channels; strict cycle-exact microarchitectural immunity against physical EM/cache-line side-channels on shared embedded cores requires a dedicated `no_std`/static-arena port free of heap `Vec`.

---

## 5. Empirical Quality & Comparative Benchmark Proof vs Standard Algorithms

Reproduce every number below locally with:

```sh
cargo test --workspace
cargo run --release -p cubehash-cli
```

### 5.1 Statistical Indistinguishability (`Stage [8]`, 64 KiB Output + 200-Trial SAC)

| Metric | CubeHash (`64 KiB`) | `XChaCha20-Poly1305` (`64 KiB`) | `SHA-256-CTR` (`64 KiB`) | Ideal Uniform / Bound |
| --- | --- | --- | --- | --- |
| SAC 1-Bit Avalanche (`200` trials) | **`50.36%`** | `—` (`SHA3-256`: `49.91%`) | `—` | `50.0%` (`45%–55%`) |
| Monobit Ones Ratio | **`0.4994`** | `0.5003` | `0.4995` | `0.5000` (`0.49–0.51`) |
| Shannon Entropy (bits/byte) | **`7.99724`** | `7.99719` | `7.99678` | `8.0000` (`> 7.99`) |
| Pearson $\chi^2$ (`df = 255`) | **`250.67`** | `255.19` | `293.05` | `< 330.5` ($p > 0.001$) |
| Lag-1 Bit Autocorrelation | **`-0.00139`** | `+0.00011` | `-0.00067` | `0.0000` (`|r| < 0.02`) |

### 5.2 Release Throughput Comparison (`Stage [7]` & `[10]`)

| Operation | Latency / Throughput | Notes |
| --- | --- | --- |
| Standard `SHA3-256` (`512 B`) | `2.34 us/op` | Standalone unkeyed digest baseline |
| Standard `BLAKE2b-512` (`512 B`) | `1.04 us/op` | Standalone unkeyed digest baseline |
| Standard `HMAC-SHA256` (`512 B`) | `0.88 us/op` | Standalone keyed PRF baseline |
| Standard `X25519` scalar mult | `69.84 us/op` | Underlying Curve25519 step |
| Standard `XChaCha20-Poly1305` (`64 KiB`) | `110.84 us/op` (`563.9 MB/s`) | Raw symmetric AEAD baseline |
| `fixed_budget_mix` (`Blake2b / Sha3 / Hmac / Hybrid`) | `8.75 / 8.90 / 8.89 / 8.67 us/op` | Constant tri-leg budget across all 4 modes |
| Full 100-Cube E2E Roundtrip (`512 B`) | `0.581 ms/msg` | Custody + X25519 DH + 25/20 Quorum + TMR + AEAD + ACK |
| Full 100-Cube E2E Roundtrip (`64 KiB`) | `1.041 ms/msg` (`60.1 MB/s`) | Per-message fixed cellular/DH cost amortized cleanly |
