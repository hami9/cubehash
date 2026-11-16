# Formal Mathematical & Cryptographic Specification

This specification documents the exact mathematical constructions, key schedules, algebraic transformations, and bounds implemented in `crates/cubehash-core`.

---

## 1. Notation & Primitives

| Symbol | Implementation | Description |
| --- | --- | --- |
| $\text{HMAC}(K, X)$ | `hmac_sha256_parts(K, &[...])` | HMAC-SHA-256 returning $256$-bit ($32$-byte) digest. |
| $\text{HKDF}(IKM, S, I, L)$ | `hkdf_expand_label(ikm, salt, info, out)` | HKDF-SHA-256 extract-and-expand producing $L$ bytes. |
| $W(S, \text{dom}, L)$ | `whitened_stream(seed, domain, out)` | Counter-mode BLAKE2b-512 stream: block $i = \text{BLAKE2b-512}(S, \text{dom}, i_{\text{LE64}})$. |
| $\text{X25519}(sk, pk)$ | `dh_exchange` | Curve25519 ECDH rejecting non-contributory / low-order outputs (`!shared.was_contributory()`). |
| $\text{AEAD}_{K}(N, A, P)$ | `aead_seal` / `aead_open` | XChaCha20 stream cipher + Poly1305 MAC ($24$-byte nonce, $16$-byte tag). |
| $d_H(X, Y)$ | `(x ^ y).count_ones()` sum | Bitwise Hamming distance between equal-length byte arrays. |
| $\langle n \rangle_8$ | `n.to_le_bytes()` | 64-bit unsigned little-endian encoding of $n$. |

---

## 2. Tripartite Custody & Hardware Execution Guard

### 2.1 Root Capability Synthesis

Given `MotherCube` $(K_{\text{mother}}, S_{\text{owner}})$, `MainCube` $(\text{cid}, P_{\text{main}}, S_{\text{chain}})$, and `AuditorCube` $(K_{\text{auditor}}, S_{\text{synth}}, \text{Algo}, \text{Comb}, \vec{c}, Q, C)$:

```math
K_M = \text{HMAC}\big(K_{\text{mother}},\; \text{"3cube-root"} \parallel S_{\text{owner}} \parallel \text{cid}\big)
```

```math
K_{\text{root}} = \text{FixedBudgetMix}\Big(\text{Algo},\; K_M,\; \text{"three-cube-custody"},\; P_{\text{main}} \parallel S_{\text{synth}} \parallel K_{\text{auditor}},\; B\Big)
```

where $B = \text{fixed\_step\_budget}$ (`4` in `standard` config). Any strict 2-of-3 subset omits either $K_{\text{mother}}$, $P_{\text{main}}$, or $K_{\text{auditor}}$ and yields an indistinguishable unrelated $256$-bit string.

### 2.2 Hardware Enclave Lock & Monotonic Capability

On device initialization, `LocalClientClockGuard` seals $r \leftarrow \{0,1\}^{256}$ onto hardware $\mathcal{H}$:

```math
S_{\mathcal{H}} = \text{Seal}_{\mathcal{H}}(\text{"cubehash-local-clock-guard-v1"}, r), \qquad \tau \leftarrow 0
```

For every state-mutating operation, caller must provide matching hardware identity `observed_hw == device_hw_id` (constant-time equality), successfully unseal $r = \text{Unseal}_{\mathcal{H}}(S_{\mathcal{H}})$, advance $\tau \leftarrow \tau + 1$ strictly monotonically, and obtain capability token:

```math
T_{\tau} = \text{HMAC}\big(r,\; \text{hw\_id} \parallel \langle \tau \rangle_8\big)
```

### 2.3 Hardware Loss Recovery Derivation

When re-provisioning onto replacement hardware $\mathcal{H}'$ using `ThreeCubeCustody`:

```math
r' = \text{HMAC}\big(K_{\text{root}},\; \text{"recover-hw-secret"} \parallel \text{hw\_id}_{\mathcal{H}'}\big)
```

and `LocalClientClockGuard` is re-sealed under $\mathcal{H}'$, permanently revoking execution under the original device.

---

## 3. Constant-Work Multi-Hash Core (`fixed_budget_mix`)

To eliminate timing variance between chosen digest algorithms (`TimeAlgorithm`), every call executes **all three independent legs** for $B \ge 1$ sequential rounds starting from zeroized accumulators $S_{\text{BLAKE}} = S_{\text{SHA3}} = S_{\text{HMAC}} = 0^{256}$:

For round $r \in \{0, \dots, B-1\}$:

```math
S_{\text{BLAKE}} \leftarrow \text{BLAKE2b-512}\big(K \parallel \text{dom} \parallel \langle r \rangle_8 \parallel S_{\text{BLAKE}} \parallel X\big)[0..32]
```

```math
S_{\text{SHA3}} \leftarrow \text{SHA3-256}\big(K \parallel \text{dom} \parallel \langle r \rangle_8 \parallel S_{\text{SHA3}} \parallel X\big)
```

```math
S_{\text{HMAC}} \leftarrow \text{HMAC}\big(K,\; \text{dom} \parallel \langle r \rangle_8 \parallel S_{\text{HMAC}} \parallel X\big)
```

Then the hybrid leg combines bit-rotations byte-wise:

```math
H_i = S_{\text{BLAKE}, i} \oplus (S_{\text{SHA3}, i} \lll 3) \oplus (S_{\text{HMAC}, i} \ggg 5) \quad \forall i \in \{0, \dots, 31\}
```

Finally, the configured target algorithm digest is selected **without secret-dependent branches** using `subtle::ConditionallySelectable` masks across $(S_{\text{BLAKE}}, S_{\text{SHA3}}, S_{\text{HMAC}}, H)$.

---

## 4. Per-Message Key Schedule, X25519 DH Ratchet & Ephemeral Quorum

Let `(sk_eph, pk_eph)` be a freshly generated CSPRNG X25519 keypair for outgoing sequence $s = \text{seq} + 1$ at epoch $e$, with random 16-byte `cube_fingerprint` $f \leftarrow \{0,1\}^{128}$:

1. **DH Exchange & Ratcheted Root** (aborts if non-contributory):

```math
Z = \text{X25519}(sk_{\text{eph}}, pk_{\text{peer}})
```

```math
K_{\text{ratchet}} = \text{HMAC}\big(K_{\text{root}},\; \text{"dh-ratchet-root-v1"} \parallel K_{\text{chain}} \parallel Z\big)
```

2. **Keyed Quorum Selection ($Q$ of $N$ cubes):**

```math
S_{\text{sel}} = \text{HMAC}\big(K_{\text{ratchet}},\; \text{"quorum-select"} \parallel S_{\text{synth}} \parallel f \parallel \langle s \rangle_8 \parallel \langle e \rangle_8\big)
```

A Fisher–Yates shuffle driven by $W(S_{\text{sel}}, \text{"quorum-perm"}, 4N)$ selects $Q$ distinct cube indices $\mathcal{Q} = (\pi(0), \dots, \pi(Q-1))$ (in `standard`: $Q = 25$ out of $N = 100$).

3. **Ephemeral Algorithm Synthesis ($K_{\text{algo}}$):**

```math
\mathcal{M}_{\mathcal{Q}} = f \parallel \langle s \rangle_8 \parallel \langle e \rangle_8 \parallel S_{\text{chain}} \parallel \Big\Vert_{i \in \mathcal{Q}} \text{core\_pattern}_i
```

```math
K_{\text{algo}} = \text{FixedBudgetMix}\big(\text{Algo},\; K_{\text{ratchet}},\; \text{"ephemeral-algo-synthesis"},\; \mathcal{M}_{\mathcal{Q}},\; B\big)
```

4. **Dual-Mode Wire Payload Derivation:**
   Let $P_{\text{core}} \leftarrow \{0,1\}^{8L_{\text{core}}}$ ($L_{\text{core}} = 32$ bytes standard).
   - **If `RawCore256` ($\text{len}(m) \le L_{\text{core}} - 8$):**
     - $P_{\text{core}}[0..2] = \text{len}(m)_{\text{LE16}}$, $P_{\text{core}}[2] = \text{0x01}$,
     - `P_core[3..8] = HMAC(K_algo, "raw-core-tag" || <s>_8)[0..5]`,
     - $P_{\text{core}}[8..8+\text{len}(m)] = m$.
   - **If `ArbitraryCiphertext`:**
     - $P_{\text{core}}[2] = \text{0x02}$, random $P_{\text{core}}[8..]$ serves as nonce salt,
     - $\text{nonce}_{24} = \text{HKDF}(K_{\text{algo}}, P_{\text{core}}[8..], \text{"cubehash-aead-nonce"}, 24)$,
     - $K_{\text{msg}} = \text{HKDF}(K_{\text{algo}}, f, \text{"cubehash-aead-payload"}, 32)$,
     - `A = f || <s>_8 || <e>_8 || pk_eph` ($64$ bytes),
     - $C_{\text{wire}} = \text{AEAD}_{K_{\text{msg}}}(\text{nonce}_{24}, A, m)$.

5. **Wire Core Masking & Packet MAC:**

```math
C_{\text{256b}} = P_{\text{core}} \oplus W(K_{\text{algo}}, \text{"wire-core-mask"}, L_{\text{core}})
```

```math
M_{\text{pkt}} = \text{HMAC}\big(K_{\text{algo}},\; \text{mode\_tag} \parallel f \parallel \langle s \rangle_8 \parallel \langle e \rangle_8 \parallel pk_{\text{eph}} \parallel C_{\text{256b}} \parallel C_{\text{wire}}\big)
```

6. **ACK Authentication & Ratchet Chain Advancement:**
   After receiver decrypts cleanly and generates a brand-new X25519 keypair $(sk'_{\text{rx}}, pk'_{\text{rx}})$:

```math
K_{\text{ack}} = \text{HMAC}(K_{\text{algo}}, \text{"delivery-ack-key-v2"})
```

```math
\text{mac}_{\text{ack}} = \text{HMAC}\big(K_{\text{ack}},\; \text{"delivery-ack-v2"} \parallel f \parallel \langle s \rangle_8 \parallel pk'_{\text{rx}}\big)
```

Upon committing ACK on both peers:

```math
K_{\text{chain}} \leftarrow \text{HMAC}\big(K_{\text{chain}},\; \text{"dh-ratchet-chain-v1"} \parallel Z \parallel pk'_{\text{rx}}\big)
```

---

## 5. Non-Linear Cellular Evolution (`25` Select / `20` Consume / `1` Kill + `1` Birth)

Using the first $C = 20$ cubes from $\mathcal{Q}$, `combine_non_linear` first maps each selected cube core $X_k$ through:

```math
d_k = \text{FixedBudgetMix}(\text{HybridTriMix}, K_{\text{algo}}, \langle k \rangle_8, X_k, B), \qquad k \in \{0, \dots, C-1\}
```

and folds them using one of three configured non-linear modes (`CombiningFn`) into a 32-byte accumulator $A$:
- **`XorFoldMix`**: $A_i \leftarrow A_i \oplus (d_{k,i} \lll ((k \bmod 7) + 1))$
- **`FeistelNonLinear`**: 2-half bytewise ARX Feistel step over $L = A[0..16], R = A[16..32]$:

```math
f_i = ((R_i \boxplus d_{k,i}) \lll 3) \oplus d_{k, i+16}, \qquad L'_i = R_i, \qquad R'_i = L_i \oplus f_i
```

- **`HmacTreeCombine`**: `A <- HMAC(K_algo, A || d_k)`

followed by a final whitening pass $S_{\text{next}} = \text{FixedBudgetMix}(\text{HybridTriMix}, K_{\text{algo}}, \text{"combine-final"}, A, B)$.

Then the deterministic oldest generation slot:

```math
k_{\text{kill}} = \arg\min_{0 \le j < N} (\text{generation}_j,\; j)
```

is replaced cleanly by a brand-new `VoxelCube` seeded from $S_{\text{next}}$ at generation $s$, and the chain state advances:

```math
S_{\text{chain}} \leftarrow \text{HMAC}\big(K_{\text{algo}},\; \text{"next-main-root"} \parallel S_{\text{chain}} \parallel S_{\text{next}}\big)
```

Notice that after $N + C = 120$ committed messages in standard $N=100$ mode, **100% of original genesis cubes have died and been regenerated** cleanly across both peers.

---

## 6. Triple Modular Redundancy (TMR) Bitwise Self-Healing

Given `seal_key` $K_S$ (either $K_{\text{root}}$ for stored mesh cubes or `HMAC(K_algo, "wire-tmr" || f || <s>_8)` for incoming wire cubes), cube UID $u$, and generation $g$:

1. **Independent Shadow Mask Generation ($L = \text{core\_bytes}$):**

```math
M_A = W\big(\text{HMAC}(K_S, \text{"tmr-shadow-a"} \parallel u \parallel \langle g \rangle_8),\; \text{"mask-a"},\; L\big)
```

```math
M_B = W\big(\text{HMAC}(K_S, \text{"tmr-shadow-b"} \parallel u \parallel \langle g \rangle_8),\; \text{"mask-b"},\; L\big)
```

```math
K_{\text{spare}} = \text{HMAC}\big(K_S,\; \text{"tmr-hot-spare"} \parallel u \parallel \langle g \rangle_8\big)
```

2. **Sub-Matrix Encoding ($L_{\text{sub}} \ge 2L + 8$):**

```math
S[0..L] = C \oplus M_A, \qquad S[L..2L] = C \oplus M_B, \qquad S[2L..2L+8] = \text{HMAC}(K_{\text{spare}}, \text{"hot-spare-mac"} \parallel C)[0..8]
```

and remaining bytes ($2L+8 \dots L_{\text{sub}}$) are filled via $W(K_{\text{spare}}, u)$.

3. **Bitwise Majority Voting Recovery:**
   Unmask $A_i = S[i] \oplus M_{A,i}$ and $B_i = S[L+i] \oplus M_{B,i}$. Recover each byte:

```math
V_i = (C_i \land A_i) \lor (C_i \land B_i) \lor (A_i \land B_i)
```

   Rewrite $C_i \leftarrow V_i$, $S[i] \leftarrow V_i \oplus M_{A,i}$, $S[L+i] \leftarrow V_i \oplus M_{B,i}$, and verify:

```math
d_H\Big(S[2L..2L+8],\; \text{HMAC}(K_{\text{spare}}, \text{"hot-spare-mac"} \parallel V)[0..8]\Big) \le 2
```

   If single-bit errors corrupted at most 1 of the 3 copies per bit position (and $\le 2$ bits of the hot-spare tag), every flipped bit is healed cleanly *before* packet MAC verification runs; multi-copy divergence ($>2$ bits in the hot-spare check) returns `CubeHashError::UnrecoverableCorruption`.

---

## 7. Provably Bijective 3D Spiral Coordinates & Nibble Shuffling

### 7.1 Coordinate Bijection Over $(\mathbb{Z}_D)^3$

For epoch $e$, `derive_bijection_params` derives `seed = HMAC(K_epoch, "coord-bijection" || <e>_8)` and selects odd integers $(a_x, a_y, a_z)$ via `next_coprime` guaranteeing:

```math
\gcd(a_x, D) = \gcd(a_y, D) = \gcd(a_z, D) = 1
```

so modular inverses $a_x^{-1}, a_y^{-1}, a_z^{-1} \pmod D$ computed via the Extended Euclidean Algorithm exist uniquely. Mapping $\Phi_{e}: (\mathbb{Z}_D)^3 \to (\mathbb{Z}_D)^3$ is the composition $\Phi_e = \mathcal{F} \circ \mathcal{A}$:

- **Layer 1 ($\mathcal{A}$ — Modular Affine):**

```math
x_1 \equiv a_x x + b_x \pmod D, \qquad y_1 \equiv a_y y + b_y \pmod D, \qquad z_1 \equiv a_z z + b_z \pmod D
```

- **Layer 2 ($\mathcal{F}$ — Triangular Keyed Feistel):**

```math
x_2 \equiv x_1 + F_1(y_1, z_1) \pmod D
```

```math
y_2 \equiv y_1 + F_2(x_2, z_1) \pmod D
```

```math
z_2 \equiv z_1 + F_3(x_2, y_2) \pmod D
```

where $F_t(u, v) = \text{HMAC}(\text{seed}, t \parallel u_{\text{LE32}} \parallel v_{\text{LE32}})[0..8]_{\text{LE64}} \bmod D$.

**Proof of Bijectivity (Exact Inverse $\Phi_e^{-1} = \mathcal{A}^{-1} \circ \mathcal{F}^{-1}$):**
Because each coordinate addition in $\mathcal{F}$ depends strictly on components already resolved downstream:

```math
z_1 \equiv z_2 - F_3(x_2, y_2) \pmod D
```

```math
y_1 \equiv y_2 - F_2(x_2, z_1) \pmod D
```

```math
x_1 \equiv x_2 - F_1(y_1, z_1) \pmod D
```

```math
x \equiv a_x^{-1}(x_1 - b_x) \pmod D, \qquad y \equiv a_y^{-1}(y_1 - b_y) \pmod D, \qquad z \equiv a_z^{-1}(z_1 - b_z) \pmod D
```

Therefore $\Phi_e$ is a **provable permutation on $(\mathbb{Z}_D)^3$ with zero collisions** (`unhop_coord_bijective(hop_coord_bijective(c)) == c` for every $c \in [0, D)^3$).

### 7.2 Bijective 250-Nibble Permutation & $O(W \cdot K)$ Window Search

Every 4-bit nibble ($2 L_{\text{sub}} = 250$ nibbles in `standard`) is permuted via deterministic Fisher–Yates seeded by $W(K_{\text{epoch}}, \langle e \rangle_8, 8 L_{\text{sub}})$. Coordinate discovery `search_spiral_window` scans only $W = \text{spiral\_window}$ (`16`) slots starting from a predicted arm offset rather than $D^3 = 10^9$ or all $N$ mesh slots.

---

## 8. Zero-Oracle Constant-Work Execution & DTE Honey Encryption

In `decrypt_zero_oracle`:
1. Instead of returning early on bad hardware ID, unseal error, sequence/epoch mismatch, invalid dimensions, non-contributory DH key, TMR corruption, packet MAC mismatch, or AEAD failure, every check folds a `0` or `1` bit into `authentic_mask: u8`.
2. **Always** evaluates TMR repair, MAC computation, AEAD decryption, `build_transition`, key generation, **and** decoy DTE synthesis over the decoy mesh (`generate_decoy_cubes`).
3. Only if `authentic_mask == 1 && transition_res.is_ok()` does it advance `local_monotonic_tick`, commit the cellular/ratchet transition, and return `ReceiveOutcome::Authentic`. Otherwise **zero** state fields are mutated and `ReceiveOutcome::HoneyDeception` returns `DteEngine::synthesize_honey_output` generated deterministically from the decoy cubes + wire probe material:
   - `Bip39ChecksumPhrase`: selects $11$ word indices from a 256-word vocabulary using bytes `seed[0..11]` and computes the 12th checksum word as `HONEY_WORDS[SHA256(seed[0..11])[0]]` — indistinguishable in structural validity from a real wallet recovery phrase.
   - `ChatPlaintext`: synthesizes natural English conversational messages (`opener + topic + tag`).
   - `RawUniform { len }`: emits $W(\text{seed}, \text{"dte-raw-uniform"}, \text{len})$.
