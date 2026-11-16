# Formal Mathematical & Cryptographic Specification

This specification documents the exact mathematical constructions, key schedules, algebraic transformations, and bounds implemented in `crates/cubehash-core`.

---

## 1. Notation & Primitives

| Symbol | Implementation | Description |
| --- | --- | --- |
| $\text{HMAC}(K, X)$ | `hmac_sha256_parts(K, &[...])` | HMAC-SHA-256 returning $256$-bit ($32$-byte) digest. |
| $\text{HKDF}(IKM, S, I, L)$ | `hkdf_expand_label(ikm, salt, info, out)` | HKDF-SHA-256 extract-and-expand producing $L$ bytes. |
| $W(S, \text{dom}, L)$ | `whitened_stream(seed, domain, out)` | Counter-mode BLAKE2b-512 stream: block $i = \text{BLAKE2b-512}(S \| \text{dom} \| i_{\text{LE64}})$. |
| $\text{X25519}(sk, pk)$ | `dh_exchange` | Curve25519 ECDH rejecting non-contributory / low-order outputs (`!shared.was_contributory()`). |
| $\text{AEAD}_{K}(N, A, P)$ | `aead_seal` / `aead_open` | XChaCha20 stream cipher + Poly1305 MAC ($24$-byte nonce, $16$-byte tag). |
| $d_H(X, Y)$ | `(x ^ y).count_ones()` sum | Bitwise Hamming distance between equal-length byte arrays. |
| $\langle n \rangle_8$ | `n.to_le_bytes()` | 64-bit unsigned little-endian encoding of $n$. |

---

## 2. Tripartite Custody & Hardware Execution Guard

### 2.1 Root Capability Synthesis

Given `MotherCube` $(K_{\text{mother}}, S_{\text{owner}})$, `MainCube` $(\text{cid}, P_{\text{main}}, S_{\text{chain}})$, and `AuditorCube` $(K_{\text{auditor}}, S_{\text{synth}}, \text{Algo}, \text{Comb}, \vec{c}, Q, C)$:

$$K_M = \text{HMAC}\big(K_{\text{mother}},\; \text{"3cube-root"} \| S_{\text{owner}} \| \text{cid}\big)$$

$$K_{\text{root}} = \text{FixedBudgetMix}\Big(\text{Algo},\; K_M,\; \text{"three-cube-custody"},\; P_{\text{main}} \| S_{\text{synth}} \| K_{\text{auditor}},\; B\Big)$$

where $B = \text{fixed\_step\_budget}$ (`4` in `standard` config). Any strict 2-of-3 subset omits either $K_{\text{mother}}$, $P_{\text{main}}$, or $K_{\text{auditor}}$ and yields an indistinguishable unrelated $256$-bit string.

### 2.2 Hardware Enclave Lock & Monotonic Capability

On device initialization, `LocalClientClockGuard` seals $r \leftarrow \{0,1\}^{256}$ onto hardware $\mathcal{H}$:

$$S_{\mathcal{H}} = \text{Seal}_{\mathcal{H}}(\text{"cubehash-local-clock-guard-v1"}, r), \qquad \tau \leftarrow 0$$

For every state-mutating operation, caller must provide matching hardware identity $\text{hw\_id}_{\text{obs}} = \text{hw\_id}_{\text{guard}}$ (constant-time equality), successfully unseal $r = \text{Unseal}_{\mathcal{H}}(S_{\mathcal{H}})$, advance $\tau \leftarrow \tau + 1$ strictly monotonically, and obtain capability token:

$$T_{\tau} = \text{HMAC}(r,\; \text{hw\_id} \| \langle \tau \rangle_8)$$

### 2.3 Hardware Loss Recovery Derivation

When re-provisioning onto replacement hardware $\mathcal{H}'$ using `ThreeCubeCustody`:

$$r' = \text{HMAC}(K_{\text{root}},\; \text{"recover-hw-secret"} \| \text{hw\_id}_{\mathcal{H}'})$$

and `LocalClientClockGuard` is re-sealed under $\mathcal{H}'$, permanently revoking execution under the original device.

---

## 3. Constant-Work Multi-Hash Core (`fixed_budget_mix`)

To eliminate timing variance between chosen digest algorithms (`TimeAlgorithm`), every call executes **all three independent legs** for $B \ge 1$ sequential rounds starting from zeroized accumulators $S_{\text{BLAKE}} = S_{\text{SHA3}} = S_{\text{HMAC}} = 0^{256}$:

For round $r \in \{0, \dots, B-1\}$:

$$S_{\text{BLAKE}} \leftarrow \text{BLAKE2b-512}\big(K \| \text{dom} \| \langle r \rangle_8 \| S_{\text{BLAKE}} \| X\big)[0..32]$$

$$S_{\text{SHA3}} \leftarrow \text{SHA3-256}\big(K \| \text{dom} \| \langle r \rangle_8 \| S_{\text{SHA3}} \| X\big)$$

$$S_{\text{HMAC}} \leftarrow \text{HMAC}\big(K,\; \text{dom} \| \langle r \rangle_8 \| S_{\text{HMAC}} \| X\big)$$

Then the hybrid leg combines bit-rotations byte-wise:

$$H_i = S_{\text{BLAKE}, i} \oplus (S_{\text{SHA3}, i} \lll 3) \oplus (S_{\text{HMAC}, i} \ggg 5) \quad \forall i \in \{0, \dots, 31\}$$

Finally, the configured target algorithm digest is selected **without secret-dependent branches** using `subtle::ConditionallySelectable` masks across $(S_{\text{BLAKE}}, S_{\text{SHA3}}, S_{\text{HMAC}}, H)$.

---

## 4. Per-Message Key Schedule, X25519 DH Ratchet & Ephemeral Quorum

Let `(sk_eph, pk_eph)` be a freshly generated CSPRNG X25519 keypair for outgoing sequence $s = \text{seq} + 1$ at epoch $e$, with random 16-byte `cube_fingerprint` $f \leftarrow \{0,1\}^{128}$:

1. **DH Exchange & Ratcheted Root:**
   $$Z = \text{X25519}(sk_{\text{eph}}, pk_{\text{peer}}) \quad (\text{abort if non-contributory})$$
   $$K_{\text{ratchet}} = \text{HMAC}\big(K_{\text{root}},\; \text{"dh-ratchet-root-v1"} \| K_{\text{chain}} \| Z\big)$$

2. **Keyed Quorum Selection ($Q$ of $N$ cubes):**
   $$S_{\text{sel}} = \text{HMAC}\big(K_{\text{ratchet}},\; \text{"quorum-select"} \| S_{\text{synth}} \| f \| \langle s \rangle_8 \| \langle e \rangle_8\big)$$
   A Fisher–Yates shuffle driven by $W(S_{\text{sel}}, \text{"quorum-perm"}, 4N)$ selects $Q$ distinct cube indices $\mathcal{Q} = (\pi(0), \dots, \pi(Q-1))$ (in `standard`: $Q = 25$ out of $N = 100$).

3. **Ephemeral Algorithm Synthesis ($K_{\text{algo}}$):**
   $$\mathcal{M}_{\mathcal{Q}} = f \| \langle s \rangle_8 \| \langle e \rangle_8 \| S_{\text{chain}} \| \big\|_{i \in \mathcal{Q}} \text{core\_pattern}_i$$
   $$K_{\text{algo}} = \text{FixedBudgetMix}\big(\text{Algo},\; K_{\text{ratchet}},\; \text{"ephemeral-algo-synthesis"},\; \mathcal{M}_{\mathcal{Q}},\; B\big)$$

4. **Dual-Mode Wire Payload Derivation:**
   Let $P_{\text{core}} \leftarrow \{0,1\}^{8L_{\text{core}}}$ ($L_{\text{core}} = 32$ bytes standard).
   - **If `RawCore256` ($\text{len}(m) \le L_{\text{core}} - 8$):**
     - $P_{\text{core}}[0..2] = \text{len}(m)_{\text{LE16}}$, $P_{\text{core}}[2] = \text{0x01}$,
     - $P_{\text{core}}[3..8] = \text{HMAC}(K_{\text{algo}}, \text{"raw-core-tag"} \| \langle s \rangle_8)[0..5]$,
     - $P_{\text{core}}[8..8+\text{len}(m)] = m$.
   - **If `ArbitraryCiphertext`:**
     - $P_{\text{core}}[2] = \text{0x02}$, random $P_{\text{core}}[8..]$ serves as nonce salt,
     - $\text{nonce}_{24} = \text{HKDF}(K_{\text{algo}}, P_{\text{core}}[8..], \text{"cubehash-aead-nonce"}, 24)$,
     - $K_{\text{msg}} = \text{HKDF}(K_{\text{algo}}, f, \text{"cubehash-aead-payload"}, 32)$,
     - $A = f \| \langle s \rangle_8 \| \langle e \rangle_8 \| pk_{\text{eph}} \in \{0,1\}^{512}$,
     - $C_{\text{wire}} = \text{AEAD}_{K_{\text{msg}}}(\text{nonce}_{24}, A, m)$.

5. **Wire Core Masking & Packet MAC:**
   $$C_{\text{256b}} = P_{\text{core}} \oplus W(K_{\text{algo}}, \text{"wire-core-mask"}, L_{\text{core}})$$
   $$M_{\text{pkt}} = \text{HMAC}\big(K_{\text{algo}},\; \text{mode\_tag} \| f \| \langle s \rangle_8 \| \langle e \rangle_8 \| pk_{\text{eph}} \| C_{\text{256b}} \| C_{\text{wire}}\big)$$

6. **ACK Authentication & Ratchet Chain Advancement:**
   After receiver decrypts cleanly and generates a brand-new X25519 keypair $(sk'_{\text{rx}}, pk'_{\text{rx}})$:
   $$K_{\text{ack}} = \text{HMAC}(K_{\text{algo}}, \text{"delivery-ack-key-v2"})$$
   $$\text{mac}_{\text{ack}} = \text{HMAC}(K_{\text{ack}},\; \text{"delivery-ack-v2"} \| f \| \langle s \rangle_8 \| pk'_{\text{rx}})$$
   Upon committing ACK on both peers:
   $$K_{\text{chain}} \leftarrow \text{HMAC}\big(K_{\text{chain}},\; \text{"dh-ratchet-chain-v1"} \| Z \| pk'_{\text{rx}}\big)$$

---

## 5. Non-Linear Cellular Evolution (`25` Select / `20` Consume / `1` Kill + `1` Birth)

Using the first $C = 20$ cubes from $\mathcal{Q}$, `combine_non_linear` first maps each selected cube core $X_k$ through:

$$d_k = \text{FixedBudgetMix}(\text{HybridTriMix}, K_{\text{algo}}, \langle k \rangle_8, X_k, B), \qquad k \in \{0, \dots, C-1\}$$

and folds them using one of three configured non-linear modes (`CombiningFn`) into a 32-byte accumulator $A$:
- **`XorFoldMix`**: $A_i \leftarrow A_i \oplus (d_{k,i} \lll ((k \bmod 7) + 1))$
- **`FeistelNonLinear`**: 2-half bytewise ARX Feistel step over $L = A[0..16], R = A[16..32]$:
  $$f_i = ((R_i \boxplus d_{k,i}) \lll 3) \oplus d_{k, i+16}, \quad L'_i = R_i, \quad R'_i = L_i \oplus f_i$$
- **`HmacTreeCombine`**: $A \leftarrow \text{HMAC}(K_{\text{algo}}, A \| d_k)$

followed by a final whitening pass $S_{\text{next}} = \text{FixedBudgetMix}(\text{HybridTriMix}, K_{\text{algo}}, \text{"combine-final"}, A, B)$.

Then the deterministic oldest generation slot:

$$k_{\text{kill}} = \arg\min_{0 \le j < N} (\text{generation}_j,\; j)$$

is replaced cleanly by a brand-new `VoxelCube` seeded from $S_{\text{next}}$ at generation $s$, and the chain state advances:

$$S_{\text{chain}} \leftarrow \text{HMAC}\big(K_{\text{algo}},\; \text{"next-main-root"} \| S_{\text{chain}} \| S_{\text{next}}\big)$$

Notice that after $N + C = 120$ committed messages in standard $N=100$ mode, **100% of original genesis cubes have died and been regenerated** cleanly across both peers.

---

## 6. Triple Modular Redundancy (TMR) Bitwise Self-Healing

Given `seal_key` $K_S$ (either $K_{\text{root}}$ for stored mesh cubes or $\text{HMAC}(K_{\text{algo}}, \text{"wire-tmr"} \| f \| \langle s \rangle_8)$ for incoming wire cubes), cube UID $u$, and generation $g$:

1. **Independent Shadow Mask Generation ($L = \text{core\_bytes}$):**
   $$M_A = W(\text{HMAC}(K_S, \text{"tmr-shadow-a"} \| u \| \langle g \rangle_8), \text{"mask-a"}, L)$$
   $$M_B = W(\text{HMAC}(K_S, \text{"tmr-shadow-b"} \| u \| \langle g \rangle_8), \text{"mask-b"}, L)$$
   $$K_{\text{spare}} = \text{HMAC}(K_S, \text{"tmr-hot-spare"} \| u \| \langle g \rangle_8)$$

2. **Sub-Matrix Encoding ($L_{\text{sub}} \ge 2L + 8$):**
   $$S[0..L] = C \oplus M_A, \qquad S[L..2L] = C \oplus M_B, \qquad S[2L..2L+8] = \text{HMAC}(K_{\text{spare}}, \text{"hot-spare-mac"} \| C)[0..8]$$
   and remaining bytes ($2L+8 \dots L_{\text{sub}}$) are filled via $W(K_{\text{spare}}, u)$.

3. **Bitwise Majority Voting Recovery:**
   Unmask $A_i = S[i] \oplus M_{A,i}$ and $B_i = S[L+i] \oplus M_{B,i}$. Recover each byte:
   $$V_i = (C_i \land A_i) \lor (C_i \land B_i) \lor (A_i \land B_i)$$
   Rewrite $C_i \leftarrow V_i$, $S[i] \leftarrow V_i \oplus M_{A,i}$, $S[L+i] \leftarrow V_i \oplus M_{B,i}$, and verify:
   $$d_H\Big(S[2L..2L+8],\; \text{HMAC}(K_{\text{spare}}, \text{"hot-spare-mac"} \| V)[0..8]\Big) \le 2$$
   If single-bit errors corrupted at most 1 of the 3 copies per bit position (and $\le 2$ bits of the hot-spare tag), every flipped bit is healed cleanly *before* packet MAC verification runs; multi-copy divergence ($>2$ bits in the hot-spare check) returns `CubeHashError::UnrecoverableCorruption`.

---

## 7. Provably Bijective 3D Spiral Coordinates & Nibble Shuffling

### 7.1 Coordinate Bijection Over $(\mathbb{Z}_D)^3$

For epoch $e$, `derive_bijection_params` derives $\text{seed} = \text{HMAC}(K_{\text{epoch}}, \text{"coord-bijection"} \| \langle e \rangle_8)$ and selects odd integers $(a_x, a_y, a_z)$ via `next_coprime` guaranteeing:

$$\gcd(a_x, D) = \gcd(a_y, D) = \gcd(a_z, D) = 1$$

so modular inverses $a_x^{-1}, a_y^{-1}, a_z^{-1} \pmod D$ computed via the Extended Euclidean Algorithm exist uniquely. Mapping $\Phi_{e}: (\mathbb{Z}_D)^3 \to (\mathbb{Z}_D)^3$ is the composition $\Phi_e = \mathcal{F} \circ \mathcal{A}$:

- **Layer 1 ($\mathcal{A}$ — Modular Affine):**
  $$x_1 \equiv a_x x + b_x \pmod D, \quad y_1 \equiv a_y y + b_y \pmod D, \quad z_1 \equiv a_z z + b_z \pmod D$$
- **Layer 2 ($\mathcal{F}$ — Triangular Keyed Feistel):**
  $$x_2 \equiv x_1 + F_1(y_1, z_1) \pmod D$$
  $$y_2 \equiv y_1 + F_2(x_2, z_1) \pmod D$$
  $$z_2 \equiv z_1 + F_3(x_2, y_2) \pmod D$$
  where $F_t(u, v) = \text{HMAC}(\text{seed}, t \| u_{\text{LE32}} \| v_{\text{LE32}})[0..8]_{\text{LE64}} \bmod D$.

**Proof of Bijectivity (Exact Inverse $\Phi_e^{-1} = \mathcal{A}^{-1} \circ \mathcal{F}^{-1}$):**
Because each coordinate addition in $\mathcal{F}$ depends strictly on components already resolved downstream:

$$z_1 \equiv z_2 - F_3(x_2, y_2) \pmod D$$
$$y_1 \equiv y_2 - F_2(x_2, z_1) \pmod D$$
$$x_1 \equiv x_2 - F_1(y_1, z_1) \pmod D$$
$$x \equiv a_x^{-1}(x_1 - b_x) \pmod D, \quad y \equiv a_y^{-1}(y_1 - b_y) \pmod D, \quad z \equiv a_z^{-1}(z_1 - b_z) \pmod D$$

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
