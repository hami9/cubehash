#![allow(clippy::missing_safety_doc, clippy::too_many_arguments)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use cubehash_core::{
    build_custody_bundle, primitives::hmac_sha256_parts, AuditorCube, CellularMesh, CombiningFn,
    CubeHashError, DeliveryAck, HoneyProfile, MainCube, MeshConfig, MotherCube, ReceiveOutcome,
    TimeAlgorithm, VirtualHardwareEnclave, WirePacket,
};
use zeroize::Zeroize;

pub const CUBEHASH_OK: i32 = 0;
pub const CUBEHASH_ERR_NULL_PTR: i32 = -1;
pub const CUBEHASH_ERR_INVALID_CONFIG: i32 = -2;
pub const CUBEHASH_ERR_UNAUTHORIZED_HW: i32 = -3;
pub const CUBEHASH_ERR_REPLAY: i32 = -4;
pub const CUBEHASH_ERR_CORRUPTED: i32 = -5;
pub const CUBEHASH_ERR_AUTH_FAILED: i32 = -6;
pub const CUBEHASH_ERR_PENDING_TX: i32 = -7;
pub const CUBEHASH_ERR_NO_PENDING_TX: i32 = -8;
pub const CUBEHASH_ERR_ACK_MISMATCH: i32 = -9;
pub const CUBEHASH_ERR_PAYLOAD_TOO_LARGE: i32 = -10;
pub const CUBEHASH_ERR_INTERNAL: i32 = -11;

pub const CUBEHASH_OUTCOME_AUTHENTIC: i32 = 1;
pub const CUBEHASH_OUTCOME_HONEY: i32 = 2;

/// Opaque configuration handle exposed across C-ABI.
pub struct CubeConfigHandle(MeshConfig);

/// Opaque session handle binding a `CellularMesh` to its device hardware enclave.
pub struct CubeSessionHandle {
    mesh: CellularMesh,
    hw: VirtualHardwareEnclave,
}

/// Heap-allocated buffer passed across C-ABI; callers must release via [`cubehash_buffer_free`].
#[repr(C)]
pub struct CubeBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl CubeBuffer {
    fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }

    fn from_vec(v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self::empty();
        }
        let mut boxed = v.into_boxed_slice();
        let len = boxed.len();
        let ptr = boxed.as_mut_ptr();
        std::mem::forget(boxed);
        Self { ptr, len }
    }
}

fn map_error(err: CubeHashError) -> i32 {
    match err {
        CubeHashError::InvalidConfig(_) => CUBEHASH_ERR_INVALID_CONFIG,
        CubeHashError::UnauthorizedHardware => CUBEHASH_ERR_UNAUTHORIZED_HW,
        CubeHashError::ClockRollbackDetected | CubeHashError::ReplayDetected => CUBEHASH_ERR_REPLAY,
        CubeHashError::UnrecoverableCorruption => CUBEHASH_ERR_CORRUPTED,
        CubeHashError::AuthenticationFailed => CUBEHASH_ERR_AUTH_FAILED,
        CubeHashError::PendingTransactionExists => CUBEHASH_ERR_PENDING_TX,
        CubeHashError::NoPendingTransaction => CUBEHASH_ERR_NO_PENDING_TX,
        CubeHashError::AckMismatch => CUBEHASH_ERR_ACK_MISMATCH,
        CubeHashError::PayloadTooLargeForCore { .. } => CUBEHASH_ERR_PAYLOAD_TOO_LARGE,
        CubeHashError::CryptoFailure(_) | CubeHashError::RngFailure => CUBEHASH_ERR_INTERNAL,
    }
}

unsafe fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(CUBEHASH_ERR_NULL_PTR);
    }
    Ok(slice::from_raw_parts(ptr, len))
}

fn ffi_guard<F>(f: F) -> i32
where
    F: FnOnce() -> i32,
{
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(CUBEHASH_ERR_INTERNAL)
}

#[no_mangle]
pub extern "C" fn cubehash_config_standard() -> *mut CubeConfigHandle {
    Box::into_raw(Box::new(CubeConfigHandle(MeshConfig::standard())))
}

#[no_mangle]
pub extern "C" fn cubehash_config_compact() -> *mut CubeConfigHandle {
    Box::into_raw(Box::new(CubeConfigHandle(MeshConfig::compact())))
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_config_custom(
    sub_matrix_bytes: usize,
    core_bytes: usize,
    weight_min_bytes: usize,
    weight_max_bytes: usize,
    mesh_size: usize,
    quorum_select: usize,
    consume_for_next: usize,
    space_dim: u32,
    out_err: *mut i32,
) -> *mut CubeConfigHandle {
    let mut cfg = MeshConfig::standard();
    cfg.sub_matrix_bytes = sub_matrix_bytes;
    cfg.core_bytes = core_bytes;
    cfg.weight_min_bytes = weight_min_bytes;
    cfg.weight_max_bytes = weight_max_bytes;
    cfg.mesh_size = mesh_size;
    cfg.quorum_select = quorum_select;
    cfg.consume_for_next = consume_for_next;
    cfg.space_dim = space_dim;

    match cfg.validate() {
        Ok(()) => {
            if !out_err.is_null() {
                *out_err = CUBEHASH_OK;
            }
            Box::into_raw(Box::new(CubeConfigHandle(cfg)))
        }
        Err(e) => {
            if !out_err.is_null() {
                *out_err = map_error(e);
            }
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_config_free(cfg: *mut CubeConfigHandle) {
    if !cfg.is_null() {
        drop(Box::from_raw(cfg));
    }
}

/// Provisions a synchronized peer `CubeSessionHandle` deterministically from a shared 32-byte
/// session seed (exchanged during initial key setup) and this device's local `(hw_id_16, hw_key_32)`.
#[no_mangle]
pub unsafe extern "C" fn cubehash_provision_device(
    cfg: *const CubeConfigHandle,
    shared_seed_32: *const u8,
    hw_id_16: *const u8,
    hw_key_32: *const u8,
    out_session: *mut *mut CubeSessionHandle,
) -> i32 {
    ffi_guard(|| {
        if cfg.is_null()
            || shared_seed_32.is_null()
            || hw_id_16.is_null()
            || hw_key_32.is_null()
            || out_session.is_null()
        {
            return CUBEHASH_ERR_NULL_PTR;
        }
        let config = (&*cfg).0.clone();
        let seed_slice = slice::from_raw_parts(shared_seed_32, 32);
        let hw_id: [u8; 16] = slice::from_raw_parts(hw_id_16, 16).try_into().unwrap();
        let hw_key: [u8; 32] = slice::from_raw_parts(hw_key_32, 32).try_into().unwrap();

        let mother_secret = hmac_sha256_parts(seed_slice, &[b"ffi-mother-secret"]);
        let owner_salt: [u8; 16] = hmac_sha256_parts(seed_slice, &[b"ffi-owner-salt"])[..16]
            .try_into()
            .unwrap();
        let chain_id: [u8; 16] = hmac_sha256_parts(seed_slice, &[b"ffi-chain-id"])[..16]
            .try_into()
            .unwrap();
        let root_pattern = hmac_sha256_parts(seed_slice, &[b"ffi-root-pattern"]);
        let auditor_secret = hmac_sha256_parts(seed_slice, &[b"ffi-auditor-secret"]);
        let synthesis_salt: [u8; 16] = hmac_sha256_parts(seed_slice, &[b"ffi-synthesis-salt"])
            [..16]
            .try_into()
            .unwrap();
        let mesh_seed = hmac_sha256_parts(seed_slice, &[b"ffi-mesh-seed"]);

        let custody = build_custody_bundle(
            MotherCube::from_custody_bytes(mother_secret, owner_salt),
            MainCube::from_parts(chain_id, root_pattern, 0),
            AuditorCube::from_parts(
                auditor_secret,
                synthesis_salt,
                TimeAlgorithm::HybridTriMix,
                CombiningFn::FeistelNonLinear,
                [19, 37, 61],
                config.quorum_select,
                config.consume_for_next,
            ),
        );

        let hw = VirtualHardwareEnclave::new(hw_id, hw_key);
        match CellularMesh::provision_device(config, custody, &hw, &mesh_seed) {
            Ok(mesh) => {
                *out_session = Box::into_raw(Box::new(CubeSessionHandle { mesh, hw }));
                CUBEHASH_OK
            }
            Err(e) => map_error(e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_send_raw_core(
    session: *mut CubeSessionHandle,
    payload: *const u8,
    payload_len: usize,
    out_packet_json: *mut CubeBuffer,
) -> i32 {
    send_inner(session, payload, payload_len, out_packet_json, true)
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_send_message(
    session: *mut CubeSessionHandle,
    plaintext: *const u8,
    plaintext_len: usize,
    out_packet_json: *mut CubeBuffer,
) -> i32 {
    send_inner(session, plaintext, plaintext_len, out_packet_json, false)
}

unsafe fn send_inner(
    session: *mut CubeSessionHandle,
    data: *const u8,
    len: usize,
    out_packet_json: *mut CubeBuffer,
    raw_core: bool,
) -> i32 {
    ffi_guard(|| {
        if session.is_null() || out_packet_json.is_null() {
            return CUBEHASH_ERR_NULL_PTR;
        }
        let slice = match slice_from_raw(data, len) {
            Ok(s) => s,
            Err(code) => return code,
        };
        let handle = &mut *session;
        let res = if raw_core {
            handle.mesh.begin_send_raw_core(&handle.hw, slice)
        } else {
            handle.mesh.begin_send_message(&handle.hw, slice)
        };
        match res {
            Ok(pkt) => match serde_json::to_vec(&pkt) {
                Ok(bytes) => {
                    *out_packet_json = CubeBuffer::from_vec(bytes);
                    CUBEHASH_OK
                }
                Err(_) => CUBEHASH_ERR_INTERNAL,
            },
            Err(e) => map_error(e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_receive_authenticated(
    session: *mut CubeSessionHandle,
    packet_json: *const u8,
    packet_len: usize,
    out_plaintext: *mut CubeBuffer,
    out_ack_json: *mut CubeBuffer,
    out_healed_bits: *mut usize,
) -> i32 {
    ffi_guard(|| {
        if session.is_null() || out_plaintext.is_null() || out_ack_json.is_null() {
            return CUBEHASH_ERR_NULL_PTR;
        }
        let pkt_bytes = match slice_from_raw(packet_json, packet_len) {
            Ok(s) => s,
            Err(code) => return code,
        };
        let mut pkt: WirePacket = match serde_json::from_slice(pkt_bytes) {
            Ok(p) => p,
            Err(_) => return CUBEHASH_ERR_AUTH_FAILED,
        };
        let handle = &mut *session;
        match handle.mesh.receive_authenticated(&handle.hw, &mut pkt) {
            Ok((pt, ack, healed)) => {
                let ack_bytes = match serde_json::to_vec(&ack) {
                    Ok(b) => b,
                    Err(_) => return CUBEHASH_ERR_INTERNAL,
                };
                *out_plaintext = CubeBuffer::from_vec(pt);
                *out_ack_json = CubeBuffer::from_vec(ack_bytes);
                if !out_healed_bits.is_null() {
                    *out_healed_bits = healed;
                }
                CUBEHASH_OK
            }
            Err(e) => map_error(e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_receive_zero_oracle(
    session: *mut CubeSessionHandle,
    packet_json: *const u8,
    packet_len: usize,
    honey_profile_tag: u8,
    out_data: *mut CubeBuffer,
    out_ack_json: *mut CubeBuffer,
    out_outcome_tag: *mut i32,
) -> i32 {
    ffi_guard(|| {
        if session.is_null()
            || out_data.is_null()
            || out_ack_json.is_null()
            || out_outcome_tag.is_null()
        {
            return CUBEHASH_ERR_NULL_PTR;
        }
        let pkt_bytes = match slice_from_raw(packet_json, packet_len) {
            Ok(s) => s,
            Err(code) => return code,
        };
        let profile = match honey_profile_tag {
            0 => HoneyProfile::Bip39ChecksumPhrase,
            1 => HoneyProfile::ChatPlaintext,
            _ => HoneyProfile::RawUniform { len: 32 },
        };
        let pkt: WirePacket = match serde_json::from_slice(pkt_bytes) {
            Ok(p) => p,
            Err(_) => {
                // Malformed JSON still receives Honey deception without error oracle!
                let handle = &*session;
                let fake = cubehash_core::DteEngine::synthesize_honey_output(
                    handle.mesh.config(),
                    profile,
                    pkt_bytes,
                    handle.mesh.decoys(),
                );
                *out_data = CubeBuffer::from_vec(fake);
                *out_ack_json = CubeBuffer::empty();
                *out_outcome_tag = CUBEHASH_OUTCOME_HONEY;
                return CUBEHASH_OK;
            }
        };

        let handle = &mut *session;
        match handle.mesh.decrypt_zero_oracle(&handle.hw, &pkt, profile) {
            ReceiveOutcome::Authentic { plaintext, ack, .. } => {
                let ack_bytes = match serde_json::to_vec(&ack) {
                    Ok(b) => b,
                    Err(_) => return CUBEHASH_ERR_INTERNAL,
                };
                *out_data = CubeBuffer::from_vec(plaintext);
                *out_ack_json = CubeBuffer::from_vec(ack_bytes);
                *out_outcome_tag = CUBEHASH_OUTCOME_AUTHENTIC;
                CUBEHASH_OK
            }
            ReceiveOutcome::HoneyDeception {
                plausible_output, ..
            } => {
                *out_data = CubeBuffer::from_vec(plausible_output);
                *out_ack_json = CubeBuffer::empty();
                *out_outcome_tag = CUBEHASH_OUTCOME_HONEY;
                CUBEHASH_OK
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_commit_ack(
    session: *mut CubeSessionHandle,
    ack_json: *const u8,
    ack_len: usize,
) -> i32 {
    ffi_guard(|| {
        if session.is_null() {
            return CUBEHASH_ERR_NULL_PTR;
        }
        let bytes = match slice_from_raw(ack_json, ack_len) {
            Ok(s) => s,
            Err(code) => return code,
        };
        let ack: DeliveryAck = match serde_json::from_slice(bytes) {
            Ok(a) => a,
            Err(_) => return CUBEHASH_ERR_ACK_MISMATCH,
        };
        let handle = &mut *session;
        match handle.mesh.commit_ack(&handle.hw, &ack) {
            Ok(()) => CUBEHASH_OK,
            Err(e) => map_error(e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_rollback_outbound(session: *mut CubeSessionHandle) -> i32 {
    ffi_guard(|| {
        if session.is_null() {
            return CUBEHASH_ERR_NULL_PTR;
        }
        let handle = &mut *session;
        match handle.mesh.rollback_outbound() {
            Ok(()) => CUBEHASH_OK,
            Err(e) => map_error(e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_hop_epoch(
    session: *mut CubeSessionHandle,
    out_epoch: *mut u64,
) -> i32 {
    ffi_guard(|| {
        if session.is_null() {
            return CUBEHASH_ERR_NULL_PTR;
        }
        let handle = &mut *session;
        match handle.mesh.hop_epoch(&handle.hw) {
            Ok(epoch) => {
                if !out_epoch.is_null() {
                    *out_epoch = epoch;
                }
                CUBEHASH_OK
            }
            Err(e) => map_error(e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_audit_stats_json(
    session: *const CubeSessionHandle,
    out_stats_json: *mut CubeBuffer,
) -> i32 {
    ffi_guard(|| {
        if session.is_null() || out_stats_json.is_null() {
            return CUBEHASH_ERR_NULL_PTR;
        }
        let handle = &*session;
        match serde_json::to_vec(&handle.mesh.audit_stats()) {
            Ok(bytes) => {
                *out_stats_json = CubeBuffer::from_vec(bytes);
                CUBEHASH_OK
            }
            Err(_) => CUBEHASH_ERR_INTERNAL,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_buffer_free(buf: CubeBuffer) {
    if !buf.ptr.is_null() && buf.len > 0 {
        let mut boxed = Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf.ptr, buf.len));
        boxed.zeroize();
        drop(boxed);
    }
}

#[no_mangle]
pub unsafe extern "C" fn cubehash_session_free(session: *mut CubeSessionHandle) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}
