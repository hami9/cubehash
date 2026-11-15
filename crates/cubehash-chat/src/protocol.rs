use cubehash_core::primitives::{hkdf_expand_label, hmac_sha256_parts};
use cubehash_core::{
    build_custody_bundle, AuditorCube, CellularMesh, CombiningFn, DeliveryAck, DuplexCubeSession,
    HardwareProvider, MainCube, MeshConfig, MotherCube, Result, ThreeCubeCustody, TimeAlgorithm,
    WirePacket,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Supported `MeshConfig` sizing profiles selectable per chat session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatMeshProfile {
    Compact,
    Standard,
    HighCapacity,
}

impl ChatMeshProfile {
    pub fn to_config(self) -> MeshConfig {
        match self {
            Self::Compact => MeshConfig::compact(),
            Self::Standard => MeshConfig::standard(),
            Self::HighCapacity => MeshConfig::high_capacity(),
        }
    }

    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "compact" => Self::Compact,
            "high" | "high_capacity" => Self::HighCapacity,
            _ => Self::Standard,
        }
    }
}

/// Frames routed transparently by the blind relay server.
///
/// The relay reads only routing headers (`from`, `to`, `pair_id`, `msg_id`) and never holds
/// any CubeHash keys, `MotherCube` material, or plaintext payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayFrame {
    Register {
        client_id: String,
    },
    Registered {
        client_id: String,
        online_peers: Vec<String>,
    },
    PeerList {
        online_peers: Vec<String>,
    },
    PairOffer {
        from: String,
        to: String,
        pair_id: String,
        eph_pub: [u8; 32],
        profile: ChatMeshProfile,
        has_psk: bool,
    },
    PairAccept {
        from: String,
        to: String,
        pair_id: String,
        eph_pub: [u8; 32],
    },
    EncryptedPacket {
        from: String,
        to: String,
        msg_id: String,
        packet: WirePacket,
    },
    AckFrame {
        from: String,
        to: String,
        msg_id: String,
        ack: DeliveryAck,
    },
    EpochHopNotice {
        from: String,
        to: String,
        new_epoch: u64,
    },
    RelayError {
        code: String,
        detail: String,
        peer: Option<String>,
    },
}

/// Sanitized telemetry record emitted by the blind relay server (contains zero keys/plaintext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTrafficEvent {
    pub seq: u64,
    pub frame_type: String,
    pub from: String,
    pub to: String,
    pub wire_fingerprint_hex: Option<String>,
    pub wire_base_bytes: Option<usize>,
    pub wire_total_bytes: Option<usize>,
    pub ciphertext_bytes: Option<usize>,
}

/// Parameters returned when deriving a paired full-duplex CubeHash session from X25519 ECDH.
pub struct DerivedChatSession {
    pub session: DuplexCubeSession,
    pub safety_fingerprint: String,
    pub config: MeshConfig,
}

/// Inputs defining the X25519 pairing transcript used to provision a paired session.
pub struct PairTranscriptParams<'a> {
    pub profile: ChatMeshProfile,
    pub shared_ecdh: &'a [u8; 32],
    pub psk: &'a [u8],
    pub pair_id: &'a str,
    pub offerer_id: &'a str,
    pub accepter_id: &'a str,
    pub offerer_pub: &'a [u8; 32],
    pub accepter_pub: &'a [u8; 32],
    pub is_offerer: bool,
}

/// Derives two synchronized directional 100-cube meshes (`offerer -> accepter` and
/// `accepter -> offerer`) from an X25519 shared secret + optional PSK, bound strictly to `local_hw`.
pub fn provision_duplex_from_ecdh(
    params: PairTranscriptParams<'_>,
    local_hw: &dyn HardwareProvider,
) -> Result<DerivedChatSession> {
    let config = params.profile.to_config();
    config.validate()?;

    let mut ikm = Vec::with_capacity(32 + params.psk.len());
    ikm.extend_from_slice(params.shared_ecdh);
    ikm.extend_from_slice(params.psk);

    let mut transcript = Vec::with_capacity(128);
    transcript.extend_from_slice(params.pair_id.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(params.offerer_id.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(params.accepter_id.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(params.offerer_pub);
    transcript.extend_from_slice(params.accepter_pub);

    let mut root_ab = [0u8; 32];
    let mut root_ba = [0u8; 32];
    let mut safety_raw = [0u8; 16];
    hkdf_expand_label(&ikm, &transcript, b"cubehash-chat-dir-ab", &mut root_ab)?;
    hkdf_expand_label(&ikm, &transcript, b"cubehash-chat-dir-ba", &mut root_ba)?;
    hkdf_expand_label(&ikm, &transcript, b"cubehash-chat-safety", &mut safety_raw)?;
    ikm.zeroize();

    let (custody_ab, seed_ab) = derive_directional_custody(&config, &root_ab);
    let (custody_ba, seed_ba) = derive_directional_custody(&config, &root_ba);

    let (tx_custody, tx_seed, rx_custody, rx_seed) = if params.is_offerer {
        (custody_ab, seed_ab, custody_ba, seed_ba)
    } else {
        (custody_ba, seed_ba, custody_ab, seed_ab)
    };

    let tx = CellularMesh::provision_device(config.clone(), tx_custody, local_hw, &tx_seed)?;
    let rx = CellularMesh::provision_device(config.clone(), rx_custody, local_hw, &rx_seed)?;

    root_ab.zeroize();
    root_ba.zeroize();

    let hex_code = hex::encode_upper(safety_raw);
    let safety_fingerprint = format!(
        "{}-{}-{}-{}",
        &hex_code[0..4],
        &hex_code[4..8],
        &hex_code[8..12],
        &hex_code[12..16]
    );

    Ok(DerivedChatSession {
        session: DuplexCubeSession { tx, rx },
        safety_fingerprint,
        config,
    })
}

fn derive_directional_custody(config: &MeshConfig, root: &[u8; 32]) -> (ThreeCubeCustody, [u8; 32]) {
    let mother_secret = hmac_sha256_parts(root, &[b"chat-mother-secret"]);
    let owner_salt: [u8; 16] = hmac_sha256_parts(root, &[b"chat-owner-salt"])[..16]
        .try_into()
        .unwrap();
    let chain_id: [u8; 16] = hmac_sha256_parts(root, &[b"chat-chain-id"])[..16]
        .try_into()
        .unwrap();
    let root_pattern = hmac_sha256_parts(root, &[b"chat-root-pattern"]);
    let auditor_secret = hmac_sha256_parts(root, &[b"chat-auditor-secret"]);
    let synthesis_salt: [u8; 16] = hmac_sha256_parts(root, &[b"chat-synth-salt"])[..16]
        .try_into()
        .unwrap();
    let mesh_seed = hmac_sha256_parts(root, &[b"chat-mesh-seed"]);

    let coeff_digest = hmac_sha256_parts(root, &[b"chat-spiral-coeffs"]);
    let c0 = (u32::from_le_bytes(coeff_digest[0..4].try_into().unwrap()) % 97) + 3;
    let c1 = (u32::from_le_bytes(coeff_digest[4..8].try_into().unwrap()) % 97) + 5;
    let c2 = (u32::from_le_bytes(coeff_digest[8..12].try_into().unwrap()) % 97) + 7;

    let custody = build_custody_bundle(
        MotherCube::from_custody_bytes(mother_secret, owner_salt),
        MainCube::from_parts(chain_id, root_pattern, 0),
        AuditorCube::from_parts(
            auditor_secret,
            synthesis_salt,
            TimeAlgorithm::HybridTriMix,
            CombiningFn::FeistelNonLinear,
            [c0, c1, c2],
            config.quorum_select,
            config.consume_for_next,
        ),
    );
    (custody, mesh_seed)
}
