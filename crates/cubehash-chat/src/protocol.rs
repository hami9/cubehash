use cubehash_core::primitives::{hkdf_expand_label, hmac_sha256_parts};
use cubehash_core::{
    build_custody_bundle, AuditorCube, CellularMesh, CombiningFn, DeliveryAck, DuplexCubeSession,
    HardwareProvider, MainCube, MeshConfig, MotherCube, Result, ThreeCubeCustody, TimeAlgorithm,
    WirePacket,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const CHAT_BUCKET_BYTES: usize = 256;

/// Custom serde module for `[u8; 64]` Ed25519 signatures.
pub mod sig64_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; 64], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(val))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<[u8; 64], D::Error> {
        let hex_str = String::deserialize(d)?;
        let raw = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        <[u8; 64]>::try_from(raw.as_slice())
            .map_err(|_| serde::de::Error::custom("expected 64-byte Ed25519 signature"))
    }
}

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

    pub fn tag_byte(self) -> u8 {
        match self {
            Self::Compact => 1,
            Self::Standard => 2,
            Self::HighCapacity => 3,
        }
    }
}

/// Authenticated peer identity advertised by the blind relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub client_id: String,
    pub ed25519_pub: [u8; 32],
}

/// Frames routed transparently by the blind TLS relay server.
///
/// Registration is Ed25519 challenge-response authenticated; the relay verifies `from` ownership
/// and enforces identity pinning while holding zero CubeHash keys or plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayFrame {
    AuthChallenge {
        nonce: [u8; 32],
    },
    RegisterAuth {
        client_id: String,
        ed25519_pub: [u8; 32],
        #[serde(with = "sig64_serde")]
        signature: [u8; 64],
    },
    Registered {
        client_id: String,
        online_peers: Vec<PeerIdentity>,
    },
    PeerList {
        online_peers: Vec<PeerIdentity>,
    },
    PairOffer {
        from: String,
        to: String,
        pair_id: String,
        eph_pub: [u8; 32],
        init_rx_dh_pub: [u8; 32],
        sender_ed25519_pub: [u8; 32],
        profile: ChatMeshProfile,
        has_psk: bool,
        #[serde(with = "sig64_serde")]
        signature: [u8; 64],
    },
    PairAccept {
        from: String,
        to: String,
        pair_id: String,
        eph_pub: [u8; 32],
        init_rx_dh_pub: [u8; 32],
        sender_ed25519_pub: [u8; 32],
        #[serde(with = "sig64_serde")]
        signature: [u8; 64],
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
        epoch_eph_pub: [u8; 32],
        sender_ed25519_pub: [u8; 32],
        #[serde(with = "sig64_serde")]
        signature: [u8; 64],
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

fn push_lp_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

pub fn auth_challenge_sign_bytes(nonce: &[u8; 32], client_id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + client_id.len());
    buf.extend_from_slice(b"cubehash-relay-register-v2");
    buf.extend_from_slice(nonce);
    push_lp_bytes(&mut buf, client_id.as_bytes());
    buf
}

#[allow(clippy::too_many_arguments)]
pub fn pair_offer_sign_bytes(
    from: &str,
    to: &str,
    pair_id: &str,
    eph_pub: &[u8; 32],
    init_rx_dh_pub: &[u8; 32],
    sender_ed25519_pub: &[u8; 32],
    profile: ChatMeshProfile,
    has_psk: bool,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(192);
    buf.extend_from_slice(b"cubehash-pair-offer-v2");
    push_lp_bytes(&mut buf, from.as_bytes());
    push_lp_bytes(&mut buf, to.as_bytes());
    push_lp_bytes(&mut buf, pair_id.as_bytes());
    buf.extend_from_slice(eph_pub);
    buf.extend_from_slice(init_rx_dh_pub);
    buf.extend_from_slice(sender_ed25519_pub);
    buf.push(profile.tag_byte());
    buf.push(u8::from(has_psk));
    buf
}

#[allow(clippy::too_many_arguments)]
pub fn pair_accept_sign_bytes(
    from: &str,
    to: &str,
    pair_id: &str,
    offerer_eph_pub: &[u8; 32],
    accepter_eph_pub: &[u8; 32],
    init_rx_dh_pub: &[u8; 32],
    sender_ed25519_pub: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(224);
    buf.extend_from_slice(b"cubehash-pair-accept-v2");
    push_lp_bytes(&mut buf, from.as_bytes());
    push_lp_bytes(&mut buf, to.as_bytes());
    push_lp_bytes(&mut buf, pair_id.as_bytes());
    buf.extend_from_slice(offerer_eph_pub);
    buf.extend_from_slice(accepter_eph_pub);
    buf.extend_from_slice(init_rx_dh_pub);
    buf.extend_from_slice(sender_ed25519_pub);
    buf
}

pub fn epoch_hop_sign_bytes(
    from: &str,
    to: &str,
    new_epoch: u64,
    epoch_eph_pub: &[u8; 32],
    sender_ed25519_pub: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(b"cubehash-epoch-hop-v2");
    push_lp_bytes(&mut buf, from.as_bytes());
    push_lp_bytes(&mut buf, to.as_bytes());
    buf.extend_from_slice(&new_epoch.to_le_bytes());
    buf.extend_from_slice(epoch_eph_pub);
    buf.extend_from_slice(sender_ed25519_pub);
    buf
}

/// Pads chat plaintext into fixed 256-byte buckets with OS CSPRNG random padding before AEAD
/// so wire packet sizes do not leak exact message byte lengths.
pub fn encode_padded_chat_payload(plaintext: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let total = 4usize
        .checked_add(plaintext.len())
        .ok_or_else(|| "message too large".to_string())?;
    let buckets = total.div_ceil(CHAT_BUCKET_BYTES).max(1);
    let padded_len = buckets * CHAT_BUCKET_BYTES;

    let mut out = vec![0u8; padded_len];
    getrandom::getrandom(&mut out[total..]).map_err(|e| e.to_string())?;
    out[0..4].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    out[4..4 + plaintext.len()].copy_from_slice(plaintext);
    Ok(out)
}

/// Unpads a 256-byte bucketed chat payload back into exact original plaintext.
pub fn decode_padded_chat_payload(buf: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if buf.len() < 4 {
        return Err("padded payload too short".to_string());
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if 4usize.checked_add(len).is_none_or(|end| end > buf.len()) {
        return Err("corrupted padded payload length".to_string());
    }
    Ok(buf[4..4 + len].to_vec())
}

/// Parameters returned when deriving a paired full-duplex CubeHash session from X25519 ECDH.
pub struct DerivedChatSession {
    pub session: DuplexCubeSession,
    pub safety_fingerprint: String,
    pub config: MeshConfig,
}

/// Inputs defining the Ed25519-authenticated X25519 pairing transcript.
pub struct PairTranscriptParams<'a> {
    pub profile: ChatMeshProfile,
    pub shared_ecdh: &'a [u8; 32],
    pub psk: &'a [u8],
    pub pair_id: &'a str,
    pub offerer_id: &'a str,
    pub accepter_id: &'a str,
    pub offerer_pub: &'a [u8; 32],
    pub accepter_pub: &'a [u8; 32],
    pub offerer_ed25519_pub: &'a [u8; 32],
    pub accepter_ed25519_pub: &'a [u8; 32],
    pub my_rx_dh_secret: &'a [u8; 32],
    pub my_rx_dh_pub: &'a [u8; 32],
    pub peer_rx_dh_pub: &'a [u8; 32],
    pub is_offerer: bool,
}

/// Derives two synchronized directional 100-cube meshes bound to the local hardware enclave,
/// binding both X25519 ephemeral keys, Ed25519 identity keys, optional PSK, and independent initial
/// DH ratchet keys so private DH ratchet scalars never overlap between peers.
pub fn provision_duplex_from_ecdh(
    params: PairTranscriptParams<'_>,
    local_hw: &dyn HardwareProvider,
) -> Result<DerivedChatSession> {
    let config = params.profile.to_config();
    config.validate()?;

    let mut ikm = Vec::with_capacity(32 + params.psk.len());
    ikm.extend_from_slice(params.shared_ecdh);
    ikm.extend_from_slice(params.psk);

    let mut transcript = Vec::with_capacity(256);
    push_lp_bytes(&mut transcript, params.pair_id.as_bytes());
    push_lp_bytes(&mut transcript, params.offerer_id.as_bytes());
    push_lp_bytes(&mut transcript, params.accepter_id.as_bytes());
    transcript.extend_from_slice(params.offerer_pub);
    transcript.extend_from_slice(params.accepter_pub);
    transcript.extend_from_slice(params.offerer_ed25519_pub);
    transcript.extend_from_slice(params.accepter_ed25519_pub);

    let mut root_ab = [0u8; 32];
    let mut root_ba = [0u8; 32];
    let mut safety_raw = [0u8; 16];
    hkdf_expand_label(&ikm, &transcript, b"cubehash-chat-dir-ab-v2", &mut root_ab)?;
    hkdf_expand_label(&ikm, &transcript, b"cubehash-chat-dir-ba-v2", &mut root_ba)?;
    hkdf_expand_label(&ikm, &transcript, b"cubehash-chat-safety-v2", &mut safety_raw)?;
    ikm.zeroize();

    let (custody_ab, seed_ab) = derive_directional_custody(&config, &root_ab);
    let (custody_ba, seed_ba) = derive_directional_custody(&config, &root_ba);

    let (tx_custody, tx_seed, rx_custody, rx_seed) = if params.is_offerer {
        (custody_ab, seed_ab, custody_ba, seed_ba)
    } else {
        (custody_ba, seed_ba, custody_ab, seed_ab)
    };

    let mut tx = CellularMesh::provision_device(config.clone(), tx_custody, local_hw, &tx_seed)?;
    let mut rx = CellularMesh::provision_device(config.clone(), rx_custody, local_hw, &rx_seed)?;

    tx.set_peer_dh_pub(*params.peer_rx_dh_pub)?;
    rx.set_local_dh_keypair(*params.my_rx_dh_secret, *params.my_rx_dh_pub)?;

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
