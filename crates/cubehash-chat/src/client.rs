use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cubehash_core::{
    HardwareProvider, HoneyProfile, MeshAuditStats, PayloadMode, ReceiveOutcome, UniqueWireCube,
    WirePacket,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{client_async, WebSocketStream};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keystore::DeviceIdentity;
use crate::protocol::{
    auth_challenge_sign_bytes, decode_padded_chat_payload, encode_padded_chat_payload,
    epoch_hop_sign_bytes, pair_accept_sign_bytes, pair_offer_sign_bytes,
    provision_duplex_from_ecdh, ChatMeshProfile, PairTranscriptParams, PeerIdentity, RelayFrame,
};
use crate::tls::{parse_ws_url, ClientTlsConfig};

const ACK_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// A single message entry displayed in the CLI chat log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRecord {
    pub msg_id: String,
    pub direction: String,
    pub peer_id: String,
    pub text: String,
    pub mode: String,
    pub status: String,
    pub healed_bits: usize,
    pub wire_bytes: usize,
}

/// Public snapshot of a paired peer session for CLI inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSummary {
    pub peer_id: String,
    pub peer_ed25519_hex: String,
    pub safety_fingerprint: String,
    pub profile: ChatMeshProfile,
    pub tx_stats: MeshAuditStats,
    pub rx_stats: MeshAuditStats,
    pub messages: Vec<ChatRecord>,
}

/// Real-time events broadcast to the terminal CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ChatUiEvent {
    PeersUpdated {
        online_peers: Vec<PeerIdentity>,
    },
    Paired {
        peer_id: String,
        peer_ed25519_hex: String,
        safety_fingerprint: String,
        profile: ChatMeshProfile,
    },
    IncomingPairRequest {
        from: String,
        from_ed25519_hex: String,
        pair_id: String,
        profile: ChatMeshProfile,
        has_psk: bool,
    },
    MessageAdded {
        record: ChatRecord,
    },
    MessageStatusUpdated {
        peer_id: String,
        msg_id: String,
        status: String,
    },
    EpochHopped {
        peer_id: String,
        direction: String,
        new_epoch: u64,
    },
    HoneyProbeResult {
        peer_id: String,
        outcome: String,
        output: String,
    },
    Notice {
        level: String,
        text: String,
    },
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct PendingPairOut {
    peer_id: String,
    #[zeroize(skip)]
    eph_secret: StaticSecret,
    eph_pub: [u8; 32],
    init_rx_dh_secret: [u8; 32],
    init_rx_dh_pub: [u8; 32],
    #[zeroize(skip)]
    profile: ChatMeshProfile,
    psk: String,
}

struct IncomingPairOffer {
    from: String,
    pair_id: String,
    eph_pub: [u8; 32],
    init_rx_dh_pub: [u8; 32],
    sender_ed25519_pub: [u8; 32],
    profile: ChatMeshProfile,
    #[allow(dead_code)]
    has_psk: bool,
}

struct PeerChatSession {
    session: cubehash_core::DuplexCubeSession,
    peer_ed25519_pub: [u8; 32],
    safety_fingerprint: String,
    profile: ChatMeshProfile,
    messages: Vec<ChatRecord>,
}

struct NodeInner {
    online_peers: Vec<PeerIdentity>,
    pending_offers_out: HashMap<String, PendingPairOut>,
    pending_offers_in: HashMap<String, IncomingPairOffer>,
    preset_psks: HashMap<String, String>,
    sessions: HashMap<String, PeerChatSession>,
    pending_acks: HashMap<String, oneshot::Sender<Result<(), String>>>,
    pending_msg_peer: HashMap<String, String>,
}

impl NodeInner {
    fn new() -> Self {
        Self {
            online_peers: Vec::new(),
            pending_offers_out: HashMap::new(),
            pending_offers_in: HashMap::new(),
            preset_psks: HashMap::new(),
            sessions: HashMap::new(),
            pending_acks: HashMap::new(),
            pending_msg_peer: HashMap::new(),
        }
    }
}

/// Hardware-bound, Ed25519-authenticated CubeHash chat client connected over TLS (`wss://`)
/// to a blind WebSocket relay.
#[derive(Clone)]
pub struct ChatNode {
    identity: Arc<Mutex<DeviceIdentity>>,
    client_id: String,
    device_hw_id: [u8; 16],
    ed25519_pub: [u8; 32],
    backend_label: String,
    inner: Arc<RwLock<NodeInner>>,
    ws_out: mpsc::UnboundedSender<RelayFrame>,
    events_tx: broadcast::Sender<ChatUiEvent>,
    id_counter: Arc<AtomicU64>,
    ws_task: Arc<tokio::task::JoinHandle<()>>,
}

impl ChatNode {
    /// Connects cleanly to a TLS (`wss://`) or opt-in plain (`ws://`) blind relay using
    /// an Ed25519 hardware-bound `DeviceIdentity` and completes challenge-response authentication.
    pub async fn connect_with_config(
        identity: DeviceIdentity,
        relay_ws_url: &str,
        tls_config: ClientTlsConfig,
        allow_insecure_ws: bool,
    ) -> Result<Self, String> {
        let parsed = parse_ws_url(relay_ws_url)?;
        if !parsed.is_tls && !allow_insecure_ws {
            return Err(
                "refusing unencrypted ws:// relay connection without --insecure-ws; use wss://"
                    .to_string(),
            );
        }

        let client_id = identity.client_id().to_string();
        let device_hw_id = identity.hardware_provider().device_hw_id();
        let ed25519_pub = identity.ed25519_pub();
        let backend_label = identity.backend_label().to_string();
        let identity_arc = Arc::new(Mutex::new(identity));

        let tcp = TcpStream::connect(&parsed.tcp_addr)
            .await
            .map_err(|e| format!("failed to connect TCP to {}: {e}", parsed.tcp_addr))?;

        let (out_tx, out_rx) = mpsc::unbounded_channel::<RelayFrame>();
        let (events_tx, _) = broadcast::channel(128);
        let inner = Arc::new(RwLock::new(NodeInner::new()));
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();

        let ws_task = if parsed.is_tls {
            let connector = tls_config.build_connector()?;
            let tls_stream = connector
                .connect(parsed.server_name, tcp)
                .await
                .map_err(|e| format!("TLS handshake failed with {}: {e}", parsed.tcp_addr))?;
            let (ws_stream, _) = client_async(&parsed.full_url, tls_stream)
                .await
                .map_err(|e| format!("WebSocket upgrade failed on {}: {e}", parsed.full_url))?;
            tokio::spawn(Self::drive_ws(
                ws_stream,
                client_id.clone(),
                Arc::clone(&identity_arc),
                Arc::clone(&inner),
                out_tx.clone(),
                out_rx,
                events_tx.clone(),
                ready_tx,
            ))
        } else {
            let (ws_stream, _) = client_async(&parsed.full_url, tcp)
                .await
                .map_err(|e| format!("WebSocket upgrade failed on {}: {e}", parsed.full_url))?;
            tokio::spawn(Self::drive_ws(
                ws_stream,
                client_id.clone(),
                Arc::clone(&identity_arc),
                Arc::clone(&inner),
                out_tx.clone(),
                out_rx,
                events_tx.clone(),
                ready_tx,
            ))
        };

        match tokio::time::timeout(CONNECT_AUTH_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(Self {
                identity: identity_arc,
                client_id,
                device_hw_id,
                ed25519_pub,
                backend_label,
                inner,
                ws_out: out_tx,
                events_tx,
                id_counter: Arc::new(AtomicU64::new(1)),
                ws_task: Arc::new(ws_task),
            }),
            Ok(Ok(Err(e))) => {
                ws_task.abort();
                Err(e)
            }
            _ => {
                ws_task.abort();
                Err("relay Ed25519 authentication handshake timed out".to_string())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn drive_ws<S>(
        ws_stream: WebSocketStream<S>,
        self_id: String,
        identity: Arc<Mutex<DeviceIdentity>>,
        inner: Arc<RwLock<NodeInner>>,
        out_tx: mpsc::UnboundedSender<RelayFrame>,
        mut out_rx: mpsc::UnboundedReceiver<RelayFrame>,
        events_tx: broadcast::Sender<ChatUiEvent>,
        ready_tx: oneshot::Sender<Result<(), String>>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut ws_sink, mut ws_rx) = ws_stream.split();
        let writer = tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                if let Ok(txt) = serde_json::to_string(&frame) {
                    if ws_sink.send(WsMessage::Text(txt.into())).await.is_err() {
                        break;
                    }
                }
            }
        });

        let mut ready_opt = Some(ready_tx);

        while let Some(Ok(msg)) = ws_rx.next().await {
            let WsMessage::Text(txt) = msg else {
                continue;
            };
            let Ok(frame) = serde_json::from_str::<RelayFrame>(&txt) else {
                continue;
            };

            match frame {
                RelayFrame::AuthChallenge { nonce } => {
                    let sign_msg = auth_challenge_sign_bytes(&nonce, &self_id);
                    let id_guard = identity.lock().await;
                    let sig = id_guard.sign(&sign_msg);
                    let ed25519_pub = id_guard.ed25519_pub();
                    drop(id_guard);
                    let _ = out_tx.send(RelayFrame::RegisterAuth {
                        client_id: self_id.clone(),
                        ed25519_pub,
                        signature: sig,
                    });
                }
                RelayFrame::Registered { online_peers, .. } => {
                    let filtered: Vec<PeerIdentity> = online_peers
                        .into_iter()
                        .filter(|p| p.client_id != self_id)
                        .collect();
                    inner.write().await.online_peers = filtered.clone();
                    if let Some(tx) = ready_opt.take() {
                        let _ = tx.send(Ok(()));
                    }
                    let _ = events_tx.send(ChatUiEvent::PeersUpdated {
                        online_peers: filtered,
                    });
                }
                RelayFrame::RelayError {
                    ref code,
                    ref detail,
                    ..
                } if ready_opt.is_some()
                    && matches!(
                        code.as_str(),
                        "auth_failed" | "identity_mismatch" | "id_in_use" | "invalid_id" | "auth_timeout"
                    ) =>
                {
                    if let Some(tx) = ready_opt.take() {
                        let _ = tx.send(Err(format!("relay rejected registration ({code}): {detail}")));
                    }
                    break;
                }
                other => {
                    Self::handle_relay_frame(
                        &self_id,
                        &identity,
                        &inner,
                        &out_tx,
                        &events_tx,
                        other,
                    )
                    .await;
                }
            }
        }

        if let Some(tx) = ready_opt.take() {
            let _ = tx.send(Err("connection closed before relay authentication completed".to_string()));
        }
        writer.abort();
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn device_hw_id_hex(&self) -> String {
        hex::encode(self.device_hw_id)
    }

    pub fn ed25519_pub(&self) -> [u8; 32] {
        self.ed25519_pub
    }

    pub fn ed25519_pub_hex(&self) -> String {
        hex::encode(self.ed25519_pub)
    }

    pub fn backend_label(&self) -> &str {
        &self.backend_label
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ChatUiEvent> {
        self.events_tx.subscribe()
    }

    pub async fn set_preset_psk(&self, peer_id: &str, psk: &str) {
        self.inner
            .write()
            .await
            .preset_psks
            .insert(peer_id.to_string(), psk.to_string());
    }

    /// Explicitly trusts/updates a peer's Ed25519 public key after out-of-band verification.
    pub async fn pin_peer_ed25519(&self, peer_id: &str, pubkey: [u8; 32]) -> Result<(), String> {
        self.identity.lock().await.pin_peer_key(peer_id, pubkey)
    }

    pub async fn online_peers(&self) -> Vec<PeerIdentity> {
        self.inner.read().await.online_peers.clone()
    }

    pub async fn online_peer_ids(&self) -> Vec<String> {
        self.inner
            .read()
            .await
            .online_peers
            .iter()
            .map(|p| p.client_id.clone())
            .collect()
    }

    pub async fn paired_summaries(&self) -> Vec<PeerSummary> {
        let guard = self.inner.read().await;
        let mut out: Vec<PeerSummary> = guard
            .sessions
            .iter()
            .map(|(peer_id, ps)| PeerSummary {
                peer_id: peer_id.clone(),
                peer_ed25519_hex: hex::encode(ps.peer_ed25519_pub),
                safety_fingerprint: ps.safety_fingerprint.clone(),
                profile: ps.profile,
                tx_stats: ps.session.tx.audit_stats(),
                rx_stats: ps.session.rx.audit_stats(),
                messages: ps.messages.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        out
    }

    /// Initiates an Ed25519-signed X25519 key exchange over the blind relay with independent
    /// initial DH ratchet keys.
    pub async fn initiate_pair(
        &self,
        peer_id: &str,
        psk: Option<&str>,
        profile: ChatMeshProfile,
    ) -> Result<String, String> {
        if peer_id == self.client_id {
            return Err("cannot pair with yourself".to_string());
        }
        let (eph_secret, eph_pub) = generate_static_x25519()?;
        let (init_rx_dh_secret, init_rx_dh_pub) = generate_raw_x25519()?;

        let seq = self.id_counter.fetch_add(1, Ordering::Relaxed);
        let pair_id = format!("{}-{}-{}", self.client_id, peer_id, seq);
        let psk_str = psk.unwrap_or("").to_string();
        let has_psk = !psk_str.is_empty();

        self.inner.write().await.pending_offers_out.insert(
            pair_id.clone(),
            PendingPairOut {
                peer_id: peer_id.to_string(),
                eph_secret,
                eph_pub,
                init_rx_dh_secret,
                init_rx_dh_pub,
                profile,
                psk: psk_str,
            },
        );

        let msg_bytes = pair_offer_sign_bytes(
            &self.client_id,
            peer_id,
            &pair_id,
            &eph_pub,
            &init_rx_dh_pub,
            &self.ed25519_pub,
            profile,
            has_psk,
        );
        let signature = self.identity.lock().await.sign(&msg_bytes);

        self.ws_out
            .send(RelayFrame::PairOffer {
                from: self.client_id.clone(),
                to: peer_id.to_string(),
                pair_id: pair_id.clone(),
                eph_pub,
                init_rx_dh_pub,
                sender_ed25519_pub: self.ed25519_pub,
                profile,
                has_psk,
                signature,
            })
            .map_err(|_| "relay channel closed".to_string())?;

        Ok(pair_id)
    }

    /// Explicitly accepts a verified pending pairing request from `peer_id`.
    pub async fn accept_pair_offer(&self, peer_id: &str, psk: &str) -> Result<String, String> {
        let offer = self
            .inner
            .write()
            .await
            .pending_offers_in
            .remove(peer_id)
            .ok_or_else(|| format!("no pending pair request from '{peer_id}'"))?;
        Self::complete_incoming_offer(
            &self.client_id,
            &self.identity,
            &self.inner,
            &self.ws_out,
            &self.events_tx,
            offer,
            psk,
        )
        .await
    }

    /// Sends a message (or compact <=24B `RawCore256` payload) and awaits receiver `DeliveryAck`.
    /// Uses 256-byte bucket padding for AEAD chat payloads and rolls back cleanly on drop/timeout.
    pub async fn send_message(
        &self,
        peer_id: &str,
        text: &str,
        raw_core_mode: bool,
    ) -> Result<ChatRecord, String> {
        self.send_with_noise(peer_id, text, raw_core_mode, 0).await
    }

    /// Sends a message with optional simulated wire bit-rot (`flip_bytes` bytes corrupted) to
    /// exercise live Bitwise Majority Voting (TMR) recovery.
    pub async fn send_with_noise(
        &self,
        peer_id: &str,
        text: &str,
        raw_core_mode: bool,
        flip_bytes: usize,
    ) -> Result<ChatRecord, String> {
        let msg_seq = self.id_counter.fetch_add(1, Ordering::Relaxed);
        let msg_id = format!("msg-{}-{msg_seq}", self.client_id);

        let padded_envelope = if raw_core_mode {
            None
        } else {
            Some(encode_padded_chat_payload(text.as_bytes())?)
        };

        let (packet, rx_ack, wire_bytes, mode_label) = {
            let id_guard = self.identity.lock().await;
            let hw = id_guard.hardware_provider().clone();
            drop(id_guard);

            let mut guard = self.inner.write().await;
            let ps = guard
                .sessions
                .get_mut(peer_id)
                .ok_or_else(|| format!("not paired with '{peer_id}'; pair first"))?;

            let mut pkt = if raw_core_mode {
                ps.session
                    .begin_send_raw_core(&hw, text.as_bytes())
                    .map_err(|e| e.to_string())?
            } else {
                ps.session
                    .begin_send_message(&hw, padded_envelope.as_ref().unwrap())
                    .map_err(|e| e.to_string())?
            };

            if flip_bytes > 0 {
                let half = flip_bytes.min(pkt.wire_cube.partial_256b.len() / 2);
                for i in 0..half {
                    pkt.wire_cube.partial_256b[i] ^= 0x5A;
                    let shadow_off = pkt.wire_cube.partial_256b.len() / 2 + i;
                    if shadow_off < pkt.wire_cube.partial_1000b.len() {
                        pkt.wire_cube.partial_1000b[shadow_off] ^= 0xA5;
                    }
                }
            }

            let wb = pkt.wire_cube.total_byte_len();
            let mode = if raw_core_mode {
                "RawCore256".to_string()
            } else if flip_bytes > 0 {
                format!("ArbitraryAEAD (+noise {flip_bytes}B)")
            } else {
                "ArbitraryAEAD".to_string()
            };

            let rec = ChatRecord {
                msg_id: msg_id.clone(),
                direction: "out".to_string(),
                peer_id: peer_id.to_string(),
                text: text.to_string(),
                mode: mode.clone(),
                status: "awaiting_ack".to_string(),
                healed_bits: 0,
                wire_bytes: wb,
            };
            ps.messages.push(rec.clone());
            let _ = self.events_tx.send(ChatUiEvent::MessageAdded { record: rec });

            let (tx_ack, rx_ack) = oneshot::channel();
            guard.pending_acks.insert(msg_id.clone(), tx_ack);
            guard
                .pending_msg_peer
                .insert(msg_id.clone(), peer_id.to_string());

            (pkt, rx_ack, wb, mode)
        };

        if self
            .ws_out
            .send(RelayFrame::EncryptedPacket {
                from: self.client_id.clone(),
                to: peer_id.to_string(),
                msg_id: msg_id.clone(),
                packet,
            })
            .is_err()
        {
            self.rollback_failed_send(peer_id, &msg_id, "relay disconnected")
                .await;
            return Err("relay disconnected; outbound state rolled back".to_string());
        }

        match tokio::time::timeout(ACK_TIMEOUT, rx_ack).await {
            Ok(Ok(Ok(()))) => Ok(ChatRecord {
                msg_id,
                direction: "out".to_string(),
                peer_id: peer_id.to_string(),
                text: text.to_string(),
                mode: mode_label,
                status: "delivered_ack".to_string(),
                healed_bits: 0,
                wire_bytes,
            }),
            Ok(Ok(Err(reason))) => {
                self.rollback_failed_send(peer_id, &msg_id, &reason).await;
                Err(format!("{reason}; outbound mesh rolled back"))
            }
            _ => {
                self.rollback_failed_send(peer_id, &msg_id, "ack_timeout")
                    .await;
                Err("ACK timed out; outbound mesh rolled back".to_string())
            }
        }
    }

    /// Triggers synchronized Bijective Epoch Hopping + DH Ratchet advancement on `tx`
    /// and delivers an Ed25519-signed notice to `peer_id`.
    pub async fn hop_epoch(&self, peer_id: &str) -> Result<u64, String> {
        let id_guard = self.identity.lock().await;
        let hw = id_guard.hardware_provider().clone();
        let (new_epoch, epoch_eph_pub) = {
            let mut guard = self.inner.write().await;
            let ps = guard
                .sessions
                .get_mut(peer_id)
                .ok_or_else(|| format!("not paired with '{peer_id}'"))?;
            ps.session
                .hop_epoch_tx_ratchet(&hw)
                .map_err(|e| e.to_string())?
        };

        let sign_msg = epoch_hop_sign_bytes(
            &self.client_id,
            peer_id,
            new_epoch,
            &epoch_eph_pub,
            &self.ed25519_pub,
        );
        let signature = id_guard.sign(&sign_msg);
        drop(id_guard);

        self.ws_out
            .send(RelayFrame::EpochHopNotice {
                from: self.client_id.clone(),
                to: peer_id.to_string(),
                new_epoch,
                epoch_eph_pub,
                sender_ed25519_pub: self.ed25519_pub,
                signature,
            })
            .map_err(|_| "relay channel closed".to_string())?;
        let _ = self.events_tx.send(ChatUiEvent::EpochHopped {
            peer_id: peer_id.to_string(),
            direction: "tx".to_string(),
            new_epoch,
        });
        Ok(new_epoch)
    }

    /// Executes constant-work `decrypt_zero_oracle` against a tampered probe on `peer_id`'s RX mesh.
    pub async fn simulate_honey_probe(&self, peer_id: &str) -> Result<String, String> {
        let hw = self.identity.lock().await.hardware_provider().clone();
        let mut guard = self.inner.write().await;
        let ps = guard
            .sessions
            .get_mut(peer_id)
            .ok_or_else(|| format!("not paired with '{peer_id}'"))?;

        let forged = WirePacket {
            wire_cube: UniqueWireCube {
                cube_fingerprint: [0xDEu8; 16],
                partial_256b: vec![0xAAu8; ps.session.rx.config().core_bytes],
                partial_1000b: vec![0x55u8; ps.session.rx.config().sub_matrix_bytes],
                weight_padding: Vec::new(),
            },
            sequence: ps.session.rx.sequence() + 1,
            epoch: ps.session.rx.epoch(),
            ratchet_pub: [0x11u8; 32],
            payload_mode: PayloadMode::RawCore256,
            packet_mac: [0xFFu8; 32],
        };

        match ps
            .session
            .decrypt_zero_oracle(&hw, &forged, HoneyProfile::ChatPlaintext)
        {
            ReceiveOutcome::HoneyDeception {
                plausible_output, ..
            } => {
                let txt = String::from_utf8_lossy(&plausible_output).to_string();
                let _ = self.events_tx.send(ChatUiEvent::HoneyProbeResult {
                    peer_id: peer_id.to_string(),
                    outcome: "HoneyDeception (constant-work zero oracle, zero desync)".to_string(),
                    output: txt.clone(),
                });
                Ok(txt)
            }
            ReceiveOutcome::Authentic { .. } => Err("unexpected authentic probe".to_string()),
        }
    }

    async fn rollback_failed_send(&self, peer_id: &str, msg_id: &str, reason: &str) {
        let mut guard = self.inner.write().await;
        guard.pending_acks.remove(msg_id);
        guard.pending_msg_peer.remove(msg_id);
        if let Some(ps) = guard.sessions.get_mut(peer_id) {
            let _ = ps.session.rollback_outbound();
            if let Some(m) = ps.messages.iter_mut().find(|m| m.msg_id == msg_id) {
                m.status = format!("rolled_back ({reason})");
            }
        }
        let _ = self.events_tx.send(ChatUiEvent::MessageStatusUpdated {
            peer_id: peer_id.to_string(),
            msg_id: msg_id.to_string(),
            status: format!("rolled_back ({reason})"),
        });
    }

    async fn handle_relay_frame(
        self_id: &str,
        identity: &Arc<Mutex<DeviceIdentity>>,
        inner: &Arc<RwLock<NodeInner>>,
        ws_out: &mpsc::UnboundedSender<RelayFrame>,
        events_tx: &broadcast::Sender<ChatUiEvent>,
        frame: RelayFrame,
    ) {
        match frame {
            RelayFrame::PeerList { online_peers } => {
                let filtered: Vec<PeerIdentity> = online_peers
                    .into_iter()
                    .filter(|p| p.client_id != self_id)
                    .collect();
                inner.write().await.online_peers = filtered.clone();
                let _ = events_tx.send(ChatUiEvent::PeersUpdated {
                    online_peers: filtered,
                });
            }
            RelayFrame::PairOffer {
                from,
                to,
                pair_id,
                eph_pub,
                init_rx_dh_pub,
                sender_ed25519_pub,
                profile,
                has_psk,
                signature,
            } => {
                let sign_msg = pair_offer_sign_bytes(
                    &from,
                    &to,
                    &pair_id,
                    &eph_pub,
                    &init_rx_dh_pub,
                    &sender_ed25519_pub,
                    profile,
                    has_psk,
                );
                if to != self_id
                    || !DeviceIdentity::verify_signature(&sender_ed25519_pub, &sign_msg, &signature)
                {
                    let _ = events_tx.send(ChatUiEvent::Notice {
                        level: "security_alert".to_string(),
                        text: format!("REJECTED forged or misrouted PairOffer from '{from}'"),
                    });
                    return;
                }

                if let Err(alert) = identity
                    .lock()
                    .await
                    .verify_or_pin_peer(&from, sender_ed25519_pub)
                {
                    let _ = events_tx.send(ChatUiEvent::Notice {
                        level: "security_alert".to_string(),
                        text: alert,
                    });
                    return;
                }

                let preset = inner.read().await.preset_psks.get(&from).cloned();
                let offer = IncomingPairOffer {
                    from: from.clone(),
                    pair_id: pair_id.clone(),
                    eph_pub,
                    init_rx_dh_pub,
                    sender_ed25519_pub,
                    profile,
                    has_psk,
                };
                // Only auto-accept when this client explicitly pre-authorized a peer PSK;
                // all other offers require explicit operator approval via `/accept`.
                if let Some(psk) = preset {
                    let _ = Self::complete_incoming_offer(
                        self_id, identity, inner, ws_out, events_tx, offer, &psk,
                    )
                    .await;
                } else {
                    inner
                        .write()
                        .await
                        .pending_offers_in
                        .insert(from.clone(), offer);
                    let _ = events_tx.send(ChatUiEvent::IncomingPairRequest {
                        from,
                        from_ed25519_hex: hex::encode(sender_ed25519_pub),
                        pair_id,
                        profile,
                        has_psk,
                    });
                }
            }
            RelayFrame::PairAccept {
                from,
                to,
                pair_id,
                eph_pub,
                init_rx_dh_pub,
                sender_ed25519_pub,
                signature,
            } => {
                let pending = inner.write().await.pending_offers_out.remove(&pair_id);
                let Some(p) = pending else {
                    return;
                };
                if to != self_id || from != p.peer_id {
                    let _ = events_tx.send(ChatUiEvent::Notice {
                        level: "security_alert".to_string(),
                        text: format!("REJECTED PairAccept from unexpected sender '{from}'"),
                    });
                    return;
                }

                let sign_msg = pair_accept_sign_bytes(
                    &from,
                    self_id,
                    &pair_id,
                    &p.eph_pub,
                    &eph_pub,
                    &init_rx_dh_pub,
                    &sender_ed25519_pub,
                );
                if !DeviceIdentity::verify_signature(&sender_ed25519_pub, &sign_msg, &signature) {
                    let _ = events_tx.send(ChatUiEvent::Notice {
                        level: "security_alert".to_string(),
                        text: format!("REJECTED PairAccept from '{from}' with invalid Ed25519 signature"),
                    });
                    return;
                }

                let mut id_guard = identity.lock().await;
                if let Err(alert) = id_guard.verify_or_pin_peer(&from, sender_ed25519_pub) {
                    let _ = events_tx.send(ChatUiEvent::Notice {
                        level: "security_alert".to_string(),
                        text: alert,
                    });
                    return;
                }
                let hw = id_guard.hardware_provider().clone();
                let my_ed_pub = id_guard.ed25519_pub();
                drop(id_guard);

                let peer_pub = PublicKey::from(eph_pub);
                let shared_obj = p.eph_secret.diffie_hellman(&peer_pub);
                if !shared_obj.was_contributory() {
                    let _ = events_tx.send(ChatUiEvent::Notice {
                        level: "security_alert".to_string(),
                        text: format!("REJECTED non-contributory X25519 PairAccept from '{from}'"),
                    });
                    return;
                }
                let mut shared = shared_obj.to_bytes();

                match provision_duplex_from_ecdh(
                    PairTranscriptParams {
                        profile: p.profile,
                        shared_ecdh: &shared,
                        psk: p.psk.as_bytes(),
                        pair_id: &pair_id,
                        offerer_id: self_id,
                        accepter_id: &from,
                        offerer_pub: &p.eph_pub,
                        accepter_pub: &eph_pub,
                        offerer_ed25519_pub: &my_ed_pub,
                        accepter_ed25519_pub: &sender_ed25519_pub,
                        my_rx_dh_secret: &p.init_rx_dh_secret,
                        my_rx_dh_pub: &p.init_rx_dh_pub,
                        peer_rx_dh_pub: &init_rx_dh_pub,
                        is_offerer: true,
                    },
                    &hw,
                ) {
                    Ok(derived) => {
                        let fp = derived.safety_fingerprint.clone();
                        let peer_ed_hex = hex::encode(sender_ed25519_pub);
                        inner.write().await.sessions.insert(
                            p.peer_id.clone(),
                            PeerChatSession {
                                session: derived.session,
                                peer_ed25519_pub: sender_ed25519_pub,
                                safety_fingerprint: fp.clone(),
                                profile: p.profile,
                                messages: Vec::new(),
                            },
                        );
                        let _ = events_tx.send(ChatUiEvent::Paired {
                            peer_id: p.peer_id.clone(),
                            peer_ed25519_hex: peer_ed_hex,
                            safety_fingerprint: fp,
                            profile: p.profile,
                        });
                    }
                    Err(e) => {
                        let _ = events_tx.send(ChatUiEvent::Notice {
                            level: "error".to_string(),
                            text: format!("pairing failed: {e}"),
                        });
                    }
                }
                shared.zeroize();
            }
            RelayFrame::EncryptedPacket {
                from,
                msg_id,
                mut packet,
                ..
            } => {
                let hw = identity.lock().await.hardware_provider().clone();
                let wire_bytes = packet.wire_cube.total_byte_len();
                let is_raw = matches!(packet.payload_mode, PayloadMode::RawCore256);
                let mode_str = if is_raw { "RawCore256" } else { "ArbitraryAEAD" };

                let result = {
                    let mut guard = inner.write().await;
                    if let Some(ps) = guard.sessions.get_mut(&from) {
                        match ps.session.receive_authenticated(&hw, &mut packet) {
                            Ok((pt, ack, healed_bits)) => {
                                let raw_bytes = if is_raw {
                                    Ok(pt)
                                } else {
                                    decode_padded_chat_payload(&pt)
                                };
                                match raw_bytes {
                                    Ok(actual_pt) => {
                                        let text = String::from_utf8_lossy(&actual_pt).to_string();
                                        let rec = ChatRecord {
                                            msg_id: msg_id.clone(),
                                            direction: "in".to_string(),
                                            peer_id: from.clone(),
                                            text,
                                            mode: mode_str.to_string(),
                                            status: if healed_bits > 0 {
                                                format!("healed_{healed_bits}_bits")
                                            } else {
                                                "verified".to_string()
                                            },
                                            healed_bits,
                                            wire_bytes,
                                        };
                                        ps.messages.push(rec.clone());
                                        Ok((rec, ack))
                                    }
                                    Err(e) => Err(format!("invalid padded chat payload from {from}: {e}")),
                                }
                            }
                            Err(e) => Err(format!("rejected packet from {from}: {e}")),
                        }
                    } else {
                        Err(format!("received packet from unpaired peer {from}"))
                    }
                };

                match result {
                    Ok((rec, ack)) => {
                        let _ = ws_out.send(RelayFrame::AckFrame {
                            from: self_id.to_string(),
                            to: from,
                            msg_id,
                            ack,
                        });
                        let _ = events_tx.send(ChatUiEvent::MessageAdded { record: rec });
                    }
                    Err(err_text) => {
                        let _ = events_tx.send(ChatUiEvent::Notice {
                            level: "warn".to_string(),
                            text: err_text,
                        });
                    }
                }
            }
            RelayFrame::AckFrame {
                from, msg_id, ack, ..
            } => {
                let hw = identity.lock().await.hardware_provider().clone();
                let mut guard = inner.write().await;
                let commit_res = if let Some(ps) = guard.sessions.get_mut(&from) {
                    match ps.session.commit_ack(&hw, &ack) {
                        Ok(()) => {
                            if let Some(m) = ps.messages.iter_mut().find(|m| m.msg_id == msg_id) {
                                m.status = "delivered_ack".to_string();
                            }
                            Ok(())
                        }
                        Err(e) => Err(e.to_string()),
                    }
                } else {
                    Err("unknown peer".to_string())
                };
                guard.pending_msg_peer.remove(&msg_id);
                if let Some(tx) = guard.pending_acks.remove(&msg_id) {
                    let _ = tx.send(commit_res.clone());
                }
                if commit_res.is_ok() {
                    let _ = events_tx.send(ChatUiEvent::MessageStatusUpdated {
                        peer_id: from,
                        msg_id,
                        status: "delivered_ack".to_string(),
                    });
                }
            }
            RelayFrame::EpochHopNotice {
                from,
                to,
                new_epoch,
                epoch_eph_pub,
                sender_ed25519_pub,
                signature,
            } => {
                let sign_msg = epoch_hop_sign_bytes(
                    &from,
                    &to,
                    new_epoch,
                    &epoch_eph_pub,
                    &sender_ed25519_pub,
                );
                if to != self_id
                    || !DeviceIdentity::verify_signature(&sender_ed25519_pub, &sign_msg, &signature)
                {
                    let _ = events_tx.send(ChatUiEvent::Notice {
                        level: "security_alert".to_string(),
                        text: format!("REJECTED unsigned/forged EpochHopNotice from '{from}'"),
                    });
                    return;
                }

                let hw = identity.lock().await.hardware_provider().clone();
                let mut guard = inner.write().await;
                if let Some(ps) = guard.sessions.get_mut(&from) {
                    if ps.peer_ed25519_pub != sender_ed25519_pub {
                        let _ = events_tx.send(ChatUiEvent::Notice {
                            level: "security_alert".to_string(),
                            text: format!("REJECTED EpochHopNotice from '{from}': Ed25519 key mismatch"),
                        });
                        return;
                    }
                    if let Err(e) = ps
                        .session
                        .hop_epoch_rx_ratchet(&hw, new_epoch, epoch_eph_pub)
                    {
                        let _ = events_tx.send(ChatUiEvent::Notice {
                            level: "error".to_string(),
                            text: format!("epoch hop sync failed: {e}"),
                        });
                        return;
                    }
                    let _ = events_tx.send(ChatUiEvent::EpochHopped {
                        peer_id: from,
                        direction: "rx".to_string(),
                        new_epoch,
                    });
                }
            }
            RelayFrame::RelayError { code, detail, peer } => {
                let mut guard = inner.write().await;
                if code == "peer_offline" {
                    let matching: Vec<String> = guard
                        .pending_msg_peer
                        .iter()
                        .filter(|(_, target)| peer.as_ref().is_none_or(|p| *target == p))
                        .map(|(mid, _)| mid.clone())
                        .collect();
                    for mid in matching {
                        guard.pending_msg_peer.remove(&mid);
                        if let Some(tx) = guard.pending_acks.remove(&mid) {
                            let _ = tx.send(Err(detail.clone()));
                        }
                    }
                }
                let _ = events_tx.send(ChatUiEvent::Notice {
                    level: "warn".to_string(),
                    text: format!("relay error ({code}): {detail}"),
                });
            }
            RelayFrame::AuthChallenge { .. }
            | RelayFrame::RegisterAuth { .. }
            | RelayFrame::Registered { .. } => {}
        }
    }

    async fn complete_incoming_offer(
        self_id: &str,
        identity: &Arc<Mutex<DeviceIdentity>>,
        inner: &Arc<RwLock<NodeInner>>,
        ws_out: &mpsc::UnboundedSender<RelayFrame>,
        events_tx: &broadcast::Sender<ChatUiEvent>,
        offer: IncomingPairOffer,
        psk: &str,
    ) -> Result<String, String> {
        let (eph_secret, my_pub) = generate_static_x25519()?;
        let (mut init_rx_dh_secret, init_rx_dh_pub) = generate_raw_x25519()?;

        let peer_pub = PublicKey::from(offer.eph_pub);
        let shared_obj = eph_secret.diffie_hellman(&peer_pub);
        if !shared_obj.was_contributory() {
            init_rx_dh_secret.zeroize();
            return Err("rejected non-contributory X25519 PairOffer".to_string());
        }
        let mut shared = shared_obj.to_bytes();

        let id_guard = identity.lock().await;
        let hw = id_guard.hardware_provider().clone();
        let my_ed_pub = id_guard.ed25519_pub();
        let sign_msg = pair_accept_sign_bytes(
            self_id,
            &offer.from,
            &offer.pair_id,
            &offer.eph_pub,
            &my_pub,
            &init_rx_dh_pub,
            &my_ed_pub,
        );
        let accept_sig = id_guard.sign(&sign_msg);
        drop(id_guard);

        let derived = provision_duplex_from_ecdh(
            PairTranscriptParams {
                profile: offer.profile,
                shared_ecdh: &shared,
                psk: psk.as_bytes(),
                pair_id: &offer.pair_id,
                offerer_id: &offer.from,
                accepter_id: self_id,
                offerer_pub: &offer.eph_pub,
                accepter_pub: &my_pub,
                offerer_ed25519_pub: &offer.sender_ed25519_pub,
                accepter_ed25519_pub: &my_ed_pub,
                my_rx_dh_secret: &init_rx_dh_secret,
                my_rx_dh_pub: &init_rx_dh_pub,
                peer_rx_dh_pub: &offer.init_rx_dh_pub,
                is_offerer: false,
            },
            &hw,
        )
        .map_err(|e| e.to_string())?;
        shared.zeroize();
        init_rx_dh_secret.zeroize();

        let fp = derived.safety_fingerprint.clone();
        let peer_ed_hex = hex::encode(offer.sender_ed25519_pub);
        inner.write().await.sessions.insert(
            offer.from.clone(),
            PeerChatSession {
                session: derived.session,
                peer_ed25519_pub: offer.sender_ed25519_pub,
                safety_fingerprint: fp.clone(),
                profile: offer.profile,
                messages: Vec::new(),
            },
        );

        ws_out
            .send(RelayFrame::PairAccept {
                from: self_id.to_string(),
                to: offer.from.clone(),
                pair_id: offer.pair_id,
                eph_pub: my_pub,
                init_rx_dh_pub,
                sender_ed25519_pub: my_ed_pub,
                signature: accept_sig,
            })
            .map_err(|_| "relay channel closed".to_string())?;

        let _ = events_tx.send(ChatUiEvent::Paired {
            peer_id: offer.from,
            peer_ed25519_hex: peer_ed_hex,
            safety_fingerprint: fp.clone(),
            profile: offer.profile,
        });
        Ok(fp)
    }
}

fn generate_raw_x25519() -> Result<([u8; 32], [u8; 32]), String> {
    let mut raw_sk = [0u8; 32];
    getrandom::getrandom(&mut raw_sk).map_err(|e| e.to_string())?;
    let secret = StaticSecret::from(raw_sk);
    let pub_bytes = PublicKey::from(&secret).to_bytes();
    Ok((raw_sk, pub_bytes))
}

fn generate_static_x25519() -> Result<(StaticSecret, [u8; 32]), String> {
    let mut raw_sk = [0u8; 32];
    getrandom::getrandom(&mut raw_sk).map_err(|e| e.to_string())?;
    let secret = StaticSecret::from(raw_sk);
    raw_sk.zeroize();
    let pub_bytes = PublicKey::from(&secret).to_bytes();
    Ok((secret, pub_bytes))
}

impl Drop for ChatNode {
    fn drop(&mut self) {
        if Arc::strong_count(&self.ws_task) == 1 {
            self.ws_task.abort();
        }
    }
}
