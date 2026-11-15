use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cubehash_core::{
    HardwareProvider, HoneyProfile, MeshAuditStats, OsBoundHardwareProvider, PayloadMode,
    ReceiveOutcome, UniqueWireCube, WirePacket,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::protocol::{
    provision_duplex_from_ecdh, ChatMeshProfile, PairTranscriptParams, RelayFrame,
};

const ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// A single message entry displayed in the client chat log.
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

/// Public snapshot of a paired peer session for CLI and Web UI inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSummary {
    pub peer_id: String,
    pub safety_fingerprint: String,
    pub profile: ChatMeshProfile,
    pub tx_stats: MeshAuditStats,
    pub rx_stats: MeshAuditStats,
    pub messages: Vec<ChatRecord>,
}

/// Real-time events broadcast to the Terminal CLI and Local Web UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ChatUiEvent {
    PeersUpdated {
        online_peers: Vec<String>,
    },
    Paired {
        peer_id: String,
        safety_fingerprint: String,
        profile: ChatMeshProfile,
    },
    IncomingPairRequest {
        from: String,
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

struct PendingPairOut {
    peer_id: String,
    secret: StaticSecret,
    pub_bytes: [u8; 32],
    profile: ChatMeshProfile,
    psk: String,
}

struct IncomingPairOffer {
    from: String,
    pair_id: String,
    eph_pub: [u8; 32],
    profile: ChatMeshProfile,
    #[allow(dead_code)]
    has_psk: bool,
}

struct PeerChatSession {
    session: cubehash_core::DuplexCubeSession,
    safety_fingerprint: String,
    profile: ChatMeshProfile,
    messages: Vec<ChatRecord>,
}

struct NodeInner {
    online_peers: Vec<String>,
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

/// Hardware-bound CubeHash chat client connected to a blind WebSocket relay.
#[derive(Clone)]
pub struct ChatNode {
    client_id: String,
    hw: Arc<OsBoundHardwareProvider>,
    inner: Arc<RwLock<NodeInner>>,
    ws_out: mpsc::UnboundedSender<RelayFrame>,
    events_tx: broadcast::Sender<ChatUiEvent>,
    id_counter: Arc<AtomicU64>,
    ws_task: Arc<tokio::task::JoinHandle<()>>,
}

impl ChatNode {
    /// Connects to the blind relay at `relay_ws_url` and registers `client_id`.
    pub async fn connect(
        client_id: impl Into<String>,
        relay_ws_url: &str,
        device_secret: [u8; 32],
    ) -> Result<Self, String> {
        let client_id = client_id.into();
        let hw = Arc::new(OsBoundHardwareProvider::from_host_and_secret(
            &device_secret,
            client_id.as_bytes(),
        ));

        let (ws_stream, _) = connect_async(relay_ws_url)
            .await
            .map_err(|e| format!("failed to connect to relay {relay_ws_url}: {e}"))?;
        let (mut ws_sink, mut ws_rx) = ws_stream.split();

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<RelayFrame>();
        let (events_tx, _) = broadcast::channel(128);
        let inner = Arc::new(RwLock::new(NodeInner::new()));

        let reg = RelayFrame::Register {
            client_id: client_id.clone(),
        };
        let reg_txt = serde_json::to_string(&reg).map_err(|e| e.to_string())?;
        ws_sink
            .send(WsMessage::Text(reg_txt.into()))
            .await
            .map_err(|e| format!("failed to register on relay: {e}"))?;

        let inner_clone = Arc::clone(&inner);
        let hw_clone = Arc::clone(&hw);
        let out_tx_clone = out_tx.clone();
        let events_clone = events_tx.clone();
        let cid_clone = client_id.clone();

        let ws_task = tokio::spawn(async move {
            let writer = tokio::spawn(async move {
                while let Some(frame) = out_rx.recv().await {
                    if let Ok(txt) = serde_json::to_string(&frame) {
                        if ws_sink.send(WsMessage::Text(txt.into())).await.is_err() {
                            break;
                        }
                    }
                }
            });

            while let Some(Ok(msg)) = ws_rx.next().await {
                let WsMessage::Text(txt) = msg else {
                    continue;
                };
                let Ok(frame) = serde_json::from_str::<RelayFrame>(&txt) else {
                    continue;
                };
                Self::handle_relay_frame(
                    &cid_clone,
                    &hw_clone,
                    &inner_clone,
                    &out_tx_clone,
                    &events_clone,
                    frame,
                )
                .await;
            }
            writer.abort();
        });

        Ok(Self {
            client_id,
            hw,
            inner,
            ws_out: out_tx,
            events_tx,
            id_counter: Arc::new(AtomicU64::new(1)),
            ws_task: Arc::new(ws_task),
        })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn device_hw_id_hex(&self) -> String {
        hex::encode(self.hw.device_hw_id())
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

    pub async fn online_peers(&self) -> Vec<String> {
        self.inner
            .read()
            .await
            .online_peers
            .iter()
            .filter(|p| *p != &self.client_id)
            .cloned()
            .collect()
    }

    pub async fn paired_summaries(&self) -> Vec<PeerSummary> {
        let guard = self.inner.read().await;
        let mut out: Vec<PeerSummary> = guard
            .sessions
            .iter()
            .map(|(peer_id, ps)| PeerSummary {
                peer_id: peer_id.clone(),
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

    /// Initiates an ephemeral X25519 key exchange over the blind relay to provision a paired
    /// `DuplexCubeSession` with `peer_id`.
    pub async fn initiate_pair(
        &self,
        peer_id: &str,
        psk: Option<&str>,
        profile: ChatMeshProfile,
    ) -> Result<String, String> {
        if peer_id == self.client_id {
            return Err("cannot pair with yourself".to_string());
        }
        let mut raw_sk = [0u8; 32];
        getrandom::getrandom(&mut raw_sk).map_err(|e| e.to_string())?;
        let secret = StaticSecret::from(raw_sk);
        raw_sk.zeroize();
        let pub_bytes = PublicKey::from(&secret).to_bytes();

        let seq = self.id_counter.fetch_add(1, Ordering::Relaxed);
        let pair_id = format!("{}-{}-{}", self.client_id, peer_id, seq);
        let psk_str = psk.unwrap_or("").to_string();
        let has_psk = !psk_str.is_empty();

        self.inner.write().await.pending_offers_out.insert(
            pair_id.clone(),
            PendingPairOut {
                peer_id: peer_id.to_string(),
                secret,
                pub_bytes,
                profile,
                psk: psk_str,
            },
        );

        self.ws_out
            .send(RelayFrame::PairOffer {
                from: self.client_id.clone(),
                to: peer_id.to_string(),
                pair_id: pair_id.clone(),
                eph_pub: pub_bytes,
                profile,
                has_psk,
            })
            .map_err(|_| "relay channel closed".to_string())?;

        Ok(pair_id)
    }

    /// Explicitly accepts a pending PIN-protected pairing request from `peer_id`.
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
            &self.hw,
            &self.inner,
            &self.ws_out,
            &self.events_tx,
            offer,
            psk,
        )
        .await
    }

    /// Sends a message (or compact <=24B `RawCore256` payload) and awaits receiver `DeliveryAck`.
    /// On timeout or offline peer, rolls back the sender's cellular mesh cleanly!
    pub async fn send_message(
        &self,
        peer_id: &str,
        text: &str,
        raw_core_mode: bool,
    ) -> Result<ChatRecord, String> {
        self.send_with_noise(peer_id, text, raw_core_mode, 0).await
    }

    /// Sends a message with optional simulated wire bit-rot (`flip_bytes` bytes flipped across
    /// non-overlapping offsets of `partial_256b` and `partial_1000b` shadow) to demonstrate
    /// live Bitwise Majority Voting (TMR) recovery across the WebSocket relay.
    pub async fn send_with_noise(
        &self,
        peer_id: &str,
        text: &str,
        raw_core_mode: bool,
        flip_bytes: usize,
    ) -> Result<ChatRecord, String> {
        let msg_seq = self.id_counter.fetch_add(1, Ordering::Relaxed);
        let msg_id = format!("msg-{}-{msg_seq}", self.client_id);

        let (packet, rx_ack, wire_bytes, mode_label) = {
            let mut guard = self.inner.write().await;
            let ps = guard
                .sessions
                .get_mut(peer_id)
                .ok_or_else(|| format!("not paired with '{peer_id}'; pair first"))?;

            let mut pkt = if raw_core_mode {
                ps.session
                    .begin_send_raw_core(&*self.hw, text.as_bytes())
                    .map_err(|e| e.to_string())?
            } else {
                ps.session
                    .begin_send_message(&*self.hw, text.as_bytes())
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

    /// Triggers synchronized Bijective Epoch Hopping on `tx` mesh and notifies `peer_id`.
    pub async fn hop_epoch(&self, peer_id: &str) -> Result<u64, String> {
        let new_epoch = {
            let mut guard = self.inner.write().await;
            let ps = guard
                .sessions
                .get_mut(peer_id)
                .ok_or_else(|| format!("not paired with '{peer_id}'"))?;
            ps.session.tx.hop_epoch(&*self.hw).map_err(|e| e.to_string())?
        };
        self.ws_out
            .send(RelayFrame::EpochHopNotice {
                from: self.client_id.clone(),
                to: peer_id.to_string(),
                new_epoch,
            })
            .map_err(|_| "relay channel closed".to_string())?;
        let _ = self.events_tx.send(ChatUiEvent::EpochHopped {
            peer_id: peer_id.to_string(),
            direction: "tx".to_string(),
            new_epoch,
        });
        Ok(new_epoch)
    }

    /// Runs `decrypt_zero_oracle` against a tampered probe on `peer_id`'s RX mesh to demonstrate
    /// Honey DTE output without mutating or desyncing the live chat mesh.
    pub async fn simulate_honey_probe(&self, peer_id: &str) -> Result<String, String> {
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
            payload_mode: PayloadMode::RawCore256,
            packet_mac: [0xFFu8; 32],
        };

        match ps
            .session
            .decrypt_zero_oracle(&*self.hw, &forged, HoneyProfile::ChatPlaintext)
        {
            ReceiveOutcome::HoneyDeception {
                plausible_output, ..
            } => {
                let txt = String::from_utf8_lossy(&plausible_output).to_string();
                let _ = self.events_tx.send(ChatUiEvent::HoneyProbeResult {
                    peer_id: peer_id.to_string(),
                    outcome: "HoneyDeception (zero error oracle, zero desync)".to_string(),
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
        hw: &Arc<OsBoundHardwareProvider>,
        inner: &Arc<RwLock<NodeInner>>,
        ws_out: &mpsc::UnboundedSender<RelayFrame>,
        events_tx: &broadcast::Sender<ChatUiEvent>,
        frame: RelayFrame,
    ) {
        match frame {
            RelayFrame::Registered { online_peers, .. }
            | RelayFrame::PeerList { online_peers } => {
                let filtered: Vec<String> = online_peers
                    .into_iter()
                    .filter(|p| p != self_id)
                    .collect();
                inner.write().await.online_peers = filtered.clone();
                let _ = events_tx.send(ChatUiEvent::PeersUpdated {
                    online_peers: filtered,
                });
            }
            RelayFrame::PairOffer {
                from,
                pair_id,
                eph_pub,
                profile,
                has_psk,
                ..
            } => {
                let preset = inner.read().await.preset_psks.get(&from).cloned();
                let offer = IncomingPairOffer {
                    from: from.clone(),
                    pair_id: pair_id.clone(),
                    eph_pub,
                    profile,
                    has_psk,
                };
                if !has_psk || preset.is_some() {
                    let psk = preset.unwrap_or_default();
                    let _ = Self::complete_incoming_offer(
                        self_id, hw, inner, ws_out, events_tx, offer, &psk,
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
                        pair_id,
                        profile,
                        has_psk,
                    });
                }
            }
            RelayFrame::PairAccept {
                from,
                pair_id,
                eph_pub,
                ..
            } => {
                let pending = inner.write().await.pending_offers_out.remove(&pair_id);
                let Some(p) = pending else {
                    return;
                };
                let peer_pub = PublicKey::from(eph_pub);
                let mut shared = p.secret.diffie_hellman(&peer_pub).to_bytes();
                match provision_duplex_from_ecdh(
                    PairTranscriptParams {
                        profile: p.profile,
                        shared_ecdh: &shared,
                        psk: p.psk.as_bytes(),
                        pair_id: &pair_id,
                        offerer_id: self_id,
                        accepter_id: &from,
                        offerer_pub: &p.pub_bytes,
                        accepter_pub: &eph_pub,
                        is_offerer: true,
                    },
                    &**hw,
                ) {
                    Ok(derived) => {
                        let fp = derived.safety_fingerprint.clone();
                        inner.write().await.sessions.insert(
                            p.peer_id.clone(),
                            PeerChatSession {
                                session: derived.session,
                                safety_fingerprint: fp.clone(),
                                profile: p.profile,
                                messages: Vec::new(),
                            },
                        );
                        let _ = events_tx.send(ChatUiEvent::Paired {
                            peer_id: p.peer_id,
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
                let wire_bytes = packet.wire_cube.total_byte_len();
                let mode_str = if matches!(packet.payload_mode, PayloadMode::RawCore256) {
                    "RawCore256"
                } else {
                    "ArbitraryAEAD"
                };

                let result = {
                    let mut guard = inner.write().await;
                    if let Some(ps) = guard.sessions.get_mut(&from) {
                        match ps.session.receive_authenticated(&**hw, &mut packet) {
                            Ok((pt, ack, healed_bits)) => {
                                let text = String::from_utf8_lossy(&pt).to_string();
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
                let mut guard = inner.write().await;
                let commit_res = if let Some(ps) = guard.sessions.get_mut(&from) {
                    match ps.session.commit_ack(&**hw, &ack) {
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
                from, new_epoch, ..
            } => {
                let mut guard = inner.write().await;
                if let Some(ps) = guard.sessions.get_mut(&from) {
                    while ps.session.rx.epoch() < new_epoch {
                        if let Err(e) = ps.session.rx.hop_epoch(&**hw) {
                            let _ = events_tx.send(ChatUiEvent::Notice {
                                level: "error".to_string(),
                                text: format!("epoch hop sync failed: {e}"),
                            });
                            return;
                        }
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
            RelayFrame::Register { .. } => {}
        }
    }

    async fn complete_incoming_offer(
        self_id: &str,
        hw: &Arc<OsBoundHardwareProvider>,
        inner: &Arc<RwLock<NodeInner>>,
        ws_out: &mpsc::UnboundedSender<RelayFrame>,
        events_tx: &broadcast::Sender<ChatUiEvent>,
        offer: IncomingPairOffer,
        psk: &str,
    ) -> Result<String, String> {
        let mut raw_sk = [0u8; 32];
        getrandom::getrandom(&mut raw_sk).map_err(|e| e.to_string())?;
        let secret = StaticSecret::from(raw_sk);
        raw_sk.zeroize();
        let my_pub = PublicKey::from(&secret).to_bytes();

        let peer_pub = PublicKey::from(offer.eph_pub);
        let mut shared = secret.diffie_hellman(&peer_pub).to_bytes();
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
                is_offerer: false,
            },
            &**hw,
        )
        .map_err(|e| e.to_string())?;
        shared.zeroize();

        let fp = derived.safety_fingerprint.clone();
        inner.write().await.sessions.insert(
            offer.from.clone(),
            PeerChatSession {
                session: derived.session,
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
            })
            .map_err(|_| "relay channel closed".to_string())?;

        let _ = events_tx.send(ChatUiEvent::Paired {
            peer_id: offer.from,
            safety_fingerprint: fp.clone(),
            profile: offer.profile,
        });
        Ok(fp)
    }
}

impl Drop for ChatNode {
    fn drop(&mut self) {
        if Arc::strong_count(&self.ws_task) == 1 {
            self.ws_task.abort();
        }
    }
}
