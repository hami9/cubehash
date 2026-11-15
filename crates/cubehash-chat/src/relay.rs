use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cubehash_core::PayloadMode;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::keystore::DeviceIdentity;
use crate::protocol::{
    auth_challenge_sign_bytes, epoch_hop_sign_bytes, pair_offer_sign_bytes, PeerIdentity,
    RelayFrame, RelayTrafficEvent,
};
use crate::tls::{BuiltRelayTls, RelayTlsConfig};

const MAX_TELEMETRY_HISTORY: usize = 100;
const AUTH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

struct ClientEntry {
    conn_id: u64,
    ed25519_pub: [u8; 32],
    tx: mpsc::UnboundedSender<WsMessage>,
}

/// Shared state for the zero-knowledge TLS blind relay server.
///
/// Holds ONLY active WebSocket routing handles, authenticated Ed25519 public identity pins,
/// and sanitized opaque wire metadata. Never stores encryption keys, `MotherCube` material, or plaintext.
#[derive(Clone, Default)]
pub struct BlindRelayState {
    clients: Arc<RwLock<HashMap<String, ClientEntry>>>,
    pinned_identities: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    telemetry: Arc<RwLock<VecDeque<RelayTrafficEvent>>>,
    seq_counter: Arc<AtomicU64>,
    conn_counter: Arc<AtomicU64>,
}

#[derive(Serialize)]
pub struct TelemetrySnapshot {
    pub online_peers: Vec<String>,
    pub total_routed_frames: u64,
    pub recent_frames: Vec<RelayTrafficEvent>,
}

/// Handle and TLS metadata returned when starting the blind relay server.
pub struct StartedRelay {
    pub addr: SocketAddr,
    pub is_tls: bool,
    pub tls_cert_sha256_hex: Option<String>,
    pub tls_cert_pem: Option<String>,
    pub state: BlindRelayState,
    pub handle: tokio::task::JoinHandle<()>,
}

impl BlindRelayState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn snapshot(&self) -> TelemetrySnapshot {
        let mut peers: Vec<String> = self.clients.read().await.keys().cloned().collect();
        peers.sort();
        let events: Vec<RelayTrafficEvent> =
            self.telemetry.read().await.iter().cloned().collect();
        TelemetrySnapshot {
            online_peers: peers,
            total_routed_frames: self.seq_counter.load(Ordering::Relaxed),
            recent_frames: events,
        }
    }

    async fn record_event(&self, mut event: RelayTrafficEvent) {
        event.seq = self.seq_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let mut guard = self.telemetry.write().await;
        if guard.len() >= MAX_TELEMETRY_HISTORY {
            guard.pop_front();
        }
        guard.push_back(event);
    }

    async fn current_peer_identities(&self) -> Vec<PeerIdentity> {
        let clients = self.clients.read().await;
        let mut peers: Vec<PeerIdentity> = clients
            .iter()
            .map(|(cid, entry)| PeerIdentity {
                client_id: cid.clone(),
                ed25519_pub: entry.ed25519_pub,
            })
            .collect();
        peers.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        peers
    }

    async fn broadcast_peer_list(&self) {
        let peers = self.current_peer_identities().await;
        let payload = match serde_json::to_string(&RelayFrame::PeerList {
            online_peers: peers,
        }) {
            Ok(p) => p,
            Err(_) => return,
        };
        let clients = self.clients.read().await;
        for entry in clients.values() {
            let _ = entry.tx.send(WsMessage::Text(payload.clone().into()));
        }
    }

    async fn forward_to(&self, from: &str, to: &str, raw_json: String) {
        let target = self.clients.read().await.get(to).map(|e| e.tx.clone());
        match target {
            Some(tx) => {
                let _ = tx.send(WsMessage::Text(raw_json.into()));
            }
            None => {
                if let Some(sender) = self.clients.read().await.get(from).map(|e| e.tx.clone()) {
                    let err = RelayFrame::RelayError {
                        code: "peer_offline".to_string(),
                        detail: format!("recipient '{to}' is not connected"),
                        peer: Some(to.to_string()),
                    };
                    if let Ok(txt) = serde_json::to_string(&err) {
                        let _ = sender.send(WsMessage::Text(txt.into()));
                    }
                }
            }
        }
    }
}

/// Starts the zero-knowledge WebSocket relay server on `addr` using the supplied TLS config.
pub async fn start_relay_server(
    addr: SocketAddr,
    tls_config: RelayTlsConfig,
) -> std::io::Result<StartedRelay> {
    let built_tls = BuiltRelayTls::build(tls_config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let state = BlindRelayState::new();
    let is_tls = built_tls.acceptor.is_some();
    let cert_sha256_hex = built_tls.cert_sha256.map(hex::encode);
    let cert_pem = built_tls.cert_pem.clone();
    let acceptor = built_tls.acceptor.clone();
    let state_clone = state.clone();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((tcp, _peer_addr)) = listener.accept().await else {
                continue;
            };
            let state_task = state_clone.clone();
            let acceptor_task = acceptor.clone();
            tokio::spawn(async move {
                match acceptor_task {
                    Some(tls) => {
                        if let Ok(tls_stream) = tls.accept(tcp).await {
                            if let Ok(ws_stream) = accept_async(tls_stream).await {
                                handle_socket(ws_stream, state_task).await;
                            }
                        }
                    }
                    None => {
                        if let Ok(ws_stream) = accept_async(tcp).await {
                            handle_socket(ws_stream, state_task).await;
                        }
                    }
                }
            });
        }
    });

    Ok(StartedRelay {
        addr: local_addr,
        is_tls,
        tls_cert_sha256_hex: cert_sha256_hex,
        tls_cert_pem: cert_pem,
        state,
        handle,
    })
}

async fn send_error(tx: &mpsc::UnboundedSender<WsMessage>, code: &str, detail: &str) {
    let err = RelayFrame::RelayError {
        code: code.to_string(),
        detail: detail.to_string(),
        peer: None,
    };
    if let Ok(txt) = serde_json::to_string(&err) {
        let _ = tx.send(WsMessage::Text(txt.into()));
    }
}

async fn handle_socket<S>(ws_stream: tokio_tungstenite::WebSocketStream<S>, state: BlindRelayState)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn_id = state.conn_counter.fetch_add(1, Ordering::Relaxed) + 1;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<WsMessage>();

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // 1. Issue fresh random Ed25519 challenge immediately upon connection.
    let mut challenge_nonce = [0u8; 32];
    if getrandom::getrandom(&mut challenge_nonce).is_err() {
        writer_task.abort();
        return;
    }
    let challenge = RelayFrame::AuthChallenge {
        nonce: challenge_nonce,
    };
    if let Ok(txt) = serde_json::to_string(&challenge) {
        if tx.send(WsMessage::Text(txt.into())).is_err() {
            writer_task.abort();
            return;
        }
    }

    // 2. Require authenticated RegisterAuth before permitting any routing.
    let mut authed: Option<(String, [u8; 32])> = None;
    let auth_deadline = tokio::time::Instant::now() + AUTH_HANDSHAKE_TIMEOUT;

    loop {
        let remaining = auth_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            send_error(&tx, "auth_timeout", "Ed25519 registration timed out").await;
            break;
        }
        let Ok(next_item) = tokio::time::timeout(remaining, ws_rx.next()).await else {
            send_error(&tx, "auth_timeout", "Ed25519 registration timed out").await;
            break;
        };
        let Some(Ok(msg)) = next_item else {
            break;
        };
        let WsMessage::Text(text) = msg else {
            continue;
        };
        let Ok(frame) = serde_json::from_str::<RelayFrame>(&text) else {
            continue;
        };

        match frame {
            RelayFrame::RegisterAuth {
                client_id,
                ed25519_pub,
                signature,
            } => {
                let clean_id = client_id.trim().to_string();
                if clean_id.is_empty() || clean_id.len() > 64 {
                    send_error(&tx, "invalid_id", "client_id must be 1..=64 chars").await;
                    break;
                }
                let sign_msg = auth_challenge_sign_bytes(&challenge_nonce, &clean_id);
                if !DeviceIdentity::verify_signature(&ed25519_pub, &sign_msg, &signature) {
                    send_error(&tx, "auth_failed", "invalid Ed25519 challenge signature").await;
                    break;
                }

                // Check identity pin to block offline/online impersonation of an existing client_id.
                {
                    let mut pins = state.pinned_identities.write().await;
                    if let Some(existing_pub) = pins.get(&clean_id) {
                        if existing_pub != &ed25519_pub {
                            send_error(
                                &tx,
                                "identity_mismatch",
                                "client_id is pinned to a different Ed25519 key",
                            )
                            .await;
                            break;
                        }
                    } else {
                        pins.insert(clean_id.clone(), ed25519_pub);
                    }
                }

                // Refuse hijacking an active session with the same client_id.
                {
                    let mut clients = state.clients.write().await;
                    if clients.contains_key(&clean_id) {
                        send_error(&tx, "id_in_use", "client_id is already active on relay").await;
                        break;
                    }
                    clients.insert(
                        clean_id.clone(),
                        ClientEntry {
                            conn_id,
                            ed25519_pub,
                            tx: tx.clone(),
                        },
                    );
                }

                authed = Some((clean_id.clone(), ed25519_pub));
                let peers = state.current_peer_identities().await;
                let reg = RelayFrame::Registered {
                    client_id: clean_id,
                    online_peers: peers,
                };
                if let Ok(txt) = serde_json::to_string(&reg) {
                    let _ = tx.send(WsMessage::Text(txt.into()));
                }
                state.broadcast_peer_list().await;
                break;
            }
            _ => {
                send_error(
                    &tx,
                    "unauthenticated",
                    "complete RegisterAuth before sending frames",
                )
                .await;
            }
        }
    }

    let Some((authed_id, authed_pub)) = authed else {
        // Allow error frame to flush before cancelling writer task.
        tokio::time::sleep(Duration::from_millis(25)).await;
        writer_task.abort();
        return;
    };

    // 3. Authenticated frame forwarding loop (enforces sender ownership on every frame).
    while let Some(Ok(msg)) = ws_rx.next().await {
        let WsMessage::Text(text) = msg else {
            continue;
        };
        let Ok(frame) = serde_json::from_str::<RelayFrame>(&text) else {
            continue;
        };

        let claimed_from = match &frame {
            RelayFrame::PairOffer { from, .. }
            | RelayFrame::PairAccept { from, .. }
            | RelayFrame::EncryptedPacket { from, .. }
            | RelayFrame::AckFrame { from, .. }
            | RelayFrame::EpochHopNotice { from, .. } => Some(from.as_str()),
            _ => None,
        };

        if let Some(sender) = claimed_from {
            if sender != authed_id {
                send_error(
                    &tx,
                    "spoofed_sender",
                    "frame 'from' does not match authenticated Ed25519 identity",
                )
                .await;
                continue;
            }
        }

        match &frame {
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
                    from,
                    to,
                    pair_id,
                    eph_pub,
                    init_rx_dh_pub,
                    sender_ed25519_pub,
                    *profile,
                    *has_psk,
                );
                if sender_ed25519_pub != &authed_pub
                    || !DeviceIdentity::verify_signature(sender_ed25519_pub, &sign_msg, signature)
                {
                    send_error(&tx, "bad_signature", "PairOffer failed Ed25519 verification").await;
                    continue;
                }
                state
                    .record_event(RelayTrafficEvent {
                        seq: 0,
                        frame_type: "PairOffer (Ed25519+X25519)".to_string(),
                        from: from.clone(),
                        to: to.clone(),
                        wire_fingerprint_hex: None,
                        wire_base_bytes: None,
                        wire_total_bytes: None,
                        ciphertext_bytes: None,
                    })
                    .await;
                state.forward_to(from, to, text.to_string()).await;
            }
            RelayFrame::PairAccept {
                from,
                to,
                sender_ed25519_pub,
                ..
            } => {
                if sender_ed25519_pub != &authed_pub {
                    send_error(&tx, "bad_signature", "PairAccept Ed25519 key mismatch").await;
                    continue;
                }
                state
                    .record_event(RelayTrafficEvent {
                        seq: 0,
                        frame_type: "PairAccept (Ed25519+X25519)".to_string(),
                        from: from.clone(),
                        to: to.clone(),
                        wire_fingerprint_hex: None,
                        wire_base_bytes: None,
                        wire_total_bytes: None,
                        ciphertext_bytes: None,
                    })
                    .await;
                state.forward_to(from, to, text.to_string()).await;
            }
            RelayFrame::EncryptedPacket {
                from, to, packet, ..
            } => {
                let ct_bytes = match &packet.payload_mode {
                    PayloadMode::RawCore256 => Some(0),
                    PayloadMode::ArbitraryCiphertext { ciphertext } => Some(ciphertext.len()),
                };
                state
                    .record_event(RelayTrafficEvent {
                        seq: 0,
                        frame_type: if matches!(packet.payload_mode, PayloadMode::RawCore256) {
                            "WirePacket (RawCore256)".to_string()
                        } else {
                            "WirePacket (ArbitraryAEAD)".to_string()
                        },
                        from: from.clone(),
                        to: to.clone(),
                        wire_fingerprint_hex: Some(hex::encode(packet.wire_cube.cube_fingerprint)),
                        wire_base_bytes: Some(packet.wire_cube.base_byte_len()),
                        wire_total_bytes: Some(packet.wire_cube.total_byte_len()),
                        ciphertext_bytes: ct_bytes,
                    })
                    .await;
                state.forward_to(from, to, text.to_string()).await;
            }
            RelayFrame::AckFrame { from, to, ack, .. } => {
                state
                    .record_event(RelayTrafficEvent {
                        seq: 0,
                        frame_type: "DeliveryAck".to_string(),
                        from: from.clone(),
                        to: to.clone(),
                        wire_fingerprint_hex: Some(hex::encode(ack.cube_fingerprint)),
                        wire_base_bytes: None,
                        wire_total_bytes: None,
                        ciphertext_bytes: None,
                    })
                    .await;
                state.forward_to(from, to, text.to_string()).await;
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
                    from,
                    to,
                    *new_epoch,
                    epoch_eph_pub,
                    sender_ed25519_pub,
                );
                if sender_ed25519_pub != &authed_pub
                    || !DeviceIdentity::verify_signature(sender_ed25519_pub, &sign_msg, signature)
                {
                    send_error(
                        &tx,
                        "bad_signature",
                        "EpochHopNotice failed Ed25519 verification",
                    )
                    .await;
                    continue;
                }
                state
                    .record_event(RelayTrafficEvent {
                        seq: 0,
                        frame_type: "EpochHopNotice (Signed+DH)".to_string(),
                        from: from.clone(),
                        to: to.clone(),
                        wire_fingerprint_hex: None,
                        wire_base_bytes: None,
                        wire_total_bytes: None,
                        ciphertext_bytes: None,
                    })
                    .await;
                state.forward_to(from, to, text.to_string()).await;
            }
            RelayFrame::AuthChallenge { .. }
            | RelayFrame::RegisterAuth { .. }
            | RelayFrame::Registered { .. }
            | RelayFrame::PeerList { .. }
            | RelayFrame::RelayError { .. } => {}
        }
    }

    {
        let mut guard = state.clients.write().await;
        if guard.get(&authed_id).is_some_and(|e| e.conn_id == conn_id) {
            guard.remove(&authed_id);
        }
    }
    state.broadcast_peer_list().await;
    writer_task.abort();
}
