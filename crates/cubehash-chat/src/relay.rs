use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use cubehash_core::PayloadMode;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};

use crate::protocol::{RelayFrame, RelayTrafficEvent};

const MAX_TELEMETRY_HISTORY: usize = 100;

/// Shared state for the zero-knowledge blind relay server.
///
/// Holds ONLY active WebSocket routing handles and sanitized opaque wire metadata.
/// Never stores keys, `MotherCube` material, or plaintext.
#[derive(Clone, Default)]
pub struct BlindRelayState {
    clients: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<Message>>>>,
    telemetry: Arc<RwLock<VecDeque<RelayTrafficEvent>>>,
    seq_counter: Arc<AtomicU64>,
}

#[derive(Serialize)]
pub struct TelemetrySnapshot {
    pub online_peers: Vec<String>,
    pub total_routed_frames: u64,
    pub recent_frames: Vec<RelayTrafficEvent>,
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

    async fn broadcast_peer_list(&self) {
        let clients = self.clients.read().await;
        let mut online_peers: Vec<String> = clients.keys().cloned().collect();
        online_peers.sort();
        let payload = match serde_json::to_string(&RelayFrame::PeerList { online_peers }) {
            Ok(p) => p,
            Err(_) => return,
        };
        for tx in clients.values() {
            let _ = tx.send(Message::Text(payload.clone().into()));
        }
    }

    async fn forward_to(&self, from: &str, to: &str, raw_json: String) {
        let target = self.clients.read().await.get(to).cloned();
        match target {
            Some(tx) => {
                let _ = tx.send(Message::Text(raw_json.into()));
            }
            None => {
                if let Some(sender_tx) = self.clients.read().await.get(from).cloned() {
                    let err = RelayFrame::RelayError {
                        code: "peer_offline".to_string(),
                        detail: format!("recipient '{to}' is not connected"),
                        peer: Some(to.to_string()),
                    };
                    if let Ok(txt) = serde_json::to_string(&err) {
                        let _ = sender_tx.send(Message::Text(txt.into()));
                    }
                }
            }
        }
    }
}

/// Builds the Axum router for the blind WebSocket relay + zero-knowledge traffic inspector.
pub fn build_relay_router(state: BlindRelayState) -> Router {
    Router::new()
        .route("/", get(inspector_page))
        .route("/health", get(|| async { "ok" }))
        .route("/api/telemetry", get(telemetry_handler))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

/// Starts the blind WebSocket relay server on `addr`, returning the bound `SocketAddr`.
pub async fn start_relay_server(
    addr: SocketAddr,
) -> std::io::Result<(SocketAddr, BlindRelayState, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let state = BlindRelayState::new();
    let app = build_relay_router(state.clone());
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((local_addr, state, handle))
}

async fn telemetry_handler(State(state): State<BlindRelayState>) -> Json<TelemetrySnapshot> {
    Json(state.snapshot().await)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<BlindRelayState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: BlindRelayState) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut client_id: Option<String> = None;

    while let Some(Ok(msg)) = ws_rx.next().await {
        let Message::Text(text) = msg else {
            continue;
        };
        let Ok(frame) = serde_json::from_str::<RelayFrame>(&text) else {
            continue;
        };

        match &frame {
            RelayFrame::Register { client_id: cid } => {
                let clean_id = cid.trim().to_string();
                if clean_id.is_empty() {
                    continue;
                }
                {
                    let mut guard = state.clients.write().await;
                    guard.insert(clean_id.clone(), tx.clone());
                }
                client_id = Some(clean_id.clone());

                let mut peers: Vec<String> = state.clients.read().await.keys().cloned().collect();
                peers.sort();
                let reg = RelayFrame::Registered {
                    client_id: clean_id,
                    online_peers: peers,
                };
                if let Ok(txt) = serde_json::to_string(&reg) {
                    let _ = tx.send(Message::Text(txt.into()));
                }
                state.broadcast_peer_list().await;
            }
            RelayFrame::PairOffer { from, to, .. } => {
                state
                    .record_event(RelayTrafficEvent {
                        seq: 0,
                        frame_type: "PairOffer (X25519)".to_string(),
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
            RelayFrame::PairAccept { from, to, .. } => {
                state
                    .record_event(RelayTrafficEvent {
                        seq: 0,
                        frame_type: "PairAccept (X25519)".to_string(),
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
            RelayFrame::EpochHopNotice { from, to, .. } => {
                state
                    .record_event(RelayTrafficEvent {
                        seq: 0,
                        frame_type: "EpochHopNotice".to_string(),
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
            RelayFrame::Registered { .. }
            | RelayFrame::PeerList { .. }
            | RelayFrame::RelayError { .. } => {}
        }
    }

    if let Some(cid) = client_id {
        state.clients.write().await.remove(&cid);
        state.broadcast_peer_list().await;
    }
    writer_task.abort();
}

async fn inspector_page() -> Html<&'static str> {
    Html(RELAY_INSPECTOR_HTML)
}

const RELAY_INSPECTOR_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>CubeHash Blind Relay Inspector</title>
<style>
  body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #0b1020; color: #e2e8f0; margin: 0; padding: 24px; }
  .card { background: #131b31; border: 1px solid #243154; border-radius: 12px; padding: 18px; margin-bottom: 18px; }
  h1 { margin: 0 0 8px; font-size: 20px; color: #38bdf8; }
  .badge { display: inline-block; background: #0f3a2e; color: #34d399; padding: 4px 10px; border-radius: 999px; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #243154; }
  th { color: #94a3b8; }
</style>
</head>
<body>
  <div class="card">
    <h1>CubeHash Zero-Knowledge Blind Relay</h1>
    <span class="badge">Zero Keys • Zero Plaintext • Opaque WireCube Routing Only</span>
    <p id="peers" style="margin-top:12px;color:#cbd5e1;">Loading peers...</p>
  </div>
  <div class="card">
    <h2 style="margin-top:0;font-size:15px;color:#93c5fd;">Recent Routed Wire Frames</h2>
    <table>
      <thead><tr><th>#</th><th>Type</th><th>From</th><th>To</th><th>WireCube Fingerprint</th><th>Base/Total B</th><th>CT B</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
<script>
async function refresh() {
  const res = await fetch('/api/telemetry');
  const data = await res.json();
  document.getElementById('peers').textContent = 'Online peers (' + data.online_peers.length + '): ' + (data.online_peers.join(', ') || 'none') + ' | Total frames: ' + data.total_routed_frames;
  const tbody = document.getElementById('rows');
  tbody.innerHTML = data.recent_frames.slice().reverse().map(f =>
    `<tr><td>${f.seq}</td><td>${f.frame_type}</td><td>${f.from}</td><td>${f.to}</td><td>${f.wire_fingerprint_hex || '-'}</td><td>${f.wire_base_bytes ? f.wire_base_bytes + '/' + f.wire_total_bytes : '-'}</td><td>${f.ciphertext_bytes ?? '-'}</td></tr>`
  ).join('');
}
refresh();
setInterval(refresh, 1000);
</script>
</body>
</html>
"#;
