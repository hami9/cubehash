use std::net::SocketAddr;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::client::{ChatNode, PeerSummary};
use crate::protocol::ChatMeshProfile;

#[derive(Serialize)]
struct StateSnapshot {
    client_id: String,
    hw_id: String,
    online_peers: Vec<String>,
    paired_peers: Vec<PeerSummary>,
}

#[derive(Deserialize)]
struct PairRequest {
    peer_id: String,
    psk: Option<String>,
    profile: Option<ChatMeshProfile>,
}

#[derive(Deserialize)]
struct AcceptRequest {
    peer_id: String,
    psk: Option<String>,
}

#[derive(Deserialize)]
struct SendRequest {
    peer_id: String,
    text: String,
    raw_core: Option<bool>,
    flip_bytes: Option<usize>,
}

#[derive(Deserialize)]
struct PeerActionRequest {
    peer_id: String,
}

#[derive(Serialize)]
struct ApiResponse {
    ok: bool,
    message: String,
}

/// Starts the local browser UI server bound to `addr` (`127.0.0.1`) for `node`.
///
/// All cryptography runs inside the Rust client process; the browser communicates only with localhost.
pub async fn start_web_ui(
    addr: SocketAddr,
    node: ChatNode,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let app = Router::new()
        .route("/", get(ui_page))
        .route("/api/state", get(state_handler))
        .route("/api/pair", post(pair_handler))
        .route("/api/accept", post(accept_handler))
        .route("/api/send", post(send_handler))
        .route("/api/hop", post(hop_handler))
        .route("/api/honey", post(honey_handler))
        .route("/ws/events", get(events_ws_handler))
        .with_state(node);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((local_addr, handle))
}

async fn ui_page() -> Html<&'static str> {
    Html(CLIENT_WEB_UI_HTML)
}

async fn state_handler(State(node): State<ChatNode>) -> Json<StateSnapshot> {
    Json(StateSnapshot {
        client_id: node.client_id().to_string(),
        hw_id: node.device_hw_id_hex(),
        online_peers: node.online_peers().await,
        paired_peers: node.paired_summaries().await,
    })
}

async fn pair_handler(
    State(node): State<ChatNode>,
    Json(req): Json<PairRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    let profile = req.profile.unwrap_or(ChatMeshProfile::Standard);
    match node
        .initiate_pair(&req.peer_id, req.psk.as_deref(), profile)
        .await
    {
        Ok(pair_id) => (
            StatusCode::OK,
            Json(ApiResponse {
                ok: true,
                message: format!("PairOffer sent ({pair_id})"),
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                ok: false,
                message: e,
            }),
        ),
    }
}

async fn accept_handler(
    State(node): State<ChatNode>,
    Json(req): Json<AcceptRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    match node
        .accept_pair_offer(&req.peer_id, req.psk.as_deref().unwrap_or(""))
        .await
    {
        Ok(fp) => (
            StatusCode::OK,
            Json(ApiResponse {
                ok: true,
                message: format!("Paired! Safety fingerprint: {fp}"),
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                ok: false,
                message: e,
            }),
        ),
    }
}

async fn send_handler(
    State(node): State<ChatNode>,
    Json(req): Json<SendRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    match node
        .send_with_noise(
            &req.peer_id,
            &req.text,
            req.raw_core.unwrap_or(false),
            req.flip_bytes.unwrap_or(0),
        )
        .await
    {
        Ok(rec) => (
            StatusCode::OK,
            Json(ApiResponse {
                ok: true,
                message: format!("Delivered & ACK committed ({} bytes)", rec.wire_bytes),
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                ok: false,
                message: e,
            }),
        ),
    }
}

async fn hop_handler(
    State(node): State<ChatNode>,
    Json(req): Json<PeerActionRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    match node.hop_epoch(&req.peer_id).await {
        Ok(epoch) => (
            StatusCode::OK,
            Json(ApiResponse {
                ok: true,
                message: format!("TX epoch hopped to {epoch}"),
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                ok: false,
                message: e,
            }),
        ),
    }
}

async fn honey_handler(
    State(node): State<ChatNode>,
    Json(req): Json<PeerActionRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    match node.simulate_honey_probe(&req.peer_id).await {
        Ok(fake) => (
            StatusCode::OK,
            Json(ApiResponse {
                ok: true,
                message: format!("Zero-Oracle Honey Output: {fake}"),
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                ok: false,
                message: e,
            }),
        ),
    }
}

async fn events_ws_handler(
    ws: WebSocketUpgrade,
    State(node): State<ChatNode>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| push_events(socket, node))
}

async fn push_events(socket: WebSocket, node: ChatNode) {
    let (mut sink, _) = socket.split();
    let mut rx = node.subscribe();
    while let Ok(ev) = rx.recv().await {
        if let Ok(txt) = serde_json::to_string(&ev) {
            if sink.send(Message::Text(txt.into())).await.is_err() {
                break;
            }
        }
    }
}

const CLIENT_WEB_UI_HTML: &str = r#"<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>CubeHash Secure Chat</title>
<style>
  :root { --bg:#090d16; --panel:#111827; --border:#1f2937; --accent:#38bdf8; --ok:#34d399; --warn:#fbbf24; --text:#f3f4f6; --muted:#9ca3af; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:var(--bg); color:var(--text); display:flex; height:100vh; }
  aside { width:310px; background:var(--panel); border-left:1px solid var(--border); padding:16px; display:flex; flex-direction:column; gap:12px; overflow:auto; }
  main { flex:1; display:flex; flex-direction:column; }
  header { padding:14px 18px; border-bottom:1px solid var(--border); background:var(--panel); display:flex; justify-content:space-between; align-items:center; gap:12px; }
  .pill { font-size:12px; padding:4px 10px; border-radius:999px; background:#0f2942; color:var(--accent); font-family:monospace; direction:ltr; }
  .card { background:#0d1424; border:1px solid var(--border); border-radius:10px; padding:10px; font-size:13px; }
  button { cursor:pointer; background:#0284c7; color:white; border:none; border-radius:8px; padding:8px 12px; font-size:13px; }
  button.sec { background:#1e293b; color:#e2e8f0; border:1px solid #334155; }
  button.warn { background:#92400e; }
  input, select { background:#0b1220; color:var(--text); border:1px solid #334155; border-radius:8px; padding:8px; font-size:13px; width:100%; }
  #messages { flex:1; overflow:auto; padding:18px; display:flex; flex-direction:column; gap:10px; }
  .msg { max-width:74%; padding:10px 14px; border-radius:12px; line-height:1.5; font-size:14px; }
  .msg.out { align-self:flex-start; background:#0c4a6e; border:1px solid #0284c7; }
  .msg.in { align-self:flex-end; background:#1e293b; border:1px solid #334155; }
  .meta { font-size:11px; color:var(--muted); margin-top:4px; direction:ltr; text-align:left; font-family:monospace; }
  form { display:flex; gap:8px; padding:14px; border-top:1px solid var(--border); background:var(--panel); align-items:center; }
  .peer-btn { width:100%; text-align:right; margin-top:6px; display:flex; justify-content:space-between; align-items:center; }
  .peer-btn.active { outline:2px solid var(--accent); }
  #log { font-family:monospace; font-size:11px; color:#cbd5e1; max-height:140px; overflow:auto; direction:ltr; }
</style>
</head>
<body>
  <aside>
    <div>
      <h2 style="margin:0 0 6px;font-size:17px;color:var(--accent);">CubeHash Chat</h2>
      <div class="pill" id="me">loading...</div>
    </div>
    <div class="card">
      <div style="font-weight:600;margin-bottom:6px;">همتاهای آنلاین (X25519 Pair)</div>
      <div id="online-list" style="color:var(--muted);">هیچ کاربری آنلاین نیست</div>
      <div style="margin-top:8px;display:flex;flex-direction:column;gap:6px;">
        <input id="pin" placeholder="پین اختیاری (PIN / PSK)" />
        <select id="profile">
          <option value="standard">Standard (100 cubes / 1000b)</option>
          <option value="compact">Compact (40 cubes / 512b)</option>
          <option value="high_capacity">High Capacity (160 cubes / 2048b)</option>
        </select>
      </div>
    </div>
    <div class="card" id="pending-box" style="display:none;"></div>
    <div class="card">
      <div style="font-weight:600;margin-bottom:6px;">سشن‌های جفت‌شده</div>
      <div id="paired-list"></div>
    </div>
    <div class="card" id="mesh-stats">آمار مش ۱۰۰ کیوبی اینجا نمایش داده می‌شود</div>
    <div class="card">
      <div style="font-weight:600;margin-bottom:4px;">لاگ امنیتی</div>
      <div id="log"></div>
    </div>
  </aside>
  <main>
    <header>
      <div>
        <strong id="active-title">یک همتا انتخاب یا Pair کنید</strong>
        <div id="safety" style="font-size:12px;color:var(--ok);font-family:monospace;direction:ltr;"></div>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="sec" onclick="doHop()">Epoch Hop</button>
        <button class="sec" onclick="sendNoise()">تست Bit-Rot + TMR</button>
        <button class="warn" onclick="doHoney()">تست Honey DTE</button>
      </div>
    </header>
    <div id="messages"></div>
    <form onsubmit="return sendMsg(event)">
      <label style="display:flex;align-items:center;gap:4px;font-size:12px;white-space:nowrap;">
        <input type="checkbox" id="raw-core" style="width:auto;" /> Raw 24B
      </label>
      <input id="msg-input" placeholder="پیام خود را بنویسید..." autocomplete="off" />
      <button type="submit">ارسال امن</button>
    </form>
  </main>
<script>
let state = { online_peers: [], paired_peers: [] };
let activePeer = null;

function addLog(txt) {
  const el = document.getElementById('log');
  el.innerHTML = `<div>${txt}</div>` + el.innerHTML;
}

async function refreshState() {
  const res = await fetch('/api/state');
  state = await res.json();
  document.getElementById('me').textContent = state.client_id + ' | hw:' + state.hw_id.slice(0,12);
  if (!activePeer && state.paired_peers.length > 0) activePeer = state.paired_peers[0].peer_id;
  renderSidebar();
  renderChat();
}

function renderSidebar() {
  const pairedIds = new Set(state.paired_peers.map(p => p.peer_id));
  const onlineHtml = state.online_peers.length ? state.online_peers.map(p =>
    `<div class="peer-btn"><span>${p}</span>${pairedIds.has(p) ? '<span style="color:var(--ok)">Paired</span>' : `<button onclick="pairPeer('${p}')">Pair</button>`}</div>`
  ).join('') : 'هیچ همتای دیگری آنلاین نیست';
  document.getElementById('online-list').innerHTML = onlineHtml;

  document.getElementById('paired-list').innerHTML = state.paired_peers.length ? state.paired_peers.map(p =>
    `<button class="sec peer-btn ${p.peer_id===activePeer?'active':''}" onclick="selectPeer('${p.peer_id}')"><span>${p.peer_id}</span><span style="font-size:11px;color:var(--ok)">tx:${p.tx_stats.sequence} rx:${p.rx_stats.sequence}</span></button>`
  ).join('') : '<span style="color:var(--muted)">هنوز سشنی ندارید</span>';
}

function renderChat() {
  const peer = state.paired_peers.find(p => p.peer_id === activePeer);
  if (!peer) {
    document.getElementById('active-title').textContent = 'یک همتا انتخاب یا Pair کنید';
    document.getElementById('safety').textContent = '';
    document.getElementById('messages').innerHTML = '';
    return;
  }
  document.getElementById('active-title').textContent = 'گفتگو با ' + peer.peer_id;
  document.getElementById('safety').textContent = 'Safety Code: ' + peer.safety_fingerprint + ' | Profile: ' + peer.profile;
  document.getElementById('mesh-stats').innerHTML =
    `<b>Mesh TX:</b> ${peer.tx_stats.mesh_size} cubes (${peer.tx_stats.approx_ram_bytes}B), epoch=${peer.tx_stats.epoch}, seq=${peer.tx_stats.sequence}<br>` +
    `<b>Mesh RX:</b> ${peer.rx_stats.mesh_size} cubes, epoch=${peer.rx_stats.epoch}, seq=${peer.rx_stats.sequence}<br>` +
    `<b>50/50 Ratio:</b> ${peer.tx_stats.avg_ones_ratio.toFixed(4)} | <b>Entropy:</b> ${peer.tx_stats.avg_entropy_bits_per_byte.toFixed(2)} b/B`;

  const box = document.getElementById('messages');
  box.innerHTML = peer.messages.map(m =>
    `<div class="msg ${m.direction}"><div>${escapeHtml(m.text)}</div><div class="meta">${m.mode} • ${m.wire_bytes}B • ${m.status}</div></div>`
  ).join('');
  box.scrollTop = box.scrollHeight;
}

function escapeHtml(s) {
  return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
}

function selectPeer(id) { activePeer = id; renderSidebar(); renderChat(); }

async function pairPeer(id) {
  const psk = document.getElementById('pin').value.trim();
  const profile = document.getElementById('profile').value;
  const r = await fetch('/api/pair', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({peer_id:id, psk: psk||null, profile}) });
  const j = await r.json();
  addLog(j.message);
}

async function acceptOffer(peerId) {
  const psk = prompt('پین مشترک برای ' + peerId + ' را وارد کنید:') || '';
  const r = await fetch('/api/accept', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({peer_id:peerId, psk}) });
  const j = await r.json();
  document.getElementById('pending-box').style.display = 'none';
  addLog(j.message);
  await refreshState();
}

async function sendMsg(ev) {
  ev.preventDefault();
  if (!activePeer) return false;
  const inp = document.getElementById('msg-input');
  const text = inp.value;
  if (!text) return false;
  inp.value = '';
  const raw_core = document.getElementById('raw-core').checked;
  const r = await fetch('/api/send', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({peer_id:activePeer, text, raw_core}) });
  const j = await r.json();
  if (!j.ok) addLog('ERR: ' + j.message);
  await refreshState();
  return false;
}

async function sendNoise() {
  if (!activePeer) return;
  const r = await fetch('/api/send', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({peer_id:activePeer, text:'Self-healing over noisy relay!', raw_core:false, flip_bytes:8}) });
  const j = await r.json();
  addLog(j.message);
  await refreshState();
}

async function doHop() {
  if (!activePeer) return;
  const r = await fetch('/api/hop', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({peer_id:activePeer}) });
  const j = await r.json();
  addLog(j.message);
  await refreshState();
}

async function doHoney() {
  if (!activePeer) return;
  const r = await fetch('/api/honey', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({peer_id:activePeer}) });
  const j = await r.json();
  addLog(j.message);
}

function connectEvents() {
  const ws = new WebSocket((location.protocol==='https:'?'wss://':'ws://') + location.host + '/ws/events');
  ws.onmessage = async (ev) => {
    const data = JSON.parse(ev.data);
    if (data.event === 'incoming_pair_request') {
      const box = document.getElementById('pending-box');
      box.style.display = 'block';
      box.innerHTML = `<div>درخواست جفت‌شدن با PIN از <b>${data.from}</b></div><button style="margin-top:6px;" onclick="acceptOffer('${data.from}')">پذیرفتن با PIN</button>`;
    } else if (data.event === 'epoch_hopped') {
      addLog(`Epoch hop (${data.direction}) -> ${data.new_epoch}`);
    } else if (data.event === 'notice') {
      addLog(`[${data.level}] ${data.text}`);
    }
    await refreshState();
  };
  ws.onclose = () => setTimeout(connectEvents, 1000);
}

refreshState();
connectEvents();
</script>
</body>
</html>
"#;
