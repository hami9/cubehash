use std::net::SocketAddr;

use cubehash_chat::{start_relay_server, start_web_ui, ChatMeshProfile, ChatNode, ChatUiEvent};
use cubehash_core::primitives::hmac_sha256_parts;
use tokio::io::{self, AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_usage();
        return;
    }

    match args[0].as_str() {
        "relay" => run_relay(&args[1..]).await,
        "client" => run_client(&args[1..]).await,
        other => {
            eprintln!("Unknown subcommand: {other}");
            print_usage();
            std::process::exit(2);
        }
    }
}

fn print_usage() {
    println!(
        "CubeHash Zero-Knowledge Chat\n\
         Usage:\n\
           cubehash-chat relay [--listen 127.0.0.1:9000]\n\
           cubehash-chat client --id <name> [--relay ws://127.0.0.1:9000/ws] [--web 127.0.0.1:8081] [--cli] [--hw-secret <text>]"
    );
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

async fn run_relay(args: &[String]) {
    let addr_str = arg_value(args, "--listen").unwrap_or_else(|| "127.0.0.1:9000".to_string());
    let addr: SocketAddr = addr_str.parse().expect("valid listen address");
    let (bound, _state, handle) = start_relay_server(addr)
        .await
        .expect("failed to bind blind relay server");
    println!("CubeHash Blind Relay listening on ws://{bound}/ws");
    println!("Zero-Knowledge Inspector UI: http://{bound}/");
    println!("Press Ctrl+C to stop.");
    let _ = tokio::signal::ctrl_c().await;
    handle.abort();
}

async fn run_client(args: &[String]) {
    let id = arg_value(args, "--id").unwrap_or_else(|| {
        eprintln!("--id <client_name> is required");
        std::process::exit(2);
    });
    let relay = arg_value(args, "--relay").unwrap_or_else(|| "ws://127.0.0.1:9000/ws".to_string());
    let web_addr_opt = arg_value(args, "--web");
    let cli_mode = has_flag(args, "--cli") || web_addr_opt.is_none();

    let hw_seed = arg_value(args, "--hw-secret").unwrap_or_else(|| format!("local-device-{id}"));
    let device_secret = hmac_sha256_parts(b"cubehash-client-device", &[hw_seed.as_bytes()]);

    let node = ChatNode::connect(id.clone(), &relay, device_secret)
        .await
        .expect("failed to connect to relay");
    println!(
        "Connected as '{}' (hw_id: {}) -> {}",
        node.client_id(),
        node.device_hw_id_hex(),
        relay
    );

    let mut web_handle = None;
    if let Some(web_str) = web_addr_opt {
        let web_addr: SocketAddr = web_str.parse().expect("valid --web address");
        let (bound, handle) = start_web_ui(web_addr, node.clone())
            .await
            .expect("failed to start local Web UI");
        println!("Local Client Web UI: http://{bound}/");
        web_handle = Some(handle);
    }

    if !cli_mode {
        println!("Running in Web UI mode. Press Ctrl+C to quit.");
        let _ = tokio::signal::ctrl_c().await;
        if let Some(h) = web_handle {
            h.abort();
        }
        return;
    }

    let mut events = node.subscribe();
    let event_printer = tokio::spawn(async move {
        while let Ok(ev) = events.recv().await {
            match ev {
                ChatUiEvent::PeersUpdated { online_peers } => {
                    println!("\n[peers] online: {:?}", online_peers);
                }
                ChatUiEvent::Paired {
                    peer_id,
                    safety_fingerprint,
                    profile,
                } => {
                    println!(
                        "\n[paired] {peer_id} ({profile:?}) safety_code={safety_fingerprint}"
                    );
                }
                ChatUiEvent::IncomingPairRequest {
                    from,
                    profile,
                    has_psk,
                    ..
                } => {
                    println!(
                        "\n[pair-req] from={from} profile={profile:?} has_pin={has_psk} -> use /accept {from} <pin>"
                    );
                }
                ChatUiEvent::MessageAdded { record } if record.direction == "in" => {
                    println!(
                        "\n[{peer} -> me | {mode} | {bytes}B | {status}] {text}",
                        peer = record.peer_id,
                        mode = record.mode,
                        bytes = record.wire_bytes,
                        status = record.status,
                        text = record.text
                    );
                }
                ChatUiEvent::EpochHopped {
                    peer_id,
                    direction,
                    new_epoch,
                } => {
                    println!("\n[epoch] {peer_id} ({direction}) -> epoch={new_epoch}");
                }
                ChatUiEvent::HoneyProbeResult {
                    peer_id,
                    outcome,
                    output,
                } => {
                    println!("\n[honey:{peer_id}] {outcome} -> \"{output}\"");
                }
                ChatUiEvent::Notice { level, text } => {
                    println!("\n[{level}] {text}");
                }
                _ => {}
            }
        }
    });

    println!("Commands: /peers | /pair <peer> [pin] | /accept <peer> [pin] | /to <peer> | /raw <text<=24B> | /noise <text> | /hop | /honey | /stats | /quit");
    let mut active_peer: Option<String> = None;
    let mut lines = BufReader::new(io::stdin()).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "/quit" {
            break;
        } else if trimmed == "/peers" {
            println!("Online peers: {:?}", node.online_peers().await);
        } else if let Some(rest) = trimmed.strip_prefix("/pair ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if let Some(&peer) = parts.first() {
                let pin = parts.get(1).copied();
                match node.initiate_pair(peer, pin, ChatMeshProfile::Standard).await {
                    Ok(pid) => {
                        active_peer = Some(peer.to_string());
                        println!("Sent X25519 PairOffer ({pid}) to {peer}");
                    }
                    Err(e) => println!("Pair error: {e}"),
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("/accept ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if let Some(&peer) = parts.first() {
                let pin = parts.get(1).copied().unwrap_or("");
                match node.accept_pair_offer(peer, pin).await {
                    Ok(fp) => {
                        active_peer = Some(peer.to_string());
                        println!("Paired with {peer}! Safety code: {fp}");
                    }
                    Err(e) => println!("Accept error: {e}"),
                }
            }
        } else if let Some(peer) = trimmed.strip_prefix("/to ") {
            active_peer = Some(peer.trim().to_string());
            println!("Active peer set to {}", peer.trim());
        } else if trimmed == "/stats" {
            for s in node.paired_summaries().await {
                println!(
                    "Peer={} code={} tx_seq={} rx_seq={} tx_ram={}B ratio={:.4}",
                    s.peer_id,
                    s.safety_fingerprint,
                    s.tx_stats.sequence,
                    s.rx_stats.sequence,
                    s.tx_stats.approx_ram_bytes,
                    s.tx_stats.avg_ones_ratio
                );
            }
        } else if trimmed == "/hop" {
            if let Some(peer) = &active_peer {
                match node.hop_epoch(peer).await {
                    Ok(e) => println!("TX hopped to epoch {e}"),
                    Err(e) => println!("Hop error: {e}"),
                }
            } else {
                println!("Select a peer first with /to <peer>");
            }
        } else if trimmed == "/honey" {
            if let Some(peer) = &active_peer {
                if let Err(e) = node.simulate_honey_probe(peer).await {
                    println!("Honey test error: {e}");
                }
            } else {
                println!("Select a peer first with /to <peer>");
            }
        } else if let Some(raw_text) = trimmed.strip_prefix("/raw ") {
            if let Some(peer) = &active_peer {
                match node.send_message(peer, raw_text, true).await {
                    Ok(r) => println!("[sent RawCore256 | {}B | {}]", r.wire_bytes, r.status),
                    Err(e) => println!("Send failed: {e}"),
                }
            } else {
                println!("Select a peer first with /to <peer>");
            }
        } else if let Some(noisy_text) = trimmed.strip_prefix("/noise ") {
            if let Some(peer) = &active_peer {
                match node.send_with_noise(peer, noisy_text, false, 8).await {
                    Ok(r) => println!("[sent noisy 8B bit-rot | {}B | {}]", r.wire_bytes, r.status),
                    Err(e) => println!("Send failed: {e}"),
                }
            } else {
                println!("Select a peer first with /to <peer>");
            }
        } else if let Some(peer) = &active_peer {
            match node.send_message(peer, trimmed, false).await {
                Ok(r) => println!("[sent AEAD | {}B | {}]", r.wire_bytes, r.status),
                Err(e) => println!("Send failed: {e}"),
            }
        } else {
            println!("No active peer. Use /pair <peer> or /to <peer>.");
        }
    }

    event_printer.abort();
    if let Some(h) = web_handle {
        h.abort();
    }
}
