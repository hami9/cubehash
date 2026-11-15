use std::net::SocketAddr;
use std::path::PathBuf;

use cubehash_chat::{
    parse_sha256_pin_hex, start_relay_server, ChatMeshProfile, ChatNode, ChatUiEvent,
    ClientTlsConfig, DeviceIdentity, RelayTlsConfig,
};
use tokio::io::{self, AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("help");

    match mode {
        "relay" => run_relay(&args[2..]).await,
        "client" => run_client(&args[2..]).await,
        _ => print_usage(),
    }
}

fn print_usage() {
    println!(
        "CubeHash Zero-Knowledge Headless Chat\n\
         Usage:\n\
           cubehash-chat relay [--listen 127.0.0.1:9000] [--tls-cert <pem> --tls-key <pem> | --insecure-ws]\n\
           cubehash-chat client --id <name> [--relay wss://127.0.0.1:9000/ws]\n\
             [--tls-pin <sha256_hex> | --tls-ca <pem>] [--insecure-ws]\n\
             [--hw-secret <passphrase>] [--keystore-dir <dir>]"
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

    let tls_config = if has_flag(args, "--insecure-ws") {
        eprintln!("[warning] TLS disabled (--insecure-ws); do not use outside local testing");
        RelayTlsConfig::InsecureDisabled
    } else if let (Some(cert), Some(key)) = (arg_value(args, "--tls-cert"), arg_value(args, "--tls-key")) {
        RelayTlsConfig::from_pem_paths(cert.as_ref(), key.as_ref())
            .expect("failed to load relay TLS cert/key")
    } else if arg_value(args, "--tls-cert").is_some() || arg_value(args, "--tls-key").is_some() {
        eprintln!("--tls-cert and --tls-key must be supplied together");
        std::process::exit(1);
    } else {
        RelayTlsConfig::SelfSigned {
            san_hosts: vec![
                addr.ip().to_string(),
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ],
        }
    };

    let started = start_relay_server(addr, tls_config)
        .await
        .expect("failed to bind blind relay server");

    if started.is_tls {
        println!("CubeHash Blind TLS Relay listening on wss://{}/ws", started.addr);
        if let Some(pin) = &started.tls_cert_sha256_hex {
            println!("Leaf Cert SHA-256 Pin: --tls-pin {pin}");
        }
    } else {
        println!(
            "CubeHash Blind Relay (insecure ws://) listening on ws://{}/ws",
            started.addr
        );
    }
    println!("Press Ctrl+C to stop.");

    let _ = tokio::signal::ctrl_c().await;
    started.handle.abort();
}

async fn run_client(args: &[String]) {
    let id = arg_value(args, "--id").unwrap_or_else(|| {
        eprintln!("Missing required flag --id <name>");
        std::process::exit(1);
    });
    let relay = arg_value(args, "--relay").unwrap_or_else(|| "wss://127.0.0.1:9000/ws".to_string());
    let allow_insecure_ws = has_flag(args, "--insecure-ws");
    let hw_secret = arg_value(args, "--hw-secret");
    let keystore_dir = arg_value(args, "--keystore-dir").map(PathBuf::from);

    let tls_config = if let Some(pin_hex) = arg_value(args, "--tls-pin") {
        let digest = parse_sha256_pin_hex(&pin_hex).expect("valid --tls-pin SHA-256 hex");
        ClientTlsConfig::PinnedCertSha256(digest)
    } else if let Some(ca_path) = arg_value(args, "--tls-ca") {
        let ca_pem = std::fs::read(&ca_path).expect("failed to read --tls-ca PEM file");
        ClientTlsConfig::CaPem(ca_pem)
    } else {
        ClientTlsConfig::WebPkiRoots
    };

    let identity = DeviceIdentity::load_or_create(
        &id,
        keystore_dir.as_deref(),
        hw_secret.as_deref(),
    )
    .expect("failed to load or create OS-sealed device identity");

    println!(
        "Loaded device identity '{}' (backend={}, ed25519={})",
        identity.client_id(),
        identity.backend_label(),
        identity.ed25519_pub_hex()
    );

    let node = ChatNode::connect_with_config(identity, &relay, tls_config, allow_insecure_ws)
        .await
        .expect("failed to connect to CubeHash relay");

    println!(
        "Connected client '{}' (ed25519={}) -> {relay}",
        node.client_id(),
        node.ed25519_pub_hex()
    );

    let mut rx_events = node.subscribe();
    let event_printer = tokio::spawn(async move {
        while let Ok(ev) = rx_events.recv().await {
            match ev {
                ChatUiEvent::PeersUpdated { online_peers } => {
                    let formatted: Vec<String> = online_peers
                        .iter()
                        .map(|p| {
                            let hex_key = hex::encode(p.ed25519_pub);
                            format!("{}({})", p.client_id, &hex_key[..12])
                        })
                        .collect();
                    println!("\n[peers] online: {:?}", formatted);
                }
                ChatUiEvent::Paired {
                    peer_id,
                    peer_ed25519_hex,
                    safety_fingerprint,
                    profile,
                } => {
                    println!(
                        "\n[paired] peer={peer_id} ed25519={peer_ed25519_hex} profile={profile:?} safety_code={safety_fingerprint}"
                    );
                }
                ChatUiEvent::IncomingPairRequest {
                    from,
                    from_ed25519_hex,
                    pair_id,
                    profile,
                    has_psk,
                } => {
                    println!(
                        "\n[pair-req] id={pair_id} from={from} ed25519={from_ed25519_hex} profile={profile:?} has_pin={has_psk} -> use /accept {from} <pin>"
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

    println!(
        "Commands: /peers | /trust <peer> <ed25519_hex> | /psk <peer> <pin> | /pair <peer> [pin] | /accept <peer> [pin] | /to <peer> | /raw <text<=24B> | /noise <text> | /hop | /honey | /stats | /quit"
    );
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
            let formatted: Vec<String> = node
                .online_peers()
                .await
                .into_iter()
                .map(|p| format!("{}:{}", p.client_id, hex::encode(p.ed25519_pub)))
                .collect();
            println!("Online peers: {:?}", formatted);
        } else if let Some(rest) = trimmed.strip_prefix("/trust ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() == 2 {
                match parse_sha256_pin_hex(parts[1]) {
                    Ok(pubkey) => match node.pin_peer_ed25519(parts[0], pubkey).await {
                        Ok(()) => println!("Pinned Ed25519 key for {}", parts[0]),
                        Err(e) => println!("Trust error: {e}"),
                    },
                    Err(_) => println!("Invalid 64-char hex Ed25519 public key"),
                }
            } else {
                println!("Usage: /trust <peer> <ed25519_hex>");
            }
        } else if let Some(rest) = trimmed.strip_prefix("/psk ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() == 2 {
                node.set_preset_psk(parts[0], parts[1]).await;
                println!("Set preset auto-accept PSK for {}", parts[0]);
            } else {
                println!("Usage: /psk <peer> <pin>");
            }
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
                    "Peer={} ed25519={} code={} tx_seq={} rx_seq={} tx_ram={}B ratio={:.4}",
                    s.peer_id,
                    &s.peer_ed25519_hex[..12],
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
                    Ok(e) => println!("TX hopped + DH ratcheted to epoch {e}"),
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
}
