use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use cubehash_chat::{start_relay_server, start_web_ui, ChatMeshProfile, ChatNode};

async fn wait_until<F, Fut>(mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..50 {
        if cond().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition timed out");
}

#[tokio::test]
async fn test_e2e_blind_relay_x25519_chat_tmr_epoch_and_rollback() {
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (relay_addr, relay_state, relay_handle) = start_relay_server(bind_addr).await.unwrap();
    let ws_url = format!("ws://{relay_addr}/ws");

    let alice = ChatNode::connect("alice", &ws_url, [0x11u8; 32])
        .await
        .unwrap();
    let bob = ChatNode::connect("bob", &ws_url, [0x22u8; 32])
        .await
        .unwrap();

    // Verify local Web UI starts cleanly on localhost for Alice
    let (ui_addr, ui_handle) = start_web_ui(bind_addr, alice.clone()).await.unwrap();
    assert!(ui_addr.port() > 0);

    wait_until(|| async { alice.online_peers().await.contains(&"bob".to_string()) }).await;

    // 1. Pair with shared PIN/PSK over X25519 via blind relay
    bob.set_preset_psk("alice", "secret-pin-42").await;
    alice
        .initiate_pair("bob", Some("secret-pin-42"), ChatMeshProfile::Standard)
        .await
        .unwrap();

    wait_until(|| async {
        alice.paired_summaries().await.len() == 1 && bob.paired_summaries().await.len() == 1
    })
    .await;

    let a_sum = &alice.paired_summaries().await[0];
    let b_sum = &bob.paired_summaries().await[0];
    assert_eq!(a_sum.safety_fingerprint, b_sum.safety_fingerprint);
    assert_eq!(a_sum.tx_stats.mesh_size, 100);

    // 2. Send compact RawCore256 message + full UTF-8 Persian chat message concurrently
    let r1 = alice.send_message("bob", "RAW-24B-KEY-MATERIAL", true).await.unwrap();
    assert_eq!(r1.mode, "RawCore256");

    let secret_text = "سلام باب! پیام تست رمزنگاری چت با CubeHash روی رله کور 🚀";
    let (res_a, res_b) = tokio::join!(
        alice.send_message("bob", secret_text, false),
        bob.send_message("alice", "Hello Alice! Bidirectional ACK OK.", false)
    );
    assert_eq!(res_a.unwrap().status, "delivered_ack");
    assert_eq!(res_b.unwrap().status, "delivered_ack");

    // 3. Inject real network bit-rot (8 bytes corrupted across wire cube + shadow) -> TMR heals it live!
    let noisy_text = "Message surviving 64-bit wire corruption!";
    let r_noise = alice
        .send_with_noise("bob", noisy_text, false, 8)
        .await
        .unwrap();
    assert_eq!(r_noise.status, "delivered_ack");

    let bob_msgs = &bob.paired_summaries().await[0].messages;
    let healed_rec = bob_msgs.iter().find(|m| m.text == noisy_text).unwrap();
    assert!(healed_rec.healed_bits > 0);

    // 4. Epoch Hopping across the relay + post-hop messaging
    let new_ep = alice.hop_epoch("bob").await.unwrap();
    assert_eq!(new_ep, 1);
    wait_until(|| async { bob.paired_summaries().await[0].rx_stats.epoch == 1 }).await;

    alice
        .send_message("bob", "Post-epoch-hop verified!", false)
        .await
        .unwrap();

    // 5. Honey DTE zero-oracle probe does not desync active chat
    let honey_out = bob.simulate_honey_probe("alice").await.unwrap();
    assert!(!honey_out.is_empty());
    alice
        .send_message("bob", "Still synchronized after honey probe!", false)
        .await
        .unwrap();

    // 6. Verify Blind Relay saw zero plaintext and zero keys
    let telemetry = relay_state.snapshot().await;
    let telemetry_json = serde_json::to_string(&telemetry).unwrap();
    assert!(!telemetry_json.contains("سلام باب"));
    assert!(!telemetry_json.contains("RAW-24B-KEY-MATERIAL"));
    assert!(!telemetry_json.contains("secret-pin-42"));
    assert!(telemetry.total_routed_frames >= 10);

    // 7. Disconnect Bob -> Alice's next send rolls back cleanly without desyncing tx sequence!
    let tx_seq_before = alice.paired_summaries().await[0].tx_stats.sequence;
    drop(bob);
    wait_until(|| async { !alice.online_peers().await.contains(&"bob".to_string()) }).await;
    let err = alice
        .send_message("bob", "bob is offline", false)
        .await
        .unwrap_err();
    assert!(err.contains("rolled back"));
    assert_eq!(
        alice.paired_summaries().await[0].tx_stats.sequence,
        tx_seq_before
    );

    ui_handle.abort();
    relay_handle.abort();
}
