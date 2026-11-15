use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cubehash_chat::{
    parse_sha256_pin_hex, start_relay_server, ChatMeshProfile, ChatNode, ChatUiEvent,
    ClientTlsConfig, DeviceIdentity, RelayTlsConfig,
};
use cubehash_core::HardwareProvider;

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cubehash_chat_e2e_{label}_{}_{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[tokio::test]
async fn test_wss_tls_ed25519_ratchet_padding_tmr_honey_and_rollback() {
    let relay = start_relay_server(
        "127.0.0.1:0".parse().unwrap(),
        RelayTlsConfig::SelfSigned {
            san_hosts: vec!["localhost".into(), "127.0.0.1".into()],
        },
    )
    .await
    .expect("start wss relay");
    assert!(relay.is_tls);
    let pin_hex = relay
        .tls_cert_sha256_hex
        .as_ref()
        .expect("self-signed pin hex")
        .clone();
    let pin_digest = parse_sha256_pin_hex(&pin_hex).expect("parse sha256 pin");
    let cert_pem = relay
        .tls_cert_pem
        .as_ref()
        .expect("self-signed cert PEM")
        .as_bytes()
        .to_vec();

    let wss_url = format!("wss://{}/ws", relay.addr);
    let ws_url = format!("ws://{}/ws", relay.addr);

    // 1. Refuse ws:// without explicit --insecure-ws opt-in.
    let insecure_probe_id = DeviceIdentity::ephemeral_csprng("probe-ws").unwrap();
    let err_ws = ChatNode::connect_with_config(
        insecure_probe_id,
        &ws_url,
        ClientTlsConfig::WebPkiRoots,
        false,
    )
    .await
    .err()
    .expect("must refuse plain ws:// by default");
    assert!(err_ws.contains("insecure-ws") || err_ws.contains("wss://"));

    // 2. Refuse wss:// when pinned certificate digest mismatches (MITM defense).
    let wrong_pin_id = DeviceIdentity::ephemeral_csprng("wrong-pin").unwrap();
    let err_pin = ChatNode::connect_with_config(
        wrong_pin_id,
        &wss_url,
        ClientTlsConfig::PinnedCertSha256([0xAAu8; 32]),
        false,
    )
    .await
    .err()
    .expect("must reject mismatched TLS pin");
    assert!(
        err_pin.contains("TLS handshake failed") || err_pin.contains("certificate"),
        "unexpected error: {err_pin}"
    );

    // 3. Connect Alice (pinned leaf digest) and Bob (CA PEM).
    let alice_id = DeviceIdentity::ephemeral_csprng("alice").unwrap();
    let bob_id = DeviceIdentity::ephemeral_csprng("bob").unwrap();
    let bob_ed25519 = bob_id.ed25519_pub();

    let alice = ChatNode::connect_with_config(
        alice_id,
        &wss_url,
        ClientTlsConfig::PinnedCertSha256(pin_digest),
        false,
    )
    .await
    .expect("alice connect wss pinned");
    let bob = ChatNode::connect_with_config(
        bob_id.clone(),
        &wss_url,
        ClientTlsConfig::CaPem(cert_pem),
        false,
    )
    .await
    .expect("bob connect wss ca_pem");

    // Verify relay blocks active impersonation of "bob" with a different Ed25519 key.
    let impostor_active = DeviceIdentity::ephemeral_csprng("bob").unwrap();
    let err_active = ChatNode::connect_with_config(
        impostor_active,
        &wss_url,
        ClientTlsConfig::PinnedCertSha256(pin_digest),
        false,
    )
    .await
    .err()
    .expect("impostor cannot steal active bob identity");
    assert!(
        err_active.contains("identity_mismatch") || err_active.contains("id_in_use"),
        "unexpected active hijack error: {err_active}"
    );

    // Explicitly verify out-of-band pinning works too.
    alice
        .pin_peer_ed25519("bob", bob_ed25519)
        .await
        .expect("pin bob key");

    let mut alice_events = alice.subscribe();
    let mut bob_events = bob.subscribe();

    // 4. Pairing WITHOUT preset PSK requires explicit accept_pair_offer on Bob.
    alice
        .initiate_pair("bob", Some("482910"), ChatMeshProfile::Standard)
        .await
        .expect("alice send PairOffer");

    let mut saw_incoming_req = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(ChatUiEvent::IncomingPairRequest {
            from,
            from_ed25519_hex,
            has_psk,
            ..
        })) = tokio::time::timeout(Duration::from_millis(500), bob_events.recv()).await
        {
            assert_eq!(from, "alice");
            assert_eq!(from_ed25519_hex, alice.ed25519_pub_hex());
            assert!(has_psk);
            saw_incoming_req = true;
            break;
        }
    }
    assert!(
        saw_incoming_req,
        "bob should receive explicit IncomingPairRequest when preset_psk is unset"
    );
    assert!(alice.paired_summaries().await.is_empty());

    let bob_fp = bob
        .accept_pair_offer("alice", "482910")
        .await
        .expect("bob explicitly accepts pair offer");

    let mut alice_fp = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(ChatUiEvent::Paired {
            peer_id,
            peer_ed25519_hex,
            safety_fingerprint,
            ..
        })) = tokio::time::timeout(Duration::from_millis(500), alice_events.recv()).await
        {
            assert_eq!(peer_id, "bob");
            assert_eq!(peer_ed25519_hex, bob.ed25519_pub_hex());
            alice_fp = Some(safety_fingerprint);
            break;
        }
    }
    assert_eq!(alice_fp.as_deref(), Some(bob_fp.as_str()));

    // 5. Encrypted messages with 256-byte bucketed padding hide length differences.
    let short_msg = "hi";
    let medium_msg = "Hello Bob! Testing 256B bucketed AEAD chat padding over wss:// TLS 1.3.";
    let rec_short = alice
        .send_message("bob", short_msg, false)
        .await
        .expect("send short AEAD");
    let rec_med = alice
        .send_message("bob", medium_msg, false)
        .await
        .expect("send medium AEAD");
    assert_eq!(rec_short.status, "delivered_ack");
    assert_eq!(rec_med.status, "delivered_ack");

    let padding_snap = relay.state.snapshot().await;
    let alice_aead_events: Vec<_> = padding_snap
        .recent_frames
        .iter()
        .filter(|ev| ev.from == "alice" && ev.to == "bob" && ev.frame_type == "WirePacket (ArbitraryAEAD)")
        .collect();
    assert_eq!(alice_aead_events.len(), 2);
    assert_eq!(
        alice_aead_events[0].ciphertext_bytes, alice_aead_events[1].ciphertext_bytes,
        "short and medium messages in same 256B bucket must emit identical AEAD ciphertext bytes"
    );
    assert!(
        alice_aead_events[0].ciphertext_bytes.unwrap_or(0) >= 256,
        "padded AEAD ciphertext must be at least 256B bucket size"
    );
    assert_eq!(
        alice_aead_events[0].wire_base_bytes, alice_aead_events[1].wire_base_bytes,
        "base wire cube bytes must be identical"
    );

    // Verify RawCore256 mode & Bob -> Alice reply + TMR bit-rot recovery.
    let raw_rec = bob
        .send_message("alice", "PING#42", true)
        .await
        .expect("send RawCore256");
    assert_eq!(raw_rec.status, "delivered_ack");

    let noisy_text = "Recoverable noisy message with 8 corrupted bytes across TMR replicas!";
    let noisy_rec = bob
        .send_with_noise("alice", noisy_text, false, 8)
        .await
        .expect("noisy send must heal and ACK");
    assert_eq!(noisy_rec.status, "delivered_ack");

    let alice_bob_msgs = alice.paired_summaries().await[0].messages.clone();
    assert!(alice_bob_msgs
        .iter()
        .any(|m| m.direction == "in" && m.text == "PING#42"));
    let healed_entry = alice_bob_msgs
        .iter()
        .find(|m| m.direction == "in" && m.text == noisy_text)
        .expect("alice healed noisy message");
    assert!(healed_entry.healed_bits > 0);

    // 6. DH-ratcheted epoch hop + subsequent bidirectional messaging.
    let new_epoch = alice.hop_epoch("bob").await.expect("alice hop epoch");
    assert_eq!(new_epoch, 1);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut bob_hopped = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(ChatUiEvent::EpochHopped {
            peer_id,
            direction,
            new_epoch: ep,
        })) = tokio::time::timeout(Duration::from_millis(500), bob_events.recv()).await
        {
            if peer_id == "alice" && direction == "rx" && ep == 1 {
                bob_hopped = true;
                break;
            }
        }
    }
    assert!(bob_hopped, "bob must process signed EpochHopNotice + DH ratchet");

    let post_hop_ab = alice
        .send_message("bob", "Alice->Bob post-hop DH ratcheted message!", false)
        .await
        .expect("alice->bob post-hop send");
    assert_eq!(post_hop_ab.status, "delivered_ack");

    let post_hop_ba = bob
        .send_message("alice", "Bob->Alice post-hop message!", false)
        .await
        .expect("bob->alice post-hop send");
    assert_eq!(post_hop_ba.status, "delivered_ack");

    // 7. Constant-work zero-oracle honey probe does NOT desync Bob's RX mesh.
    let honey_out = bob
        .simulate_honey_probe("alice")
        .await
        .expect("honey probe returns decoy");
    assert!(!honey_out.is_empty());

    let after_honey = alice
        .send_message("bob", "Genuine frame right after honey probe", false)
        .await
        .expect("alice->bob continues without desync after honey probe");
    assert_eq!(after_honey.status, "delivered_ack");

    // 8. Blind relay holds ZERO plaintext and ZERO key material.
    let snap = relay.state.snapshot().await;
    assert!(snap.total_routed_frames >= 6);
    let snap_json = serde_json::to_string(&snap).unwrap();
    assert!(!snap_json.contains("Hello Bob"));
    assert!(!snap_json.contains("Genuine frame"));
    assert!(!snap_json.contains("MotherCube"));

    // 9. Drop Bob -> verify offline identity pinning blocks impostor AND Alice rolls back cleanly.
    let tx_seq_before = alice.paired_summaries().await[0].tx_stats.sequence;
    drop(bob);

    let wait_offline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < wait_offline {
        if !alice.online_peer_ids().await.iter().any(|p| p == "bob") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Impostor cannot register as offline "bob" with a different Ed25519 key.
    let offline_impostor = DeviceIdentity::ephemeral_csprng("bob").unwrap();
    let err_offline_pin = ChatNode::connect_with_config(
        offline_impostor,
        &wss_url,
        ClientTlsConfig::PinnedCertSha256(pin_digest),
        false,
    )
    .await
    .err()
    .expect("offline impostor must be blocked by Ed25519 pin");
    assert!(err_offline_pin.contains("identity_mismatch"));

    // Reconnect real Bob? Send offline rollback check first while Bob is offline:
    let offline_send_err = alice
        .send_message("bob", "this must fail and roll back cleanly", false)
        .await
        .expect_err("sending to offline peer must error");
    assert!(offline_send_err.contains("offline") || offline_send_err.contains("rolled back"));

    let tx_seq_after = alice.paired_summaries().await[0].tx_stats.sequence;
    assert_eq!(
        tx_seq_before, tx_seq_after,
        "outbound TX sequence must roll back cleanly on offline failure"
    );

    // Verify legitimate Bob key CAN reconnect cleanly after disconnect.
    let bob_rejoined = ChatNode::connect_with_config(
        bob_id,
        &wss_url,
        ClientTlsConfig::PinnedCertSha256(pin_digest),
        false,
    )
    .await
    .expect("legitimate bob identity can reconnect");
    drop(bob_rejoined);
    drop(alice);
    relay.handle.abort();
}

#[tokio::test]
async fn test_preset_psk_auto_accept_and_dpapi_keystore_persistence() {
    let ks_dir = unique_temp_dir("dpapi_keystore");

    // Create OS-sealed identity with passphrase and reload across restart.
    let id1 = DeviceIdentity::load_or_create("alice-store", Some(&ks_dir), Some("2fa-pin-77"))
        .expect("create sealed keystore");
    let pub1 = id1.ed25519_pub();
    let hw1 = id1.hardware_provider().device_hw_id();

    let id1_reloaded =
        DeviceIdentity::load_or_create("alice-store", Some(&ks_dir), Some("2fa-pin-77"))
            .expect("reload sealed keystore with correct passphrase");
    assert_eq!(id1_reloaded.ed25519_pub(), pub1);
    assert_eq!(id1_reloaded.hardware_provider().device_hw_id(), hw1);

    let wrong_pass =
        DeviceIdentity::load_or_create("alice-store", Some(&ks_dir), Some("wrong-passphrase"));
    assert!(wrong_pass.is_err(), "wrong passphrase must fail unseal");

    // Test explicit preset_psk auto-accept path over wss://.
    let relay = start_relay_server(
        "127.0.0.1:0".parse().unwrap(),
        RelayTlsConfig::SelfSigned {
            san_hosts: vec!["localhost".into(), "127.0.0.1".into()],
        },
    )
    .await
    .expect("start wss relay");
    let pin = parse_sha256_pin_hex(relay.tls_cert_sha256_hex.as_ref().unwrap()).unwrap();
    let url = format!("wss://{}/ws", relay.addr);

    let bob_id = DeviceIdentity::load_or_create("bob-store", Some(&ks_dir), None)
        .expect("create bob keystore");
    let alice =
        ChatNode::connect_with_config(id1_reloaded, &url, ClientTlsConfig::PinnedCertSha256(pin), false)
            .await
            .unwrap();
    let bob = ChatNode::connect_with_config(bob_id, &url, ClientTlsConfig::PinnedCertSha256(pin), false)
        .await
        .unwrap();

    bob.set_preset_psk("alice-store", "991122").await;
    alice
        .initiate_pair("bob-store", Some("991122"), ChatMeshProfile::Compact)
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        if !alice.paired_summaries().await.is_empty() && !bob.paired_summaries().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(alice.paired_summaries().await.len(), 1);
    assert_eq!(bob.paired_summaries().await.len(), 1);

    let res = alice
        .send_message("bob-store", "Preset PSK + DPAPI persisted!", false)
        .await
        .expect("send over auto-accepted Compact profile");
    assert_eq!(res.status, "delivered_ack");

    drop(alice);
    drop(bob);
    relay.handle.abort();
    let _ = std::fs::remove_dir_all(&ks_dir);
}
