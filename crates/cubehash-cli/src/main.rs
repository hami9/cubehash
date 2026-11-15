use std::time::Instant;

use cubehash_core::primitives::{fixed_budget_mix, ones_ratio, shannon_entropy_bits_per_byte};
use cubehash_core::{
    CellularMesh, CombiningFn, CubeHashError, DteEngine, HoneyProfile, MeshConfig, ReceiveOutcome,
    ThreeCubeCustody, TimeAlgorithm, VirtualHardwareEnclave,
};

fn main() {
    println!("=== CubeHash Security Engine Audit & Verification ===\n");

    audit_profiles();
    audit_entropy_and_lifecycle();
    audit_tmr_self_healing();
    audit_cloning_and_recovery();
    audit_zero_oracle_honey();
    audit_ack_rollback_and_epochs();
    audit_fixed_budget_and_throughput();

    println!("\nALL SECURITY AUDITS PASSED SUCCESSFULLY.");
}

fn audit_profiles() {
    println!("[1] Resizable Configuration Profiles:");
    for (name, cfg) in [
        ("compact", MeshConfig::compact()),
        ("standard", MeshConfig::standard()),
        ("high_capacity", MeshConfig::high_capacity()),
    ] {
        cfg.validate().expect("valid profile");
        println!(
            "  - {:<14} mesh={} quorum={}/{} core={}B sub={}B ({} bits) base_wire={}B weight={}..={}B space={}^3",
            name,
            cfg.mesh_size,
            cfg.quorum_select,
            cfg.consume_for_next,
            cfg.core_bytes,
            cfg.sub_matrix_bytes,
            cfg.sub_matrix_bits(),
            cfg.wire_cube_base_bytes(),
            cfg.weight_min_bytes,
            cfg.weight_max_bytes,
            cfg.space_dim
        );
    }
}

fn audit_entropy_and_lifecycle() {
    let cfg = MeshConfig::standard();
    let custody = ThreeCubeCustody::generate(
        TimeAlgorithm::HybridTriMix,
        CombiningFn::FeistelNonLinear,
        cfg.quorum_select,
        cfg.consume_for_next,
    )
    .unwrap();
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let stats = alice.audit_stats();
    println!(
        "\n[2] 100-Cube Mesh Baseline: cubes={} ram={} bytes (~{:.1} KB) ones_ratio={:.4} entropy={:.3} b/B",
        stats.mesh_size,
        stats.approx_ram_bytes,
        stats.approx_ram_bytes as f64 / 1024.0,
        stats.avg_ones_ratio,
        stats.avg_entropy_bits_per_byte
    );

    let mut wire_sample = Vec::new();
    for i in 1..=110u64 {
        let mut pkt = alice
            .begin_send_message(&alice_hw, format!("audit-msg-{i}").as_bytes())
            .unwrap();
        wire_sample.extend_from_slice(&pkt.wire_cube.partial_256b);
        wire_sample.extend_from_slice(&pkt.wire_cube.partial_1000b);
        wire_sample.extend_from_slice(&pkt.wire_cube.weight_padding);
        let (_, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
        alice.commit_ack(&alice_hw, &ack).unwrap();
    }
    println!(
        "    110-msg rotation OK -> oldest_gen={} wire_ones_ratio={:.4} wire_entropy={:.4} b/B",
        alice.cubes().iter().map(|c| c.generation).min().unwrap(),
        ones_ratio(&wire_sample),
        shannon_entropy_bits_per_byte(&wire_sample)
    );
}

fn audit_tmr_self_healing() {
    let cfg = MeshConfig::standard();
    let custody = ThreeCubeCustody::generate(
        TimeAlgorithm::Blake2b,
        CombiningFn::XorFoldMix,
        cfg.quorum_select,
        cfg.consume_for_next,
    )
    .unwrap();
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let mut pkt = alice
        .begin_send_raw_core(&alice_hw, b"TMR-CRITICAL-20BYTES")
        .unwrap();
    for i in 0..8 {
        pkt.wire_cube.partial_256b[i] ^= 0xAA;
        pkt.wire_cube.partial_1000b[16 + i] ^= 0x55;
    }
    let (pt, ack, healed) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
    assert_eq!(pt, b"TMR-CRITICAL-20BYTES");
    alice.commit_ack(&alice_hw, &ack).unwrap();
    println!(
        "\n[3] Bitwise Majority Voting (TMR): injected 64 bit flips -> repaired {} bits, MAC verified OK",
        healed
    );
}

fn audit_cloning_and_recovery() {
    let cfg = MeshConfig::standard();
    let custody = ThreeCubeCustody::generate(
        TimeAlgorithm::Sha3_256,
        CombiningFn::HmacTreeCombine,
        cfg.quorum_select,
        cfg.consume_for_next,
    )
    .unwrap();
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let eve_hw = VirtualHardwareEnclave::random().unwrap();
    let new_hw = VirtualHardwareEnclave::random().unwrap();

    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let clone_err = alice.begin_send_message(&eve_hw, b"steal").unwrap_err();
    assert_eq!(clone_err, CubeHashError::UnauthorizedHardware);

    alice.recover_onto_new_hardware(&new_hw).unwrap();
    let mut pkt = alice
        .begin_send_message(&new_hw, b"recovered-device")
        .unwrap();
    let (pt, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
    assert_eq!(pt, b"recovered-device");
    alice.commit_ack(&new_hw, &ack).unwrap();
    println!("\n[4] Hardware Lock & 3-Cube Recovery: cloning blocked ({clone_err}), recovery onto new device OK");
}

fn audit_zero_oracle_honey() {
    let cfg = MeshConfig::standard();
    let custody = ThreeCubeCustody::generate(
        TimeAlgorithm::HybridTriMix,
        CombiningFn::FeistelNonLinear,
        cfg.quorum_select,
        cfg.consume_for_next,
    )
    .unwrap();
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let attacker_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let pkt = alice.begin_send_message(&alice_hw, b"real secret").unwrap();
    let decoy = bob.decrypt_zero_oracle(&attacker_hw, &pkt, HoneyProfile::Bip39ChecksumPhrase);
    let phrase = match decoy {
        ReceiveOutcome::HoneyDeception {
            plausible_output, ..
        } => String::from_utf8(plausible_output).unwrap(),
        ReceiveOutcome::Authentic { .. } => unreachable!(),
    };
    assert!(DteEngine::verify_bip39_like_checksum(&phrase));

    let real = bob.decrypt_zero_oracle(&bob_hw, &pkt, HoneyProfile::ChatPlaintext);
    match real {
        ReceiveOutcome::Authentic { plaintext, ack, .. } => {
            assert_eq!(plaintext, b"real secret");
            alice.commit_ack(&alice_hw, &ack).unwrap();
        }
        ReceiveOutcome::HoneyDeception { .. } => unreachable!(),
    }
    println!(
        "\n[5] Zero-Oracle Honey DTE: attacker probe emitted checksum-valid decoy \"{phrase}\" without desync"
    );
}

fn audit_ack_rollback_and_epochs() {
    let cfg = MeshConfig::standard();
    let custody = ThreeCubeCustody::generate(
        TimeAlgorithm::HybridTriMix,
        CombiningFn::FeistelNonLinear,
        cfg.quorum_select,
        cfg.consume_for_next,
    )
    .unwrap();
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let _lost = alice.begin_send_message(&alice_hw, b"dropped").unwrap();
    alice.rollback_outbound().unwrap();
    assert_eq!(alice.sequence(), 0);

    let e_a = alice.hop_epoch(&alice_hw).unwrap();
    let e_b = bob.hop_epoch(&bob_hw).unwrap();
    assert_eq!(e_a, e_b);

    let target = alice.coords()[55];
    let (slot, steps) = alice.lookup_spiral_window(48, target);
    assert_eq!(slot, Some(55));
    println!(
        "\n[6] Rollback & Bijective Epoch Hopping: rollback clean, epoch={e_a}, spiral lookup found slot 55 in {steps} steps"
    );
}

fn audit_fixed_budget_and_throughput() {
    println!("\n[7] Fixed Step Budget & Throughput Benchmark:");
    let key = [0x99u8; 32];
    let data = [0x44u8; 128];
    for algo in [
        TimeAlgorithm::Blake2b,
        TimeAlgorithm::Sha3_256,
        TimeAlgorithm::HmacSha256,
        TimeAlgorithm::HybridTriMix,
    ] {
        let t0 = Instant::now();
        for _ in 0..500 {
            let _ = std::hint::black_box(fixed_budget_mix(algo, &key, b"bench", &data, 4));
        }
        let elapsed_us = t0.elapsed().as_micros() as f64 / 500.0;
        println!("  - {:<14} avg={:.2} us/op", format!("{algo:?}"), elapsed_us);
    }

    let cfg = MeshConfig::standard();
    let custody = ThreeCubeCustody::generate(
        TimeAlgorithm::HybridTriMix,
        CombiningFn::FeistelNonLinear,
        cfg.quorum_select,
        cfg.consume_for_next,
    )
    .unwrap();
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let msg = vec![0x55u8; 512];
    let t0 = Instant::now();
    for _ in 0..100 {
        let mut pkt = alice.begin_send_message(&alice_hw, &msg).unwrap();
        let (_, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
        alice.commit_ack(&alice_hw, &ack).unwrap();
    }
    let per_roundtrip_ms = t0.elapsed().as_secs_f64() * 1000.0 / 100.0;
    println!("  - Full 100-cube E2E roundtrip (512B send + TMR + receive + ACK): {per_roundtrip_ms:.3} ms/msg");
}
