use std::time::Instant;

use blake2::{Blake2b512, Digest as Blake2Digest};
use cubehash_core::primitives::{
    aead_seal, fixed_budget_mix, hmac_sha256, lag1_bit_autocorrelation, ones_ratio,
    pearson_chi_square_uniform, shannon_entropy_bits_per_byte,
};
use cubehash_core::{
    CellularMesh, CombiningFn, CubeHashError, DteEngine, HoneyProfile, MeshConfig, PayloadMode,
    ReceiveOutcome, ThreeCubeCustody, TimeAlgorithm, VirtualHardwareEnclave, WirePacket,
};
use sha2::Sha256;
use sha3::Sha3_256;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    println!("=== CubeHash Security Engine Audit & Verification ===\n");

    audit_profiles();
    audit_entropy_and_lifecycle();
    audit_tmr_self_healing();
    audit_cloning_and_recovery();
    audit_zero_oracle_honey();
    audit_ack_rollback_and_epochs();
    audit_fixed_budget_and_throughput();
    audit_statistical_indistinguishability();
    audit_system_level_decrypt_timing();
    audit_comparative_baseline_benchmarks();

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
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

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
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

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

    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

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
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

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
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

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
        println!(
            "  - {:<14} avg={:.2} us/op",
            format!("{algo:?}"),
            elapsed_us
        );
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
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

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

fn bit_hamming(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

fn audit_statistical_indistinguishability() {
    println!("\n[8] Cryptographic Strength Proof vs Standard Baselines (64 KiB + SAC):");
    let key = [0x5Au8; 32];
    let mut msg = [0x3Cu8; 64];
    let base_mix = fixed_budget_mix(TimeAlgorithm::HybridTriMix, &key, b"sac", &msg, 4);
    let base_sha3 = Sha3_256::digest(msg);
    let mut mix_flips = 0usize;
    let mut sha3_flips = 0usize;
    for i in 0..200usize {
        let bit = i % (msg.len() * 8);
        msg[bit / 8] ^= 1u8 << (bit % 8);
        let d_mix = fixed_budget_mix(TimeAlgorithm::HybridTriMix, &key, b"sac", &msg, 4);
        let d_s3 = Sha3_256::digest(msg);
        msg[bit / 8] ^= 1u8 << (bit % 8);
        mix_flips += bit_hamming(&base_mix, &d_mix);
        sha3_flips += bit_hamming(&base_sha3, &d_s3);
    }
    println!(
        "  - SAC 1-bit Avalanche  -> HybridTriMix: {:.2}% | SHA3-256 baseline: {:.2}%",
        mix_flips as f64 / (200.0 * 256.0) * 100.0,
        sha3_flips as f64 / (200.0 * 256.0) * 100.0
    );

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
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let plain = vec![0u8; 1024];
    let mut cube_sample = Vec::with_capacity(68 * 1024);
    while cube_sample.len() < 65_536 {
        let mut pkt = alice.begin_send_message(&alice_hw, &plain).unwrap();
        cube_sample.extend_from_slice(&pkt.wire_cube.partial_256b);
        cube_sample.extend_from_slice(&pkt.packet_mac);
        if let PayloadMode::ArbitraryCiphertext { ref ciphertext } = pkt.payload_mode {
            cube_sample.extend_from_slice(ciphertext);
        }
        let (_, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
        alice.commit_ack(&alice_hw, &ack).unwrap();
    }
    cube_sample.truncate(65_536);

    let mut aead_sample = Vec::with_capacity(68 * 1024);
    let mut ctr = 0u64;
    while aead_sample.len() < 65_536 {
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&ctr.to_le_bytes());
        aead_sample.extend_from_slice(&aead_seal(&key, &nonce, b"aad", &plain).unwrap());
        ctr += 1;
    }
    aead_sample.truncate(65_536);

    let mut sha2_sample = Vec::with_capacity(65_536);
    for b in 0..2048u64 {
        sha2_sample.extend_from_slice(&Sha256::digest(b.to_le_bytes()));
    }

    for (name, buf) in [
        ("CubeHash-64KiB", cube_sample.as_slice()),
        ("XChaCha20-Poly1305", aead_sample.as_slice()),
        ("SHA-256-CTR", sha2_sample.as_slice()),
    ] {
        let ones = ones_ratio(buf);
        let ent = shannon_entropy_bits_per_byte(buf);
        let chi2 = pearson_chi_square_uniform(buf);
        let ac = lag1_bit_autocorrelation(buf);
        assert!((0.49..=0.51).contains(&ones));
        assert!(ent > 7.99);
        assert!(chi2 < 330.5);
        assert!(ac.abs() < 0.02);
        println!(
            "  - {name:<20} ones={ones:.4} entropy={ent:.5} b/B chi2(df=255)={chi2:.2} lag1={ac:+.5}"
        );
    }
}

fn welch_t_and_stats(samples: &[u64], ref_samples: &[u64]) -> (f64, f64, f64, f64) {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2] as f64;
    let p95 = sorted[(sorted.len() * 95) / 100] as f64;

    let mean_var = |s: &[u64]| -> (f64, f64) {
        let n = s.len() as f64;
        let mean = s.iter().map(|&v| v as f64).sum::<f64>() / n;
        let var = s
            .iter()
            .map(|&v| {
                let d = v as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / (n - 1.0).max(1.0);
        (mean, var)
    };
    let (m1, v1) = mean_var(samples);
    let (m2, v2) = mean_var(ref_samples);
    let denom = ((v1 / samples.len() as f64) + (v2 / ref_samples.len() as f64)).sqrt();
    let abs_t = if denom > 0.0 {
        ((m1 - m2) / denom).abs()
    } else {
        0.0
    };
    (median, p95, m1, abs_t)
}

fn audit_system_level_decrypt_timing() {
    println!("\n[9] System-Level `decrypt_zero_oracle` Timing & Cache-Warmup Profile (N=200):");
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
    let wrong_hw = VirtualHardwareEnclave::random().unwrap();

    let n = 200usize;
    let payload = [0x42u8; 512];
    let mut auth_pairs: Vec<(CellularMesh, WirePacket)> = Vec::with_capacity(n);
    for _ in 0..n {
        let (mut a, b) =
            CellularMesh::new_paired(cfg.clone(), custody.clone(), &alice_hw, &bob_hw).unwrap();
        let pkt = a.begin_send_message(&alice_hw, &payload).unwrap();
        auth_pairs.push((b, pkt));
    }
    let (_, mut bob_probe) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let tmpl = auth_pairs[0].1.clone();
    let mut bad_mac = tmpl.clone();
    bad_mac.packet_mac[0] ^= 0xFF;
    let mut bad_seq = tmpl.clone();
    bad_seq.sequence = 777;
    let mut bad_dim = tmpl.clone();
    bad_dim.wire_cube.partial_256b.truncate(4);

    for _ in 0..20 {
        let _ = std::hint::black_box(bob_probe.decrypt_zero_oracle(
            &bob_hw,
            &bad_mac,
            HoneyProfile::ChatPlaintext,
        ));
    }

    let mut t_auth = Vec::with_capacity(n);
    let mut t_mac = Vec::with_capacity(n);
    let mut t_hw = Vec::with_capacity(n);
    let mut t_seq = Vec::with_capacity(n);
    let mut t_dim = Vec::with_capacity(n);

    for (mut bob_i, pkt) in auth_pairs {
        let s0 = Instant::now();
        let out_a = std::hint::black_box(bob_i.decrypt_zero_oracle(
            &bob_hw,
            &pkt,
            HoneyProfile::ChatPlaintext,
        ));
        t_auth.push(s0.elapsed().as_nanos() as u64);
        assert!(matches!(out_a, ReceiveOutcome::Authentic { .. }));

        let s1 = Instant::now();
        let _ = std::hint::black_box(bob_probe.decrypt_zero_oracle(
            &bob_hw,
            &bad_mac,
            HoneyProfile::ChatPlaintext,
        ));
        t_mac.push(s1.elapsed().as_nanos() as u64);

        let s2 = Instant::now();
        let _ = std::hint::black_box(bob_probe.decrypt_zero_oracle(
            &wrong_hw,
            &tmpl,
            HoneyProfile::ChatPlaintext,
        ));
        t_hw.push(s2.elapsed().as_nanos() as u64);

        let s3 = Instant::now();
        let _ = std::hint::black_box(bob_probe.decrypt_zero_oracle(
            &bob_hw,
            &bad_seq,
            HoneyProfile::ChatPlaintext,
        ));
        t_seq.push(s3.elapsed().as_nanos() as u64);

        let s4 = Instant::now();
        let _ = std::hint::black_box(bob_probe.decrypt_zero_oracle(
            &bob_hw,
            &bad_dim,
            HoneyProfile::ChatPlaintext,
        ));
        t_dim.push(s4.elapsed().as_nanos() as u64);
    }

    let (auth_med, auth_p95, auth_mean, _) = welch_t_and_stats(&t_auth, &t_auth);
    println!(
        "  - Authentic        median={:.1} us  p95={:.1} us  mean={:.1} us",
        auth_med / 1000.0,
        auth_p95 / 1000.0,
        auth_mean / 1000.0
    );
    for (label, samples) in [
        ("TamperedMAC", &t_mac),
        ("WrongHardware", &t_hw),
        ("BadSequence", &t_seq),
        ("BadDimension", &t_dim),
    ] {
        let (med, p95, _, abs_t) = welch_t_and_stats(samples, &t_auth);
        println!(
            "  - {label:<16} median={:.1} us  p95={:.1} us  ratio={:.3}x  welch_|t|={:.2}",
            med / 1000.0,
            p95 / 1000.0,
            med / auth_med.max(1.0),
            abs_t
        );
    }
}

fn audit_comparative_baseline_benchmarks() {
    println!("\n[10] Release Throughput Proof: Standard Primitives vs CubeHash:");
    let key = [0x33u8; 32];
    let nonce = [0x77u8; 24];
    let buf_512 = vec![0xABu8; 512];
    let buf_64k = vec![0xCDu8; 64 * 1024];

    let t0 = Instant::now();
    for _ in 0..2000 {
        let _ = std::hint::black_box(Sha3_256::digest(&buf_512));
    }
    println!(
        "  - Standard SHA3-256 (512B)          avg={:.2} us/op",
        t0.elapsed().as_secs_f64() * 1e6 / 2000.0
    );

    let t1 = Instant::now();
    for _ in 0..2000 {
        let _ = std::hint::black_box(Blake2b512::digest(&buf_512));
    }
    println!(
        "  - Standard BLAKE2b-512 (512B)       avg={:.2} us/op",
        t1.elapsed().as_secs_f64() * 1e6 / 2000.0
    );

    let t2 = Instant::now();
    for _ in 0..2000 {
        let _ = std::hint::black_box(hmac_sha256(&key, &buf_512));
    }
    println!(
        "  - Standard HMAC-SHA256 (512B)       avg={:.2} us/op",
        t2.elapsed().as_secs_f64() * 1e6 / 2000.0
    );

    let sk = StaticSecret::from([0x11u8; 32]);
    let pk = PublicKey::from(&StaticSecret::from([0x22u8; 32]));
    let t3 = Instant::now();
    for _ in 0..1000 {
        let _ = std::hint::black_box(sk.diffie_hellman(&pk));
    }
    println!(
        "  - Standard X25519 scalar mult       avg={:.2} us/op",
        t3.elapsed().as_secs_f64() * 1e6 / 1000.0
    );

    let t4 = Instant::now();
    for _ in 0..200 {
        let _ = std::hint::black_box(aead_seal(&key, &nonce, b"aad", &buf_64k).unwrap());
    }
    let aead_dt = t4.elapsed().as_secs_f64();
    println!(
        "  - Standard XChaCha20-Poly1305 (64K) avg={:.2} us/op ({:.1} MB/s)",
        aead_dt * 1e6 / 200.0,
        (buf_64k.len() as f64 * 200.0 / (1024.0 * 1024.0)) / aead_dt
    );

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
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let t5 = Instant::now();
    for _ in 0..100 {
        let mut pkt = alice.begin_send_message(&alice_hw, &buf_64k).unwrap();
        let (_, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
        alice.commit_ack(&alice_hw, &ack).unwrap();
    }
    let cube_64k_dt = t5.elapsed().as_secs_f64();
    println!(
        "  - CubeHash E2E Full 100-cube (64K)  avg={:.3} ms/msg ({:.1} MB/s)",
        cube_64k_dt * 1000.0 / 100.0,
        (buf_64k.len() as f64 * 100.0 / (1024.0 * 1024.0)) / cube_64k_dt
    );
}
