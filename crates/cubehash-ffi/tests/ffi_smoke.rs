use std::ffi::CStr;

use cubehash_ffi::{
    cubehash_audit_stats_json, cubehash_buffer_free, cubehash_commit_ack, cubehash_config_compact,
    cubehash_config_custom, cubehash_config_free, cubehash_config_standard, cubehash_hop_epoch,
    cubehash_provision_device, cubehash_receive_authenticated, cubehash_receive_zero_oracle,
    cubehash_rollback_outbound, cubehash_send_message, cubehash_send_raw_core,
    cubehash_session_free, CubeBuffer, CUBEHASH_ERR_INVALID_CONFIG, CUBEHASH_OK,
    CUBEHASH_OUTCOME_AUTHENTIC, CUBEHASH_OUTCOME_HONEY,
};

#[test]
fn test_ffi_full_lifecycle_and_zero_oracle() {
    unsafe {
        let cfg = cubehash_config_standard();
        assert!(!cfg.is_null());

        let mut custom_err = 0;
        let bad_cfg = cubehash_config_custom(20, 32, 8, 16, 10, 4, 2, 100, &mut custom_err);
        assert!(bad_cfg.is_null());
        assert_eq!(custom_err, CUBEHASH_ERR_INVALID_CONFIG);

        let compact = cubehash_config_compact();
        assert!(!compact.is_null());
        cubehash_config_free(compact);

        let shared_seed = [0x5Au8; 32];
        let alice_hw_id = [0x11u8; 16];
        let alice_hw_key = [0x22u8; 32];
        let bob_hw_id = [0x33u8; 16];
        let bob_hw_key = [0x44u8; 32];

        let mut alice = std::ptr::null_mut();
        let mut bob = std::ptr::null_mut();
        assert_eq!(
            cubehash_provision_device(
                cfg,
                shared_seed.as_ptr(),
                alice_hw_id.as_ptr(),
                alice_hw_key.as_ptr(),
                &mut alice
            ),
            CUBEHASH_OK
        );
        assert_eq!(
            cubehash_provision_device(
                cfg,
                shared_seed.as_ptr(),
                bob_hw_id.as_ptr(),
                bob_hw_key.as_ptr(),
                &mut bob
            ),
            CUBEHASH_OK
        );

        // 1. Raw core mode + rollback
        let mut pkt_buf = CubeBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let raw_msg = b"ffi-raw-core-16b";
        assert_eq!(
            cubehash_send_raw_core(alice, raw_msg.as_ptr(), raw_msg.len(), &mut pkt_buf),
            CUBEHASH_OK
        );
        cubehash_buffer_free(pkt_buf);
        assert_eq!(cubehash_rollback_outbound(alice), CUBEHASH_OK);

        // 2. Arbitrary message send -> authenticated receive -> commit ACK
        let msg = b"Hello from C-ABI FFI!";
        let mut msg_pkt = CubeBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        assert_eq!(
            cubehash_send_message(alice, msg.as_ptr(), msg.len(), &mut msg_pkt),
            CUBEHASH_OK
        );

        let mut pt_buf = CubeBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let mut ack_buf = CubeBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let mut healed = 999usize;
        assert_eq!(
            cubehash_receive_authenticated(
                bob,
                msg_pkt.ptr,
                msg_pkt.len,
                &mut pt_buf,
                &mut ack_buf,
                &mut healed
            ),
            CUBEHASH_OK
        );
        assert_eq!(healed, 0);
        let pt_slice = std::slice::from_raw_parts(pt_buf.ptr, pt_buf.len);
        assert_eq!(pt_slice, msg);
        assert_eq!(
            cubehash_commit_ack(alice, ack_buf.ptr, ack_buf.len),
            CUBEHASH_OK
        );
        cubehash_buffer_free(msg_pkt);
        cubehash_buffer_free(pt_buf);
        cubehash_buffer_free(ack_buf);

        // 3. Zero-oracle forged packet yields Honey output (never error) + real msg still works
        let forged = b"{\"not\":\"valid\"}";
        let mut honey_out = CubeBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let mut honey_ack = CubeBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let mut outcome = 0;
        assert_eq!(
            cubehash_receive_zero_oracle(
                bob,
                forged.as_ptr(),
                forged.len(),
                0,
                &mut honey_out,
                &mut honey_ack,
                &mut outcome
            ),
            CUBEHASH_OK
        );
        assert_eq!(outcome, CUBEHASH_OUTCOME_HONEY);
        assert!(honey_out.len > 0);
        assert!(honey_ack.ptr.is_null());
        cubehash_buffer_free(honey_out);

        // 4. Epoch hop + zero-oracle authentic receive + stats JSON
        let mut epoch_a = 0u64;
        let mut epoch_b = 0u64;
        assert_eq!(cubehash_hop_epoch(alice, &mut epoch_a), CUBEHASH_OK);
        assert_eq!(cubehash_hop_epoch(bob, &mut epoch_b), CUBEHASH_OK);
        assert_eq!(epoch_a, 1);
        assert_eq!(epoch_b, 1);

        let mut msg2_pkt = CubeBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        assert_eq!(
            cubehash_send_message(alice, b"after-ffi-hop".as_ptr(), 13, &mut msg2_pkt),
            CUBEHASH_OK
        );
        let mut data2 = CubeBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let mut ack2 = CubeBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        assert_eq!(
            cubehash_receive_zero_oracle(
                bob,
                msg2_pkt.ptr,
                msg2_pkt.len,
                1,
                &mut data2,
                &mut ack2,
                &mut outcome
            ),
            CUBEHASH_OK
        );
        assert_eq!(outcome, CUBEHASH_OUTCOME_AUTHENTIC);
        assert_eq!(
            std::slice::from_raw_parts(data2.ptr, data2.len),
            b"after-ffi-hop"
        );
        assert_eq!(
            cubehash_commit_ack(alice, ack2.ptr, ack2.len),
            CUBEHASH_OK
        );
        cubehash_buffer_free(msg2_pkt);
        cubehash_buffer_free(data2);
        cubehash_buffer_free(ack2);

        let mut stats_buf = CubeBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        assert_eq!(cubehash_audit_stats_json(alice, &mut stats_buf), CUBEHASH_OK);
        let stats_str = std::str::from_utf8(std::slice::from_raw_parts(stats_buf.ptr, stats_buf.len)).unwrap();
        assert!(stats_str.contains("\"mesh_size\":100"));
        let _ = CStr::from_bytes_with_nul;
        cubehash_buffer_free(stats_buf);

        cubehash_session_free(alice);
        cubehash_session_free(bob);
        cubehash_config_free(cfg);
    }
}
