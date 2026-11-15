#ifndef CUBEHASH_H
#define CUBEHASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CubeConfigHandle CubeConfigHandle;
typedef struct CubeSessionHandle CubeSessionHandle;

typedef struct CubeBuffer {
    uint8_t *ptr;
    size_t len;
} CubeBuffer;

enum CubeHashStatus {
    CUBEHASH_OK = 0,
    CUBEHASH_ERR_NULL_PTR = -1,
    CUBEHASH_ERR_INVALID_CONFIG = -2,
    CUBEHASH_ERR_UNAUTHORIZED_HW = -3,
    CUBEHASH_ERR_REPLAY = -4,
    CUBEHASH_ERR_CORRUPTED = -5,
    CUBEHASH_ERR_AUTH_FAILED = -6,
    CUBEHASH_ERR_PENDING_TX = -7,
    CUBEHASH_ERR_NO_PENDING_TX = -8,
    CUBEHASH_ERR_ACK_MISMATCH = -9,
    CUBEHASH_ERR_PAYLOAD_TOO_LARGE = -10,
    CUBEHASH_ERR_INTERNAL = -11
};

enum CubeHashOutcome {
    CUBEHASH_OUTCOME_AUTHENTIC = 1,
    CUBEHASH_OUTCOME_HONEY = 2
};

enum CubeHashHoneyProfile {
    CUBEHASH_HONEY_BIP39 = 0,
    CUBEHASH_HONEY_CHAT = 1,
    CUBEHASH_HONEY_RAW32 = 2
};

CubeConfigHandle *cubehash_config_standard(void);
CubeConfigHandle *cubehash_config_compact(void);
CubeConfigHandle *cubehash_config_custom(
    size_t sub_matrix_bytes,
    size_t core_bytes,
    size_t weight_min_bytes,
    size_t weight_max_bytes,
    size_t mesh_size,
    size_t quorum_select,
    size_t consume_for_next,
    uint32_t space_dim,
    int32_t *out_err
);
void cubehash_config_free(CubeConfigHandle *cfg);

int32_t cubehash_provision_device(
    const CubeConfigHandle *cfg,
    const uint8_t *shared_seed_32,
    const uint8_t *hw_id_16,
    const uint8_t *hw_key_32,
    CubeSessionHandle **out_session
);

int32_t cubehash_send_raw_core(
    CubeSessionHandle *session,
    const uint8_t *payload,
    size_t payload_len,
    CubeBuffer *out_packet_json
);

int32_t cubehash_send_message(
    CubeSessionHandle *session,
    const uint8_t *plaintext,
    size_t plaintext_len,
    CubeBuffer *out_packet_json
);

int32_t cubehash_receive_authenticated(
    CubeSessionHandle *session,
    const uint8_t *packet_json,
    size_t packet_len,
    CubeBuffer *out_plaintext,
    CubeBuffer *out_ack_json,
    size_t *out_healed_bits
);

int32_t cubehash_receive_zero_oracle(
    CubeSessionHandle *session,
    const uint8_t *packet_json,
    size_t packet_len,
    uint8_t honey_profile_tag,
    CubeBuffer *out_data,
    CubeBuffer *out_ack_json,
    int32_t *out_outcome_tag
);

int32_t cubehash_commit_ack(
    CubeSessionHandle *session,
    const uint8_t *ack_json,
    size_t ack_len
);

int32_t cubehash_rollback_outbound(CubeSessionHandle *session);

int32_t cubehash_hop_epoch(CubeSessionHandle *session, uint64_t *out_epoch);

int32_t cubehash_audit_stats_json(
    const CubeSessionHandle *session,
    CubeBuffer *out_stats_json
);

void cubehash_buffer_free(CubeBuffer buf);
void cubehash_session_free(CubeSessionHandle *session);

#ifdef __cplusplus
}
#endif

#endif /* CUBEHASH_H */
