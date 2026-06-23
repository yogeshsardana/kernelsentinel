#ifndef KS_ATTESTATION_H
#define KS_ATTESTATION_H

#include "kernelsentinel.h"
#include "ks_errors.h"

typedef struct ks_tpm2_context ks_tpm2_context_t;

typedef struct {
    uint32_t token_id;
    uint8_t public_key[64];
    uint8_t signature[256];
    uint32_t signature_len;
} ks_hsm_token_t;

typedef struct {
    uint32_t num_tokens;
    ks_hsm_token_t tokens[KS_MAX_HSM_TOKENS];
    uint32_t quorum_required;
} ks_hsm_quorum_t;

ks_error_t ks_tpm2_init(ks_tpm2_context_t **ctx, int tcti_type, const char *device_path);
void ks_tpm2_destroy(ks_tpm2_context_t *ctx);

ks_error_t ks_tpm2_pcr_read(ks_tpm2_context_t *ctx, uint32_t pcr_index, uint8_t *hash_out, size_t *hash_len);
ks_error_t ks_tpm2_pcr_extend(ks_tpm2_context_t *ctx, uint32_t pcr_index, const uint8_t *hash, size_t hash_len);
ks_error_t ks_tpm2_quote(ks_tpm2_context_t *ctx, uint32_t pcr_index, const uint8_t *nonce, size_t nonce_len, uint8_t *quote_out, size_t *quote_len);
ks_error_t ks_tpm2_get_random(ks_tpm2_context_t *ctx, uint8_t *buf, size_t len);

ks_error_t ks_hsm_quorum_sign(ks_hsm_quorum_t *quorum, const uint8_t *data, size_t data_len, uint8_t *signature_out, size_t *sig_len);
ks_error_t ks_hsm_quorum_verify(ks_hsm_quorum_t *quorum, const uint8_t *data, size_t data_len, const uint8_t *signature, size_t sig_len);
ks_error_t ks_hsm_quorum_collect(ks_hsm_quorum_t *quorum, uint32_t required);

ks_error_t ks_attestation_create(const uint8_t *policy_hash, size_t hash_len, ks_attestation_t *out);
ks_error_t ks_attestation_verify(const ks_attestation_t *attestation, const uint8_t *expected_hash, size_t hash_len);
int ks_attestation_compare(const ks_attestation_t *a, const ks_attestation_t *b);

#endif
