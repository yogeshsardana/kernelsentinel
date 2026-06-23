#ifndef KS_TPM2_ATTESTATION_H
#define KS_TPM2_ATTESTATION_H

#include "include/kernelsentinel.h"
#include "include/ks_attestation.h"
#include "include/ks_errors.h"

ks_error_t ks_tpm2_init(ks_tpm2_context_t **ctx, int tcti_type, const char *device_path);
void ks_tpm2_destroy(ks_tpm2_context_t *ctx);

ks_error_t ks_tpm2_pcr_read(ks_tpm2_context_t *ctx, uint32_t pcr_index, uint8_t *hash_out, size_t *hash_len);
ks_error_t ks_tpm2_pcr_extend(ks_tpm2_context_t *ctx, uint32_t pcr_index, const uint8_t *hash, size_t hash_len);
ks_error_t ks_tpm2_quote(ks_tpm2_context_t *ctx, uint32_t pcr_index, const uint8_t *nonce, size_t nonce_len, uint8_t *quote_out, size_t *quote_len);
ks_error_t ks_tpm2_get_random(ks_tpm2_context_t *ctx, uint8_t *buf, size_t len);

ks_error_t ks_tpm2_pcr_policy_chain(ks_tpm2_context_t *ctx, const uint8_t *policy_hash, size_t hash_len, uint32_t base_pcr);
ks_error_t ks_tpm2_verify_quote(ks_tpm2_context_t *ctx, const uint8_t *quote, size_t quote_len, const uint8_t *nonce, size_t nonce_len);

#endif
