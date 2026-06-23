#ifndef KS_HSM_QUORUM_H
#define KS_HSM_QUORUM_H

#include "include/ks_attestation.h"
#include "include/ks_errors.h"

ks_error_t ks_hsm_quorum_init(ks_hsm_quorum_t *quorum, uint32_t total_tokens, uint32_t required);
ks_error_t ks_hsm_quorum_add_token(ks_hsm_quorum_t *quorum, uint32_t token_id, const uint8_t *pubkey, size_t pubkey_len);
ks_error_t ks_hsm_quorum_sign(ks_hsm_quorum_t *quorum, const uint8_t *data, size_t data_len, uint8_t *signature_out, size_t *sig_len);
ks_error_t ks_hsm_quorum_verify(ks_hsm_quorum_t *quorum, const uint8_t *data, size_t data_len, const uint8_t *signature, size_t sig_len);
int ks_hsm_quorum_check(const ks_hsm_quorum_t *quorum);

#endif
