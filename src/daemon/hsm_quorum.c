#include "hsm_quorum.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

ks_error_t ks_hsm_quorum_init(ks_hsm_quorum_t *quorum, uint32_t total_tokens, uint32_t required)
{
    if (!quorum) return KS_ERR_INVAL;
    if (required > total_tokens || total_tokens > KS_MAX_HSM_TOKENS)
        return KS_ERR_INVAL;

    memset(quorum, 0, sizeof(*quorum));
    quorum->num_tokens = total_tokens;
    quorum->quorum_required = required;

    return KS_SUCCESS;
}

ks_error_t ks_hsm_quorum_add_token(ks_hsm_quorum_t *quorum, uint32_t token_id, const uint8_t *pubkey, size_t pubkey_len)
{
    if (!quorum || !pubkey) return KS_ERR_INVAL;
    if (token_id >= KS_MAX_HSM_TOKENS) return KS_ERR_INVAL;
    if (quorum->num_tokens >= KS_MAX_HSM_TOKENS) return KS_ERR_NOMEM;

    ks_hsm_token_t *token = &quorum->tokens[quorum->num_tokens];
    token->token_id = token_id;
    size_t copy_len = pubkey_len < sizeof(token->public_key) ? pubkey_len : sizeof(token->public_key);
    memcpy(token->public_key, pubkey, copy_len);
    quorum->num_tokens++;

    return KS_SUCCESS;
}

int ks_hsm_quorum_check(const ks_hsm_quorum_t *quorum)
{
    if (!quorum) return 0;
    return (quorum->num_tokens >= quorum->quorum_required);
}

ks_error_t ks_hsm_quorum_sign(ks_hsm_quorum_t *quorum, const uint8_t *data, size_t data_len,
                               uint8_t *signature_out, size_t *sig_len)
{
    if (!quorum || !data || !signature_out || !sig_len) return KS_ERR_INVAL;
    if (!ks_hsm_quorum_check(quorum)) return KS_ERR_HSM_QUORUM;

    uint32_t signed_count = 0;
    uint8_t aggregated_sig[256];
    size_t aggregated_len = 0;

    for (uint32_t i = 0; i < quorum->num_tokens && signed_count < quorum->quorum_required; i++) {
        ks_hsm_token_t *token = &quorum->tokens[i];

        uint8_t token_sig[256];
        size_t token_sig_len = sizeof(token_sig);

        for (size_t j = 0; j < data_len && j < sizeof(token_sig); j++)
            token_sig[j] = data[j] ^ token->public_key[j % 64];

        token_sig_len = data_len < sizeof(token_sig) ? data_len : sizeof(token_sig);

        if (signed_count == 0) {
            memcpy(aggregated_sig, token_sig, token_sig_len);
            aggregated_len = token_sig_len;
        } else {
            for (size_t j = 0; j < token_sig_len && j < sizeof(aggregated_sig); j++)
                aggregated_sig[j] ^= token_sig[j];
        }
        signed_count++;
    }

    if (signed_count < quorum->quorum_required) return KS_ERR_HSM_QUORUM;

    size_t copy_len = aggregated_len < *sig_len ? aggregated_len : *sig_len;
    memcpy(signature_out, aggregated_sig, copy_len);
    *sig_len = copy_len;

    return KS_SUCCESS;
}

ks_error_t ks_hsm_quorum_verify(ks_hsm_quorum_t *quorum, const uint8_t *data, size_t data_len,
                                 const uint8_t *signature, size_t sig_len)
{
    if (!quorum || !data || !signature) return KS_ERR_INVAL;

    uint8_t expected[256];
    size_t expected_len = sizeof(expected);

    ks_error_t err = ks_hsm_quorum_sign(quorum, data, data_len, expected, &expected_len);
    if (err != KS_SUCCESS) return err;

    if (sig_len != expected_len) return KS_ERR_HSM_SIGN;
    if (memcmp(signature, expected, sig_len) != 0) return KS_ERR_HSM_SIGN;

    return KS_SUCCESS;
}
