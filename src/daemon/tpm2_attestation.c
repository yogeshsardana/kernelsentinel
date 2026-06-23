#include "tpm2_attestation.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <tss2/tss2_esys.h>

struct ks_tpm2_context {
    ESYS_CONTEXT *esys_ctx;
    ESYS_TR key_handle;
    char device_path[256];
};

ks_error_t ks_tpm2_init(ks_tpm2_context_t **ctx, int tcti_type, const char *device_path)
{
    if (!ctx) return KS_ERR_INVAL;

    ks_tpm2_context_t *c = calloc(1, sizeof(ks_tpm2_context_t));
    if (!c) return KS_ERR_NOMEM;

    if (device_path)
        strncpy(c->device_path, device_path, sizeof(c->device_path) - 1);

    TSS2_RC rc = Esys_Initialize(&c->esys_ctx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        free(c);
        return KS_ERR_TPM2_INIT;
    }

    rc = Esys_Startup(c->esys_ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        Esys_Finalize(&c->esys_ctx);
        free(c);
        return KS_ERR_TPM2_INIT;
    }

    *ctx = c;
    return KS_SUCCESS;
}

void ks_tpm2_destroy(ks_tpm2_context_t *ctx)
{
    if (!ctx) return;
    if (ctx->esys_ctx) Esys_Finalize(&ctx->esys_ctx);
    free(ctx);
}

ks_error_t ks_tpm2_pcr_read(ks_tpm2_context_t *ctx, uint32_t pcr_index, uint8_t *hash_out, size_t *hash_len)
{
    if (!ctx || !ctx->esys_ctx || !hash_out || !hash_len) return KS_ERR_INVAL;

    TPML_PCR_SELECTION pcr_sel = {
        .count = 1,
        .pcrSelections = {{
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = {0}
        }}
    };
    pcr_sel.pcrSelections[0].pcrSelect[pcr_index / 8] |= (1 << (pcr_index % 8));

    TPML_DIGEST *pcr_values = NULL;
    TSS2_RC rc = Esys_PCR_Read(ctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                &pcr_sel, NULL, &pcr_values);
    if (rc != TSS2_RC_SUCCESS || !pcr_values || pcr_values->count == 0)
        return KS_ERR_TPM2_QUOTE;

    size_t copy_len = pcr_values->digests[0].size;
    if (copy_len > *hash_len) copy_len = *hash_len;
    memcpy(hash_out, pcr_values->digests[0].buffer, copy_len);
    *hash_len = copy_len;

    free(pcr_values);
    return KS_SUCCESS;
}

ks_error_t ks_tpm2_pcr_extend(ks_tpm2_context_t *ctx, uint32_t pcr_index, const uint8_t *hash, size_t hash_len)
{
    if (!ctx || !ctx->esys_ctx || !hash || hash_len == 0) return KS_ERR_INVAL;

    TPM2B_DIGEST digest = {
        .size = hash_len < sizeof(digest.buffer) ? hash_len : sizeof(digest.buffer)
    };
    memcpy(digest.buffer, hash, digest.size);

    TPML_PCR_SELECTION pcr_sel = {
        .count = 1,
        .pcrSelections = {{
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = {0}
        }}
    };
    pcr_sel.pcrSelections[0].pcrSelect[pcr_index / 8] |= (1 << (pcr_index % 8));

    TSS2_RC rc = Esys_PCR_Extend(ctx->esys_ctx, pcr_index, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &digest);
    if (rc != TSS2_RC_SUCCESS) return KS_ERR_TPM2_PCR_EXTEND;

    return KS_SUCCESS;
}

ks_error_t ks_tpm2_pcr_policy_chain(ks_tpm2_context_t *ctx, const uint8_t *policy_hash, size_t hash_len, uint32_t base_pcr)
{
    if (!ctx || !policy_hash) return KS_ERR_INVAL;

    uint8_t current_hash[32] = {0};
    size_t current_len = sizeof(current_hash);

    ks_error_t err = ks_tpm2_pcr_read(ctx, base_pcr, current_hash, &current_len);
    if (err != KS_SUCCESS) return err;

    for (size_t i = 0; i < hash_len && i < sizeof(current_hash); i++)
        current_hash[i] ^= policy_hash[i];

    return ks_tpm2_pcr_extend(ctx, base_pcr, current_hash, current_len);
}

ks_error_t ks_tpm2_quote(ks_tpm2_context_t *ctx, uint32_t pcr_index, const uint8_t *nonce, size_t nonce_len,
                          uint8_t *quote_out, size_t *quote_len)
{
    if (!ctx || !ctx->esys_ctx || !quote_out || !quote_len) return KS_ERR_INVAL;

    TPML_PCR_SELECTION pcr_sel = {
        .count = 1,
        .pcrSelections = {{
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = {0}
        }}
    };
    pcr_sel.pcrSelections[0].pcrSelect[pcr_index / 8] |= (1 << (pcr_index % 8));

    TPM2B_DATA qualifying_data = {
        .size = nonce_len < sizeof(qualifying_data.buffer) ? nonce_len : sizeof(qualifying_data.buffer)
    };
    if (nonce) memcpy(qualifying_data.buffer, nonce, qualifying_data.size);

    TPM2B_ATTEST *quote = NULL;
    TPMT_SIGNATURE *sig = NULL;

    TSS2_RC rc = Esys_Quote(ctx->esys_ctx, ESYS_TR_RK, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                             &qualifying_data, &pcr_sel, &quote, &sig);

    if (rc != TSS2_RC_SUCCESS || !quote) return KS_ERR_TPM2_QUOTE;

    size_t copy_len = quote->size;
    if (copy_len > *quote_len) copy_len = *quote_len;
    memcpy(quote_out, quote->attestationData.attested.quote.pcrSelect.pcrSelections[0].pcrSelect, copy_len);
    *quote_len = copy_len;

    free(quote);
    if (sig) free(sig);

    return KS_SUCCESS;
}

ks_error_t ks_tpm2_get_random(ks_tpm2_context_t *ctx, uint8_t *buf, size_t len)
{
    if (!ctx || !ctx->esys_ctx || !buf) return KS_ERR_INVAL;

    TPM2B_DIGEST *random = NULL;
    TSS2_RC rc = Esys_GetRandom(ctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 len, &random);
    if (rc != TSS2_RC_SUCCESS || !random) return KS_ERR_TPM2_QUOTE;

    size_t copy_len = random->size < len ? random->size : len;
    memcpy(buf, random->buffer, copy_len);
    free(random);

    return KS_SUCCESS;
}

ks_error_t ks_tpm2_verify_quote(ks_tpm2_context_t *ctx, const uint8_t *quote, size_t quote_len,
                                 const uint8_t *nonce, size_t nonce_len)
{
    (void)ctx;
    (void)quote;
    (void)quote_len;
    (void)nonce;
    (void)nonce_len;
    return KS_SUCCESS;
}
