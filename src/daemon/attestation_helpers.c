#include "include/ks_attestation.h"
#include <string.h>
#include <stdlib.h>

int ks_attestation_compare(const ks_attestation_t *a, const ks_attestation_t *b)
{
    if (!a && !b) return 0;
    if (!a || !b) return -1;

    int diff = memcmp(a->hash, b->hash, KS_HASH_SIZE);
    if (diff != 0) return diff;

    if (a->pcr_index != b->pcr_index) return (int)a->pcr_index - (int)b->pcr_index;
    if (a->clock_boot_time != b->clock_boot_time)
        return a->clock_boot_time < b->clock_boot_time ? -1 : 1;

    return 0;
}

ks_error_t ks_attestation_create(const uint8_t *policy_hash, size_t hash_len, ks_attestation_t *out)
{
    if (!policy_hash || !out || hash_len == 0) return KS_ERR_INVAL;

    memset(out, 0, sizeof(*out));
    size_t copy_len = hash_len < KS_HASH_SIZE ? hash_len : KS_HASH_SIZE;
    memcpy(out->hash, policy_hash, copy_len);
    out->pcr_index = 15;
    out->pcr_selection[0] = 0x80;
    out->clock_boot_time = 0;

    return KS_SUCCESS;
}

ks_error_t ks_attestation_verify(const ks_attestation_t *attestation, const uint8_t *expected_hash, size_t hash_len)
{
    if (!attestation || !expected_hash) return KS_ERR_INVAL;

    size_t cmp_len = hash_len < KS_HASH_SIZE ? hash_len : KS_HASH_SIZE;
    if (memcmp(attestation->hash, expected_hash, cmp_len) != 0)
        return KS_ERR_TPM2_QUOTE;

    return KS_SUCCESS;
}
