#ifndef KS_ERRORS_H
#define KS_ERRORS_H

typedef enum {
    KS_SUCCESS = 0,
    KS_ERR_GENERIC = -1,
    KS_ERR_NOMEM = -2,
    KS_ERR_INVAL = -3,
    KS_ERR_NOTFOUND = -4,
    KS_ERR_PERM = -5,
    KS_ERR_BPF_LOAD = -6,
    KS_ERR_BPF_ATTACH = -7,
    KS_ERR_TPM2_INIT = -8,
    KS_ERR_TPM2_QUOTE = -9,
    KS_ERR_TPM2_PCR_EXTEND = -10,
    KS_ERR_HSM_QUORUM = -11,
    KS_ERR_HSM_SIGN = -12,
    KS_ERR_POLICY_PARSE = -13,
    KS_ERR_POLICY_EVAL = -14,
    KS_ERR_POLICY_VERSION = -15,
    KS_ERR_RING_BUF = -16,
    KS_ERR_CONFIG = -17,
    KS_ERR_IO = -18,
    KS_ERR_NOT_SUPPORTED = -19
} ks_error_t;

#endif
