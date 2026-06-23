#ifndef KS_CONFIG_H
#define KS_CONFIG_H

#include "include/ks_errors.h"

typedef struct {
    char bpf_prog_dir[4096];
    char policy_dir[4096];
    char tpm2_device[256];
    int tpm2_tcti_type;
    unsigned int ring_buf_size;
    unsigned int quorum_required;
    unsigned int quorum_total;
    int log_level;
    char log_file[4096];
    int daemonize;
    char pid_file[256];
    unsigned int eval_timeout_ms;
    unsigned int attestation_interval_s;
    unsigned int max_events_per_sec;
} ks_config_t;

ks_error_t ks_config_load(ks_config_t *cfg, const char *path);
ks_error_t ks_config_default(ks_config_t *cfg);
void ks_config_dump(const ks_config_t *cfg);

#endif
